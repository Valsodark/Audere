//! Concord relay server.
//!
//! A dumb router for end-to-end encrypted blobs. It never sees plaintext
//! messages, keys, or media — it only forwards ciphertext between members of
//! a room and relays (encrypted) WebRTC signaling. Voice and video flow
//! peer-to-peer and never touch this server at all.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{mpsc, Mutex};

type Tx = mpsc::UnboundedSender<String>;

/// room name -> (client id -> (display name, outbound channel))
type Rooms = Arc<Mutex<HashMap<String, HashMap<String, (String, Tx)>>>>;

const MAX_BLOB: usize = 1 << 20; // 1 MiB per relayed message

#[tokio::main]
async fn main() {
    let state: Rooms = Arc::default();
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let app = Router::new()
        .route("/", get(|| async { "concord relay" }))
        .route("/config.json", get(config))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Concord relay listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind port");
    axum::serve(listener, app).await.expect("server error");
}

/// ICE servers handed to clients. Override with e.g.
/// ICE_SERVERS='[{"urls":"stun:stun.l.google.com:19302"},{"urls":"turn:t.example.com:3478","username":"u","credential":"p"}]'
async fn config() -> impl IntoResponse {
    let ice = std::env::var("ICE_SERVERS")
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| json!([{ "urls": "stun:stun.l.google.com:19302" }]));
    // The desktop client fetches this cross-origin (its page origin is
    // tauri.localhost), so CORS must be open. The payload is not sensitive.
    (
        [(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
        Json(json!({ "iceServers": ice })),
    )
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Rooms>) -> impl IntoResponse {
    ws.max_message_size(MAX_BLOB + 4096)
        .on_upgrade(move |socket| handle(socket, state))
}

async fn handle(socket: WebSocket, state: Rooms) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Writer task: forwards queued messages, pings every 30 s to reap dead links.
    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(Duration::from_secs(30));
        ping.tick().await; // first tick fires immediately; skip it
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Some(msg) => {
                        if sink.send(Message::Text(msg.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut my_id: Option<String> = None;
    let mut my_room: Option<String> = None;

    while let Some(Ok(msg)) = stream.next().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };

        match v["type"].as_str() {
            Some("join") if my_id.is_none() => {
                let room: String = v["room"]
                    .as_str()
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(64)
                    .collect();
                let mut name: String = v["name"]
                    .as_str()
                    .unwrap_or("anon")
                    .trim()
                    .chars()
                    .take(32)
                    .collect();
                if name.is_empty() {
                    name = "anon".into();
                }
                if room.is_empty() {
                    continue;
                }

                let id = uuid::Uuid::new_v4().to_string();
                let mut rooms = state.lock().await;
                let members = rooms.entry(room.clone()).or_default();

                // Roster as it was before this client joined.
                let peers: Vec<Value> = members
                    .iter()
                    .map(|(pid, (pname, _))| json!({ "id": pid, "name": pname }))
                    .collect();
                let _ = tx.send(json!({ "type": "welcome", "id": id, "peers": peers }).to_string());

                let join_msg = json!({ "type": "peer-join", "id": id, "name": name }).to_string();
                for (_, (_, ptx)) in members.iter() {
                    let _ = ptx.send(join_msg.clone());
                }

                members.insert(id.clone(), (name, tx.clone()));
                my_id = Some(id);
                my_room = Some(room);
            }
            // Encrypted broadcast blob (chat message or E2E control message).
            Some("chat") => {
                let (Some(id), Some(room), Some(data)) = (&my_id, &my_room, v["data"].as_str())
                else {
                    continue;
                };
                if data.len() > MAX_BLOB {
                    continue;
                }
                let rooms = state.lock().await;
                if let Some(members) = rooms.get(room) {
                    let out = json!({ "type": "chat", "from": id, "data": data }).to_string();
                    for (pid, (_, ptx)) in members.iter() {
                        if pid != id {
                            let _ = ptx.send(out.clone());
                        }
                    }
                }
            }
            // Encrypted WebRTC signaling blob for one specific peer.
            Some("signal") => {
                let (Some(id), Some(room), Some(to), Some(data)) =
                    (&my_id, &my_room, v["to"].as_str(), v["data"].as_str())
                else {
                    continue;
                };
                if data.len() > MAX_BLOB {
                    continue;
                }
                let rooms = state.lock().await;
                if let Some((_, ptx)) = rooms.get(room).and_then(|m| m.get(to)) {
                    let _ = ptx.send(
                        json!({ "type": "signal", "from": id, "data": data }).to_string(),
                    );
                }
            }
            // Latency probe: echoed straight back to the sender, never relayed.
            Some("ping") => {
                let _ = tx.send(json!({ "type": "pong", "n": v["n"] }).to_string());
            }
            _ => {}
        }
    }

    // Cleanup on disconnect.
    if let (Some(id), Some(room)) = (my_id, my_room) {
        let mut rooms = state.lock().await;
        if let Some(members) = rooms.get_mut(&room) {
            members.remove(&id);
            if members.is_empty() {
                rooms.remove(&room);
            } else {
                let out = json!({ "type": "peer-leave", "id": id }).to_string();
                for (_, (_, ptx)) in members.iter() {
                    let _ = ptx.send(out.clone());
                }
            }
        }
    }
    writer.abort();
}
