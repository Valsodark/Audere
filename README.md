# Audere

A self-hosted, Discord-style chat app with **end-to-end encrypted text chat, voice chat, camera and screen sharing**. Native executables, written in Rust.

- `server/` — the relay server (`concord-server.exe`). A small, fast binary you host anywhere. It only ever sees ciphertext.
- `client/` — the desktop app (`concord.exe`). Rust (Tauri 2) shell using the system WebView2 runtime, which provides the same hardened WebRTC media engine as Chromium (Opus, VP8/VP9, echo cancellation, hardware acceleration). UI assets are embedded in the binary — it is a single standalone exe.

## How the encryption works

- Everyone in a room enters the same **room passphrase**. Each client stretches it with PBKDF2 (310,000 iterations, SHA-256) into an AES-256-GCM key — locally. The passphrase and key never leave your device.
- Every chat message and control message is encrypted with that key before it is sent. The server relays opaque blobs.
- Voice and video use WebRTC **peer-to-peer** (mesh) with mandatory DTLS-SRTP encryption. Media never touches the server.
- The WebRTC signaling (SDP offers/answers, ICE candidates) is *itself* encrypted with the room key before being relayed, so the server cannot tamper with the DTLS fingerprints and man-in-the-middle the media. End-to-end encryption therefore holds for text, voice, and video.

### What the server *can* see (threat model)

- IP addresses, connection times, display names, room names, message sizes and timing.
- Who is in which room and (from signaling volume) who is in a voice call.
- **Not** message contents, keys, passphrases, audio, or video.

### Limitations to be aware of

- Anyone who knows (or guesses) the room passphrase can read that room. Use long, random passphrases and share them out-of-band (e.g. in person or via Signal).
- The room key is static — there is no forward secrecy: if the passphrase leaks, past captured traffic for that room could be decrypted.
- Voice/video is a full mesh: every participant sends to every other participant. Works great up to ~6–8 people in a call; beyond that you need an SFU, which is out of scope for "simple".
- The server has no accounts/authentication — anyone who can reach it can *connect* (they still can't read anything without the passphrase). For a public-internet deployment, put it behind a reverse proxy with auth, or keep it inside a VPN (WireGuard/Tailscale is perfect for this).
- Messages are not stored anywhere. History exists only in the clients that were online to receive it. That is a feature.

## Building

Requirements (Windows): [Rust](https://rustup.rs) and the MSVC Build Tools (C++ workload). The client additionally needs the WebView2 runtime, which is preinstalled on Windows 10/11.

```powershell
# Server
cd server
cargo build --release
# -> target\release\concord-server.exe

# Client
cd client\src-tauri
cargo build --release
# -> target\release\concord.exe
```

The server also builds on Linux/macOS unchanged (`cargo build --release`). The client is cross-platform via Tauri (on Linux it uses WebKitGTK instead of WebView2).

## Running

**Server** (on the machine you self-host from):

```powershell
concord-server.exe            # listens on port 3000
```

Environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `PORT` | Listen port | `3000` |
| `ICE_SERVERS` | JSON array of STUN/TURN servers handed to clients | Google STUN |

Example with a TURN server:

```powershell
$env:ICE_SERVERS = '[{"urls":"stun:stun.l.google.com:19302"},{"urls":"turn:turn.example.com:3478","username":"user","credential":"pass"}]'
concord-server.exe
```

**Client**: run `concord.exe`, enter:

- **Server** — where your relay runs, e.g. `192.168.1.10:3000`, or `wss://chat.example.com` if you put it behind a TLS reverse proxy.
- **Display name** — whatever you like.
- **Room** + **passphrase** — same values = same room. Different passphrase = unreadable gibberish.

Then use **Join Voice**, and once in voice: mute, camera share, or screen share.

## Screen sharing

Audere does not use `getDisplayMedia`. Every route through it in WebView2 drags in Chromium's own permission prompt, source picker and "sharing your screen" bar, none of which can be restyled or suppressed without breaking capture. The whole path is native instead:

- **Source picker** — monitors and windows are enumerated in Rust with live thumbnails, and drawn in the app's own UI. No system dialog appears at any point.
- **Capture** — Windows.Graphics.Capture on the GPU. Capture options (cursor, border suppression, update interval) are negotiated downwards until the machine accepts them, because older Windows builds reject the whole session rather than ignoring an unsupported option.
- **Encoding** — H.264 through Media Foundation on whichever hardware encoder exists (NVENC, QuickSync, AMF), falling back to a software MFT.
- **Playback** — encoded frames are decoded in the webview with WebCodecs and fed straight into a video track, so pixels never round-trip through a canvas or a JPEG.
- **Audio** — WASAPI process loopback captures what the machine is playing while excluding Audere's own process tree, so the other participants' voices are not echoed back to them. Machines too old for that API fall back to device loopback and say so.

A GDI plus JPEG path remains as a fallback wherever the above is unavailable.

Quality lives in the popover on the share button: **30 or 60 fps**, **360p / 480p / 720p / 1080p**, and **Adjust automatically**, which watches each peer connection's bandwidth estimate and steps down the ladder when the link cannot carry the stream. Your choice is the ceiling; auto only ever moves below it. Because WebRTC alone can lower bitrate but not what is captured, re-capturing smaller is what keeps a struggling link sharp rather than smeared.

## Remote control

The viewer hovers a shared screen tile and clicks **Control**. The person sharing gets a dialog and must click **Allow control** — nothing happens without that click. Once granted, the viewer's mouse and keyboard drive the remote machine; press **Esc** to stop.

Input events travel over a WebRTC data channel: peer-to-peer and DTLS-encrypted, so they never reach the relay server. On the host they are replayed with the Win32 `SendInput` API.

Control ends automatically when screen sharing stops, when the peer disconnects, or when the host presses **Ctrl+Alt+Break** (panic key), and the host can click the red banner to revoke at any time.

**Understand what you are granting**: an approved peer has the same access to your computer that you do — files, browser sessions, everything. Only grant it to someone you trust, and revoke when you are done. Because Concord does not run elevated, the remote peer cannot click UAC prompts, which also means UAC dialogs will freeze the session until you dismiss them locally.

### When to use something else

Concord's screen share is good for "look at my code" and casual co-working. For gaming-grade remote desktop — 4K, 120 fps, sub-10 ms latency, hardware NVENC encoding, gamepad passthrough — use [Sunshine](https://github.com/LizardByte/Sunshine) (host) with [Moonlight](https://moonlight-stream.org) (client) instead. Both are free, open source, self-hosted, and work well over Tailscale. They are purpose-built streaming stacks and will beat anything WebRTC-based for that job.

## Deployment notes

- **LAN / VPN**: works out of the box with plain `ws://host:3000`.
- **Public internet**: put the server behind a TLS reverse proxy (Caddy makes this two lines) and connect with `wss://`. Also strongly consider running your own [coturn](https://github.com/coturn/coturn) TURN server — without TURN, calls between two strictly-NATed networks may fail to connect peer-to-peer.
- Example Caddyfile:

  ```
  chat.example.com {
      reverse_proxy localhost:3000
  }
  ```

## Repo layout

```
audere/
├── server/              # Rust relay server (axum + tokio)
│   └── src/main.rs
└── client/
    ├── ui/              # app UI (embedded into the exe at build time)
    └── src-tauri/       # Rust app shell (Tauri 2)
        └── src/
            ├── capture.rs        # source enumeration + GDI/JPEG fallback
            ├── capture_hw.rs     # Graphics Capture + Media Foundation H.264
            ├── capture_audio.rs  # WASAPI loopback (excludes our own audio)
            └── input.rs          # SendInput injection for remote control
```

Because the UI is embedded at build time, editing anything under `client/ui/` needs a rebuild, not just a restart.

## Publishing a release

Binaries are attached to a [GitHub Release](https://github.com/Valsodark/Audere/releases) so people can download them without installing Rust. Pushing a version tag builds and uploads them automatically:

```powershell
git tag v1.0.0
git push origin v1.0.0
```

[`.github/workflows/release.yml`](.github/workflows/release.yml) then builds both binaries on a Windows runner, packages them as `Audere-1.0.0-windows-x64.zip` together with the licence and readme, writes a SHA-256 checksum beside it, and opens the release as a **draft**. Review it on the Releases page and press Publish when it looks right — nothing goes public on its own.

The same workflow can be run by hand from the Actions tab, which is the easy way to confirm a build works before committing to a tag.

Version numbers are cheap; use one tag per released build and never move a published tag, since anyone who downloaded the old one has no way to tell it changed.

## Antivirus warnings

Audere captures the screen, captures system audio, and — only after an explicit click by the person being controlled — injects synthetic mouse and keyboard input. Those are the same capabilities remote-access malware uses, so heuristic scanners sometimes flag builds of this kind, particularly unsigned ones.

Two things help, and one actually fixes it:

- The full source is here, and the binaries build from it with a plain `cargo build --release`, so the behaviour can be audited rather than trusted.
- The executables carry publisher, copyright and description metadata, which unsigned malware usually lacks.
- The real fix is an Authenticode code-signing certificate (see below). Until a build is signed, Windows SmartScreen may warn on first run, and the warning fades as installs accumulate. A false positive can also be submitted to Microsoft at <https://www.microsoft.com/wdsi/filesubmission>.

### Signing a build

A certificate proves the binary came from a known identity and has not been altered since. Where to get one:

| Option | Cost | Notes |
|---|---|---|
| [Certum Open Source](https://shop.certum.eu/open-source-code-signing.html) | ~€30–90/yr | Cheapest route for a public open-source project like this one. Requires ID verification; arrives on a hardware token. |
| [Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/) | ~$10/mo | Microsoft's own service, no hardware token to carry. Identity verification required. |
| Standard OV (Sectigo, SSL.com, DigiCert) | ~$200–400/yr | Industry baseline. Hardware token is mandatory for all OV certificates since 2023. |
| EV certificate | ~$400–700/yr | The only option that grants SmartScreen reputation immediately rather than earning it. |
| Self-signed | free | Useful for testing the pipeline only. It does nothing for anyone else, since their machine does not trust your certificate. |

Once you hold one, signing is a single command:

```powershell
# certificate installed in the Windows certificate store
.\scripts\sign.ps1 -Thumbprint <cert-thumbprint>

# or from a .pfx file
.\scripts\sign.ps1 -PfxPath .\audere.pfx -PfxPassword (Read-Host -AsSecureString)
```

[`scripts/sign.ps1`](scripts/sign.ps1) signs both release binaries, timestamps them with an RFC 3161 server, and verifies the result against the same rules Windows applies to a downloaded program. Timestamping matters: without it, signatures stop being trusted the day the certificate expires; with it, anything signed while the certificate was valid stays valid.

## License

[GNU Affero General Public License v3.0](LICENSE).

In plain terms: anyone may use, modify and share this, including commercially. But if they distribute a modified version — or run one as a service other people can reach over a network — they must publish their changes under this same license. For a privacy tool that is the point: a hosted fork cannot quietly become closed software that users are asked to trust.

Copyright (c) 2026 Audere.
