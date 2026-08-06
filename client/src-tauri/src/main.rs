// Hide the console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod capture;
mod capture_audio;
mod capture_hw;
mod input;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            input::inject_input,
            capture::list_capture_sources,
            capture::start_native_capture,
            capture::next_frame,
            capture::stop_native_capture,
            capture_hw::start_hw_capture,
            capture_hw::next_hw_chunk,
            capture_hw::stop_hw_capture,
            capture_hw::hw_stats,
            capture_hw::hw_log,
            capture_audio::start_share_audio,
            capture_audio::next_audio_chunk,
            capture_audio::stop_share_audio
        ])
        .run(tauri::generate_context!())
        .expect("error while running Concord");
}
