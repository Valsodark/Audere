//! System audio for screen sharing (WASAPI loopback).
//!
//! Captures what the machine is playing so a shared video or game is heard by
//! everyone, then hands raw float PCM to the webview, which turns it into a
//! second track on the existing peer connections.
//!
//! The capture deliberately targets *process* loopback with our own process
//! tree excluded, rather than the whole device. Plain device loopback would
//! also pick up the other participants' voices coming out of the speakers and
//! send them straight back, so everyone would hear themselves echo. Machines
//! without that API (before Windows 10 build 20348) fall back to device
//! loopback, which works but has exactly that echo, so the UI says so.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

#[derive(serde::Serialize)]
pub struct AudioStart {
    pub sample_rate: u32,
    pub channels: u16,
    /// False when we had to fall back to whole-device capture, which echoes.
    pub excludes_own_audio: bool,
}

/// Captured PCM waiting for the webview. Bounded: audio that arrives faster
/// than it is pulled should drop, never queue into growing latency.
pub struct AudioQueue {
    chunks: Mutex<std::collections::VecDeque<Vec<u8>>>,
    cond: Condvar,
    running: AtomicBool,
}

const MAX_QUEUED: usize = 16;

impl AudioQueue {
    fn new() -> Arc<AudioQueue> {
        Arc::new(AudioQueue {
            chunks: Mutex::new(std::collections::VecDeque::new()),
            cond: Condvar::new(),
            running: AtomicBool::new(true),
        })
    }

    fn push(&self, pcm: Vec<u8>) {
        let mut q = self.chunks.lock().unwrap();
        while q.len() >= MAX_QUEUED {
            q.pop_front();
        }
        q.push_back(pcm);
        self.cond.notify_all();
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.cond.notify_all();
    }

    /// Blocks for audio, then drains whatever else arrived. Empty means ended.
    fn take_batch(&self) -> Vec<u8> {
        let mut q = self.chunks.lock().unwrap();
        loop {
            if !q.is_empty() {
                let mut out = Vec::new();
                while let Some(c) = q.pop_front() {
                    out.extend_from_slice(&c);
                }
                return out;
            }
            if !self.running.load(Ordering::SeqCst) {
                return Vec::new();
            }
            let (guard, _) = self
                .cond
                .wait_timeout(q, std::time::Duration::from_millis(500))
                .unwrap();
            q = guard;
        }
    }
}

static CURRENT: Mutex<Option<Arc<AudioQueue>>> = Mutex::new(None);

#[cfg(windows)]
mod imp {
    use super::{AudioQueue, AudioStart};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::Media::Audio::*;
    use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Threading::{
        CreateEventW, GetCurrentProcessId, SetEvent, WaitForSingleObject,
    };
    use windows::Win32::System::Variant::VT_BLOB;
    use windows::core::{implement, Interface};

    static RUNNING: AtomicBool = AtomicBool::new(false);

    // Defined here rather than pulling in two more Windows feature crates for
    // a pair of integers.
    const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
    const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;

    /// `ActivateAudioInterfaceAsync` reports completion through this callback;
    /// the calling thread just waits on the event it signals.
    #[implement(IActivateAudioInterfaceCompletionHandler)]
    struct ActivationHandler {
        done: HANDLE,
    }

    impl IActivateAudioInterfaceCompletionHandler_Impl for ActivationHandler_Impl {
        fn ActivateCompleted(
            &self,
            _operation: windows::core::Ref<'_, IActivateAudioInterfaceAsyncOperation>,
        ) -> windows::core::Result<()> {
            unsafe {
                let _ = SetEvent(self.done);
            }
            Ok(())
        }
    }

    /// Loopback capture of everything this machine plays *except* our own
    /// process tree, so the participants' voices are not echoed back.
    unsafe fn activate_process_loopback() -> Result<IAudioClient, String> {
        unsafe {
            let done =
                CreateEventW(None, true, false, None).map_err(|e| e.to_string())?;

            // Boxed so the blob the propvariant points at cannot move, and
            // stays put for as long as the activation call can read it.
            let mut params = Box::new(AUDIOCLIENT_ACTIVATION_PARAMS {
                ActivationType: AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK,
                Anonymous: AUDIOCLIENT_ACTIVATION_PARAMS_0 {
                    ProcessLoopbackParams: AUDIOCLIENT_PROCESS_LOOPBACK_PARAMS {
                        TargetProcessId: GetCurrentProcessId(),
                        ProcessLoopbackMode:
                            PROCESS_LOOPBACK_MODE_EXCLUDE_TARGET_PROCESS_TREE,
                    },
                },
            });

            // The activation parameters travel as a VT_BLOB propvariant.
            // ManuallyDrop because the blob is ours, not COM-allocated: letting
            // anything clear this variant would free a pointer it does not own.
            let mut prop = std::mem::ManuallyDrop::new(PROPVARIANT::default());
            {
                let inner = &mut prop.Anonymous.Anonymous;
                inner.vt = VT_BLOB;
                inner.Anonymous.blob.cbSize =
                    std::mem::size_of::<AUDIOCLIENT_ACTIVATION_PARAMS>() as u32;
                inner.Anonymous.blob.pBlobData = params.as_mut() as *mut _ as *mut u8;
            }

            // Held in a binding, not a temporary: the callback fires on another
            // thread and must find the object still alive.
            let handler: IActivateAudioInterfaceCompletionHandler =
                ActivationHandler { done }.into();
            let operation = ActivateAudioInterfaceAsync(
                VIRTUAL_AUDIO_DEVICE_PROCESS_LOOPBACK,
                &IAudioClient::IID,
                Some(&*prop),
                &handler,
            )
            .map_err(|e| e.to_string())?;

            if WaitForSingleObject(done, 3000) != WAIT_OBJECT_0 {
                return Err("audio activation timed out".into());
            }

            let mut hr = windows::core::HRESULT(0);
            let mut unknown: Option<windows::core::IUnknown> = None;
            operation
                .GetActivateResult(&mut hr, &mut unknown)
                .map_err(|e| e.to_string())?;
            hr.ok().map_err(|e| e.to_string())?;
            unknown
                .ok_or("no audio client returned")?
                .cast::<IAudioClient>()
                .map_err(|e| e.to_string())
        }
    }

    /// A WAVEFORMATEX plus whatever `cbSize` extension follows it, kept as
    /// bytes. The mix format is almost always WAVEFORMATEXTENSIBLE, whose 22
    /// trailing bytes WASAPI reads back — copying only the fixed-size header
    /// leaves it reading past the end of the allocation.
    struct Format(Vec<u8>);

    impl Format {
        unsafe fn from_ptr(p: *const WAVEFORMATEX) -> Format {
            unsafe {
                let total = std::mem::size_of::<WAVEFORMATEX>() + (*p).cbSize as usize;
                Format(std::slice::from_raw_parts(p as *const u8, total).to_vec())
            }
        }

        fn as_ptr(&self) -> *const WAVEFORMATEX {
            self.0.as_ptr() as *const WAVEFORMATEX
        }

        fn header(&self) -> WAVEFORMATEX {
            unsafe { *self.as_ptr() }
        }
    }

    unsafe fn activate_device_loopback() -> Result<(IAudioClient, Format), String> {
        unsafe {
            let enumerator: IMMDeviceEnumerator =
                CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
                    .map_err(|e| e.to_string())?;
            let device = enumerator
                .GetDefaultAudioEndpoint(eRender, eConsole)
                .map_err(|e| e.to_string())?;
            let client: IAudioClient =
                device.Activate(CLSCTX_ALL, None).map_err(|e| e.to_string())?;
            let mix = client.GetMixFormat().map_err(|e| e.to_string())?;
            let format = Format::from_ptr(mix);
            windows::Win32::System::Com::CoTaskMemFree(Some(mix as *const _));
            Ok((client, format))
        }
    }

    /// 32-bit float stereo: what the process-loopback client must be given
    /// explicitly, and what the webview wants anyway.
    fn float_format(sample_rate: u32, channels: u16) -> Format {
        let bits = 32u16;
        let block_align = channels * bits / 8;
        let wf = WAVEFORMATEX {
            wFormatTag: WAVE_FORMAT_IEEE_FLOAT,
            nChannels: channels,
            nSamplesPerSec: sample_rate,
            nAvgBytesPerSec: sample_rate * block_align as u32,
            nBlockAlign: block_align,
            wBitsPerSample: bits,
            cbSize: 0,
        };
        unsafe { Format::from_ptr(&wf) }
    }

    /// Everything COM-related lives on the capture thread: the interfaces are
    /// apartment-bound and not `Send`, so the caller only receives the
    /// negotiated format back through a channel.
    pub fn start(queue: Arc<AudioQueue>) -> Result<AudioStart, String> {
        stop();
        RUNNING.store(true, Ordering::SeqCst);
        let (tx, rx) = std::sync::mpsc::channel::<Result<AudioStart, String>>();

        std::thread::spawn(move || {
            unsafe {
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            }
            match capture_loop(&queue, &tx) {
                Ok(()) => {}
                Err(e) => {
                    // If setup failed the caller is still waiting on the channel.
                    let _ = tx.send(Err(e));
                }
            }
            queue.stop();
        });

        rx.recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "audio capture did not start".to_string())?
    }

    fn capture_loop(
        queue: &Arc<AudioQueue>,
        tx: &std::sync::mpsc::Sender<Result<AudioStart, String>>,
    ) -> Result<(), String> {
        // Preferred path: everything except us. Falls back to the whole device.
        let (client, format, excludes_own_audio) = unsafe {
            match activate_process_loopback() {
                Ok(c) => (c, float_format(48_000, 2), true),
                Err(e) => {
                    crate::capture_hw::log_line(&format!(
                        "process loopback unavailable ({e}); using device loopback"
                    ));
                    let (c, f) = activate_device_loopback()?;
                    (c, f, false)
                }
            }
        };

        let event = unsafe { CreateEventW(None, false, false, None) }
            .map_err(|e| e.to_string())?;

        unsafe {
            client
                .Initialize(
                    AUDCLNT_SHAREMODE_SHARED,
                    AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
                    // 20 ms of buffer: enough to absorb scheduling jitter
                    // without adding audible delay.
                    200_000,
                    0,
                    format.as_ptr(),
                    None,
                )
                .map_err(|e| format!("audio init failed: {e}"))?;
            client.SetEventHandle(event).map_err(|e| e.to_string())?;
        }

        let capture: IAudioCaptureClient =
            unsafe { client.GetService() }.map_err(|e| e.to_string())?;
        unsafe { client.Start() }.map_err(|e| e.to_string())?;

        // WAVEFORMATEX is packed, so its fields are read into locals before use.
        let header = format.header();
        let channels = header.nChannels;
        let bits = header.wBitsPerSample;
        let rate = header.nSamplesPerSec;
        let tag = header.wFormatTag;
        let is_float =
            tag == WAVE_FORMAT_IEEE_FLOAT || (tag == WAVE_FORMAT_EXTENSIBLE && bits == 32);
        let frame_bytes = (bits / 8) as usize * channels as usize;
        crate::capture_hw::log_line(&format!(
            "audio {rate}Hz {channels}ch {bits}bit float={is_float} exclusive_of_self={excludes_own_audio}"
        ));

        let _ = tx.send(Ok(AudioStart {
            sample_rate: rate,
            channels,
            excludes_own_audio,
        }));

        while RUNNING.load(Ordering::SeqCst) && queue.running.load(Ordering::SeqCst) {
            if unsafe { WaitForSingleObject(event, 200) } != WAIT_OBJECT_0 {
                continue; // nothing playing right now
            }
            loop {
                let mut data: *mut u8 = std::ptr::null_mut();
                let mut frames = 0u32;
                let mut flags = 0u32;
                if unsafe { capture.GetBuffer(&mut data, &mut frames, &mut flags, None, None) }
                    .is_err()
                    || frames == 0
                {
                    break;
                }
                let silent = flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0;
                let mut pcm = vec![0u8; frames as usize * 4 * channels as usize];
                if !silent {
                    let src =
                        unsafe { std::slice::from_raw_parts(data, frames as usize * frame_bytes) };
                    if is_float {
                        let n = pcm.len().min(src.len());
                        pcm[..n].copy_from_slice(&src[..n]);
                    } else if bits == 16 {
                        // Widen PCM16 to the float the webview expects.
                        for (out, sample) in pcm.chunks_exact_mut(4).zip(src.chunks_exact(2)) {
                            let v = i16::from_le_bytes([sample[0], sample[1]]);
                            out.copy_from_slice(&(v as f32 / 32768.0).to_le_bytes());
                        }
                    }
                }
                let _ = unsafe { capture.ReleaseBuffer(frames) };
                queue.push(pcm);
            }
        }

        unsafe {
            let _ = client.Stop();
        }
        Ok(())
    }

    pub fn stop() {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{AudioQueue, AudioStart};
    use std::sync::Arc;
    pub fn start(_queue: Arc<AudioQueue>) -> Result<AudioStart, String> {
        Err("system audio capture is Windows-only".into())
    }
    pub fn stop() {}
}

#[tauri::command]
pub async fn start_share_audio() -> Result<AudioStart, String> {
    let queue = AudioQueue::new();
    let started = tauri::async_runtime::spawn_blocking({
        let queue = queue.clone();
        move || imp::start(queue)
    })
    .await
    .map_err(|e| e.to_string())??;

    if let Some(old) = CURRENT.lock().unwrap().replace(queue) {
        old.stop();
    }
    Ok(started)
}

/// Interleaved 32-bit float PCM. Empty means capture ended.
#[tauri::command]
pub async fn next_audio_chunk() -> tauri::ipc::Response {
    let queue = CURRENT.lock().unwrap().clone();
    let bytes = match queue {
        Some(q) => tauri::async_runtime::spawn_blocking(move || q.take_batch())
            .await
            .unwrap_or_default(),
        None => Vec::new(),
    };
    tauri::ipc::Response::new(bytes)
}

#[tauri::command]
pub async fn stop_share_audio() {
    if let Some(q) = CURRENT.lock().unwrap().take() {
        q.stop();
    }
    let _ = tauri::async_runtime::spawn_blocking(imp::stop).await;
}
