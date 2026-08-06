//! Hardware screen-share pipeline.
//!
//! Windows.Graphics.Capture grabs the picked source on the GPU, frames are
//! converted to NV12 and encoded to H.264 by whatever hardware encoder Media
//! Foundation exposes (NVENC / QuickSync / AMF). The webview pulls the
//! encoded chunks and decodes them with WebCodecs, so a 1080p60 share costs
//! a few KB per frame instead of a full JPEG, and no frame is ever decoded
//! in JavaScript.
//!
//! `capture.rs` keeps the older GDI + JPEG path as a fallback for machines
//! or sources this pipeline cannot handle.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// What the webview needs to configure its `VideoDecoder`.
#[derive(serde::Serialize)]
pub struct HwStart {
    pub width: u32,
    pub height: u32,
    /// WebCodecs codec string; the bitstream is Annex-B, so no description.
    pub codec: String,
}

/// Encoded frames waiting to be pulled by the webview. Only a couple of
/// frames are kept: a viewer that falls behind should skip, not lag.
pub struct ChunkQueue {
    chunks: Mutex<std::collections::VecDeque<Vec<u8>>>,
    cond: Condvar,
    running: AtomicBool,
}

const MAX_QUEUED_CHUNKS: usize = 4;

impl ChunkQueue {
    fn new() -> Arc<ChunkQueue> {
        Arc::new(ChunkQueue {
            chunks: Mutex::new(std::collections::VecDeque::new()),
            cond: Condvar::new(),
            running: AtomicBool::new(true),
        })
    }

    fn push(&self, chunk: Vec<u8>) {
        let mut q = self.chunks.lock().unwrap();
        while q.len() >= MAX_QUEUED_CHUNKS {
            q.pop_front();
        }
        q.push_back(chunk);
        self.cond.notify_all();
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.cond.notify_all();
    }

    /// Blocks for the next chunk, then drains whatever else is already queued.
    /// Batching matters: one IPC round trip per frame would cap the share at
    /// whatever the round trip costs, regardless of how fast capture runs.
    /// Each chunk is length-prefixed; an empty vec means the session ended.
    fn take_batch(&self) -> Vec<u8> {
        let mut q = self.chunks.lock().unwrap();
        loop {
            if !q.is_empty() {
                let mut out = Vec::new();
                while let Some(c) = q.pop_front() {
                    out.extend_from_slice(&(c.len() as u32).to_le_bytes());
                    out.extend_from_slice(&c);
                }
                return out;
            }
            if !self.running.load(Ordering::SeqCst) {
                return Vec::new();
            }
            let (guard, _) = self
                .cond
                .wait_timeout(q, std::time::Duration::from_millis(1000))
                .unwrap();
            q = guard;
        }
    }
}

static CURRENT: Mutex<Option<Arc<ChunkQueue>>> = Mutex::new(None);

/// Per-stage counters so a slow share can be diagnosed from the running app
/// instead of a profiler. Reset at the start of every session.
pub mod stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub static CAPTURED: AtomicU64 = AtomicU64::new(0);
    pub static ENCODED: AtomicU64 = AtomicU64::new(0);
    pub static CONVERT_US: AtomicU64 = AtomicU64::new(0);
    pub static READBACK_US: AtomicU64 = AtomicU64::new(0);
    pub static ENCODE_US: AtomicU64 = AtomicU64::new(0);

    pub fn reset() {
        CAPTURED.store(0, Ordering::Relaxed);
        ENCODED.store(0, Ordering::Relaxed);
        CONVERT_US.store(0, Ordering::Relaxed);
        READBACK_US.store(0, Ordering::Relaxed);
        ENCODE_US.store(0, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Diagnostics land in a temp file so a slow share can be inspected after the
/// fact instead of being described from memory.
pub fn log_path() -> std::path::PathBuf {
    std::env::temp_dir().join("concord-capture.log")
}

pub fn log_line(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{secs}] {msg}");
    }
}

#[tauri::command]
pub fn hw_log(line: String) {
    log_line(&line);
}

#[derive(serde::Serialize)]
pub struct HwStats {
    pub captured: u64,
    pub encoded: u64,
    /// Mean BGRA -> NV12 conversion cost per captured frame, milliseconds.
    pub convert_ms: f64,
    /// Mean time inside the encoder per produced frame, milliseconds.
    pub encode_ms: f64,
}

#[tauri::command]
pub fn hw_stats() -> HwStats {
    let captured = stats::get(&stats::CAPTURED).max(1);
    let encoded = stats::get(&stats::ENCODED).max(1);
    HwStats {
        captured: stats::get(&stats::CAPTURED),
        encoded: stats::get(&stats::ENCODED),
        convert_ms: stats::get(&stats::CONVERT_US) as f64 / captured as f64 / 1000.0,
        encode_ms: stats::get(&stats::ENCODE_US) as f64 / encoded as f64 / 1000.0,
    }
}

#[cfg(windows)]
mod imp {
    use super::{ChunkQueue, HwStart};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
    use windows::core::Interface;

    use rayon::prelude::*;

    use windows_capture::capture::{CaptureControl, Context, GraphicsCaptureApiHandler};
    use windows_capture::frame::Frame;
    use windows_capture::graphics_capture_api::InternalCaptureControl;
    use windows_capture::monitor::Monitor;
    use windows_capture::settings::{
        ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
        MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
    };
    use windows_capture::window::Window as CaptureWindow;

    /// Handoff between the capture callback and the encoder thread. Only the
    /// newest frame is kept, so a slow encoder drops frames instead of
    /// building latency.
    pub struct Shared {
        running: AtomicBool,
        slot: Mutex<Option<(Vec<u8>, i64)>>, // NV12 bytes + timestamp (µs)
        slot_cv: Condvar,
        /// Encoder dimensions, known up front from the picked source so the
        /// session never has to wait for a frame to start.
        dims: Mutex<Option<(u32, u32)>>,
        dims_cv: Condvar,
        /// Most recent frame, resent while the screen sits still. Graphics
        /// Capture delivers frames only on change, and a decoder that gets
        /// nothing for seconds looks exactly like a broken share.
        last: Mutex<Option<Vec<u8>>>,
        /// Frame budget. Not every Windows build honours the capture API's own
        /// update-interval cap, so the rate is enforced here instead.
        frame_interval: Duration,
        start: Instant,
    }

    impl Shared {
        fn new(w: u32, h: u32, fps: u32) -> Arc<Shared> {
            Arc::new(Shared {
                running: AtomicBool::new(true),
                slot: Mutex::new(None),
                slot_cv: Condvar::new(),
                dims: Mutex::new(Some((w, h))),
                dims_cv: Condvar::new(),
                last: Mutex::new(None),
                frame_interval: Duration::from_micros(1_000_000 / fps.max(1) as u64),
                start: Instant::now(),
            })
        }

        pub fn stop(&self) {
            self.running.store(false, Ordering::SeqCst);
            self.slot_cv.notify_all();
            self.dims_cv.notify_all();
        }

        fn put(&self, nv12: &[u8], ts_us: i64) {
            let mut slot = self.slot.lock().unwrap();
            match slot.as_mut() {
                Some((buf, ts)) => {
                    buf.clear();
                    buf.extend_from_slice(nv12);
                    *ts = ts_us;
                }
                None => *slot = Some((nv12.to_vec(), ts_us)),
            }
            self.slot_cv.notify_all();
        }

        /// Blocks until the next frame; `None` once the session stops. A still
        /// screen produces no new frames, so the previous one is resent to keep
        /// the stream ticking over.
        fn take(&self) -> Option<(Vec<u8>, i64)> {
            let mut slot = self.slot.lock().unwrap();
            loop {
                if let Some((buf, ts)) = slot.take() {
                    *self.last.lock().unwrap() = Some(buf.clone());
                    return Some((buf, ts));
                }
                if !self.running.load(Ordering::SeqCst) {
                    return None;
                }
                let (guard, timeout) = self
                    .slot_cv
                    .wait_timeout(slot, Duration::from_millis(150))
                    .unwrap();
                slot = guard;
                if timeout.timed_out() {
                    if let Some(buf) = self.last.lock().unwrap().clone() {
                        return Some((buf, self.start.elapsed().as_micros() as i64));
                    }
                }
            }
        }

        fn wait_dims(&self, timeout: Duration) -> Option<(u32, u32)> {
            let deadline = Instant::now() + timeout;
            let mut dims = self.dims.lock().unwrap();
            loop {
                if let Some(d) = *dims {
                    return Some(d);
                }
                if !self.running.load(Ordering::SeqCst) || Instant::now() >= deadline {
                    return None;
                }
                let (guard, _) = self
                    .dims_cv
                    .wait_timeout(dims, Duration::from_millis(100))
                    .unwrap();
                dims = guard;
            }
        }
    }

    // ---- capture ----

    pub struct Handler {
        shared: Arc<Shared>,
        raw: Vec<u8>,  // unpadded BGRA staging buffer
        nv12: Vec<u8>, // encoder input
        accepted: u64, // frames kept so far, for rate pacing
    }

    impl GraphicsCaptureApiHandler for Handler {
        type Flags = Arc<Shared>;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
            Ok(Handler {
                shared: ctx.flags,
                raw: Vec::new(),
                nv12: Vec::new(),
                accepted: 0,
            })
        }

        fn on_frame_arrived(
            &mut self,
            frame: &mut Frame,
            control: InternalCaptureControl,
        ) -> Result<(), Self::Error> {
            let Handler {
                shared,
                raw,
                nv12,
                accepted,
            } = self;

            if !shared.running.load(Ordering::SeqCst) {
                control.stop();
                return Ok(());
            }

            // Drop surplus frames before the readback, so an over-eager capture
            // source costs nothing. Pacing counts against elapsed time rather
            // than the last accepted frame: a deadline measured from arrival
            // rounds every wait up to the source's own frame interval, which
            // silently halves the rate whenever the source runs just faster
            // than the budget (90 fps in, 45 fps out).
            let elapsed = shared.start.elapsed().as_micros() as u64;
            let budget = shared.frame_interval.as_micros() as u64;
            if *accepted > elapsed / budget.max(1) {
                return Ok(());
            }
            *accepted += 1;

            let (sw, sh) = (frame.width(), frame.height());
            if sw < 2 || sh < 2 {
                return Ok(());
            }

            // Encoder dimensions are fixed for the whole session; later frames
            // (window resizes) are rescaled into them.
            let Some((tw, th)) = *shared.dims.lock().unwrap() else {
                return Ok(());
            };
            if super::stats::get(&super::stats::CAPTURED) == 0 {
                super::log_line(&format!("first frame {sw}x{sh} -> {tw}x{th}"));
            }

            // The GPU -> CPU readback is the other per-frame cost, so it is
            // timed separately from the colour conversion.
            let readback_start = Instant::now();
            let buffer = frame.buffer()?;
            let bgra = buffer.as_nopadding_buffer(raw);
            super::stats::add(
                &super::stats::READBACK_US,
                readback_start.elapsed().as_micros() as u64,
            );
            if bgra.len() < (sw * sh * 4) as usize {
                return Ok(());
            }

            nv12.resize((tw as usize * th as usize * 3) / 2, 0);
            let convert_start = Instant::now();
            bgra_to_nv12(bgra, sw, sh, nv12, tw, th);
            super::stats::add(
                &super::stats::CONVERT_US,
                convert_start.elapsed().as_micros() as u64,
            );
            super::stats::add(&super::stats::CAPTURED, 1);

            let ts = shared.start.elapsed().as_micros() as i64;
            shared.put(nv12, ts);
            Ok(())
        }

        fn on_closed(&mut self) -> Result<(), Self::Error> {
            super::log_line("capture source closed");
            self.shared.stop();
            Ok(())
        }
    }

    /// BGRA -> NV12 with nearest-neighbour scaling. NV12 is what every
    /// hardware H.264 encoder takes, and doing the conversion here keeps the
    /// GPU->encoder handoff a single copy.
    fn bgra_to_nv12(src: &[u8], sw: u32, sh: u32, dst: &mut [u8], tw: u32, th: u32) {
        let (tw_u, th_u) = (tw as usize, th as usize);
        let y_size = tw_u * th_u;
        let (y_plane, uv_plane) = dst.split_at_mut(y_size);
        let src_stride = sw as usize * 4;
        let same = sw == tw && sh == th;

        // One row per task: the planes are disjoint and every row reads its own
        // slice of the source, so the whole pass parallelises cleanly.
        y_plane
            .par_chunks_mut(tw_u)
            .enumerate()
            .for_each(|(y, dst_row)| {
                let sy = if same {
                    y
                } else {
                    (y as u64 * sh as u64 / th as u64) as usize
                };
                let src_row = &src[sy * src_stride..sy * src_stride + sw as usize * 4];
                if same {
                    // Walking both sides in lockstep drops the bounds checks
                    // and index math out of the inner loop.
                    for (out, px) in dst_row.iter_mut().zip(src_row.chunks_exact(4)) {
                        let (b, g, r) = (px[0] as i32, px[1] as i32, px[2] as i32);
                        *out = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8;
                    }
                } else {
                    for (x, out) in dst_row.iter_mut().enumerate() {
                        let p = (x as u64 * sw as u64 / tw as u64) as usize * 4;
                        let (b, g, r) =
                            (src_row[p] as i32, src_row[p + 1] as i32, src_row[p + 2] as i32);
                        *out = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8;
                    }
                }
            });

        // Chroma is half resolution in both directions; sampling the top-left
        // pixel of each 2x2 block is enough for screen content.
        uv_plane
            .par_chunks_mut(tw_u)
            .enumerate()
            .for_each(|(half_y, dst_row)| {
                let y = half_y * 2;
                let sy = if same {
                    y
                } else {
                    (y as u64 * sh as u64 / th as u64) as usize
                };
                let src_row = &src[sy * src_stride..sy * src_stride + sw as usize * 4];
                for x in (0..tw_u).step_by(2) {
                    let p = if same {
                        x * 4
                    } else {
                        (x as u64 * sw as u64 / tw as u64) as usize * 4
                    };
                    let (b, g, r) =
                        (src_row[p] as i32, src_row[p + 1] as i32, src_row[p + 2] as i32);
                    dst_row[x] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128) as u8;
                    dst_row[x + 1] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128) as u8;
                }
            });
    }

    // ---- Media Foundation H.264 encoder ----

    static MF_INIT: std::sync::Once = std::sync::Once::new();

    fn pack_u64(a: u32, b: u32) -> u64 {
        ((a as u64) << 32) | b as u64
    }

    struct Encoder {
        transform: IMFTransform,
        is_async: bool,
        provides_samples: bool,
        /// SPS/PPS reported by the encoder, re-sent ahead of every keyframe so
        /// a decoder that joins late can start.
        seq_header: Vec<u8>,
    }

    fn create_encoder(w: u32, h: u32, fps: u32, bitrate: u32) -> Result<Encoder, String> {
        unsafe {
            let in_info = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Video,
                guidSubtype: MFVideoFormat_NV12,
            };
            let out_info = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Video,
                guidSubtype: MFVideoFormat_H264,
            };

            // Hardware first, then whatever else can encode H.264.
            let mut transform = None;
            let mut is_async = false;
            for flags in [
                MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
                MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER,
            ] {
                let mut activates: *mut Option<IMFActivate> = std::ptr::null_mut();
                let mut count = 0u32;
                if MFTEnumEx(
                    MFT_CATEGORY_VIDEO_ENCODER,
                    flags,
                    Some(&in_info),
                    Some(&out_info),
                    &mut activates,
                    &mut count,
                )
                .is_err()
                    || count == 0
                {
                    continue;
                }
                let list = std::slice::from_raw_parts(activates, count as usize);
                for activate in list.iter().flatten() {
                    if let Ok(t) = activate.ActivateObject::<IMFTransform>() {
                        let attrs = t.GetAttributes().ok();
                        let async_mft = attrs
                            .as_ref()
                            .and_then(|a| a.GetUINT32(&MF_TRANSFORM_ASYNC).ok())
                            .unwrap_or(0)
                            == 1;
                        if let Some(a) = attrs.as_ref() {
                            if async_mft {
                                let _ = a.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1);
                            }
                            // Screen sharing wants latency, not compression.
                            let _ = a.SetUINT32(&MF_LOW_LATENCY, 1);
                        }
                        transform = Some(t);
                        is_async = async_mft;
                        break;
                    }
                }
                windows::Win32::System::Com::CoTaskMemFree(Some(activates as *const _));
                if transform.is_some() {
                    break;
                }
            }

            let transform = transform.ok_or("no H.264 encoder available")?;

            // Output type must be set before input type.
            let out_type = MFCreateMediaType().map_err(|e| e.to_string())?;
            out_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .map_err(|e| e.to_string())?;
            out_type
                .SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT32(&MF_MT_AVG_BITRATE, bitrate)
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT64(&MF_MT_FRAME_SIZE, pack_u64(w, h))
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT64(&MF_MT_FRAME_RATE, pack_u64(fps, 1))
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_u64(1, 1))
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .map_err(|e| e.to_string())?;
            out_type
                .SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main.0 as u32)
                .map_err(|e| e.to_string())?;
            // A keyframe every two seconds keeps late joiners from waiting long.
            let _ = out_type.SetUINT32(&MF_MT_MAX_KEYFRAME_SPACING, fps * 2);
            transform
                .SetOutputType(0, &out_type, 0)
                .map_err(|e| format!("encoder rejected H.264 output: {e}"))?;

            let in_type = MFCreateMediaType().map_err(|e| e.to_string())?;
            in_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .map_err(|e| e.to_string())?;
            in_type
                .SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)
                .map_err(|e| e.to_string())?;
            in_type
                .SetUINT64(&MF_MT_FRAME_SIZE, pack_u64(w, h))
                .map_err(|e| e.to_string())?;
            in_type
                .SetUINT64(&MF_MT_FRAME_RATE, pack_u64(fps, 1))
                .map_err(|e| e.to_string())?;
            in_type
                .SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_u64(1, 1))
                .map_err(|e| e.to_string())?;
            in_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .map_err(|e| e.to_string())?;
            transform
                .SetInputType(0, &in_type, 0)
                .map_err(|e| format!("encoder rejected NV12 input: {e}"))?;

            let info = transform.GetOutputStreamInfo(0).map_err(|e| e.to_string())?;
            let provides_samples = info.dwFlags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                    | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32)
                != 0;

            let seq_header = sequence_header(&transform);

            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(|e| e.to_string())?;
            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(|e| e.to_string())?;

            Ok(Encoder {
                transform,
                is_async,
                provides_samples,
                seq_header,
            })
        }
    }

    /// SPS/PPS blob from the negotiated output type, if the encoder publishes
    /// one out of band.
    fn sequence_header(transform: &IMFTransform) -> Vec<u8> {
        unsafe {
            let Ok(ct) = transform.GetOutputCurrentType(0) else {
                return Vec::new();
            };
            let Ok(size) = ct.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) else {
                return Vec::new();
            };
            if size == 0 {
                return Vec::new();
            }
            let mut buf = vec![0u8; size as usize];
            if ct
                .GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None)
                .is_err()
            {
                return Vec::new();
            }
            buf
        }
    }

    fn make_sample(nv12: &[u8], ts_us: i64, fps: u32) -> Result<IMFSample, String> {
        unsafe {
            let buffer = MFCreateMemoryBuffer(nv12.len() as u32).map_err(|e| e.to_string())?;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            buffer
                .Lock(&mut ptr, None, None)
                .map_err(|e| e.to_string())?;
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), ptr, nv12.len());
            buffer.Unlock().map_err(|e| e.to_string())?;
            buffer
                .SetCurrentLength(nv12.len() as u32)
                .map_err(|e| e.to_string())?;

            let sample = MFCreateSample().map_err(|e| e.to_string())?;
            sample.AddBuffer(&buffer).map_err(|e| e.to_string())?;
            // Media Foundation counts in 100ns units.
            sample
                .SetSampleTime(ts_us * 10)
                .map_err(|e| e.to_string())?;
            let _ = sample.SetSampleDuration(10_000_000 / fps.max(1) as i64);
            Ok(sample)
        }
    }

    /// Pulls one encoded frame if the encoder has one ready.
    /// `Ok(None)` means "needs more input", not failure.
    fn process_output(enc: &mut Encoder) -> Result<Option<Vec<u8>>, String> {
        let started = Instant::now();
        unsafe {
            let sample = if enc.provides_samples {
                None
            } else {
                let info = enc
                    .transform
                    .GetOutputStreamInfo(0)
                    .map_err(|e| e.to_string())?;
                let buffer = MFCreateMemoryBuffer(info.cbSize.max(1 << 20))
                    .map_err(|e| e.to_string())?;
                let s = MFCreateSample().map_err(|e| e.to_string())?;
                s.AddBuffer(&buffer).map_err(|e| e.to_string())?;
                Some(s)
            };

            let mut out = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(sample),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            };
            let mut status = 0u32;
            let result = enc
                .transform
                .ProcessOutput(0, std::slice::from_mut(&mut out), &mut status);

            let produced = std::mem::ManuallyDrop::take(&mut out.pSample);
            let _ = std::mem::ManuallyDrop::take(&mut out.pEvents);

            if let Err(e) = result {
                if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT {
                    return Ok(None);
                }
                if e.code() == MF_E_TRANSFORM_STREAM_CHANGE {
                    // Encoder renegotiated: accept its type and carry on.
                    if let Ok(t) = enc.transform.GetOutputAvailableType(0, 0) {
                        let _ = enc.transform.SetOutputType(0, &t, 0);
                    }
                    enc.seq_header = sequence_header(&enc.transform);
                    return Ok(None);
                }
                return Err(e.to_string());
            }

            let Some(sample) = produced else {
                return Ok(None);
            };

            let keyframe = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) == 1;
            let ts_us = sample.GetSampleTime().unwrap_or(0) / 10;

            let buffer = sample
                .ConvertToContiguousBuffer()
                .map_err(|e| e.to_string())?;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len = 0u32;
            buffer
                .Lock(&mut ptr, None, Some(&mut len))
                .map_err(|e| e.to_string())?;
            let payload = std::slice::from_raw_parts(ptr, len as usize).to_vec();
            let _ = buffer.Unlock();

            // 9-byte header the webview parses: keyframe flag + timestamp.
            let prepend_header = keyframe && !enc.seq_header.is_empty() && !starts_with_sps(&payload);
            let mut chunk =
                Vec::with_capacity(9 + payload.len() + if prepend_header { enc.seq_header.len() } else { 0 });
            chunk.push(u8::from(keyframe));
            chunk.extend_from_slice(&ts_us.to_le_bytes());
            if prepend_header {
                chunk.extend_from_slice(&enc.seq_header);
            }
            chunk.extend_from_slice(&payload);
            super::stats::add(&super::stats::ENCODE_US, started.elapsed().as_micros() as u64);
            super::stats::add(&super::stats::ENCODED, 1);
            Ok(Some(chunk))
        }
    }

    /// True when the Annex-B payload already opens with a sequence parameter
    /// set, in which case the out-of-band copy would be redundant.
    fn starts_with_sps(data: &[u8]) -> bool {
        let nal = if data.starts_with(&[0, 0, 0, 1]) {
            data.get(4)
        } else if data.starts_with(&[0, 0, 1]) {
            data.get(3)
        } else {
            None
        };
        matches!(nal, Some(b) if b & 0x1f == 7)
    }

    fn encoder_thread(shared: Arc<Shared>, queue: Arc<ChunkQueue>, fps: u32, bitrate: u32) {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
        MF_INIT.call_once(|| unsafe {
            let _ = MFStartup(MF_SDK_VERSION << 16 | MF_API_VERSION, MFSTARTUP_NOSOCKET);
        });

        let Some((w, h)) = shared.wait_dims(Duration::from_secs(3)) else {
            shared.stop();
            queue.stop();
            return;
        };

        let mut enc = match create_encoder(w, h, fps, bitrate) {
            Ok(e) => e,
            Err(e) => {
                super::log_line(&format!("encoder setup failed: {e}"));
                shared.stop();
                queue.stop();
                return;
            }
        };
        super::log_line(&format!(
            "session {w}x{h} @{fps}fps bitrate={bitrate} async_mft={} provides_samples={}",
            enc.is_async, enc.provides_samples
        ));

        {
            // Background reporter: one line every two seconds showing what each
            // stage actually managed.
            let shared = shared.clone();
            std::thread::spawn(move || {
                let (mut last_cap, mut last_enc) = (0u64, 0u64);
                while shared.running.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_secs(2));
                    let cap = super::stats::get(&super::stats::CAPTURED);
                    let enc = super::stats::get(&super::stats::ENCODED);
                    let conv_us = super::stats::get(&super::stats::CONVERT_US);
                    let read_us = super::stats::get(&super::stats::READBACK_US);
                    let enc_us = super::stats::get(&super::stats::ENCODE_US);
                    super::log_line(&format!(
                        "captured {}/s encoded {}/s readback {:.1}ms convert {:.1}ms encode {:.1}ms",
                        (cap - last_cap) / 2,
                        (enc - last_enc) / 2,
                        read_us as f64 / cap.max(1) as f64 / 1000.0,
                        conv_us as f64 / cap.max(1) as f64 / 1000.0,
                        enc_us as f64 / enc.max(1) as f64 / 1000.0,
                    ));
                    last_cap = cap;
                    last_enc = enc;
                }
            });
        }

        if enc.is_async {
            run_async(&mut enc, &shared, &queue, fps);
        } else {
            run_sync(&mut enc, &shared, &queue, fps);
        }

        unsafe {
            let _ = enc.transform.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = enc.transform.ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
        shared.stop();
        queue.stop();
    }

    /// Hardware encoders are asynchronous MFTs: they ask for input and
    /// announce output through an event queue rather than inline.
    fn run_async(enc: &mut Encoder, shared: &Arc<Shared>, queue: &Arc<ChunkQueue>, fps: u32) {
        let Ok(events) = enc.transform.cast::<IMFMediaEventGenerator>() else {
            return run_sync(enc, shared, queue, fps);
        };
        let mut idle_since = Instant::now();

        while shared.running.load(Ordering::SeqCst) {
            // Polling instead of a blocking GetEvent keeps the thread able to
            // notice the session stopping.
            let event = unsafe { events.GetEvent(MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS(1)) };
            let Ok(event) = event else {
                if idle_since.elapsed() > Duration::from_secs(10) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
                continue;
            };
            idle_since = Instant::now();

            let Ok(kind) = (unsafe { event.GetType() }) else {
                continue;
            };
            if kind == METransformNeedInput.0 as u32 {
                let Some((nv12, ts)) = shared.take() else { break };
                let Ok(sample) = make_sample(&nv12, ts, fps) else { break };
                if unsafe { enc.transform.ProcessInput(0, &sample, 0) }.is_err() {
                    break;
                }
            } else if kind == METransformHaveOutput.0 as u32 {
                match process_output(enc) {
                    Ok(Some(chunk)) => queue.push(chunk),
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        }
    }

    /// Software encoders take a frame and hand back whatever they have.
    fn run_sync(enc: &mut Encoder, shared: &Arc<Shared>, queue: &Arc<ChunkQueue>, fps: u32) {
        while shared.running.load(Ordering::SeqCst) {
            let Some((nv12, ts)) = shared.take() else { break };
            let Ok(sample) = make_sample(&nv12, ts, fps) else { break };
            if unsafe { enc.transform.ProcessInput(0, &sample, 0) }.is_err() {
                break;
            }
            loop {
                match process_output(enc) {
                    Ok(Some(chunk)) => queue.push(chunk),
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
        }
    }

    // ---- session control ----

    enum CaptureHandle {
        Running(CaptureControl<Handler, <Handler as GraphicsCaptureApiHandler>::Error>),
    }

    static SESSION: Mutex<Option<(Arc<Shared>, CaptureHandle)>> = Mutex::new(None);

    /// Starts capture with the richest settings the machine accepts.
    ///
    /// Cursor capture, border suppression and the update-interval cap are all
    /// newer Graphics Capture features, and a machine missing any one of them
    /// fails the whole session rather than ignoring the option. So each is
    /// dropped in turn until the capture starts.
    fn start_with_fallbacks<T>(
        item: T,
        shared: &Arc<Shared>,
        fps: u32,
    ) -> Result<CaptureControl<Handler, <Handler as GraphicsCaptureApiHandler>::Error>, String>
    where
        T: Copy + Send + 'static,
        T: TryInto<windows_capture::settings::GraphicsCaptureItemType>,
    {
        let interval =
            MinimumUpdateIntervalSettings::Custom(Duration::from_micros(1_000_000 / fps as u64));
        let attempts = [
            (
                CursorCaptureSettings::WithCursor,
                DrawBorderSettings::WithoutBorder,
                interval,
            ),
            (
                CursorCaptureSettings::WithCursor,
                DrawBorderSettings::WithoutBorder,
                MinimumUpdateIntervalSettings::Default,
            ),
            (
                CursorCaptureSettings::WithCursor,
                DrawBorderSettings::Default,
                MinimumUpdateIntervalSettings::Default,
            ),
            (
                CursorCaptureSettings::Default,
                DrawBorderSettings::Default,
                MinimumUpdateIntervalSettings::Default,
            ),
        ];

        let mut last = String::from("capture failed");
        for (idx, (cursor, border, interval)) in attempts.into_iter().enumerate() {
            match Handler::start_free_threaded(Settings::new(
                item,
                cursor,
                border,
                SecondaryWindowSettings::Default,
                interval,
                DirtyRegionSettings::Default,
                ColorFormat::Bgra8,
                shared.clone(),
            )) {
                Ok(control) => {
                    super::log_line(&format!("capture started with settings tier {idx}"));
                    return Ok(control);
                }
                Err(e) => {
                    last = e.to_string();
                    super::log_line(&format!("capture tier {idx} rejected: {last}"));
                }
            }
        }
        Err(last)
    }

    pub fn start(
        id: &str,
        max_w: u32,
        fps: u32,
        bitrate: u32,
        src_w: u32,
        src_h: u32,
        queue: Arc<ChunkQueue>,
    ) -> Result<HwStart, String> {
        stop();
        super::stats::reset();

        let fps = fps.clamp(5, 60);
        if src_w < 2 || src_h < 2 {
            return Err("source has no size".into());
        }
        // Dimensions come from the picked source, so the encoder can start
        // before the first frame lands.
        let width = src_w.min(max_w.max(320)) & !1;
        let height = (((src_h as u64 * width as u64) / src_w as u64) as u32).max(2) & !1;
        let shared = Shared::new(width, height, fps);

        let control = if let Some(rest) = id.strip_prefix("monitor:") {
            let handle = rest
                .split(':')
                .next()
                .and_then(|h| h.parse::<isize>().ok())
                .ok_or("bad monitor id")?;
            let monitor = Monitor::from_raw_hmonitor(handle as *mut std::ffi::c_void);
            start_with_fallbacks(monitor, &shared, fps)
                .map_err(|e| format!("monitor capture failed: {e}"))?
        } else if let Some(rest) = id.strip_prefix("window:") {
            let handle = rest.parse::<isize>().map_err(|_| "bad window id")?;
            let window = CaptureWindow::from_raw_hwnd(handle as *mut std::ffi::c_void);
            start_with_fallbacks(window, &shared, fps)
                .map_err(|e| format!("window capture failed: {e}"))?
        } else {
            return Err("unknown source id".into());
        };

        {
            let shared = shared.clone();
            let queue = queue.clone();
            std::thread::spawn(move || encoder_thread(shared, queue, fps, bitrate));
        }

        *SESSION.lock().unwrap() = Some((shared, CaptureHandle::Running(control)));

        Ok(HwStart {
            width,
            height,
            // Main profile; the level is advisory and Chromium accepts it.
            codec: "avc1.4D0028".into(),
        })
    }

    pub fn stop() {
        if let Some((shared, handle)) = SESSION.lock().unwrap().take() {
            shared.stop();
            let CaptureHandle::Running(control) = handle;
            let _ = control.stop();
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{ChunkQueue, HwStart};
    use std::sync::Arc;
    pub fn start(
        _id: &str,
        _max_w: u32,
        _fps: u32,
        _bitrate: u32,
        _src_w: u32,
        _src_h: u32,
        _queue: Arc<ChunkQueue>,
    ) -> Result<HwStart, String> {
        Err("hardware capture is Windows-only".into())
    }
    pub fn stop() {}
}

#[tauri::command]
pub async fn start_hw_capture(
    id: String,
    max_w: u32,
    fps: u32,
    bitrate: u32,
    src_w: u32,
    src_h: u32,
) -> Result<HwStart, String> {
    let queue = ChunkQueue::new();
    let started = tauri::async_runtime::spawn_blocking({
        let queue = queue.clone();
        move || imp::start(&id, max_w, fps, bitrate, src_w, src_h, queue)
    })
    .await
    .map_err(|e| e.to_string())??;

    if let Some(old) = CURRENT.lock().unwrap().replace(queue) {
        old.stop();
    }
    Ok(started)
}

/// One encoded frame: `[keyframe: u8][timestamp_us: i64 LE][Annex-B H.264]`.
/// An empty response means the share ended.
#[tauri::command]
pub async fn next_hw_chunk() -> tauri::ipc::Response {
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
pub async fn stop_hw_capture() {
    if let Some(q) = CURRENT.lock().unwrap().take() {
        q.stop();
    }
    let _ = tauri::async_runtime::spawn_blocking(imp::stop).await;
}
