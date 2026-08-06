//! Native enumeration of shareable sources (monitors and windows) with JPEG
//! thumbnails, backing the in-app screen-share picker. WebView2 only offers
//! its stock share dialog, so the picker UI lives in our webview and asks
//! this module for the source list.

#[derive(serde::Serialize, Clone)]
pub struct CaptureSource {
    /// "monitor:<hmonitor>:<x>,<y>,<w>,<h>" or "window:<hwnd>" — carries both
    /// the handle the Graphics Capture path needs and the rect the GDI
    /// fallback blits from.
    pub id: String,
    pub kind: &'static str, // "monitor" | "window"
    pub name: String,
    pub width: i32,
    pub height: i32,
    /// data:image/jpeg;base64,… preview, ready for an <img src>.
    pub thumb: String,
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// One live native-capture session. The capture thread keeps only the most
/// recent JPEG frame; the webview pulls frames with `next_frame`, so a slow
/// consumer just skips frames instead of building a queue.
pub struct Session {
    latest: Mutex<Option<Vec<u8>>>,
    cond: Condvar,
    running: AtomicBool,
}

static CURRENT: Mutex<Option<Arc<Session>>> = Mutex::new(None);

#[derive(serde::Serialize)]
pub struct CaptureDims {
    pub width: i32,
    pub height: i32,
}

#[cfg(windows)]
mod imp {
    use super::{CaptureDims, CaptureSource, Session};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use windows::Win32::Foundation::{HWND, LPARAM, RECT, TRUE};
    use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
    use windows::Win32::Graphics::Gdi::*;
    // PrintWindow is filed under XPS printing in the Win32 metadata.
    use windows::Win32::Storage::Xps::{PrintWindow, PRINT_WINDOW_FLAGS};
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::core::BOOL;

    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const THUMB_W: i32 = 320;

    /// A 32-bit top-down DIB selected into a memory DC, so GDI can draw into
    /// it and we can read the pixels straight out of `bits`.
    struct Dib {
        dc: HDC,
        bmp: HBITMAP,
        old: HGDIOBJ,
        bits: *mut u8,
        w: i32,
        h: i32,
    }

    impl Dib {
        fn new(w: i32, h: i32) -> Option<Dib> {
            unsafe {
                let bi = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER {
                        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: w,
                        biHeight: -h, // negative = top-down rows
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: 0, // BI_RGB
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let mut bits = std::ptr::null_mut();
                let bmp = CreateDIBSection(None, &bi, DIB_RGB_COLORS, &mut bits, None, 0).ok()?;
                let dc = CreateCompatibleDC(None);
                if dc.is_invalid() {
                    let _ = DeleteObject(bmp.into());
                    return None;
                }
                let old = SelectObject(dc, bmp.into());
                SetStretchBltMode(dc, HALFTONE);
                let _ = SetBrushOrgEx(dc, 0, 0, None);
                Some(Dib { dc, bmp, old, bits: bits as *mut u8, w, h })
            }
        }

        fn jpeg_bytes(&self, quality: u8) -> Option<Vec<u8>> {
            unsafe {
                let _ = GdiFlush();
            }
            let bgra =
                unsafe { std::slice::from_raw_parts(self.bits, (self.w * self.h * 4) as usize) };
            let mut out = Vec::with_capacity((self.w * self.h / 4) as usize);
            // Encoding BGRA directly skips a full-frame channel swap.
            jpeg_encoder::Encoder::new(&mut out, quality)
                .encode(bgra, self.w as u16, self.h as u16, jpeg_encoder::ColorType::Bgra)
                .ok()?;
            Some(out)
        }

        fn jpeg_data_url(&self) -> Option<String> {
            Some(format!(
                "data:image/jpeg;base64,{}",
                STANDARD.encode(self.jpeg_bytes(70)?)
            ))
        }
    }

    impl Drop for Dib {
        fn drop(&mut self) {
            unsafe {
                SelectObject(self.dc, self.old);
                let _ = DeleteDC(self.dc);
                let _ = DeleteObject(self.bmp.into());
            }
        }
    }

    fn thumb_size(w: i32, h: i32) -> (i32, i32) {
        let tw = THUMB_W.min(w.max(1));
        let th = ((h as i64 * tw as i64) / w.max(1) as i64).max(1) as i32;
        (tw, th)
    }

    // ---- monitors ----

    unsafe extern "system" fn collect_monitors(
        hm: HMONITOR,
        _dc: HDC,
        _rc: *mut RECT,
        lparam: LPARAM,
    ) -> BOOL {
        let list = unsafe { &mut *(lparam.0 as *mut Vec<HMONITOR>) };
        list.push(hm);
        TRUE
    }

    fn monitor_source(idx: usize, hm: HMONITOR) -> Option<CaptureSource> {
        unsafe {
            let mut info = MONITORINFOEXW::default();
            info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
            if !GetMonitorInfoW(hm, &mut info.monitorInfo).as_bool() {
                return None;
            }
            let r = info.monitorInfo.rcMonitor;
            let (w, h) = (r.right - r.left, r.bottom - r.top);
            if w <= 0 || h <= 0 {
                return None;
            }
            let (tw, th) = thumb_size(w, h);
            let dib = Dib::new(tw, th)?;
            let screen = GetDC(None);
            if screen.is_invalid() {
                return None;
            }
            // CAPTUREBLT includes layered (transparent) windows in the shot.
            let _ = StretchBlt(
                dib.dc, 0, 0, tw, th,
                Some(screen), r.left, r.top, w, h,
                ROP_CODE(SRCCOPY.0 | CAPTUREBLT.0),
            );
            ReleaseDC(None, screen);
            let thumb = dib.jpeg_data_url()?;
            let primary = (info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY) != 0;
            Some(CaptureSource {
                id: format!("monitor:{}:{},{},{},{}", hm.0 as isize, r.left, r.top, w, h),
                kind: "monitor",
                name: if primary {
                    format!("Screen {} (primary)", idx + 1)
                } else {
                    format!("Screen {}", idx + 1)
                },
                width: w,
                height: h,
                thumb,
            })
        }
    }

    // ---- windows ----

    unsafe extern "system" fn collect_windows(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let list = unsafe { &mut *(lparam.0 as *mut Vec<HWND>) };
        list.push(hwnd);
        TRUE
    }

    /// Top-level windows a person would recognise: visible, titled, not ours,
    /// not tool windows, not DWM-cloaked ghosts (suspended UWP apps).
    fn shareable(hwnd: HWND) -> bool {
        unsafe {
            if !IsWindowVisible(hwnd).as_bool() || IsIconic(hwnd).as_bool() {
                return false;
            }
            if GetWindowTextLengthW(hwnd) == 0 {
                return false;
            }
            let ex = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
            if ex & WS_EX_TOOLWINDOW.0 != 0 {
                return false;
            }
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == GetCurrentProcessId() {
                return false;
            }
            let mut cloaked = 0u32;
            let _ = DwmGetWindowAttribute(
                hwnd,
                DWMWA_CLOAKED,
                &mut cloaked as *mut _ as *mut _,
                std::mem::size_of::<u32>() as u32,
            );
            if cloaked != 0 {
                return false;
            }
            let mut cls = [0u16; 64];
            let n = GetClassNameW(hwnd, &mut cls);
            let cls = String::from_utf16_lossy(&cls[..n.max(0) as usize]);
            // Desktop shell windows carry titles ("Program Manager") but are
            // never something a person means to share.
            cls != "Progman" && cls != "WorkerW"
        }
    }

    fn window_source(hwnd: HWND) -> Option<CaptureSource> {
        unsafe {
            let len = GetWindowTextLengthW(hwnd);
            let mut buf = vec![0u16; len as usize + 1];
            let n = GetWindowTextW(hwnd, &mut buf);
            let name = String::from_utf16_lossy(&buf[..n.max(0) as usize]);

            let mut r = RECT::default();
            GetWindowRect(hwnd, &mut r).ok()?;
            let (w, h) = (r.right - r.left, r.bottom - r.top);
            if w < 80 || h < 60 {
                return None; // slivers aren't worth a tile
            }

            // PrintWindow renders at native size only, so draw the full
            // window first and scale down from that.
            let full = Dib::new(w, h)?;
            // 2 = PW_RENDERFULLCONTENT: also captures DirectComposition
            // surfaces (browsers, UWP), which plain PrintWindow leaves black.
            if !PrintWindow(hwnd, full.dc, PRINT_WINDOW_FLAGS(2)).as_bool() {
                return None;
            }
            let (tw, th) = thumb_size(w, h);
            let dib = Dib::new(tw, th)?;
            let _ = StretchBlt(dib.dc, 0, 0, tw, th, Some(full.dc), 0, 0, w, h, SRCCOPY);
            let thumb = dib.jpeg_data_url()?;

            Some(CaptureSource {
                id: format!("window:{}", hwnd.0 as isize),
                kind: "window",
                name,
                width: w,
                height: h,
                thumb,
            })
        }
    }

    pub fn list() -> Vec<CaptureSource> {
        let mut out = Vec::new();

        let mut monitors: Vec<HMONITOR> = Vec::new();
        unsafe {
            let _ = EnumDisplayMonitors(
                None,
                None,
                Some(collect_monitors),
                LPARAM(&mut monitors as *mut _ as isize),
            );
        }
        for (idx, hm) in monitors.into_iter().enumerate() {
            if let Some(src) = monitor_source(idx, hm) {
                out.push(src);
            }
        }

        // EnumWindows walks top-level windows in z-order, so the list comes
        // out roughly "most relevant first" like Discord's picker.
        let mut windows: Vec<HWND> = Vec::new();
        unsafe {
            let _ = EnumWindows(
                Some(collect_windows),
                LPARAM(&mut windows as *mut _ as isize),
            );
        }
        for hwnd in windows {
            if shareable(hwnd) {
                if let Some(src) = window_source(hwnd) {
                    out.push(src);
                }
            }
        }

        out
    }

    // ---- native capture (frames for the webview to stream) ----
    //
    // GDI capture of the picked source: full-resolution grab with the cursor
    // overlaid, aspect-fit scale into a fixed output size, JPEG-encode, hand
    // to the session. The webview paints frames onto a canvas and streams
    // that over the existing mesh, so no WebView2 share dialog is involved.

    enum Target {
        Monitor(RECT),
        Window(HWND),
    }

    // HWND is a raw pointer, but the capture thread is its only user.
    unsafe impl Send for Target {}

    fn parse_target(id: &str) -> Result<Target, String> {
        if let Some(rest) = id.strip_prefix("monitor:") {
            // Skip the HMONITOR field; the GDI path works from the rect.
            let rect = rest.split_once(':').map(|(_, r)| r).unwrap_or(rest);
            let mut it = rect.split(',').map(|p| p.parse::<i32>());
            match (it.next(), it.next(), it.next(), it.next()) {
                (Some(Ok(x)), Some(Ok(y)), Some(Ok(w)), Some(Ok(h))) if w > 0 && h > 0 => {
                    Ok(Target::Monitor(RECT {
                        left: x,
                        top: y,
                        right: x + w,
                        bottom: y + h,
                    }))
                }
                _ => Err("bad monitor id".into()),
            }
        } else if let Some(rest) = id.strip_prefix("window:") {
            let hwnd = rest.parse::<isize>().map_err(|_| "bad window id")?;
            Ok(Target::Window(HWND(hwnd as *mut _)))
        } else {
            Err("unknown source id".into())
        }
    }

    fn target_rect(t: &Target) -> Option<RECT> {
        match t {
            Target::Monitor(r) => Some(*r),
            Target::Window(hwnd) => unsafe {
                if !IsWindow(Some(*hwnd)).as_bool() {
                    return None;
                }
                let mut r = RECT::default();
                GetWindowRect(*hwnd, &mut r).ok()?;
                (r.right > r.left && r.bottom > r.top).then_some(r)
            },
        }
    }

    /// Draws the cursor into `dc` (which holds a capture whose top-left is
    /// `origin` in screen coordinates).
    fn draw_cursor(dc: HDC, origin_x: i32, origin_y: i32) {
        unsafe {
            let mut ci = CURSORINFO {
                cbSize: std::mem::size_of::<CURSORINFO>() as u32,
                ..Default::default()
            };
            if GetCursorInfo(&mut ci).is_err() || ci.flags != CURSOR_SHOWING {
                return;
            }
            let mut ii = ICONINFO::default();
            if GetIconInfo(ci.hCursor.into(), &mut ii).is_err() {
                return;
            }
            let _ = DrawIconEx(
                dc,
                ci.ptScreenPos.x - origin_x - ii.xHotspot as i32,
                ci.ptScreenPos.y - origin_y - ii.yHotspot as i32,
                ci.hCursor.into(),
                0,
                0,
                0,
                None,
                DI_NORMAL,
            );
            if !ii.hbmMask.is_invalid() {
                let _ = DeleteObject(ii.hbmMask.into());
            }
            if !ii.hbmColor.is_invalid() {
                let _ = DeleteObject(ii.hbmColor.into());
            }
        }
    }

    /// Grabs one frame into `full` (source resolution), cursor included.
    fn grab(target: &Target, r: RECT, full: &Dib) -> bool {
        unsafe {
            let (w, h) = (r.right - r.left, r.bottom - r.top);
            match target {
                Target::Monitor(_) => {
                    let screen = GetDC(None);
                    if screen.is_invalid() {
                        return false;
                    }
                    let ok = StretchBlt(
                        full.dc, 0, 0, w, h,
                        Some(screen), r.left, r.top, w, h,
                        ROP_CODE(SRCCOPY.0 | CAPTUREBLT.0),
                    )
                    .as_bool();
                    ReleaseDC(None, screen);
                    if !ok {
                        return false;
                    }
                }
                Target::Window(hwnd) => {
                    if !PrintWindow(*hwnd, full.dc, PRINT_WINDOW_FLAGS(2)).as_bool() {
                        return false;
                    }
                }
            }
            draw_cursor(full.dc, r.left, r.top);
            true
        }
    }

    pub fn start(
        id: &str,
        max_w: i32,
        fps: u32,
        session: Arc<Session>,
    ) -> Result<CaptureDims, String> {
        let target = parse_target(id)?;
        let r = target_rect(&target).ok_or("source is gone")?;
        let (sw, sh) = (r.right - r.left, r.bottom - r.top);

        // Output size is fixed for the whole share; later source resizes are
        // aspect-fit into it so the canvas never has to change dimensions.
        let ow = sw.min(max_w.max(320));
        let oh = ((sh as i64 * ow as i64) / sw as i64).max(1) as i32;
        let fps = fps.clamp(1, 60);

        std::thread::spawn(move || {
            let interval = Duration::from_millis(1000 / fps as u64);
            let mut full: Option<Dib> = None;
            let out = match Dib::new(ow, oh) {
                Some(d) => d,
                None => {
                    session.stop();
                    return;
                }
            };
            while session.running.load(Ordering::SeqCst) {
                let t0 = Instant::now();
                let Some(r) = target_rect(&target) else { break };
                let (w, h) = (r.right - r.left, r.bottom - r.top);
                if full.as_ref().map(|d| (d.w, d.h)) != Some((w, h)) {
                    full = Dib::new(w, h);
                }
                let Some(full_dib) = full.as_ref() else { break };
                if !grab(&target, r, full_dib) {
                    break;
                }

                // Aspect-fit into the fixed output, black bars if needed.
                let scale = f64::min(ow as f64 / w as f64, oh as f64 / h as f64);
                let dw = ((w as f64 * scale) as i32).max(1);
                let dh = ((h as f64 * scale) as i32).max(1);
                unsafe {
                    let _ = PatBlt(out.dc, 0, 0, ow, oh, BLACKNESS);
                    let _ = StretchBlt(
                        out.dc,
                        (ow - dw) / 2,
                        (oh - dh) / 2,
                        dw,
                        dh,
                        Some(full_dib.dc),
                        0,
                        0,
                        w,
                        h,
                        SRCCOPY,
                    );
                }
                let Some(jpeg) = out.jpeg_bytes(75) else { break };
                session.publish(jpeg);

                let spent = t0.elapsed();
                if spent < interval {
                    std::thread::sleep(interval - spent);
                }
            }
            session.stop();
        });

        Ok(CaptureDims {
            width: ow,
            height: oh,
        })
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{CaptureDims, CaptureSource, Session};
    use std::sync::Arc;
    pub fn list() -> Vec<CaptureSource> {
        Vec::new()
    }
    pub fn start(
        _id: &str,
        _max_w: i32,
        _fps: u32,
        _session: Arc<Session>,
    ) -> Result<CaptureDims, String> {
        Err("native capture is Windows-only for now".into())
    }
}

impl Session {
    fn new() -> Arc<Session> {
        Arc::new(Session {
            latest: Mutex::new(None),
            cond: Condvar::new(),
            running: AtomicBool::new(true),
        })
    }

    fn publish(&self, jpeg: Vec<u8>) {
        *self.latest.lock().unwrap() = Some(jpeg);
        self.cond.notify_all();
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.cond.notify_all();
    }

    /// Blocks until a fresh frame is available; empty bytes mean the session
    /// ended (source closed or capture stopped).
    fn take_frame(&self) -> Vec<u8> {
        let mut latest = self.latest.lock().unwrap();
        loop {
            if let Some(b) = latest.take() {
                return b;
            }
            if !self.running.load(Ordering::SeqCst) {
                return Vec::new();
            }
            let (guard, _) = self
                .cond
                .wait_timeout(latest, std::time::Duration::from_millis(1000))
                .unwrap();
            latest = guard;
        }
    }
}

#[tauri::command]
pub async fn list_capture_sources() -> Vec<CaptureSource> {
    // GDI capture of every window takes a moment — keep it off the runtime.
    tauri::async_runtime::spawn_blocking(imp::list)
        .await
        .unwrap_or_default()
}

#[tauri::command]
pub async fn start_native_capture(
    id: String,
    max_w: i32,
    fps: u32,
) -> Result<CaptureDims, String> {
    let session = Session::new();
    let dims = imp::start(&id, max_w, fps, session.clone())?;
    // Swap in the new session; a previous share's thread sees `running`
    // drop and winds down on its own.
    if let Some(old) = CURRENT.lock().unwrap().replace(session) {
        old.stop();
    }
    Ok(dims)
}

#[tauri::command]
pub async fn next_frame() -> tauri::ipc::Response {
    let session = CURRENT.lock().unwrap().clone();
    let bytes = match session {
        Some(s) => tauri::async_runtime::spawn_blocking(move || s.take_frame())
            .await
            .unwrap_or_default(),
        None => Vec::new(),
    };
    tauri::ipc::Response::new(bytes)
}

#[tauri::command]
pub async fn stop_native_capture() {
    if let Some(s) = CURRENT.lock().unwrap().take() {
        s.stop();
    }
}
