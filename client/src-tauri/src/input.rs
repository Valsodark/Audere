//! Synthetic mouse/keyboard injection for remote control.
//!
//! The frontend only reaches this after the user of *this* machine clicks
//! "Allow control" in the consent dialog; events arrive over a peer-to-peer,
//! DTLS-encrypted data channel and never touch the relay server.

#[cfg(windows)]
mod imp {
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

    /// Screen coordinates arrive normalised to 0.0..1.0 so they survive any
    /// resolution difference between the two machines.
    #[derive(serde::Deserialize)]
    #[serde(tag = "t")]
    pub enum InputEvent {
        Move { x: f64, y: f64 },
        Down { x: f64, y: f64, button: u8 },
        Up { x: f64, y: f64, button: u8 },
        Wheel { dy: f64 },
        Key { code: String, key: String, down: bool },
    }

    fn send(inputs: &[INPUT]) {
        unsafe {
            SendInput(inputs, std::mem::size_of::<INPUT>() as i32);
        }
    }

    /// One wheel notch, as defined by the Win32 `WHEEL_DELTA` constant.
    const WHEEL_DELTA: f64 = 120.0;

    fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: i32) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    // Wheel deltas are signed; the field itself is unsigned.
                    mouseData: data as u32,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Absolute mouse positioning uses a 0..65535 grid over the primary screen.
    fn abs(v: f64) -> i32 {
        (v.clamp(0.0, 1.0) * 65535.0).round() as i32
    }

    fn move_to(x: f64, y: f64) -> INPUT {
        mouse(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
            abs(x),
            abs(y),
            0,
        )
    }

    /// Maps a DOM `MouseEvent.button` to press/release flags.
    fn button_flags(button: u8, down: bool) -> MOUSE_EVENT_FLAGS {
        match (button, down) {
            (0, true) => MOUSEEVENTF_LEFTDOWN,
            (0, false) => MOUSEEVENTF_LEFTUP,
            (1, true) => MOUSEEVENTF_MIDDLEDOWN,
            (1, false) => MOUSEEVENTF_MIDDLEUP,
            (2, true) => MOUSEEVENTF_RIGHTDOWN,
            (_, false) => MOUSEEVENTF_RIGHTUP,
            _ => MOUSEEVENTF_LEFTDOWN,
        }
    }

    fn key_input(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Maps a DOM `KeyboardEvent.code` to a Windows virtual-key code.
    /// Returns `None` for printable keys, which are sent as Unicode instead so
    /// they land correctly regardless of the remote keyboard layout.
    fn vk_from_code(code: &str) -> Option<VIRTUAL_KEY> {
        let vk = match code {
            "Enter" | "NumpadEnter" => VK_RETURN,
            "Tab" => VK_TAB,
            "Backspace" => VK_BACK,
            "Delete" => VK_DELETE,
            "Escape" => VK_ESCAPE,
            "ArrowUp" => VK_UP,
            "ArrowDown" => VK_DOWN,
            "ArrowLeft" => VK_LEFT,
            "ArrowRight" => VK_RIGHT,
            "Home" => VK_HOME,
            "End" => VK_END,
            "PageUp" => VK_PRIOR,
            "PageDown" => VK_NEXT,
            "Insert" => VK_INSERT,
            "ShiftLeft" => VK_LSHIFT,
            "ShiftRight" => VK_RSHIFT,
            "ControlLeft" => VK_LCONTROL,
            "ControlRight" => VK_RCONTROL,
            "AltLeft" => VK_LMENU,
            "AltRight" => VK_RMENU,
            "MetaLeft" => VK_LWIN,
            "MetaRight" => VK_RWIN,
            "CapsLock" => VK_CAPITAL,
            "Space" => VK_SPACE,
            "F1" => VK_F1,
            "F2" => VK_F2,
            "F3" => VK_F3,
            "F4" => VK_F4,
            "F5" => VK_F5,
            "F6" => VK_F6,
            "F7" => VK_F7,
            "F8" => VK_F8,
            "F9" => VK_F9,
            "F10" => VK_F10,
            "F11" => VK_F11,
            "F12" => VK_F12,
            _ => return None,
        };
        Some(vk)
    }

    pub fn inject(ev: InputEvent) {
        match ev {
            InputEvent::Move { x, y } => send(&[move_to(x, y)]),
            InputEvent::Down { x, y, button } => {
                send(&[move_to(x, y), mouse(button_flags(button, true), 0, 0, 0)])
            }
            InputEvent::Up { x, y, button } => {
                send(&[move_to(x, y), mouse(button_flags(button, false), 0, 0, 0)])
            }
            InputEvent::Wheel { dy } => {
                // DOM wheel deltas are inverted relative to Windows notches.
                let clicks = -(dy / 100.0).clamp(-10.0, 10.0);
                send(&[mouse(MOUSEEVENTF_WHEEL, 0, 0, (clicks * WHEEL_DELTA) as i32)]);
            }
            InputEvent::Key { code, key, down } => {
                let flags = if down {
                    KEYBD_EVENT_FLAGS(0)
                } else {
                    KEYEVENTF_KEYUP
                };
                if let Some(vk) = vk_from_code(&code) {
                    send(&[key_input(vk, 0, flags)]);
                } else {
                    // Printable character: inject the literal Unicode scalar.
                    let mut chars = key.chars();
                    if let (Some(c), None) = (chars.next(), chars.next()) {
                        for unit in c.encode_utf16(&mut [0u16; 2]).iter() {
                            send(&[key_input(
                                VIRTUAL_KEY(0),
                                *unit,
                                flags | KEYEVENTF_UNICODE,
                            )]);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    #[derive(serde::Deserialize)]
    #[serde(tag = "t")]
    pub enum InputEvent {
        Other,
    }
    pub fn inject(_ev: InputEvent) {}
}

pub use imp::InputEvent;

#[tauri::command]
pub fn inject_input(ev: InputEvent) {
    imp::inject(ev);
}
