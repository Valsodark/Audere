//! RNNoise (via the pure-Rust `nnnoiseless` port) exposed to WASM with a
//! plain C ABI: fixed input/output buffers in linear memory plus a `process`
//! call per 10 ms frame. No wasm-bindgen — the worklet reads and writes the
//! buffers through `Float32Array` views (see `../../ui/noise-worklet.js`).

use nnnoiseless::DenoiseState;

/// 480 samples: one 10 ms frame at 48 kHz, the rate RNNoise is trained on.
const FRAME: usize = DenoiseState::FRAME_SIZE;

static mut STATE: Option<Box<DenoiseState<'static>>> = None;
static mut INPUT: [f32; FRAME] = [0.0; FRAME];
static mut OUTPUT: [f32; FRAME] = [0.0; FRAME];

/// Where the worklet writes one frame of mic samples (Web Audio ±1.0 floats).
#[no_mangle]
pub extern "C" fn input_ptr() -> *mut f32 {
    std::ptr::addr_of_mut!(INPUT) as *mut f32
}

/// Where the denoised frame appears after `process`.
#[no_mangle]
pub extern "C" fn output_ptr() -> *const f32 {
    std::ptr::addr_of!(OUTPUT) as *const f32
}

#[no_mangle]
pub extern "C" fn frame_size() -> usize {
    FRAME
}

/// Denoises INPUT into OUTPUT; returns the voice probability (0..1).
/// RNNoise works in i16 sample range, so the ±1.0 floats are scaled up on the
/// way in and back down on the way out — the worklet never sees that detail.
#[no_mangle]
pub extern "C" fn process() -> f32 {
    unsafe {
        let state = (*std::ptr::addr_of_mut!(STATE)).get_or_insert_with(DenoiseState::new);
        let input = &mut *std::ptr::addr_of_mut!(INPUT);
        let output = &mut *std::ptr::addr_of_mut!(OUTPUT);
        for s in input.iter_mut() {
            *s *= 32768.0;
        }
        let vad = state.process_frame(output, input);
        for s in output.iter_mut() {
            *s /= 32768.0;
        }
        vad
    }
}
