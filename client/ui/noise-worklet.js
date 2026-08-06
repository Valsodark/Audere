'use strict';

/*
 * Mic noise suppression: RNNoise between the microphone and the WebRTC
 * sender (rnnoise.wasm, built from ../noise-wasm).
 *
 * The main thread compiles the wasm and passes the Module in
 * processorOptions — an Instance can't be structured-cloned, a Module can.
 * RNNoise eats 10 ms frames (480 samples at 48 kHz) while Web Audio delivers
 * 128 at a time, so samples pool in `pending` until a frame is full and
 * denoised frames queue in `ready`; the pooling adds ~10 ms of latency.
 *
 * A 'bypass' message flips a passthrough flag, so toggling suppression never
 * touches the peer connections.
 */

class Denoiser extends AudioWorkletProcessor {
  constructor(options) {
    super();
    this.wasm = new WebAssembly.Instance(options.processorOptions.module).exports;
    this.frame = this.wasm.frame_size();
    this.wasm.process(); // first call allocates state, which can grow memory
    this.pending = new Float32Array(this.frame);
    this.pendingLen = 0;
    this.ready = []; // denoised frames waiting to be played out
    this.readyOff = 0; // read position within ready[0]
    this.bypass = false;
    this.port.onmessage = e => {
      if (typeof e.data?.bypass === 'boolean') {
        this.bypass = e.data.bypass;
        // Stale denoised audio would replay after a toggle; drop it.
        this.ready.length = 0;
        this.readyOff = 0;
        this.pendingLen = 0;
      }
    };
    // Proof of life: the main thread falls back to the raw mic if wasm
    // instantiation threw before this line.
    this.port.postMessage({ ready: true });
  }

  // Views into wasm memory, rebuilt if the buffer was detached by a grow.
  views() {
    if (!this.inView || this.inView.buffer !== this.wasm.memory.buffer) {
      this.inView = new Float32Array(this.wasm.memory.buffer, this.wasm.input_ptr(), this.frame);
      this.outView = new Float32Array(this.wasm.memory.buffer, this.wasm.output_ptr(), this.frame);
    }
    return this;
  }

  process(inputs, outputs) {
    const inp = inputs[0][0]; // mono: voice; extra mic channels add nothing
    const out = outputs[0][0];
    if (!out) return true;
    if (!inp) {
      out.fill(0);
      return true;
    }
    if (this.bypass) {
      out.set(inp);
      return true;
    }

    const { inView, outView } = this.views();
    for (let i = 0; i < inp.length; ) {
      const n = Math.min(this.frame - this.pendingLen, inp.length - i);
      this.pending.set(inp.subarray(i, i + n), this.pendingLen);
      this.pendingLen += n;
      i += n;
      if (this.pendingLen === this.frame) {
        inView.set(this.pending);
        this.wasm.process();
        this.ready.push(outView.slice());
        this.pendingLen = 0;
      }
    }

    for (let o = 0; o < out.length; o++) {
      const head = this.ready[0];
      if (!head) {
        out[o] = 0; // warm-up: first ~10 ms while the initial frame pools
        continue;
      }
      out[o] = head[this.readyOff++];
      if (this.readyOff === head.length) {
        this.ready.shift();
        this.readyOff = 0;
      }
    }
    return true;
  }
}

registerProcessor('denoise', Denoiser);
