'use strict';

/*
 * Plays the interleaved float PCM captured from the system's audio output.
 *
 * The main thread pulls buffers over IPC and posts them here; this processor
 * drains them into the audio graph, which then feeds a MediaStreamDestination
 * so the capture becomes an ordinary WebRTC track.
 *
 * Buffers are dropped rather than queued when playback falls behind: a screen
 * share wants audio in step with the picture, and a backlog only turns into
 * permanent delay.
 */

// ~400 ms at 20 ms per buffer, past which the stream is treated as behind.
const MAX_BUFFERS = 20;

class PcmPlayer extends AudioWorkletProcessor {
  constructor() {
    super();
    this.queue = [];
    this.offset = 0; // read position within queue[0], in samples
    this.port.onmessage = e => {
      if (e.data === 'flush') {
        this.queue.length = 0;
        this.offset = 0;
        return;
      }
      this.queue.push(e.data);
      while (this.queue.length > MAX_BUFFERS) this.queue.shift();
    };
  }

  process(inputs, outputs) {
    const out = outputs[0];
    const channels = out.length;
    const frames = out[0].length;

    for (let i = 0; i < frames; i++) {
      const chunk = this.queue[0];
      if (!chunk) {
        // Underrun: silence is better than a repeat.
        for (let c = 0; c < channels; c++) out[c][i] = 0;
        continue;
      }
      for (let c = 0; c < channels; c++) out[c][i] = chunk[this.offset + c] || 0;
      this.offset += channels;
      if (this.offset >= chunk.length) {
        this.queue.shift();
        this.offset = 0;
      }
    }
    return true;
  }
}

registerProcessor('pcm-player', PcmPlayer);
