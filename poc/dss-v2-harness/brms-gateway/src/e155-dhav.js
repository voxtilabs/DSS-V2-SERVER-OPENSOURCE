// E-155: Dahua private RTP payload container ("DHAV").
//
// RE evidence (research/rea/E152_DHAV_HEADER.md):
//   parser = Dahua::StreamParser::CDHAVStream::ParseData @ StreamParsermd.dll
//            +0x180034ac0 (vtable 0x180089F20 slot 12)
//   layout (all little endian):
//     +0   "DHAV"                     (44 48 41 56)
//     +4   u8  class                  0xFC = video
//     +5   u8  sub-class
//     +6/7 u8  reserved
//     +8   u32 frame counter (not validated)
//     +12  u32 record length = 24 + extraLen + NAL + 8
//     +16  u32 unix seconds (not validated)
//     +20  u8  opaque
//     +21  u8  opaque
//     +22  u8  extraLen (TLV block length; guard: <= len-24)
//     +23  u8  opaque
//     +24  TLV block (extraLen bytes): 0x80 = w/8,h/8 - 0x81 = fps,codec -
//          0x94 = ...
//         Annex-B NALs (00 00 00 01 ...)
//         +8 trailing bytes (never read)
//   No checksum. Annex-B is mandatory downstream (CRawH264Stream scans 00 00 01).
//   MDP has no fallback: a payload without this header returns parser error 6.

export const DHAV_MAGIC = Buffer.from('DHAV', 'latin1');

export function isDhav(payload) {
  return Boolean(payload && payload.length >= 4 &&
    payload[0] === 0x44 && payload[1] === 0x48 && payload[2] === 0x41 && payload[3] === 0x56);
}

// Observed TLV block of an H.265 stream (extraLen 12): 0x80 w/8,h/8,
// 0x81 fps, codec, ?; 0x94 ...
// E-164: the dimensions are NOT constants — they come from the camera's own
// SPS (the first sample here was a 1280x720 camera while the lab camera is
// 1920x1080; declaring the wrong size leaves the player with a green picture).
const TLV_HEVC = Buffer.from([0x80, 0x00, 0xA0, 0x5A, 0x81, 0x1E, 0x0C, 0x1E, 0x94, 0x02, 0x01, 0x00]);
const TLV_H264 = Buffer.from([0x80, 0x00, 0xA0, 0x5A, 0x81, 0x1E, 0x01, 0x1E]);

// Build the TLV with the real frame size (w/8 and h/8, as the sample shows:
// 160/90 for 1280x720). fps and the codec id stay at the captured defaults
// (30 fps, 0x0C = HEVC / 0x01 = H.264) because the SDP does not carry them.
export function dhavExtraFor(codec, width, height, fps = 30) {
  const w = Math.max(1, Math.round(Number(width) / 8));
  const h = Math.max(1, Math.round(Number(height) / 8));
  const f = Math.max(1, Math.min(255, Number(fps) || 30));
  const size = [0x80, (w >> 8) & 0xFF, w & 0xFF, h & 0xFF];
  if (codec === 'h264') return Buffer.from([...size, 0x81, f, 0x01, f]);
  return Buffer.from([...size, 0x81, f, 0x0C, f, 0x94, 0x02, 0x01, 0x00]);
}

// Rough codec sniff on an Annex-B payload: find the first start code, then read
// the NAL header (H.265: type = (b0>>1)&0x3f with b1&7 == tid; H.264: b0&0x1f).
export function sniffCodec(payload) {
  for (let i = 0; i + 5 < payload.length && i < 64; i++) {
    if (payload[i] === 0 && payload[i + 1] === 0 && payload[i + 2] === 1) {
      const b0 = payload[i + 3];
      const b1 = payload[i + 4];
      if ((b1 & 0x07) === (b1 & 0x07) && ((b0 >> 1) & 0x3f) <= 40 && (b0 & 0x80) === 0) {
        const t265 = (b0 >> 1) & 0x3f;
        if (t265 === 32 || t265 === 33 || t265 === 34 || t265 === 19 || t265 === 20 || t265 === 1 || t265 === 2) return 'h265';
      }
      const t264 = b0 & 0x1f;
      if (t264 >= 1 && t264 <= 12) return 'h264';
    }
  }
  return 'h265';
}

export function createDhavState() {
  return { counter: 0, extra: null, codec: null, injected: false };
}

// Wrap one RTP payload (standard H.264/H.265 as delivered by MediaMTX) into the
// Dahua container. The bitstream must already be Annex-B.
export function wrapWithDhav(payload, state) {
  if (isDhav(payload)) return payload;
  if (!state.codec) state.codec = sniffCodec(payload);
  if (!state.extra) state.extra = state.codec === 'h264' ? TLV_H264 : TLV_HEVC;
  const extra = state.extra;
  const recordLen = 24 + extra.length + payload.length + 8;
  const head = Buffer.alloc(24 + extra.length);
  head.write('DHAV', 0, 'latin1');
  head[4] = 0xFC;      // video class
  head[5] = 0x00;      // sub-class
  head[6] = 0x00;
  head[7] = 0x00;
  head.writeUInt32LE(state.counter >>> 0, 8);
  head.writeUInt32LE(recordLen >>> 0, 12);
  head.writeUInt32LE(Math.floor(Date.now() / 1000) >>> 0, 16);
  head[20] = 0x00;
  head[21] = 0x00;
  head[22] = extra.length & 0xFF;
  head[23] = 0x00;
  extra.copy(head, 24);
  state.counter = (state.counter + 1) >>> 0;
  return Buffer.concat([head, payload, Buffer.alloc(8)]);
}
