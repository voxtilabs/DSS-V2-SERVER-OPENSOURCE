// E-156: RTP depacketization to Annex-B for the DHAV container.
//
// The ONVIF cameras deliver standard RFC 7798 (H.265) / RFC 6184 (H.264) RTP:
//   - single NAL
//   - AP (H.265 type 48) / STAP-A (H.264 type 24): [u16 len][NAL]...
//   - FU  (H.265 type 49) / FU-A (H.264 type 28): start/middle/end fragments
// The Dahua container (e155-dhav.js) needs a plain Annex-B bitstream, so each
// RTP packet is converted here. Fragments that continue a NAL are emitted
// without a new start code, which keeps the concatenated stream valid.

function annexb(nal) {
  return Buffer.concat([Buffer.from([0, 0, 0, 1]), nal]);
}

export function depacketizeH265(p, state) {
  if (!p || p.length < 2) return null;
  // already Annex-B (some cameras): pass through
  if (p[0] === 0 && p[1] === 0 && p.length >= 4 && (p[2] === 1 || (p[2] === 0 && p[3] === 1))) return p;
  const type = (p[0] >> 1) & 0x3f;
  if (type === 48) { // AP: [u16 len][NAL]...
    const out = [];
    let i = 2;
    while (i + 2 <= p.length) {
      const len = p.readUInt16BE(i);
      i += 2;
      if (len === 0 || i + len > p.length) break;
      out.push(annexb(p.subarray(i, i + len)));
      i += len;
    }
    return out.length ? Buffer.concat(out) : null;
  }
  if (type === 49) { // FU
    if (p.length < 3) return null;
    const fu = p[2];
    const start = (fu & 0x80) !== 0;
    const end = (fu & 0x40) !== 0;
    const fuType = fu & 0x3f;
    const data = p.subarray(3);
    if (start) {
      const nalHead = Buffer.from([((p[0] & 0x81) | (fuType << 1)) & 0xff, p[1]]);
      return Buffer.concat([Buffer.from([0, 0, 0, 1]), nalHead, data]);
    }
    if (data.length === 0) return null;
    return data;
  }
  // single NAL packet
  return annexb(p);
}

export function depacketizeH264(p) {
  if (!p || p.length < 2) return null;
  if (p[0] === 0 && p[1] === 0 && p.length >= 4 && (p[2] === 1 || (p[2] === 0 && p[3] === 1))) return p;
  const type = p[0] & 0x1f;
  if (type === 24) { // STAP-A
    const out = [];
    let i = 1;
    while (i + 2 <= p.length) {
      const len = p.readUInt16BE(i);
      i += 2;
      if (len === 0 || i + len > p.length) break;
      out.push(annexb(p.subarray(i, i + len)));
      i += len;
    }
    return out.length ? Buffer.concat(out) : null;
  }
  if (type === 28) { // FU-A: [NAL header][FU header][data...]
    if (p.length < 3) return null;
    const fu = p[1];
    const start = (fu & 0x80) !== 0;
    const fuType = fu & 0x1f;
    const data = p.subarray(2);
    if (start) {
      const nalHead = Buffer.from([(p[0] & 0xe0) | fuType]);
      return Buffer.concat([Buffer.from([0, 0, 0, 1]), nalHead, data]);
    }
    if (data.length === 0) return null;
    return data;
  }
  return annexb(p);
}

// Pick the codec from the first packet and convert every packet to Annex-B.
export function rtpToAnnexB(payload, state) {
  if (!state.codec) {
    const t265 = (payload[0] >> 1) & 0x3f;
    const t264 = payload[0] & 0x1f;
    if (t265 === 48 || t265 === 49) state.codec = 'h265';
    else if (t264 === 24 || t264 === 28 || (t264 >= 1 && t264 <= 23)) state.codec = 'h264';
    else state.codec = 'h265';
  }
  return state.codec === 'h264' ? depacketizeH264(payload) : depacketizeH265(payload);
}

// E-164: the Dahua DHAV "extra" TLV declares the frame size, and a wrong size
// leaves the client with a green picture. The size comes from the camera's own
// SPS (published by MediaMTX as sprop-sps in the SDP), never from a constant.
function bitsOf(buf) {
  const out = [];
  for (let i = 0; i < buf.length; i++) {
    if (i + 2 < buf.length && buf[i] === 0 && buf[i + 1] === 0 && buf[i + 2] === 3) { out.push(0, 0); i += 2; continue; }
    out.push(buf[i]);
  }
  const clean = Buffer.from(out);
  let bit = 0;
  const total = clean.length * 8;
  const u = (n) => {
    let v = 0;
    for (let i = 0; i < n; i++) {
      if (bit >= total) throw new Error('eof');
      v = (v << 1) | ((clean[bit >> 3] >> (7 - (bit & 7))) & 1);
      bit++;
    }
    return v >>> 0;
  };
  const ue = () => {
    let z = 0;
    while (u(1) === 0) { z++; if (z > 32) throw new Error('ue'); }
    return z === 0 ? 0 : ((1 << z) - 1) + u(z);
  };
  return { u, skip: (n) => { bit += n; }, ue };
}

export function hevcSpsSize(buf) {
  try {
    const r = bitsOf(buf);
    r.u(16);                       // NAL header
    r.u(4); const maxSub = r.u(3); r.u(1);
    r.u(2); r.u(1); r.u(5);        // profile space/tier/idc
    r.u(32);                       // compatibility flags
    r.u(1); r.u(1); r.u(1); r.u(1); // progressive/interlaced/non-packed/frame-only
    r.skip(43); r.u(1); r.u(8);    // reserved + inbld + level
    const present = [];
    for (let i = 0; i < maxSub; i++) present.push([r.u(1), r.u(1)]);
    if (maxSub > 0) for (let i = maxSub; i < 8; i++) r.u(2);
    for (let i = 0; i < maxSub; i++) {
      if (present[i][0]) r.skip(88);
      if (present[i][1]) r.skip(8);
    }
    r.ue();                        // sps_seq_parameter_set_id
    const chroma = r.ue();
    if (chroma === 3) r.u(1);
    const width = r.ue();
    const height = r.ue();
    let cropW = width, cropH = height;
    if (r.u(1)) {
      const subW = (chroma === 1 || chroma === 2) ? 2 : 1;
      const subH = chroma === 1 ? 2 : 1;
      const left = r.ue(), right = r.ue(), top = r.ue(), bottom = r.ue();
      cropW = width - (left + right) * subW;
      cropH = height - (top + bottom) * subH;
    }
    return { width: cropW, height: cropH };
  } catch {
    return null;
  }
}

// codec + picture size from the SDP MediaMTX publishes (sprop-* is base64).
export function sdpCodecSize(sdp) {
  const text = String(sdp || '');
  const codec = /a=rtpmap:\d+\s+H265\//i.test(text) ? 'h265' : (/a=rtpmap:\d+\s+H264\//i.test(text) ? 'h264' : null);
  const fmtp = /a=fmtp:\d+\s+([^\r\n]+)/i.exec(text);
  if (!fmtp) return { codec, width: 0, height: 0 };
  const sps = /sprop-sps=([^;\s]+)/i.exec(fmtp[1]);
  if (!sps) return { codec, width: 0, height: 0 };
  const nal = Buffer.from(sps[1], 'base64');
  const size = codec === 'h265' ? hevcSpsSize(nal) : null;
  return { codec, width: size ? size.width : 0, height: size ? size.height : 0 };
}

// E-158: build the Annex-B parameter sets from MediaMTX's SDP
// (a=fmtp:96 sprop-vps=...; sprop-sps=...; sprop-pps=...). The DSS client never
// sends DESCRIBE, so it has no out-of-band codec config; the real Dahua server
// starts the stream with the parameter sets in-band. We inject them once, at
// the beginning of each session, from the SDP MediaMTX already publishes.
export function parameterSetsFromSdp(sdp) {
  try {
    const fmtp = /a=fmtp:\d+\s+([^\r\n]+)/i.exec(sdp || '');
    if (!fmtp) return null;
    const get = (k) => {
      const m = new RegExp(k + '=([^;\\s]+)', 'i').exec(fmtp[1]);
      return m ? Buffer.from(m[1], 'base64') : null;
    };
    const parts = [];
    for (const k of ['sprop-vps', 'sprop-sps', 'sprop-pps']) {
      const nal = get(k);
      if (nal && nal.length) parts.push(Buffer.from([0, 0, 0, 1]), nal);
    }
    return parts.length ? Buffer.concat(parts) : null;
  } catch (e) {
    return null;
  }
}
