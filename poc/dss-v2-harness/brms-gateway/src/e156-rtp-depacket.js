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
