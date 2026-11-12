// Minimal HEVC SPS parser: resolution/crop/profile/level.
// Usage: node tools/hevc-sps-parse.cjs <base64sps> [more...]
function unescape(buf) {
  const out = [];
  for (let i = 0; i < buf.length; i++) {
    if (i + 2 < buf.length && buf[i] === 0 && buf[i + 1] === 0 && buf[i + 2] === 3) {
      out.push(0, 0);
      i += 2;
      continue;
    }
    out.push(buf[i]);
  }
  return Buffer.from(out);
}

function makeReader(buf) {
  let bit = 0;
  const total = buf.length * 8;
  return {
    u(n) {
      let v = 0;
      for (let i = 0; i < n; i++) {
        if (bit >= total) throw new Error('eof');
        const byte = buf[bit >> 3];
        const b = (byte >> (7 - (bit & 7))) & 1;
        v = (v << 1) | b;
        bit++;
      }
      return v >>> 0;
    },
    skip(n) { bit += n; },
    ue() {
      let zeros = 0;
      while (this.u(1) === 0) { zeros++; if (zeros > 32) throw new Error('ue overflow'); }
      if (zeros === 0) return 0;
      return ((1 << zeros) - 1) + this.u(zeros);
    },
    get pos() { return bit; }
  };
}

function parseSps(b64) {
  const raw = Buffer.from(b64, 'base64');
  const buf = unescape(raw);
  const r = makeReader(buf);
  r.u(16); // NAL header (2 bytes: forbidden+type+layer+tid)
  const vpsId = r.u(4);
  const maxSubLayersMinus1 = r.u(3);
  const tidNesting = r.u(1);
  // profile_tier_level(1, maxSubLayersMinus1)
  const profileSpace = r.u(2);
  const tier = r.u(1);
  const profileIdc = r.u(5);
  const compat = r.u(32);
  const progressive = r.u(1), interlaced = r.u(1), nonPacked = r.u(1), frameOnly = r.u(1);
  r.skip(43);
  const inbld = r.u(1);
  const levelIdc = r.u(8);
  const subProfilePresent = [];
  const subLevelPresent = [];
  for (let i = 0; i < maxSubLayersMinus1; i++) {
    subProfilePresent.push(r.u(1));
    subLevelPresent.push(r.u(1));
  }
  if (maxSubLayersMinus1 > 0) {
    for (let i = maxSubLayersMinus1; i < 8; i++) r.u(2);
  }
  for (let i = 0; i < maxSubLayersMinus1; i++) {
    if (subProfilePresent[i]) r.skip(88);
    if (subLevelPresent[i]) r.skip(8);
  }
  const spsId = r.ue();
  const chromaFormatIdc = r.ue();
  let separateColourPlane = 0;
  if (chromaFormatIdc === 3) separateColourPlane = r.u(1);
  const width = r.ue();
  const height = r.ue();
  const conformanceWindow = r.u(1);
  let left = 0, right = 0, top = 0, bottom = 0;
  if (conformanceWindow) { left = r.ue(); right = r.ue(); top = r.ue(); bottom = r.ue(); }
  const subW = chromaFormatIdc === 1 || chromaFormatIdc === 2 ? 2 : 1;
  const subH = chromaFormatIdc === 1 ? 2 : 1;
  const cropW = width - (left + right) * subW;
  const cropH = height - (top + bottom) * subH;
  return {
    vpsId, maxSubLayersMinus1, tidNesting, profileSpace, tier, profileIdc,
    progressive, interlaced, levelIdc, spsId, chromaFormatIdc, separateColourPlane,
    width, height, conformanceWindow, left, right, top, bottom, cropW, cropH,
    nalType: (raw[0] >> 1) & 0x3f, bytes: raw.length
  };
}

const args = process.argv.slice(2);
for (const a of args) {
  try {
    const s = parseSps(a);
    console.log(JSON.stringify(s));
    console.log(`  -> ${s.cropW}x${s.cropH} (raw ${s.width}x${s.height}) | profile ${s.profileIdc} level ${s.levelIdc / 30} | chroma ${s.chromaFormatIdc} | TLV 0x80 = ${String.fromCharCode(0)}${(s.cropW / 8) >> 8}|${(s.cropW / 8) & 0xff}|${(s.cropH / 8) & 0xff}`);
    console.log(`  -> TLV bytes: 80 ${((s.cropW / 8) >> 8).toString(16).padStart(2, '0')} ${((s.cropW / 8) & 0xff).toString(16).padStart(2, '0')} ${((s.cropH / 8) & 0xff).toString(16).padStart(2, '0')}`);
  } catch (e) {
    console.log('ERR', a.slice(0, 20), e.message);
  }
}
