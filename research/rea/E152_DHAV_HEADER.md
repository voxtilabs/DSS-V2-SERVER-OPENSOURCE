# E152 — Dahua private RTP payload header ("DHAV"): exact layout, parser, and synthesis recipe

Status: **answered** (5/5 questions), with three residual unknowns explicitly listed in §8.
Analysis host: Windows 11, REA 6.8.0 + Ghidra 12.1.4 provider (no Hopper on win32).
Nothing under `C:\DSS` was modified (read-only imports; Ghidra runs on a temp snapshot).

---

## 0. Where the parser actually lives (correction to the task premise)

The task pointed at `MDP.exe` and `DPSDK.dll`. Both are the wrong module for this
header, and that is itself a finding:

| Artifact | SHA-256 | `DHAV` magic present? | Role |
|---|---|---|---|
| `MDP.exe` (4,314,208 B) | `02c57545…1898d119` | **No** — no string, no imm32 in any byte order (`search_bytes 44484156`, `44414856`, `56414844`, `56414856` → 0 hits; `search_strings DHAV` → 0 hits) | RTSP client + media orchestration. Never inspects the private header. |
| `DPSDK.dll` (17,078,880 B) | — | **No** (full-directory byte scan, see below) | Platform SDK; not on the RTP payload path for this header. |
| **`StreamParsermd.dll` (821,856 B)** | `cfe4b172…c9811a` | **Yes** (5 hits, 2 of them executable immediates) | **The DHAV parser.** `Dahua::StreamParser::CDHAVStream`, `Dahua::StreamParser::CDHAVFile`. |
| `VAXPlayer.dll` | — | Yes | Decode engine (`CVaxPlayer::inputData`) — consumes the *stripped* NAL body. |
| `play.dll`, `netsdk.dll`, `avnetsdk.dll`, `configsdk.dll` | — | Yes | Playback/file and device-SDK paths (out of scope here). |

Byte scan method (`node scan_magic.mjs` over `C:\DSS\DSS Client`, ASCII `DHAV`/`dhav`
plus the byte-reversed dword forms) — files with hits: `avnetsdk.dll`, `configsdk.dll`,
`netsdk.dll`, `play.dll`, `StreamParsermd.dll`, `VAXPlayer.dll`. **`MDP.exe` and
`DPSDK.dll` are absent from that list.**

`MDP.exe`'s import table (PE import directory RVA `0x387060`) shows the actual data
path — it imports `StreamParsermd.dll` **by ordinal only**:

```
ord 1  SP_CreateStreamParser      ord 3  SP_GetOneFrame      ord 12 SP_Destroy
ord 2  SP_ParseData               ord 5  SP_ClearBuffer      ord 13 SP_GetLastError
```

plus `VAXPlayer.dll` (`?inputData@CVaxPlayer@@QEAAHPEAEK@Z`, `?openStream@CVaxPlayer@@…`).
So: **MDP → StreamParsermd (DHAV container demux) → VAXPlayer (decode)**.

---

## 1. Q1 — Parser, address, and exact struct layout

### 1.1 The validating function

| Item | Value |
|---|---|
| Function | `FUN_180034ac0` — `Dahua::StreamParser::CDHAVStream::ParseData` |
| Address | `0x180034ac0` (StreamParsermd.dll, image base `0x180000000`) |
| Class vtable | `0x180089f20`; this method is slot 12 → vtable slot at `0x180089f80` (verified: the qword at `0x180089f80` is `0x180034ac0`) |
| Sibling (DAV **file / slice** parser) | `FUN_180050950` (calls `FUN_18004f730` + `FUN_18004f820` instead of `FUN_1800333a0` + `FUN_180033490`) |
| Magics referenced | `0x180034b4b` and `0x1800509af` (code), `0x1800906cc` (.rdata, name registry), `0x1800b6795`, `0x1800b7e5d` (.data) |

Exact decompiled logic of `FUN_180034ac0` (Ghidra, verbatim structure):

```c
if (param_2 != 0 && param_3 != 0) {
  piVar3  = *(int **)(param_3 + 0x1C);   /* input buffer pointer */
  uVar2   = param_3[9];                  /* input length  (byte +0x24) */
  if (0x17 < uVar2) {                    /* need > 23 bytes          */
    iVar6 = uVar2 - 0x18;                /* len - 24                 */
    if (*piVar3 == 0x56414844) {         /* "DHAV" little-endian     */
      FUN_1800333a0(param_1, piVar3, param_3);                 /* 24-byte fixed header  */
      if ((int)(uint)*(byte *)((longlong)piVar3 + 0x16) <= iVar6) {   /* byte[22] <= len-24 */
        FUN_180033490(param_1, (longlong)(piVar3 + 6),          /* TLV block at +24 */
                      (uint)*(byte *)((longlong)piVar3 + 0x16),  /* its length = byte[22] */
                      param_3, &local_98);
        iVar4 = piVar3[3];                                      /* dword @ +12: record length */
        lVar5 = (longlong)(piVar3 + 6) + *(byte *)((longlong)piVar3 + 0x16);  /* body ptr */
        iVar6 = iVar6 - *(byte *)((longlong)piVar3 + 0x16);
        if (iVar4 == param_3[9]) {                              /* field == whole buffer */
          *(longlong *)(param_3 + 4) = lVar5;                   /* out ptr  (+0x10) */
          param_3[6] = iVar6 + -8;                              /* out len  (+0x18) = len-24-extra-8 */
        } else {
          iVar4 = (iVar4 - extraLen) + -0x20;                   /* = field12 - extra - 32 */
          param_3[6] = iVar4;
          if (iVar6 < iVar4) param_3[6] = iVar6;                /* clamp to available */
        }
        return 0;                                               /* OK */
      }
    }
  }
}
return 6;   /* SP error "not my container / truncated" */
```

`FUN_1800333a0` (fixed-header classify) reads **only** `byte[+4]` and `byte[+5]`:

```c
c = *(char *)(p + 4);
if (c == 0xFD) { cls = 1; sub = byte[5]==1 ? 0x12 : byte[5]==2 ? 0x14 : 0; }
else if (c == 0xFC) { cls = 1; sub = 1;  if (byte[5] == 1) sub = 0x13; }
else if (c == 0xF0) { cls = 2; }                       /* audio   */
else if (c == 0xFE) { cls = 1; sub = 2; }
else if (c == 0xFB) { cls = 1; sub = 8; }
else if (c == 0xF1 || c == 0xF2) { cls = 3; sub = table_180089e00[byte[5]]; }
else if (c == 0x55) { cls = 3; sub = byte[5] ? byte[5] : 0x100; }
else { cls = 0; }
```

`FUN_180033490` (TLV block) is a tag/length walker over the block at `+24`; each entry is
`[tag u8][sub u8][len/aux u8][aux u8]` with a per-tag step of 4, 8 or `1+len`
(the step is encoded in the tag's own first data byte — see `0xB0..0xB5` cases).
Tags observed in real captures: `0x80` (width = `b[2]<<3`, height = `b[3]<<3`),
`0x81` (codec-subtype = `b[2]`, `b[3]` = frame rate), `0x85`, `0x88` (8-byte blob),
`0x91`, `0x92`, `0x93`, `0x94`, `0x99`, `0x9A`, `0x9B`, `0x9C`, `0xA0`, `0xA1`,
`0xB0..0xB5`. Unknown tags are skipped by 4 or by `b[1]`.

### 1.2 Exact struct

All multi-byte integers are **little-endian**. Verified against both captures by
`node dhav_decode.mjs` (no hand arithmetic).

```
offset size field
------ ---- --------------------------------------------------------------
0x00    4   magic  = 'D','H','A','V'  (loaded as dword 0x56414844)
0x04    1   media/frame class     0xFC = video (validated by FUN_1800333a0)
0x05    1   sub-class             with 0xFC: 0x00 keeps sub=1, 0x01 -> sub=0x13
0x06    1   reserved              0 in both captures
0x07    1   reserved              0 in both captures
0x08    4   u32 frame counter     per-stream, monotonic; NOT validated by the parser
0x0C    4   u32 record length     total bytes of THIS record = 24 + extra + NAL + 8
0x10    4   u32 unix time (s)     e.g. 0x6AD8AE6A = 2026-10-21T12:22:02Z; NOT validated
0x14    1   opaque               0x81 (H.265 capture) / 0x26 (H.264 capture)
0x15    1   opaque               0xFC (H.265 capture) / 0x16 (H.264 capture)
0x16    1   u8  extraLen         length of the TLV block that follows  <-- the size knob
0x17    1   opaque               0xBC (H.265 capture) / 0x74 (H.264 capture)
0x18    extraLen   TLV block     (see tags above)  — starts at 0x18 == 24
0x18+extraLen      NAL payload   Annex-B start code first (0x00000001)
...                (end of record) 8 trailing bytes, never read by the parser
```

Header-to-NAL distance = `0x18 + extraLen` — this is what the Frida capture measured as
"~36 for H.265, ~32 for H.264":

| Capture | magic | b4 | b5 | counter (+8) | **recLen (+12)** | time (+16) | b20..b23 | **extra (+22)** | NAL at |
|---|---|---|---|---|---|---|---|---|---|
| H.265 | DHAV | FC | 00 | 69,468,049 | **2,299** | 1792585322 | `81 FC 0C BC` | **12** | **36** |
| H.264 | DHAV | FC | 00 | 39,435 | **8,688** | 1792585323 | `26 16 08 74` | **8** | **32** |

Both bodies start with `00 00 00 01` (`000000010203` / `00000001460130`) — i.e. the
Annex-B start code sits exactly at `24 + extraLen`, with no padding steps in between.

### 1.3 The "+12 unknown" and the checksum question

* **`+12` is not unknown — it is the record length.** `FUN_180034ac0` compares it with the
  current buffer length and derives the payload length from it:
  `nalLen = field12 - extraLen - 0x20` (= `- 24 header - 8 tail`), clamped to what is
  already buffered. Measured: `2299 - 12 - 32 = 2255` (H.265), `8688 - 8 - 32 = 8648` (H.264).
* **There is no checksum anywhere in the DHAV path.** No CRC, no checksum field, no
  validation of bytes `+8`/`+16`, and the 8 trailing bytes of each record are never read
  (the code only subtracts 8 from the length). The only integrity check is the 4-byte magic
  plus `len > 0x17` plus `byte[22] <= len-24`.

---

## 2. Q2 — Is the header length fixed? Exact rule

**Not fixed.** It is `24 + extraLen (+8 tail)`, where `extraLen = byte[0x16]`.

* Rule enforced in `FUN_180034ac0`: `buffer_len > 0x17` **and**
  `byte[0x16] <= buffer_len - 0x18`.
* NAL body pointer = `payload + 0x18 + byte[0x16]`; body length derived as in §1.3.
* `byte[0x16]` is produced by the *device*, per codec/firmware. Measured: **12** for the
  H.265 channel (TLV `80 … 81 … 94 …`), **8** for the H.264 channel (single TLV `88 …`).
  It is **not** derived from the codec id, not from the payload size, and not from the
  channel type; the codec id lives *inside* the TLV block (tag `0x81`) and in the SDP
  codec field that `MDP.exe` passes alongside (see §4), not in the fixed 24 bytes.
* Total record layout: `[24 B header][extraLen B TLV][NAL data][8 B tail]`,
  `recordLen(@+12) = 32 + extraLen + nalLen`.

---

## 3. Q3 — Annex-B required, or length-prefixed NAL accepted?

**Annex-B is required. A length-prefixed NAL will not be accepted.**

* The DHAV container itself does **not** parse NALs: it slices out `[body, bodyLen]` purely
  arithmetically (§1.1) and hands it on. It performs **no** start-code check.
* The consumer of that body is the raw NAL scanner
  `FUN_180039fa0` = `Dahua::StreamParser::CRawH264Stream::ParseData`
  (`.\Src\StreamAnalzyer\RawStream\RawH264Stream.cpp`), which searches for start codes:

```c
uVar10 = GetByte(data, i+2);  if ((u8)uVar10 != 0 && (u8)uVar10 != 1) { i += 3; continue; }
uVar10 = GetByte(data, i  );  if ((u8)uVar10 != 0 && (u8)uVar10 != 1) { i += 1; continue; }
b1 = GetByte(data, i+1);  b3 = GetByte(data, i+3);
ok  = IsStartCode((b3<<24)|(b1<<16)|(b2<<8)|b0) ||        /* 00 00 01 xx / 00 00 00 01 */
      IsStartCode((b1<<16)|(b2<<8)|b0);
i   = ok ? (4 - (b3 != 0)) + i : i + 1;                   /* 3- or 4-byte start code */
nalType = GetByte(data, i) & 0x1F;
if (nalType == 0 || (0x0E..0x12) || (0x14..0x1F)) skip;   /* only 1,5,6,7,8,9,0x13 accepted */
/* frame boundaries accumulated at SPS(7)/PPS(8)/SEI(6)/AUD(9); SPS+PPS+slice -> I-frame */
```

  A 4-byte *length* prefix (`00 00 0A 1B …`) passes the first zero test but then
  `b3 != 0` and the 3-byte variant fails, so the scanner loses sync; a 2-byte `00 1B`
  prefix fails immediately. Only length-prefixed AVC inside MP4 (`avcC`/`hvcC`) is handled,
  by a different class (`CMP4File::HasH264CodecInfo`, "Avcc Lost Nal Data"), i.e. **not** on
  the RTP/DHAV path.

---

## 4. Q4 — Fallback that accepts standard RTP without "DHAV"?

**No fallback was found in MDP.exe; the DHAV magic test is unconditional on the RTP path.**

Evidence chain (all in `MDP.exe`):

1. RTP receive → `FUN_140284850` = `RTSPSDK::CRTSPBaseUnit::onRTPPacket`
   (`.\Base\RTSPBaseUnit.cpp`, line 0xB1) → payload pointer/length via `FUN_14029c680`,
   then a virtual dispatch `(**(code**)(*this + 0x70))(this, payload, len, rtp)` — the
   payload including the DHAV header is passed through verbatim, at offset 0.
2. The demuxer is created lazily in `FUN_14011cbd0`:

```c
if (*obj == 0) { *obj = SP_CreateStreamParser( (int)obj[1] ); return *obj != 0; }
```
3. `obj[1]` (i.e. `+0x08`) is written **once**, by `FUN_140113350`, with a **hard-coded
   constant**:

```c
FUN_140113350(obj, mediaStream, codec /*+0x40*/, param4 /*+0x43*/) {
  ...
  pv = operator_new(0x10);  obj[7] = FUN_14011cbc0(pv, 0x100000);   /* 0x100000 = parser type */
  FUN_14011cbd0(obj[7]);
}
```
4. `SP_CreateStreamParser` has exactly **one** call site in the whole image
   (import thunk `0x1401363b8 → [0x1402C2EA0]`, sole caller `0x14011cbe9`), and the type is
   the same constant `0x100000` for every stream, every codec, every server.
   **There is no code path that switches the parser type on the RTSP `Server:` header, on
   the SDP, on the payload type, or on a parse failure.** (`MDP.exe` only ever *sends*
   `Dahua Rtsp Client/2.0` (string `0x140305E10`); it has no "Dahua Rtsp Server" string and
   no per-vendor branch.)
5. In `StreamParsermd.dll` the DHAV container check is a plain `if (*p == 0x56414844) … else
   return 6;` — error 6 goes back up to `SP_ParseData`, and MDP only has
   `SP_GetLastError`/`SP_ClearBuffer`/`SP_Destroy` to react with.

Consequence for an open-source gateway: **a vanilla MediaMTX RTP stream (standard RTP,
Annex-B payload, no private header) is not accepted by `MDP.exe`'s media pipeline.** The
RTSP signalling may succeed (MDP is a normal client: DESCRIBE/SETUP/PLAY over :9100 works),
but the first payload is rejected at the container layer and no video is produced.

Caveat / residual unknown (see §8): the numeric meaning of the type constant `0x100000`
inside `StreamParsermd.dll` was not resolved. If that id means "auto/private container", the
analyzer could in principle try the sibling `CRawH264Stream` (Annex-B) after the DHAV
parser returns 6. The static evidence is against it — there is no magic-sniffing code other
than the two DHAV checks (`0x180034b4b`, `0x1800509af`), and no code that inspects
`+0x18`/`+0x1C` before choosing a handler — but a 1-packet live test settles it (§9).

---

## 5. Q5 — Minimal exact recipe to synthesize an accepted DHAV header (H.265 Annex-B)

Two equivalent strategies. **(A)** replay the device's own header shape verbatim
(recommended, proven by capture); **(B)** minimal header with `extraLen = 0`.

### A. Verbatim-shaped (recommended)

For each frame, emit exactly one RTP payload per DHAV record
(`[DHAV 24][TLV][Annex-B frame][8 zero bytes]`):

```
0x00  44 48 41 56              'DHAV'
0x04  FC                        media class = video
0x05  00                        sub-class
0x06  00 00                     reserved
0x08  <u32 LE frame counter>    monotonic, +1 per frame (any start value)
0x0C  <u32 LE recordLen>        = 24 + extraLen + nalLen + 8
0x10  <u32 LE unix seconds>     time.time()
0x14  81                       (copy from capture; not validated)
0x15  FC                       (copy from capture; not validated)
0x16  0C                       extraLen = 12
0x17  BC                       (copy from capture; not validated)
0x18  80 00 <w/8> <h/8>        TLV 0x80: width = b<<3, height = b<<3   (1280x720 -> A0 5A)
0x1C  81 1E 0C 1E              TLV 0x81: codec-subtype 0x0C (HEVC), 0x1E = 30 fps
0x20  94 02 01 00              TLV 0x94
0x24  00 00 00 01 <NAL...>     Annex-B: 4-byte start code then NAL units
...   00 00 00 00 00 00 00 00  8 trailing bytes (never read; zeros are fine)
```

* `extraLen = 0x0C` → the NAL data begins at **payload+36** (matches the H.265 capture).
* For **H.264** use `extraLen = 0x08` and the captured block `88 C7 32 2B 33 00 00 00`
  → NAL data begins at **payload+32** (matches the H.264 capture).
* **`+12` must be the true record length including the 8-byte tail.** If `+12` equals the
  RTP payload length, the parser takes the "one whole record" branch and returns
  `payloadLen - 32 - extraLen` bytes; forgetting the 8 tail bytes truncates the frame by 8.
* **No checksum.** Nothing else is validated: `+8` and `+16` may be anything (use counter and
  real time for sanity/DB compatibility), `+20/+21/+23` are opaque and unused, the 8 trailing
  bytes are unused.
* Fragmentation is allowed but not required: the device sends a 2,299-byte H.265 record
  across several RTP packets (header appears only in the first packet of the record, the
  remaining packets are pure continuation bytes). MDP re-assembles; `StreamParsermd` returns
  as much of the body as it already has (`field12 - extra - 32`, clamped to buffered bytes).
  Emitting one complete record per RTP payload is simpler and handled by the same code.

### B. Minimal (`extraLen = 0`) — untested but consistent with the code

`[DHAV 24][Annex-B][8 zeros]`, `byte[0x16] = 0`, NAL data at payload+24, `+12 = payloadLen`.
`FUN_180033490` is then called with length 0 and does nothing, so width/height/fps are never
set in the analyzer; the codec comes from the SDP (see below). Prefer A.

### Reference implementation (Node, no dependencies)

```js
function dhavHeader({ nalLen, counter, timeSec, hevc, width = 0, height = 0, fps = 30 }) {
  const extra = hevc
    ? Buffer.from([0x80, 0x00, (width/8)|0, (height/8)|0,
                   0x81, fps, 0x0C, 0x1E, 0x94, 0x02, 0x01, 0x00])   // 12 bytes
    : Buffer.from([0x88, 0xC7, 0x2B, 0x33, 0x00, 0x00, 0x00, 0x00]);  // 8 bytes (device sample)
  const h = Buffer.alloc(24);
  h.write('DHAV', 0, 'latin1');
  h[4] = 0xFC; h[5] = 0x00; h[6] = 0x00; h[7] = 0x00;
  h.writeUInt32LE(counter >>> 0, 8);
  h.writeUInt32LE(24 + extra.length + nalLen + 8, 12);   // record length
  h.writeUInt32LE(timeSec >>> 0, 16);
  h[20] = 0x81; h[21] = 0xFC; h[22] = extra.length; h[23] = 0xBC;
  return Buffer.concat([h, extra]);                       // append Annex-B + 8 zero bytes
}
// payload = Buffer.concat([dhavHeader({...}), annexBFrame, Buffer.alloc(8)])
```

---

## 6. Wire-level facts a gateway must also satisfy (from the same RE session)

* RTP is standard: `V=2`, `PT 0x6A` (H.265) / `0xEA` (H.264), `SSRC` = the value from SETUP;
  12-byte header; the DHAV record starts at payload offset 0.
* Interleaved framing on :9100 is `$ <channel> <u16 len> <RTP packet>`.
* MDP identifies the codec from the RTSP **SDP** and passes it out-of-band:
  `FUN_140113350(obj, mediaStream, codec, x)` stores `codec` at `obj+0x40`
  (same function that pins parser type `0x100000`). The DHAV TLV `0x81` carries a second,
  in-band codec hint (`0x0C` observed for HEVC) that is stored but not validated
  (`FUN_180033490` case `0x81`: `switch(b[2]) { 1,3→1; 2→2; 5→3; 8→4; 9→9; 10→10;
  0xB→0xB; 0xC→0xC; 0xD→0x23; 0xE→0x81; default→0 }`).
* `StreamParsermd.dll` also contains a **name→id registry** (`FUN_180065720`) that shows the
  container vocabulary MDP's parser understands, including `"DHAV" → 8`, `"DHSTD" → 8`,
  `"RTP" → 0x14`, `"H264"/"AVC" → 0x16`, `"H265"/"HEVC" → 0x17`, `"PSSTD" → 0x0C`,
  `"TSSTD" → 0x1C`, plus the third-party private formats `DONGYANG/STAR/LIYUAN/…`
  (`0x81..0x94`). Useful if the gateway ever needs to speak a sibling private format.

---

## 7. Server implementation action

1. **Do not ship a "standard RTP to MDP" path.** Pointing MDP (`DSS Client`) at a vanilla
   MediaMTX/RTSP source will connect, negotiate and PLAY, but the media demuxer rejects the
   first payload (`magic != "DHAV"` → error 6). If the gateway must serve the Dahua client,
   it has to emit the DHAV container itself (step 3).
2. **Keep the existing transport contract**: `Server: Dahua Rtsp Server/2.0` is not what
   selects the parser (nothing in MDP reads it), so matching the header string alone buys
   nothing. What matters is: interleaved `$` framing on :9100, `PT 0x6A/0xEA`, and a payload
   that starts with `44 48 41 56`.
3. **Emit one DHAV record per frame** with the §5 recipe:
   `24-byte header (magic, class 0xFC, counter, recordLen, unix time, extraLen)`
   + `extraLen` TLV bytes (`0x80` dimensions, `0x81` codec/fps, `0x94`)
   + `00 00 00 01` + NAL units + `8` zero bytes, and set `+12 = 24 + extraLen + nalLen + 8`.
   Use `extraLen = 12` for H.265 and `8` for H.264, or `0` for the minimal form.
4. **No checksum to compute.** `+8`, `+16`, `+20/+21/+23` and the trailing 8 bytes are not
   validated; fill them with real values for interoperability with the DVR/DAV side, not
   because MDP checks them.
5. **Add a regression test** that feeds a synthesized record into `StreamParsermd.dll`
   directly: `SP_CreateStreamParser(0x100000)` → `SP_ParseData(record, len)` must return 0 and
   `SP_GetOneFrame` must yield exactly the Annex-B bytes (frame length = `recordLen - 32 - extraLen`).
   This isolates the container from RTSP/DSS plumbing and pins the offsets used above.
6. **Do not attempt to reuse DPSDK.dll for this** — it contains no DHAV handling at all
   (byte scan), so any integration work there is wasted effort.

---

## 8. Residual unknowns (explicit)

1. **Meaning of `SP_CreateStreamParser` type `0x100000`** inside `StreamParsermd.dll`.
   `MDP.exe` hard-codes it (`FUN_140113350`); the id→class mapping function was not located
   (the class factory `FUN_180078210` only stores the id at `analyzer+0x10`; `CDHAVStream`'s
   vtable at `0x180089F20` has no resolvable constructor cross-reference).
   Static evidence says the id selects the private-container analyzer; a live test (§9) closes it.
2. **Semantics of the 4 opaque bytes `+0x14..+0x17` (except `+0x16`)** and of the 8-byte
   record tail. Unused by `CDHAVStream::ParseData`; likely the DAV file writer's
   frame-number/time extension. Not needed for synthesis.
3. **`CDHAVFile` variant** (`FUN_180050950`, `FUN_18004f730`/`FUN_18004f820`, slice parser
   `SP_CreateSliceParser`) was only located, not fully decompiled: file playback may use a
   slightly different tail convention (seek index). Out of scope for the gateway.

## 9. How to close unknown #1 in five minutes

Run MDP with a local RTSP server that (a) answers with `Server: Dahua Rtsp Server/2.0` and
(b) sends plain H.264 Annex-B RTP without any private header; hook `StreamParsermd!SP_ParseData`
return value. `0` = a raw fallback exists (gateway can skip DHAV); `6` on every packet =
no fallback, confirming the conclusion in §4.

---

## Appendix — commands used (reproducible)

```text
mcp rea open_binary  C:\DSS\DSS Client\MDP.exe            --provider ghidra
mcp rea search_strings DHAV                               (0 hits)
mcp rea search_bytes 44484156 | 44414856 | 56414844 | 56414856   (0 hits in MDP.exe)
mcp rea search_strings Rtsp | Dahua                       (RTSPSDK surface, "Dahua Rtsp Client/2.0")
mcp rea xrefs 0x1402c2ea0 (SP_CreateStreamParser IAT) → thunk 0x1401363b8 → caller 0x14011cbe9
mcp rea procedure_pseudo_code 0x140284850   # RTSPSDK::CRTSPBaseUnit::onRTPPacket
mcp rea procedure_pseudo_code 0x14011cbd0 / 0x140113350   # parser creation, type 0x100000
mcp rea open_binary  C:\DSS\DSS Client\StreamParsermd.dll --provider ghidra
mcp rea search_bytes 44484156 → 0x180034b4b, 0x1800509af, 0x1800906cc, 0x1800b6795, 0x1800b7e5d
mcp rea procedure_pseudo_code 0x180034ac0   # CDHAVStream::ParseData  (magic + lengths)
mcp rea procedure_pseudo_code 0x1800333a0   # 24-byte fixed header classify
mcp rea procedure_pseudo_code 0x180033490   # TLV walker at +24
mcp rea procedure_pseudo_code 0x180039fa0   # CRawH264Stream::ParseData (Annex-B scan)
mcp rea procedure_pseudo_code 0x180065720   # name→id registry ("DHAV"→8, "H264"→0x16, …)
node scan_magic.mjs  'C:\DSS\DSS Client' DHAV,dhav     # which modules carry the magic
node dump_strings.mjs <dll> 5                          # StreamParser class/format names
node dhav_decode.mjs                                   # decode both captures (§1.2 table)
```
