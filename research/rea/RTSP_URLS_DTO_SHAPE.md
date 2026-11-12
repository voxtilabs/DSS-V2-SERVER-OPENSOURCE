# RTSP URL DTO shape — REA decompiler pass on DPSDK.dll

Target: `C:\DSS\DSS Client\DPSDK.dll` (byte-identical to `dssv2-setup\dssclient-extracted\DPSDK.dll`)
- SHA-256 `ce43c8b799505f0f2a45c02639f892a426233ad40960d3696cb6150bfccc0d47`, 17,078,880 B, PE32+ x86-64, ImageBase `0x180000000`
- Provider: Ghidra 12.1.4 (REA MCP), read-only, ephemeral import
- Scripts used (scratchpad): `dto_fields.mjs`, `lea_dump.mjs` — they parse the PE section table and do **all** address arithmetic; no hand hex math was used.

This pass **corrects two errors** in `DSS_SERVER_CONTRACT_MAP.md` (§1.1b) and answers the four questions.

---

## 0. Correction: the addresses were wrong and those functions are not parsers

`xref.mjs` in the previous pass walked back to a `0xCC` padding run and reported the enclosing functions as
`0x1806d5eb0` / `0x1806db570`. Verified now with `resolve_containing_procedure`:

| Instruction that loads the key string | True containing function |
|---|---|
| `0x1806d69dc` (`LEA R9,[0x180cdbfc0 "rtspUrls"]`) | **`0x1806d60f0`** (`FUN_1806d60f0`, body `0x1806d60f0-0x1806d86fb`, 9,740 B) |
| `0x1806d6a1b` (`LEA R9,[0x180cdbfd0 "rtspUrl"]`) | `0x1806d60f0` (same function) |
| `0x1806dbf2c` (`rtspUrls`) | **`0x1806db600`** (`FUN_1806db600`, body `0x1806db600-0x1806ddbef`, 9,712 B) |
| `0x1806dbf6b` (`rtspUrl`) | `0x1806db600` (same function) |
| `0x180680060` (`urlType`) | `0x18067fea0` (710 B) |
| `0x1806808f0` (`urlType`) | `0x180680730` (710 B) |

`0x1806d5eb0` is an unrelated 335-byte DTO free/error-string helper (it frees a child list, then copies two
string fields at `this+0x538` / `this+0x540` into an error string at `this+0x18`). It reads no JSON key.
Decompiled in full — see `analyze_function 0x1806d5eb0`.

**Consequence:** the earlier claim "`rtspUrls` is read before `rtspUrl`, therefore the array form wins" is not
supported. These two functions do **not** parse JSON and contain no precedence logic. They build a **DTO field
schema** (see §1). Both `rtspUrls` and `rtspUrl` are simply two field descriptors of the same DTO.

---

## 1. Element type of `rtspUrls` — **array of OBJECTS** `{ streamType, rtspUrl }`

### 1.1 The registrar

Both big functions call the schema registrar; decompiled at `0x1807512d0`:

```c
void FUN_1807512d0(longlong fieldset, undefined4 offset, undefined4 kind,
                   undefined8 namePtr, undefined4 arrayFlag)
```
It appends one 0x20-byte record `{offset(int32), kind(int32), arrayFlag(int32), ?, namePtr, 0}` to
`fieldset->buf` and bumps `fieldset->count` (`fieldset+0x20`). Nothing is read from JSON here.

### 1.2 The two registration sites (verbatim decoded immedia, via `lea_dump.mjs`)

`FUN_1806d60f0` (site A), raw instruction windows:

```
0x1806d69be  LEA R9,[0x180cdb728 "channelMac"]    then: 45 8d 44 24 02   (kind  = 2)
                                                         ba 88 00 00 00   (off   = 0x88)
                                                         44 89 64 24 20   (arrayFlag = 0)
0x1806d69dc  LEA R9,[0x180cdbfc0 "rtspUrls"]      then: 45 8d 44 24 10   (kind  = 0x10)
                                                         ba 90 00 00 00   (off   = 0x90)
                                                        c7 44 24 20 01.. (arrayFlag = 1)
0x1806d69fd  LEA R9,[0x180cae548 "streamType"]    then: 45 8d 44 24 02   (kind  = 2)
                                                        33 d2            (off   = 0)     48 8b c8 (rcx = new fieldset)
                                                        48 8b d8          (rbx = the NEW fieldset just created)
0x1806d6a1b  LEA R9,[0x180cdbfd0 "rtspUrl"]       then: 41 8d 54 24 08   (off   = 8)
                                                        45 8d 44 24 02   (kind  = 2)
                                                        48 8b cb          (rcx = rbx, i.e. the same new fieldset)
0x1806d6a39  LEA R9,[0x180cae6b8 "channelSeq"]    then: kind=2, off = 0xb0, rcx = rdi  (back on the parent fieldset)
```

`FUN_1806db600` (site B) is byte-for-byte the same pattern one slot later:

```
0x1806dbf0e  "channelMac"  kind=2  off=0x90  arrayFlag=0
0x1806dbf2c  "rtspUrls"    kind=0x10 off=0x98 arrayFlag=1
0x1806dbf4d  "streamType"  kind=2  off=0     on a NEW fieldset (rbx = rax)
0x1806dbf6b  "rtspUrl"     kind=2  off=8     on that same new fieldset
0x1806dbf89  "channelSeq"  kind=2  off=0xb8  back on the parent
```

So in **both** DTOs the array field is immediately followed by a freshly allocated fieldset holding exactly two
string members — the element schema:

```
rtspUrls : array (arrayFlag = 1) of  { streamType: string   @ +0
                                      rtspUrl:    string   @ +8 }
```

### 1.3 Why `kind` proves the element is an object and not a string

`kind` for primitives is a small type code (`1` = presence bool, `2` = **string**). For composite fields the value
equals the **byte size of the element/sub-struct**, and `arrayFlag` says whether it is a list:

| Field in the same DTO | kind | arrayFlag | Nested schema registered right after | Size check |
|---|---|---|---|---|
| `dstBeginTime` (`0x1806d81c5`) | `0x20` | **0** (single object) | `time` @ 0 | 32 B single struct |
| **`rtspUrls`** | **`0x10`** | **1** | `streamType`@0, `rtspUrl`@8 | 16 B = 2 × 8-byte string ptrs ✔ |
| `controllers` | `0x18` | 1 | `property` @0, … | 24 B |
| `channels` | `0x38` / `0x18` / `0x08` | 1 | unit/seq/name members | 3 channel-DTO variants |
| `uvssUnits`, `audioUnits`, `easUnits`… | `0x38`/`0x40`/`0x50`/`0x68` | 1 | `unitSeq`, `unitType`, `channelName` … | variable element size |

`rtspUrls` carries `kind = 0x10` = **16 bytes = exactly two 8-byte string pointers**, matching the two members
registered on its element fieldset. It is therefore `list<{streamType:string, rtspUrl:string}>`, **not**
`list<string>`. A plain `array of strings` would have to be registered as an array with a string element, which
never occurs for this key.

### 1.4 Encoding

Both members are registered with `kind = 2`, the same code used for `deviceName`, `orgCode`, `channelSeq`,
`channelMac`, `loginName`, `rtspUrl` on other fields. `kind 2` fields are stored as raw C strings (`_strdup`,
`strcpy`, `strncmp` consumers) — **plain text, not base64**. Nothing on this path base64-decodes.

### 1.5 Does a non-empty array suppress a singular `rtspUrl`?

Not answerable from these two functions (they are schema builders). What *is* established, and matters more:

- `rtspUrl` (singular) exists in the schema **only at offset 8 of each array element**. In both DTOs the
  top-level slots next to the array (`+0x90/+0x98`) are `channelMac` and then `channelSeq` — there is **no
  top-level singular `rtspUrl` field** in either DTO.
- The whole binary contains exactly **two** references to the literal `rtspUrls` and two to `rtspUrl`
  (`xrefs 0x180cdbfc0` → `0x1806d69dc`, `0x1806dbf2c`; `xrefs 0x180cdbfd0` → `0x1806d6a1b`, `0x1806dbf6b`).

➡ A top-level `"rtspUrl"` string emitted next to `"rtspUrls"` is simply **ignored** by these DTOs; it is neither a
fallback nor a winner. Emit the array.

---

## 2. What `urlType` and `scheme` actually are — **request-side selectors, not array filters**

`FUN_18067fea0` (and its 710-byte twin `FUN_180680730`, the RTSPS/TLS variant) build the **request** DTO for the
live-URI call. Decompiled in full:

```c
fieldset = malloc(0x28); ... *(undefined4*)fieldset = 0x48;       // struct size 0x48
FUN_1807512d0(fieldset, 0x00, 2, "planId",   0);
FUN_1807512d0(fieldset, 0x08, 2, "duration", 0);
FUN_1807512d0(fieldset, 0x10, 2, "subType",  0);
FUN_1807512d0(fieldset, 0x18, 2, "dataType", 0);
FUN_1807512d0(fieldset, 0x20, 2, "urlType",  0);
FUN_1807512d0(fieldset, 0x28, 2, "extend",   0);
FUN_1807512d0(fieldset, 0x30, 2, "channelId",0);
FUN_1807512d0(fieldset, 0x38, 2, "scheme",   0);
FUN_1807512d0(fieldset, 0x40, 2, "trackId",  0);
_Dst[0] = "MediaRealMonitorUri";  _Dst[1] = "Media.RealMonitor.Uri";
_Dst[2] = "GET";                  _Dst[6] = "application/json;charset=UTF-8";
```

Findings:

1. **Method is `GET`** for `Media.RealMonitor.Uri` (not POST). Params therefore travel as query string/params
   object, content type `application/json;charset=UTF-8`.
2. `urlType`, `scheme`, `subType`, `dataType`, `channelId`, `trackId`, `planId`, `duration`, `extend` are all
   **request fields the client sends to us** — all `kind = 2` strings. They select nothing inside `rtspUrls`.
3. There is **no enum/validation table** for `urlType` or `scheme` in these functions: the DTO declares them as
   free-form strings with no allowed-value check, no clamping, no default. The client-side request builder
   (`FUN_18067fc60`-style helper pair used for free/validate) only reports missing/invalid *strings*.
4. So the semantic ("1 = direct/standard URL", "2 = gateway/relay", `scheme` = `rtsp`/`rtsps`) is **ours to
   define**. The safe contract: accept any value, never reject on unknown `urlType`/`scheme`, and answer with a URL
   whose scheme matches `scheme` (`rtsp` for `FUN_18067fea0`, `rtsps` for the `FUN_180680730` RTSPS path).

> Practical rule for the gateway: treat `urlType`/`scheme` as hints. If `scheme` is `rtsps` (or the device field
> `enableRtspTls` @ `0x180cdb870` is set) return an `rtsps://` URL on the TLS port; otherwise return `rtsp://`.

---

## 3. `CRTSPBaseClient::Start` @ `0x180849bd0` — it does **not** set a default wait time

Full decompilation:

```c
void FUN_180849bd0(longlong this) {
  if (*(char *)(this + 0xb8) != '\0') { FUN_1808895f0(this + 8, 0); return; }
  log(..., ".\\Base\\RTSPBaseClient.cpp", 0x4f3, "RTSPSDK::CRTSPBaseClient::Start", ...,
      "[DPSDK] MediaSessionID=[%d], RtspThreadWaitTime = %d",
      *(int*)(this + 0x18), *(int*)(this + 0x2c));
  FUN_1808895f0(this + 8, *(undefined4 *)(this + 0x2c));   // <-- thread wait = field +0x2c
}
```

- The wait is simply `*(int*)(this + 0x2c)`; `Start` only logs and forwards it (line 0x4f3 of
  `RTSPBaseClient.cpp`). **There is no literal default in `Start`.**
- If `this+0xb8 != 0` (session already flagged started/stopped) it calls the wait with `0` and returns.
- The value is set elsewhere: export **`DPSDK_SetRtspThreadWaitTime`** (`0x180ef7e9d`, string at that VA) and the
  server-supplied config key **`threadWaitTime`** (`0x180c3f128`, referenced from `0x180a098b5`, `0x180a0b85c`,
  `0x180a0d557` — config parsing code).
- ➡ The SETUP wait is therefore **configurable by our server**, not fixed. Feeding `threadWaitTime` in the
  config/environment response raises the client's SETUP timeout. Which config endpoint carries it was not
  enumerated in this pass (no default constant exists to report).

---

## 4. SETUP 200 response requirements — confirmed by decompilation

### 4.1 Header-line parser `FUN_180b45d90` (487 B), decompiled in full

```c
if (line_has_prefix(line, "CSeq:", 5)) {
    skip spaces/tabs; strtol(...); if (!parsed) { log("Unable to read the CSeq header: [%s]"); return 0x55; }
    ... store cseq ...; return 0;
}
if (line_has_prefix(line, "Session:", 8)) {
    skip spaces/tabs; if (empty) { log("Got a blank Session ID"); return 0x56; }
    token = chars until ';' | ' ' | '\t' | CR
    if (this->expectedSessionId == NULL) { strdup(token) into this+0x910; return 0; }   // ADOPTS it
    else if (len differs || strncmp(token, expected) != 0) {
        log("Got RTSP Session ID Line [%s], but wanted ID [%s]", token, expected); return 0x56;
    }
    return 0;
}
if (line_has_prefix(line, "Transport:", 10)) { return FUN_180b458f0(this, line+10); }
return 0;                    // any other header is ignored
```

Conclusions:

- **`CSeq:` is mandatory** and must parse as decimal (`strtol`); otherwise error **0x55**.
- **`Session:` is mandatory and must be non-empty** (blank → error **0x56**, "Got a blank Session ID").
- **The session id is NOT pre-agreed.** On the first response that carries `Session:` the client *adopts*
  whatever id we return (`this+0x910 == NULL` branch, no comparison). The `wanted ID` comparison only applies to
  subsequent responses — so the id must be **stable** from SETUP onwards for PLAY/PAUSE/TEARDOWN, and changing it
  mid-session produces error 0x56 with the "but wanted ID" log line.
- The token is truncated at `;`, space, tab or CR — so `Session: 12345678;timeout=60` is fine (`12345678` kept).

### 4.2 Transport parser `FUN_180b458f0`, decompiled in full

Walks semicolon-separated tokens, finds `interleaved=`, parses channel `a` and optional `-b` with each value in
`0..255` and `b >= a`, then sets bits `a..b` in a used-channel bitmap at `this+0x12f4`.

- `"Unable to read the interleaved parameter from Transport header: [%s]"` is logged when the values are
  unparsable/out of range.
- Note it still returns `0` on that failure (the failure is reported, not fatal at this level) — but the interleaved
  channel bitmap is what the TCP demuxer uses, so **without `interleaved=a-b` the TCP payload cannot be dispatched
  and PLAY produces no video** even though the status line was 200.

➡ Required SETUP 200 headers: `CSeq: <same decimal>`, `Session: <non-empty, stable>`,
`Transport: RTP/AVP/TCP;unicast;interleaved=0-1` (channels 0..255, second ≥ first).

---

## 5. Answers in one line each

1. **`rtspUrls` is an array of OBJECTS**, element = `{ "streamType": <string>, "rtspUrl": <string> }` (kind 0x10 =
   16-byte element, arrayFlag 1). Both values are **plain strings**, no base64. A top-level singular `rtspUrl` is
   not part of either DTO and is ignored.
2. **`urlType`/`scheme` are request parameters of the `GET Media.RealMonitor.Uri` call**, free-form strings with no
   client-side enum or filtering; they are hints for the server to pick URL/scheme.
3. **`Start` sets no default** `RtspThreadWaitTime`; it forwards `*(this+0x2c)`, which is set by
   `DPSDK_SetRtspThreadWaitTime` and the server-supplied `threadWaitTime` config key.
4. **Yes to both:** the SETUP 200 must carry a parseable `CSeq:`, a **non-empty** `Session:` and a `Transport:`
   containing `interleaved=a-b`. The session id does **not** need to be pre-agreed for the SETUP response (it is
   adopted), but it must then stay identical for every later response.

---

## 6. Server implementation action

### 6.1 Device / channel DTOs (where `rtspUrls` actually lives)

Replace any `rtspUrl`/`rtspUrls`-of-strings with this exact shape. `streamType` and `rtspUrl` are the only two
element keys, both strings; `streamType` is a **string** (`"0"` main / `"1"` sub), per repo rule that counters are
strings.

```json
{
  "deviceCode": "1000000",
  "deviceName": "Dahua Cam",
  "channelSeq": "1",
  "rtspUrls": [
    { "streamType": "0", "rtspUrl": "rtsp://10.0.0.5:9100/cam/realmonitor?channel=1&subtype=0" },
    { "streamType": "1", "rtspUrl": "rtsp://10.0.0.5:9100/cam/realmonitor?channel=1&subtype=1" }
  ]
}
```

Do **not** emit a sibling top-level `"rtspUrl"` string next to `"rtspUrls"` — neither DTO declares it, so it is
dead weight (previous report's "also return the singular fallback" advice is wrong for these DTOs).

### 6.2 `Media.RealMonitor.Uri` (StartVideo)

The client sends a `GET` with these 9 possible string params (all optional, no enum validation):

```
planId, duration, subType, dataType, urlType, extend, channelId, scheme, trackId
```

Answer with a dialable URL, the token/trackId pair, and both discriminators. `token` and `trackID` are appended by
the client itself as `?token=`/`&token=` + `&trackID=` (`0x180c04178`, `0x180c04188`), so the base URL we return
must not already contain `token=`/`trackID=`.

```json
{
  "code": 0,
  "msg": "OK",
  "data": {
    "url": "rtsp://10.0.0.5:9100/cam/realmonitor?channel=1&subtype=0",
    "rtspUrl": "rtsp://10.0.0.5:9100/cam/realmonitor?channel=1&subtype=0",
    "token": "0000000000000000",
    "trackId": "0",
    "mediaType": "1",
    "streamType": "0",
    "subType": "0",
    "urlType": "1",
    "scheme": "rtsp"
  }
}
```

Caveat, stated explicitly: §6.2's key set (`url`/`rtspUrl`/`token`/`trackId`/`mediaType`/`streamType`) comes from
the surrounding DTO pool and the failure log format at `0x180ca9460`, **not** from a decompiled
`Media.RealMonitor.Uri` *response* schema — that response schema was not located in this pass (the only two
functions referencing `rtspUrl*` are the device/channel DTOs of §1). §6.1 is decompiler-proven; §6.2 remains
strings/log-derived.

### 6.3 RTSP responder

- `RTSP/1.0 200 OK`, echo the request `CSeq` verbatim as a decimal.
- `Session:` always present, non-empty, and identical on every response for the life of the session
  (the client adopts it at SETUP, then enforces it).
- For TCP: `Transport: RTP/AVP/TCP;unicast;interleaved=0-1` (0..255, second ≥ first).
- Answer SETUP in < 1 s; do not block on the upstream camera.

---

## 7. Method / evidence index

| Claim | Tool call | Address |
|---|---|---|
| container of the key LEAs (not `0x1806d5eb0`) | `resolve_containing_procedure` | `0x1806d60f0`, `0x1806db600`, `0x18067fea0`, `0x180680730` |
| schema registrar semantics | `procedure_pseudo_code` | `0x1807512d0` |
| all 131 field registrations of DTO A | `dto_fields.mjs` + `read_bytes` | `0x1806d60f0-0x1806d86fb` |
| exact `rtspUrls`/`rtspUrl` immedia | `lea_dump.mjs` | `0x1806d69dc`, `0x1806d69fd`, `0x1806d6a1b`, `0x1806dbf2c`, `0x1806dbf4d`, `0x1806dbf6b` |
| request DTO of `Media.RealMonitor.Uri` | `procedure_pseudo_code` | `0x18067fea0` (twin `0x180680730`) |
| `Start` wait-time source | `procedure_pseudo_code` | `0x180849bd0` |
| Session/CSeq/Transport rules | `procedure_pseudo_code` | `0x180b45d90`, `0x180b458f0` |
| no other `rtspUrls`/`rtspUrl` readers | `xrefs` | `0x180cdbfc0`, `0x180cdbfd0`, `0x180c64310` |

Residual unknowns: (a) the `Media.RealMonitor.Uri` **response** schema (not located); (b) which config endpoint
carries `threadWaitTime`; (c) whether the client prefers `streamType` `"0"` or `"1"` for the live tile (the
selection code was not traced).
