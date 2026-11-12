# DSS client — pass 4: Playback / Snapshot / Download / PTZ response schemas

Target: `C:\DSS\DSS Client\DPSDK.dll`
- SHA-256 `ce43c8b799505f0f2a45c02639f892a426233ad40960d3696cb6150bfccc0d47`, 17,078,880 B, PE32+ x86-64, ImageBase `0x180000000`
- Provider: Ghidra 12.1.4 via REA MCP (`open_binary`, `procedure_pseudo_code`, `procedure_callees`), read-only, ephemeral import.
- Local PE scripts in the session scratchpad do **all** address arithmetic (no hand hex math):
  `p4.mjs` (`locate` / `xrefs` / `callers` / `callees` / `range` / `hex`), `keyscan.mjs` (fieldset-registration decoder),
  `dto_fields.mjs` (registrar decoder for the direct-form builders).
- Terminology, proven last pass and re-confirmed here: `FUN_1807512d0(fieldset, offset, kind, name, arrayFlag)` appends one
  field descriptor. `kind 0` = 32-bit slot, `kind 1` = **bool**, `kind 2` = **string (char\*)**, `kind 3` = **8-byte
  JSON number**, `kind 100` = nested object/array, `kind >= 0x08` on an array field = element/container size.

> Scope note: this pass **decompiled** every response descriptor listed below. Previous documents
> (`DSS_SERVER_CONTRACT_MAP.md`, `RTSP_URLS_DTO_SHAPE.md`, `DSS_RESIDUAL_PASS3.md`) had to guess these; §1–§4 replace
> those guesses. The `Media.RealMonitor.Uri` 11-key live DTO from pass 3 stands unchanged.

---

## 0. How the client writes and reads a DTO (mechanics that constrain the JSON)

Two facts recovered this pass decide the JSON encoding of every endpoint on this page.

**0.1 Requests are GET query strings, not JSON bodies.**
`Dpsdk::CRestLogicalImplVSL::StartPlaybackByTime`'s request descriptor installs `FUN_1806804f0` in slot `0xb`
(the request serializer). Decompiled, it walks the three fieldsets attached to the request instance
(`+0x70`, `+0x78`, `+0x80`), serializes the real fieldset with `FUN_180753c00` and **appends the resulting text to the
URL buffer at `+0x18`** via `FUN_18055f570`. There is no body writer on this path.

```c
// FUN_1806804f0 (request serializer for playback/uri and its siblings)
_Memory = FUN_1807545d0(param_1 + 0x70, DAT_180f76938);  // free previous fieldset render
*(param_1 + 0x38) = FUN_180758590(_Memory);              // render the "absent" stub -> empty
_Memory_00 = FUN_180752f20(param_1 + 0x78, DAT_180f76940);   // stub  -> "" ; FUN_18055f570(url, "") is skipped
_Memory_01 = FUN_180753c00(param_1 + 0x80, DAT_180f76948);   // REAL fieldset -> "k=v&k=v"
FUN_18055f570(param_1 + 0x18, _Memory_01);               // append to the URL
```
⇒ every endpoint in §1–§4 arrives at the gateway as `GET <path>?<query>` with `Content-Type:
application/json;charset=UTF-8` declared but unused. **The gateway must parse query parameters, not a body.**

**0.2 Response JSON is bound field-by-field, and the *JSON node type* must match the *field kind*.**
`FUN_180754c60` is the tree→DTO binder. Its dispatch on the target field kind is explicit:

```c
// FUN_180754c60 (excerpt, node types: 0/1 = JSON bool, 3 = JSON number, 4 = JSON string, 6 = object/array)
if (fieldKind == 1) {                        // bool field
    if (nodeType == 1) *(u32*)dst = 1;       // JSON true
    else if (nodeType == 0) *(u32*)dst = 0;  // JSON false          <-- a "0"/"1" *number* is NOT accepted
}
else if (fieldKind == 2) {                   // string field
    if (nodeType == 4) *(char**)dst = _strdup(node->str);
}
else if (fieldKind == 3) {                   // 8-byte number field
    if (nodeType == 3) *(u64*)dst = node->num;                     // a *quoted* "12.5" is NOT accepted
}
```
**Consequence for the gateway:** fields declared `kind 1` must be emitted as JSON `true`/`false`; fields declared
`kind 3` must be emitted as JSON **numbers**; only `kind 2` fields are strings. This is the one place the repo rule
"counters are strings" does not apply — and it silently fails (field left zeroed) if we get it wrong.

---

## 1. `playback/uri` — Playback tab

### 1.1 Call sites

| Function | Address | Source | Path literal |
|---|---|---|---|
| `Dpsdk::CRestLogicalImplVSL::StartPlaybackByTime` | `0x180233650` | `RestLogicalImplVSL.cpp:0x1c2` (req) / `0x1e1` (fail log) | `playback/uri` @ `0x180c97c00` |
| `Dpsdk::CRestLogicalImplVSL::StartPlaybackByFile` | `0x180234060` | same file | `playback/uri` (same literal) |

Both xrefs of `0x180c97c00` are inside these two functions (`0x180233a26`→`0x180233650`, `0x180234436`→`0x180234060`).
Both use the **same** request descriptor and the **same** inline response descriptor, so the contract is identical for
time-based and file-based playback.

### 1.2 Request descriptor — `FUN_180680730` (710 B), topic `Storage.Record.GetPlaybackUri`

```c
// FUN_180680730   (decompiled verbatim)
_Dst = malloc(200); memset(_Dst,0,200);
// fieldsets DAT_180f76938 / DAT_180f76940 = 8-byte "absent" stubs (hasFieldOf_nouse / _nouse)
DAT_180f76948 = malloc(0x28); *(u32*)DAT_180f76948 = 0x48;          // request DTO = 0x48 bytes, 9 string slots
FUN_1807512d0(DAT_180f76948, 0x00, 2, "resource",    0);
FUN_1807512d0(DAT_180f76948, 0x08, 2, "endTime",     0);
FUN_1807512d0(DAT_180f76948, 0x10, 2, "duration",    0);
FUN_1807512d0(DAT_180f76948, 0x18, 2, "subType",     0);
FUN_1807512d0(DAT_180f76948, 0x20, 2, "urlType",     0);
FUN_1807512d0(DAT_180f76948, 0x28, 2, "scheme",      0);
FUN_1807512d0(DAT_180f76948, 0x30, 2, "beginTime",   0);
FUN_1807512d0(DAT_180f76948, 0x38, 2, "location",    0);
FUN_1807512d0(DAT_180f76948, 0x40, 2, "channelCode", 0);
_Dst[0]="StorageRecordGetPlaybackUri"; _Dst[1]="Storage.Record.GetPlaybackUri";
_Dst[2]="GET"; _Dst[6]="application/json;charset=UTF-8";
_Dst[0xb]=FUN_1806804f0;  _Dst[0xc]=FUN_18074e3c0;  _Dst[0xd]=FUN_180680640;
```

### 1.3 What the client actually fills — `StartPlaybackByTime`

Request DTO base is descriptor `+0x80` (every write lands in `0x80..0xC0`, matching the 9 declared offsets):

```c
// FUN_180233650, after the descriptor is created and "playback/uri" dispatched
*(lVar6 + 0xC0) = _strdup(param_2 + 0x60);                    // channelCode   = camera code (std::string body)
*(lVar6 + 0xA8) = _strdup("RTSP");                            // scheme        = literal "RTSP"   (never lowercase)
*(lVar6 + 0x90) = _strdup("600");                             // duration      = literal "600" (seconds)
*(lVar6 + 0xB0) = _strdup(str(param_2 + 0xA8));               // beginTime     = caller-supplied string
*(lVar6 + 0x88) = _strdup(str(param_2 + 0xB8));               // endTime       = caller-supplied string
*(lVar6 + 0xB8) = _strdup(itoa(*(int*)(param_2 + 0x50), 2));  // location      = itoa(...,radix 2) -> BINARY mask text
*(lVar6 + 0x98) = _strdup(itoa(*(int*)(param_2 + 0x48) - 1)); // subType       = streamType - 1
*(lVar6 + 0xA0) = _strdup(*(char*)(param_2 + 0x1C0) ? "2" : "1"); // urlType  = 2 when RTSPS/TLS, else 1
// resource (offset 0x00) is NEVER written by either playback caller -> arrives empty
FUN_1800d3840(session, lVar6, "playback/uri", 1);             // dispatch
```

Notes worth acting on:
- **`beginTime` / `endTime` — not `startTime`/`endTime`.** The request key is `beginTime`. (`startTime` @ `0x180caf6f0`
  and `endTime` @ `0x180caf410` exist elsewhere in the pool but are not part of this DTO.)
- **`location` is a binary bitmask rendered by `itoa(v, 2)`** (`FUN_1800ce9b0(...,2)`): e.g. `0` → `"0"`, `1` → `"1"`,
  `3` → `"11"`. Treat it as an opaque storage-location mask string.
- **`resource` is sent empty.** Do not require it, and do not use it to select the stream — `channelCode` does that.
- Failure log string (`0x180234...`, file line `0x1e1`):
  `"Playback StartPlaybackByTime Request Failed iRet[%d] ! strCameraId = %s, iStreamType = %d, strURL = %s"`
  — note `strURL`, i.e. the response is expected to contain a URL, and it is what the RTSP client dials.

### 1.4 Response descriptor — built **inline** in the caller (no separate builder function)

This is why pass 3's "find a `FUN_xxxx` response builder" approach found nothing for playback. The DTO is assembled by
hand inside `FUN_180233650` / `FUN_180234060`:

```c
_Dst = malloc(0x68); memset(_Dst,0,0x68);           // response object
DAT_180f76950 = malloc(0x28); *(u32*)DAT_180f76950 = 0x10;   // DTO = 0x10 bytes = 2 slots
// slot 0:  offset 0, kind 2 (string), arrayFlag 0, name = DAT_180cd76ac == "uri"
// slot 1:  offset 8, kind 1 (bool  ), arrayFlag 0, name = "cascade"
_Dst[0x40]=FUN_180680a00; _Dst[0x48]=FUN_180680a20; _Dst[0x50]=FUN_180680b10;   // to-json / from-json / free
iVar4 = FUN_18055d860(session, lVar6 /*req*/, _Dst /*resp*/, 10);
if (iVar4 == 0) {
    std::string::operator=(param_3 + 0x30, str(*(char**)(_Dst + 0x58)));  // DTO slot 0 -> "uri"
    *(bool*)(param_3 + 0xB0) = *(int*)(_Dst + 0x60) != 0;                 // DTO slot 1 -> "cascade"
}
```

`read_bytes 0x180cd76ac` = `75 72 69 00` = **`uri`** (immediately after `…Record.GetFileDownloadUri`).
Response DTO base = response object `+0x58`; **exactly two fields**, nothing else is parsed.

| DTO off | JSON key | kind | JSON type | meaning |
|---|---|---|---|---|
| +0x00 | **`uri`** | 2 | string | the playback RTSP URL the client dials (`strURL` in the failure log) |
| +0x08 | **`cascade`** | 1 | **bool** (`true`/`false`) | cascade/relay flag; read as `!= 0` into the play-params struct |

There is **no** `url`, `rtspUrl`, `rtspUrls`, `startTime`, `endTime`, `recordType` or `streamType` in this response.
Playback time/recordType are request-side only (`beginTime`, `endTime`, `subType`) — the server does not echo them.

### 1.5 Exact JSON the gateway must emit

Request (what arrives):
```
GET {base}/playback/uri?channelCode=1000000%240&beginTime=2026-11-12%2004%3A00%3A00&endTime=2026-11-12%2005%3A00%3A00&duration=600&subType=0&urlType=1&scheme=RTSP&location=0
```
Response:
```json
{
  "code": 1000,
  "msg": "Success",
  "data": {
    "uri": "rtsp://127.0.0.1:9100/playback/1000000_0?playmode=playback",
    "cascade": false
  }
}
```
Rules: `uri` a **string**; `cascade` a JSON **boolean** (a `"0"` string or a `0` number is silently dropped by
`FUN_180754c60` and leaves the flag false). The URL must be dialable as-is and must tolerate `?token=`/`&token=` +
`&trackID=` appending (pass-3 §1.3). For playback the RTSP transport carries `playmode=playback` (or
`playmode=download` for §3) — the modifier pool is `0x180c03dc8`–`0x180c03eb0` in the old contract map.

---

## 2. `realmonitor/snapshot/` — Live View snapshot

### 2.1 Call site — `Dpsdk::CRestLogical::PlatformSnapshot` @ `0x18024f760`

Source provenance: `.\Logic\RestLogic\RestLogicalPreview.cpp` line `0x48` (param guard), `0x4F` (alloc), `0x71` (fail log).
Only one caller of the request descriptor `FUN_180692250` (`0x18024f83e`), and only one caller of `PlatformSnapshot`.

### 2.2 Request descriptor — `FUN_180692250`

```c
// FUN_180692250
_Dst = malloc(0x88); memset(_Dst,0,0x88);
DAT_180f76e58 (size 8)  -> FUN_1807512d0(.., 0, 2, "optional",  0);
DAT_180f76e60 (size 8)  -> FUN_1807512d0(.., 0, 2, "channelId", 0);
DAT_180f76e68 (size 8)  -> FUN_1807512d0(.., 0, 2, &DAT_180caed2c /* "time" */, 0);
_Dst[0]="MediaRealMonitorSnapshot"; _Dst[1]="Media.RealMonitor.Snapshot";
_Dst[2]="GET"; _Dst[6]="application/json;charset=UTF-8";
_Dst[0xb]=FUN_180692010; _Dst[0xc]=FUN_18074e3c0; _Dst[0xd]=FUN_180692160;
```

Third key confirmed by bytes: `0x180caed2c` = `74 69 6d 65 00` = **`time`** (same pool entry used by `dstBeginTime`).

Filled by the caller (DTO base `+0x70`):
```c
*(lVar7 + 0x78) = _strdup(pChannelID);   // channelId  (a NULL pChannelID is rejected with -4 before this)
*(lVar7 + 0x80) = _strdup(time);         // time       (std::string from param_3)
// "optional" (offset 0x70) is left empty
FUN_1800d3840(param_1, lVar7, "realmonitor/snapshot/", 1);   // NOTE trailing slash in the literal
```
There is **no** `width`, `height`, `quality`, `streamType` or `subType` key — the snapshot is taken at whatever the
device's default resolution is. Do not expect them and do not require them.

### 2.3 Response descriptor — inline, **one** field: `content`

```c
_Dst = malloc(0x60); memset(_Dst,0,0x60);
DAT_180f76e70 = malloc(0x28); *(u32*)DAT_180f76e70 = 8;      // DTO = 8 bytes = 1 slot
// slot 0: offset 0, kind 2 (string), arrayFlag 0, name = "content"
_Dst[0x40]=FUN_1806923d0; _Dst[0x48]=FUN_1806923f0; _Dst[0x50]=FUN_1806924e0;
iVar4 = FUN_18055d860(uVar6, lVar7, _Dst, 8);
if (iVar4 == 0) {
  if (*(char**)(_Dst + 0x58) != NULL) {                     // DTO slot 0
    len  = strlen(content);
    if (0 < len) {
      iVar5 = ((len + 3) >> 2) * 3 + 4;                     // 4/3 expansion -> base64
      out   = operator_new(iVar5); *param_4 = out; memset(out, 0, iVar5);
      iVar5 = FUN_1807904e0(content, len, out, iVar5);      // <-- BASE64 DECODE
      *param_5 = (iVar5 < 0) ? 0 : iVar5;                   // decoded byte count (image size)
    }
  }
}
```

`FUN_1807904e0` decompiled = a textbook base64 decoder: it selects an alphabet table (`DAT_180bf11b0` standard,
`DAT_180bf1200` when the input contains `-`, i.e. URL-safe), rejects `length % 4`, honours `=` padding
(`(n>>2)*3 - pad`), and accumulates 6 bits per symbol.

⇒ **`realmonitor/snapshot/` returns the image itself, base64-encoded, in a single key `content`. It does NOT return a
URL.** The buffer goes straight into the snapshot bitmap; any URL here would fail to decode and be dropped.

### 2.4 Exact JSON

Request: `GET {base}/realmonitor/snapshot/?channelId=1000000%240&time=2026-11-12T04%3A00%3A00`
Response:
```json
{ "code": 1000, "msg": "Success", "data": { "content": "/9j/4AAQSkZJRgABAQAAAQABAAD..." } }
```
`content` = raw JPEG/PNG bytes, standard base64, `=` padded, no `data:` URI prefix, no newlines. Size is checked only
implicitly (a `-1` from the decoder is clamped to 0 ⇒ a zero-byte snapshot).

---

## 3. Download URIs

### 3.1 `download/uri` — `Dpsdk::CRestLogicalImplVSL::StartPBDownloadByTime` @ `0x1802349c0`

Source: `RestLogicalImplVSL.cpp` `0x220` (alloc), `0x237` (fail).

Request descriptor **`FUN_180681ca0`**, topic `Storage.Record.GetDownloadUri`:

```c
DAT_180f76998 (size 0x20) -> FUN_1807513e0(DAT_180f76998, 0, 0x18, "dimensionHideNode", 1);
    // ^ array, arrayFlag 1, element size 0x18; the NEW fieldset returned is the element schema:
    FUN_1807512d0(elem, 0x00, 2, "begintime", 0);
    FUN_1807512d0(elem, 0x08, 2, "filename",  0);
    FUN_1807512d0(elem, 0x10, 2, "endtime",   0);
DAT_180f769a0 (size 8)  -> hasFieldOf_nouse / _nouse  (absent stub)
DAT_180f769a8 (size 8)  -> FUN_1807512d0(.., 0, 2, "channelCode", 0);
_Dst[0]="StorageRecordGetDownloadUri"; _Dst[1]="Storage.Record.GetDownloadUri";
_Dst[2]="GET"; _Dst[6]="application/json;charset=UTF-8";
_Dst[0xb]=FUN_180681a60; _Dst[0xc]=FUN_18074e3c0; _Dst[0xd]=FUN_180681bb0;
```

**Note the schema name `dimensionHideNode`** (`0x180cd78b8`) is a Dahua copy-paste leftover — the *elements* are clearly
record-clip descriptors `{begintime, filename, endtime}`. Emit/accept it under that exact key.

Caller fills: `channelCode` at `+0x98`, and appends 0x18-byte elements `{beginTime, filename, endTime}` to the array
container at `+0x70` (ptr/len/cap/count at `0x70/0x78/0x80/0x88`), count at `+0x88`.

Response descriptor inline, **one** field:
```c
_Dst = malloc(0x60); ... DAT_180f769b0 = malloc(0x28); *(u32*)DAT_180f769b0 = 8;
// slot 0: offset 0, kind 2 (string), name = &DAT_180cd76ac == "uri"
if (iVar4 == 0) std::string::operator=(param_3, str(*(char**)(_Dst + 0x58)));   // uri -> output string
```

### 3.2 `record/downalod/uri` — `0x180235360` (Dahua's typo is in the **path literal** `0x180c97d70`)

Request descriptor **`FUN_18067e390`**, response descriptor **`FUN_18067e6b0`** (`keyscan` on both, validated against
the decompiler's `dimensionHideNode` case):

| side | field | off | kind | JSON |
|---|---|---|---|---|
| request | `offset` | 0x00 | 2 | string (byte offset into the file) |
| request | `file` | 0x08 | 2 | string (the `filename` taken from the `download/uri` element) |
| request | `size` | 0x10 | 2 | string (byte count to fetch) |
| **response** | **`uri`** | 0x00 | 2 | string — single field, DTO size 8 |

### 3.3 URL scheme for both

Both return a plain **RTSP** URL — the same hand-off as `playback/uri`: the string is copied into a `std::string` and
passed to the media session, which then appends the download transport modifiers from the contract map §1.5:
`%s;playmode=download[;tcpmode=passive|active][;device_domain_id=%s]` (`0x180c03cb8`–`0x180c03d60`).
⇒ Serve `rtsp://<media-host>:<media-port>/...` and be prepared for a `Transport: …;playmode=download…` SETUP.
**No `http://`, no `file://`, no `https` download link** is expected by this DTO.

### 3.4 Exact JSON

```
GET {base}/download/uri?channelCode=1000000%240&dimensionHideNode=[{"begintime":"...","filename":"...","endtime":"..."}]
→ {"code":1000,"msg":"Success","data":{"uri":"rtsp://127.0.0.1:9100/download?playmode=download"}}

GET {base}/record/downalod/uri?file=abc.mp4&offset=0&size=1048576
→ {"code":1000,"msg":"Success","data":{"uri":"rtsp://127.0.0.1:9100/download/abc.mp4?playmode=download"}}
```

---

## 4. PTZ

### 4.1 `dpsdkPtz/ptz` — `Dpsdk::CRestLogical::GetPtzInfo` @ `0x1800dc180`

Source: `.\Logic\RestLogic\RestLogical.cpp` lines `0x781` (param guard), `0x782`, `0x78a` (alloc), `0x79a` (fail).
Path literal `0x180c80238`.

```c
lVar4 = FUN_180582660();     // request  descriptor
lVar6 = FUN_1805829f0();     // response descriptor
FUN_1800d3840(param_1, lVar4, "dpsdkPtz/ptz", 1);
*(lVar4 + 0x80) = _strdup(param_2);        // field 0
*(lVar4 + 0x88) = _strdup(param_2 + 0x38); // field 1
iVar2 = FUN_18055d860(uVar12, lVar4, lVar6, 10);
if (iVar2 == 0) { *param_3 = *(lVar6+0x58); param_3[1] = *(lVar6+0x60); param_3[2] = *(lVar6+0x68); }
```

**Request — `FUN_180582660`, topic `Access.DpsdkPtz.GetPtz`, method `GET`:** `deviceCode` (offset 0, string),
`channelSeq` (offset 8, string).

**Response — `FUN_1805829f0`:** DTO size `0x18` = three 8-byte slots, all **`kind 3`**:

```c
FUN_1807512d0(DAT_180f72610, 0x00, 3, "ptzPan",  0);
FUN_1807512d0(DAT_180f72610, 0x08, 3, "ptzTilt", 0);
FUN_1807512d0(DAT_180f72610, 0x10, 3, "ptzZoom", 0);
```
`kind 3` = 8-byte **JSON number** by `FUN_180754c60` (§0.2). Emitting `"12.5"` (a string) leaves the slot zeroed;
emitting `12.5` binds. This is the PTZ position read-back (pan/tilt/zoom) used to draw the PTZ pad state.

```json
{ "code": 1000, "msg": "Success",
  "data": { "ptzPan": 0.0, "ptzTilt": 0.0, "ptzZoom": 1.0 } }
```

### 4.2 `ptz/preset/goto/channels/` — `Dpsdk::CRestLogicalImplVSL::PtzLocatePresetPoint` @ `0x180241360`

Source: `RestLogicalImplVSL.cpp` lines `0x6ef` (param guard), `0x6f7` (alloc), `0x703` (success log), `0x707` (fail).

```c
lVar7 = FUN_1806855a0();                              // request descriptor
FUN_1800d3840(*(param_1+8), lVar7, "ptz/preset/goto/channels/", 1);
// paramList array container at +0x70 (ptr/len/cap/count)
*(lVar7+0x70)=*(lVar7+0x78)=*(lVar7+0x80)=*(lVar7+0x88)=0;
local_res10[0] = _strdup(param_2);                    // element part 1 (preset identifier)
FUN_180560600(lVar7 + 0x78, local_res10, 8);
local_res20 = (param_2+0x40) ? _strdup(param_2+0x40) : NULL;   // element part 2
FUN_180560600(lVar7 + 0x78, &local_res20, 8);
*(lVar7 + 0x70) = *(u64*)(param_2 + 0x80);            // count / flags word
```

**Request descriptor `FUN_1806855a0`, topic `Access.Ptz.TurnToPreset`, method `PUT`:**

```c
DAT_180f76a98 (size 8)   -> FUN_1807512d0(.., 0x00, 3, "speed",     0);   // element schema: one 8-byte NUMERIC
DAT_180f76aa0 (size 0x20) -> FUN_1807512d0(.., 0x00, 2, "paramList", 1);  // ARRAY field
DAT_180f76aa8 (size 8)   -> hasFieldOf_nouse / _nouse
_Dst[2] = "PUT";  _Dst[0xb]=FUN_180685360; _Dst[0xc]=FUN_18074e3c0; _Dst[0xd]=FUN_1806854b0;
```

⇒ the body is `{"paramList":[...]}` where each element carries the preset identifier plus an optional
**numeric** `speed`. `speed` is `kind 3` ⇒ a JSON number, not a string.

**Response: EMPTY.** The response descriptor built inside `FUN_180241360` contains only the
`hasFieldOf_nouse`/`_nouse` stub (`*(u32*)puVar9 = 8`) — **no field is parsed from the reply**. The client reads only
the transport result (`FUN_18055d860(...) == 0`) and logs
`"'PtzLocatePresetPoint' PSDKAPI_REQUEST is success, error code = %d"`. Nothing else is validated.

```json
{ "code": 1000, "msg": "Success", "data": {} }
```

### 4.3 The rest of the PTZ family — same shape

Descriptor builders reached from the PTZ REST functions in `0x18023F400..0x180244000` (`p4.mjs callees`):

| REST literal | VA | Caller | Request descriptor | Request schema (verified) |
|---|---|---|---|---|
| `ptz/preset/goto/channels/` | `0x180c98568` | `0x180241360` PtzLocatePresetPoint | `0x1806855a0` | `paramList[]` element `{speed:number}` — **PUT** |
| `ptz/preset/channels/` | `0x180c98468` | `0x1802405c0`, `0x180240c40`, `0x180241c50` | `0x180686220`, `0x180686590`, `0x18068d0f0` | `paramList[]` only |
| `ptz/location/channels/` | `0x180c98368` | `0x18023f550`, `0x1802d8150` | `0x180683f60` | `paramList[]` element = `windowWidth`, `windowHeight`, `candidateBoxWidth`, `candidateBoxHeight`, `candidateBoxMidx`, `candidateBoxMidy`, `zoomOut` (+`paramList` nested) |
| `ptz/arrange/channels/` | `0x180c98420` | `0x18023ff40` | `0x180687c60` | same `paramList[]` family |
| `ptz/fi/focus/` | `0x180c98818` | `0x180242b80` | (no in-region descriptor — fills DTO directly) | `paramList[]` family |
| `ptz/fi/iris/` | `0x180c98850` | `0x1802434b0` | same | `paramList[]` family |
| `dpsdkPtz/ptzZoomMax` | `0x180c80300` | `0x1800dcd50` | `0x180585100` | `deviceCode`, `channelSeq` (verified); its **response** descriptor is built inline in `0x1800dcd50` and was **not** read this pass — see residual unknown 6 |

Two structural facts that matter more than the individual key lists:
1. **Every PTZ command is `PUT`/`GET` with a `paramList` array** — there is no flat `command`/`speed`/`presetIndex`
   body anywhere in this family. A gateway that expects flat keys will never see them.
2. **Every PTZ command's response schema is the `hasFieldOf_nouse` stub** — the client validates *nothing* in the reply
   except the envelope code. Any well-formed success envelope works; do not spend effort shaping PTZ responses.

⚠ The `DMS/Ptz/*` RPC family (`0x180cde...` register) is **not** the transport used by these code paths — the paths
above are the REST literals actually referenced from `RestLogicalImplVSL.cpp` / `RestLogical.cpp`. Keep serving the
`DMS/Ptz/*` RPC stubs if the web UI needs them, but they do not unblock the desktop PTZ pad.

---

## 5. Endpoint summary table

| # | Path (exact literal) | VA | Method | Caller (source line) | Request keys | Response keys (kind) |
|---|---|---|---|---|---|---|
| 1 | `playback/uri` | `0x180c97c00` | GET | `StartPlaybackByTime` `0x180233650` / `StartPlaybackByFile` `0x180234060` | `resource`,`endTime`,`duration`,`subType`,`urlType`,`scheme`,`beginTime`,`location`,`channelCode` (all str) | **`uri`(2), `cascade`(1=bool)** |
| 2 | `realmonitor/snapshot/` | `0x180c99538` | GET | `PlatformSnapshot` `0x18024f760` (`RestLogicalPreview.cpp:0x48`) | `optional`,`channelId`,`time` (all str) | **`content`(2) = base64 image** |
| 3 | `download/uri` | `0x180c97cf0` | GET | `StartPBDownloadByTime` `0x1802349c0` | `dimensionHideNode[]{begintime,filename,endtime}`, `channelCode` | **`uri`(2)** |
| 4 | `record/downalod/uri` | `0x180c97d70` | GET | `0x180235360` | `offset`,`file`,`size` | **`uri`(2)** |
| 5 | `dpsdkPtz/ptz` | `0x180c80238` | GET | `GetPtzInfo` `0x1800dc180` (`RestLogical.cpp:0x781`) | `deviceCode`,`channelSeq` | **`ptzPan`(3), `ptzTilt`(3), `ptzZoom`(3)** — numbers |
| 6 | `ptz/preset/goto/channels/` | `0x180c98568` | PUT | `PtzLocatePresetPoint` `0x180241360` (`RestLogicalImplVSL.cpp:0x6ef`) | `paramList[]{…,speed(3)}` | *(empty — stub only)* |
| 7 | `dpsdkPtz/ptzZoomMax` | `0x180c80300` | GET | `0x1800dcd50` | `deviceCode`,`channelSeq` | numeric (`kind 3` family) |

---

## 6. Evidence index

| Claim | Tool | Address |
|---|---|---|
| `playback/uri` referenced only from the two playback callers | `p4.mjs xrefs` | `0x180233a26`, `0x180234436` |
| playback **request** descriptor = `Storage.Record.GetPlaybackUri`, 9 string keys, GET | `procedure_pseudo_code` | **`0x180680730`** |
| playback request fills + `beginTime`/`endTime`/`location`(itoa radix 2)/`subType`/`urlType` | `procedure_pseudo_code` | `0x180233650` |
| playback **response** = inline DTO `{uri:string, cascade:bool}`, size 0x10 | `procedure_pseudo_code` | `0x180233650` (DTO block), `0x180234060` |
| response key bytes `75 72 69 00` = `uri` | `p4.mjs hex` | `0x180cd76ac` |
| GET params are appended to the URL (query string) | `procedure_pseudo_code` | `0x1806804f0` |
| JSON node type must match field kind (bool vs number vs string) | `procedure_pseudo_code` | **`0x180754c60`** |
| snapshot request descriptor `{optional, channelId, time}`, GET | `procedure_pseudo_code` | **`0x180692250`** |
| `time` key bytes at `0x180caed2c` | `p4.mjs hex` | `0x180caed2c` |
| snapshot path literal has a trailing slash | `p4.mjs locate` | `0x180c99538` |
| snapshot response `{content}` + base64 decode path | `procedure_pseudo_code` | `0x18024f760` |
| `FUN_1807904e0` is base64 (standard + URL-safe tables, `=` padding) | `procedure_pseudo_code` | `0x1807904e0` |
| `download/uri` descriptor: `dimensionHideNode[]{begintime,filename,endtime}`, `channelCode` | `procedure_pseudo_code` | **`0x180681ca0`** |
| `download/uri` response `{uri}` + consumer | `procedure_pseudo_code` | `0x1802349c0` |
| `record/downalod/uri` request `{offset,file,size}` / response `{uri}` | `keyscan.mjs` + `procedure_callees` | `0x18067e390`, `0x18067e6b0` |
| `dpsdkPtz/ptz` request `{deviceCode,channelSeq}` / response `{ptzPan,ptzTilt,ptzZoom}` kind 3 | `procedure_pseudo_code` | `0x180582660`, `0x1805829f0` |
| PTZ caller + path + `paramList` build | `procedure_pseudo_code` | `0x1800dc180`, `0x180241360` |
| `ptz/preset/goto/channels/` descriptor, PUT, `paramList[]`/`speed`(kind 3) | `procedure_pseudo_code` | **`0x1806855a0`** |
| PTZ command response = `hasFieldOf_nouse` stub (nothing parsed) | `procedure_pseudo_code` | `0x180241360` |
| PTZ family descriptor map | `p4.mjs callees` + `keyscan.mjs` | `0x180683f60`, `0x180686220`, `0x180686590`, `0x180687c60`, `0x18068d0f0` |
| `dpsdkPtz/ptzZoomMax` request = `{deviceCode, channelSeq}` | `p4.mjs callees` + `keyscan.mjs` | `0x1800dcd50` → `0x180585100` |

### Residual unknowns
1. **`kind 3` numeric width.** `FUN_180754c60` copies 8 raw bytes from a JSON-number node, so the value is
   double-or-int64 depending on the JSON parser's node layout (not recovered this pass). Emit plain JSON numbers;
   if the pad later shows garbage, try integral values before assuming a different field.
2. **Query-string encoding.** `FUN_180753c00`/`FUN_18055f570` produce the query text, but the escaping rules
   (esp. for `beginTime` with spaces/colons and for `dimensionHideNode` JSON) were not decompiled. The gateway should
   accept both raw and percent-encoded forms and tolerate a JSON array passed either encoded or verbatim.
3. **Envelope `code` value.** All five endpoints call `FUN_18055d860(session, req, resp, N)` and treat `0` as success;
   the envelope parsing it performs (and which numeric `code` it accepts) is not decompiled. Keep the existing
   `{"code":1000,"msg":"Success","data":{…}}` convention used by the working endpoints.
4. **`StartPlaybackByFile` differences.** It reuses `0x180680730`, so the key set is identical; whether it additionally
   populates `resource` or `filename`-style values was not read line-by-line (it does not create a different descriptor).
5. **`ptz/fi/focus` / `ptz/fi/iris`** build their DTO without a separate descriptor function in the scanned region
   (`0x180242b80`, `0x1802434b0`); the `paramList` family is assumed by pattern, not proven field-by-field.
6. **`dpsdkPtz/ptzZoomMax` response fields.** Its request descriptor `0x180585100` declares only
   `deviceCode`/`channelSeq` (verified with `keyscan.mjs`); the response DTO is assembled inline in `0x1800dcd50` and
   was not decompiled. If the PTZ zoom slider needs a real maximum, read that function next (expect a single
   `kind 3` numeric, by analogy with `ptzZoom`).
7. **`ptz/location/channels/` and `ptz/arrange/channels/`** key lists came from `keyscan.mjs` on their descriptor
   builders (`0x180683f60`, `0x180687c60`) and were not confirmed against a decompile; the element/`paramList`
   nesting in particular should be re-read before implementation.

---

## 7. Server implementation actions — ordered by importance for the DSS client

**Priority 1 — Playback tab (the whole tab is dead today, and it is the client's primary screen after Live View)**
1. **`GET {brms|videoService}/…/playback/uri` → `{"code":1000,"msg":"Success","data":{"uri":"rtsp://<media-host>:<port>/…","cascade":false}}`.**
   Two keys only. `uri` is a string and is exactly what the RTSP client dials (`strURL` in the failure log); `cascade`
   **must be a JSON boolean**. Current `src/e129-p1-coverage.js:43,57,58` returns `url:''` — that field does not even
   exist in the DTO, so it must be renamed to `uri` and given a real value.
2. **Read the request as a query string**, not a body: `channelCode` selects the channel (not `resource`, which is sent
   empty), `beginTime`/`endTime` bound the window, `subType = streamType-1`, `urlType` is `1` or `2`, `scheme` is the
   literal `"RTSP"`, `location` is a **binary** storage-mask string (`"0"`, `"1"`, `"11"`, …) — treat it as opaque.
3. Serve the playback RTSP stream with `playmode=playback` on SETUP and honour `Range: clock=`/`npt=` (the client emits
   `SEEK_FILE`/`SEEK_TIME` as `PLAY` + `Range`), keeping the pass-3 SETUP contract (echo `CSeq`, non-empty stable
   `Session:`, `Transport: …interleaved=a-b`, < 1 s).

**Priority 2 — Live View snapshot (one-line unblock, highest value per effort)**
4. **`GET …/realmonitor/snapshot/?channelId=<id>&time=<t>` → `{"code":1000,"data":{"content":"<base64 JPEG>"}}`.**
   Return the **image bytes**, base64-encoded — not a URL. Route both `realmonitor/snapshot` and
   `realmonitor/snapshot/` (the literal carries a trailing slash). No `width`/`height`/`quality` parameters are sent, so
   do not require them; snapshot at the channel's default resolution.

**Priority 3 — PTZ (the entire PTZ panel is inert)**
5. Register `ptz/preset/goto/channels/` (**PUT**) and `ptz/preset/channels/`, `ptz/location/channels/`,
   `ptz/arrange/channels/`, `ptz/fi/{focus,iris}/` (**PUT/GET**) in the `paramList[]` shape, and
   `dpsdkPtz/ptz` + `dpsdkPtz/ptzZoomMax` (**GET**, `deviceCode`+`channelSeq`).
6. For every PTZ **command** endpoint the response body is irrelevant — `{"code":1000,"msg":"Success","data":{}}` is a
   complete answer; the client parses no PTZ response fields. Spend no effort there. Return the envelope immediately so
   the pad does not block on a device round-trip.
7. `dpsdkPtz/ptz` must answer with `ptzPan`/`ptzTilt`/`ptzZoom` as JSON **numbers** (`kind 3`). All three are read as
   raw 8-byte values; a quoted string is dropped and the pad renders zeros.

**Priority 4 — Download / clip export**
8. `download/uri` → `{"data":{"uri":"rtsp://…?playmode=download"}}`; accept the request key **`dimensionHideNode`**
   (Dahua's typo) as an array of `{begintime, filename, endtime}` and `channelCode`.
9. `record/downalod/uri` (typo is in the path) → `{"data":{"uri":"rtsp://…"}}`; request keys `file`, `offset`, `size`.
   Both URLs are **RTSP**, served by the same media endpoint, tagged with `Transport: …;playmode=download`.

**Priority 5 — hardening / generalisation**
10. Apply the §0.2 type rule globally: `kind 1` → JSON bool, `kind 3` → JSON number, `kind 2` → string. Any gateway
    helper that coerces every leaf to a string silently zeroes bool and numeric fields.
11. Audit the remaining `DEFAULT_DATA` stubs against the same method: find the descriptor builder for each endpoint
    (`p4.mjs callers` on the path literal → `callees` → the `FUN_18068xxxx`/`FUN_18058xxxx` builder) and read its
    fieldsets, instead of guessing key names from the surrounding `.rdata` pool. `keyscan.mjs` decodes the compact
    `mov edx,off / lea r9,name / lea r8d,[rdx+delta]` registration form used by most of these builders and is ~40×
    cheaper than a decompile.
