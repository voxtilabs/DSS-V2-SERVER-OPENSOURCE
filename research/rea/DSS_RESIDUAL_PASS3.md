# DSS residual pass 3 — `Media.RealMonitor.Uri` response schema, RTSP wait/retry, REST coverage

Target: `C:\Users\bruno\Downloads\dssv2-setup\dssclient-extracted\DPSDK.dll`
- SHA-256 `ce43c8b799505f0f2a45c02639f892a426233ad40960d3696cb6150bfccc0d47`, 17,078,880 B, PE32+ x86-64, ImageBase `0x180000000`
- Provider: Ghidra 12.1.4 via REA MCP (read-only). Every address below is a provider-reported VA or the result of a
  `node .mjs` PE-header script (`range.mjs`, `srv-diff.mjs`, `routecmp3.mjs`) — no hand hex arithmetic.
- Corrects/extends `DSS_SERVER_CONTRACT_MAP.md` §1.1b and `RTSP_URLS_DTO_SHAPE.md` §6.2 (both of which had to guess the
  response key set; it is now decompiled).

---

## 1. `Media.RealMonitor.Uri` — the RESPONSE schema (decompiled)

### 1.1 The call is built by two descriptor builders, not one

`functionCode "MediaRealMonitorUri"` (`0x180cd77b0`) and `topic "Media.RealMonitor.Uri"` (`0x180cd77c8`) have exactly
one referrer each: `0x1806800f4` / `0x180680101`, both inside **`FUN_18067fea0`** (710 B) — the *request* descriptor.
The *response* descriptor is a **separate** builder: **`FUN_180680310`**, called from the same caller.

```c
// FUN_18067fea0  (request descriptor; xrefs of both id strings land here)
_Dst = malloc(200);
// fieldsets DAT_180f76918 / DAT_180f76920 = 8-byte "absent" stubs
// ( only: hasFieldOf_nouse[bool, kind 1] , _nouse[kind 0] )
DAT_180f76928 = malloc(0x28); *(u32*)DAT_180f76928 = 0x48;      // request DTO = 0x48 bytes
FUN_1807512d0(0x180f76928, 0x00, 2, "planId",    0);
FUN_1807512d0(0x180f76928, 0x08, 2, "duration",  0);
FUN_1807512d0(0x180f76928, 0x10, 2, "subType",   0);
FUN_1807512d0(0x180f76928, 0x18, 2, "dataType",  0);
FUN_1807512d0(0x180f76928, 0x20, 2, "urlType",   0);
FUN_1807512d0(0x180f76928, 0x28, 2, "extend",    0);
FUN_1807512d0(0x180f76928, 0x30, 2, "channelId", 0);
FUN_1807512d0(0x180f76928, 0x38, 2, "scheme",    0);
FUN_1807512d0(0x180f76928, 0x40, 2, "trackId",   0);
_Dst[0]="MediaRealMonitorUri"; _Dst[1]="Media.RealMonitor.Uri"; _Dst[2]="GET";
_Dst[6]="application/json;charset=UTF-8";
_Dst[0xb]=FUN_18067fc60;   // request serializer (query-string builder)
_Dst[0xc]=FUN_18074e3c0;   // HTTP Digest Authorization builder (NOT a parser)
_Dst[0xd]=FUN_18067fdb0;   // destructor (frees the three fieldsets)
```

`FUN_18074e3c0` is the `Authorization: Digest username=…, realm=…, nonce=…, uri=…` builder (verbatim format string in
its body) — so slot `0xc` is auth, **not** response parsing. That is why the previous pass found no response schema in
this function.

### 1.2 The response DTO — `FUN_180680310` (this is the answer)

```c
void *FUN_180680310(void) {                     // response descriptor for StartRealPlay
  _Dst = malloc(0xb0); memset(_Dst,0,0xb0);
  DAT_180f76930 = malloc(0x28); *(u32*)DAT_180f76930 = 0x58;     // response DTO = 0x58 bytes = 11 string slots
  FUN_1807512d0(DAT_180f76930, 0x00, 2, "connectType", 0);
  FUN_1807512d0(DAT_180f76930, 0x08, 2, "protocol",    0);
  FUN_1807512d0(DAT_180f76930, 0x10, 2, "trackId",     0);
  FUN_1807512d0(DAT_180f76930, 0x18, 2, &DAT_180caf7cc, 0);      // "ip"     (bytes 69 70 00)
  FUN_1807512d0(DAT_180f76930, 0x20, 2, &DAT_180cbaf04, 0);      // "port"   (bytes 70 6f 72 74 00)
  FUN_1807512d0(DAT_180f76930, 0x28, 2, "token",       0);
  FUN_1807512d0(DAT_180f76930, 0x30, 2, "stunPort",    0);
  FUN_1807512d0(DAT_180f76930, 0x38, 2, &DAT_180caf99c, 0);      // "url"    (bytes 75 72 6c 00)
  FUN_1807512d0(DAT_180f76930, 0x40, 2, "stunEnable",  0);
  FUN_1807512d0(DAT_180f76930, 0x48, 2, "session",     0);
  FUN_1807512d0(DAT_180f76930, 0x50, 2, "minRate",     0);
  *(_Dst+0x40)=FUN_180680170; *(_Dst+0x48)=FUN_180680190; *(_Dst+0x50)=FUN_180680280;
  return _Dst;
}
```

Registrar semantics are those proven last pass (`FUN_1807512d0` appends `{offset, kind, arrayFlag, name}`; `kind 2` =
**string**, `kind 1` = bool, values ≥ 0x10 = byte size of a composite). Every one of the eleven fields is `kind 2`
with `arrayFlag 0` ⇒ **all eleven are plain JSON strings, none is an array or object**.

### 1.3 Consumer — `FUN_180236060`: what the client does with each key

Called by `StartRealPlay` with `(response, playParams)`. The DTO lives at `response+0x58`; the mapping is exact and
in order:

| DTO off | JSON key | Conversion in client | Meaning for us |
|---|---|---|---|
| +0x00 | `connectType` | `atoi()` → int (params[0]) | **numeric string** |
| +0x08 | `protocol` | `atoi()` → int (params[1]) | **numeric string** |
| +0x10 | `trackId` | string copy (std::string) | plain text |
| +0x18 | `ip` | string copy | media host |
| +0x20 | `port` | `atoi()` → int | **numeric string**, e.g. `"9100"` |
| +0x28 | `token` | string copy | plain text |
| +0x30 | `stunPort` | `atoi()` → int | numeric string (`"0"` ok) |
| +0x38 | **`url`** | **string copy** | **the dialable RTSP URL** |
| +0x40 | `stunEnable` | `atoi()!=0` → bool | `"0"`/`"1"` |
| +0x48 | `session` | `atoi()` → int | numeric string |
| +0x50 | `minRate` | string copy | plain text (`""` ok) |

```c
// FUN_180236060 (excerpt, DTO base +0x58)
*param_3      = atoi(*(char**)(param_2+0x58));   // connectType
param_3[1]    = atoi(*(char**)(param_2+0x60));   // protocol
param_3[0x16] = atoi(*(char**)(param_2+0x78));   // port
param_3[0x2f] = atoi(*(char**)(param_2+0xa0));   // session
*(bool*)(param_3+0x2e) = atoi(*(char**)(param_2+0x98)) != 0;   // stunEnable
std::string::operator=(param_3+2,  str(param_2+0x68));          // trackId
std::string::operator=(param_3+0xc, str(param_2+0x70));         // ip
std::string::operator=(param_3+0x18,str(param_2+0x80));         // token
std::string::operator=(param_3+0x24,str(param_2+0x90));         // url  <-- live URL
std::string::operator=(param_3+0x30,str(param_2+0xa8));         // minRate
```

### 1.4 The caller — `Dpsdk::CRestLogicalImplVSL::StartRealPlay` @ `0x1802359f0`

Source provenance string: `.\Logic\RestLogic\RestLogicalImplVSL.cpp` line **0x269**. It builds the request and the
REST path:

```c
lVar4 = FUN_18067fea0();          // request descriptor
lVar7 = FUN_180680310();          // response descriptor
std::string path("realmonitor/uri");                       // -> REST path suffix
FUN_1800d3840(session, lVar4, path, 1, ...);               // dispatch
*(lVar4+0xb0) = strdup(*(param_2+0x40));                   // channelId  (cameraId)
*(lVar4+0x90) = strdup(itoa(*(int*)(param_2+8) - 1));      // subType = streamType-1
*(lVar4+0xb8) = strdup("RTSP");                            // scheme
*(lVar4+0x88) = strdup("600");                             // duration (seconds)
*(lVar4+0xc0) = strdup(*(param_2+0x18));                   // trackId (client-chosen)
*(lVar4+0x98) = strdup(itoa(*(param_2+0xb0)));             // dataType
*(lVar4+0xa0) = strdup(param_2[0x1f0] ? "2" : "1");        // urlType 1=plain, 2=TLS/RTSPS
// failure log (0x180c97e00):
// "Start Video Request Failed iRet[%d] ! strCameraId = %s, iStreamType = %d, strTrackID = %s, dataType = %d"
FUN_180236060(param_1, lVar7, param_3);                    // parse response -> play params
```

Request offsets line up with the request fieldset at base `0x80` (`0x88=duration`, `0x90=subType`, `0x98=dataType`,
`0xa0=urlType`, `0xb0=channelId`, `0xb8=scheme`, `0xc0=trackId`), i.e. every declared request key except `planId`
and `extend` is always populated.

### 1.5 Gateway answer for `GET <base>/realmonitor/uri`

```json
{ "code": 1000, "desc": "Success",
  "data": {
    "connectType": "1",
    "protocol":    "1",
    "trackId":     "0",
    "ip":          "127.0.0.1",
    "port":        "9100",
    "token":       "0000000000000000",
    "stunPort":    "0",
    "url":         "rtsp://127.0.0.1:9100/<devicePath>",
    "stunEnable":  "0",
    "session":     "1",
    "minRate":     ""
  } }
```

Rules proven by §1.3: `url` is a **single string** (there is no `rtspUrls` array and no `rtspUrl` singular in this
DTO), all eleven values must be JSON **strings**, and `connectType/protocol/port/session/stunPort/stunEnable` are
`atoi`-parsed so they must be numeric strings. `url` must not already contain `token=`/`trackID=` (the RTSP client
appends them, `0x180c04178` / `0x180c04188`). The request is `GET` with `application/json;charset=UTF-8`, optionally
with a Digest `Authorization` header (`FUN_18074e3c0`) — the endpoint must tolerate an unauthenticated GET and/or
Digest.

---

## 2. `CRTSPBaseClient::Start` @ `0x180849bd0` — wait time default and retry

```c
void FUN_180849bd0(longlong this) {
  if (*(char*)(this+0xb8) != 0) { FUN_1808895f0(this+8, 0); return; }   // already started -> wait 0
  log(".\\Base\\RTSPBaseClient.cpp", 0x4f3, "RTSPSDK::CRTSPBaseClient::Start",
      "[DPSDK] MediaSessionID=[%d], RtspThreadWaitTime = %d",
      *(int*)(this+0x18), *(int*)(this+0x2c));
  FUN_1808895f0(this+8, *(u32*)(this+0x2c));       // wait time -> timer
}
```

- **No literal in `Start`.** `this+0x2c` is written only by the constructor **`FUN_18084fcf0`**:
  `*(u32*)((char*)this + 0x2c) = param_4;`
- **The default is the global `DAT_180f55894`.** `DPSDK_SetRtspThreadWaitTime` (`0x1800099c0`) is the only writer and
  rejects values ≤ 1:

```c
undefined8 DPSDK_SetRtspThreadWaitTime(uint v) { if (1 < v) DAT_180f55894 = v; return 0; }
```

- **Static initial value = 1** (image bytes at `0x180f55894`: `01 00 00 00`; the neighbouring `0x180f55890` is also 1).
  So the shipped default is **`RtspThreadWaitTime = 1`**.
- **Unit = seconds.** The consumer multiplies by 1000 before arming the timer:

```c
// FUN_1808895f0(this, waitSeconds)
plVar2 = *(longlong**)(this + 8);
plVar2[0xc] = (waitSeconds & 0xffffffff) * 1000;   // -> milliseconds
... schedule FUN_1808894c0 (timer callback) ...
```

  ⇒ default SETUP/thread wait = **1 s (1000 ms)**; the value is a *per-session* knob (`DAT_180f55894`, read at 13 code
  sites, e.g. `0x180344972` in `CPreviewEncodeMDP::StartRealPlay`, which copies it into the media-param struct).
  Server-supplied config key `threadWaitTime` (`0x180c3f128`) overrides it per device; `rtspTimeout` (`0x180c3f248`)
  is the device-side tag (absent from the server build — see §4).
- **Retry count: there is none at the RTSP layer.** `ConnectServer` (`0x180849a60`) performs exactly **one** connect
  (`vtable+0x18`, log `ConnectServer IP=[%s], PORT=[%d], ConnectRet=[%d]` at `RTSPBaseClient.cpp:0x4e3`) and returns
  `-1` on failure — no loop, no counter. `Start` issues no retry. The only retry machinery in the binary is HTTP-layer
  (`"set timeouts for state %d; Total % I64d, retry %d maxtry %d"` `0x180c648f0`, libcurl strings) and a DTO flag
  `allowRetry` (`0x180cdde28`, unrelated to RTSP).
  ⇒ A failed SETUP is **not** retried by the client; it surfaces as `[PSDK] OnSetupResponse failed[iRet]`. Size our
  relay so the SETUP 200 is emitted well inside 1 s, and treat 1 s as the hard ceiling unless we can push a larger
  `threadWaitTime` through device config.

---

## 3. REST inventory vs gateway routes

Method: `routecmp3.mjs` (scratchpad) collects every path-like literal / template tail from
`poc/dss-v2-harness/brms-gateway/src/*.js` (779 tails) and matches each of the 946 fragments in
`research/rea/data/rest-paths.txt` with a version-insensitive suffix test (`v1.0/`,`v1.1/` stripped; gateway route
tail must END WITH the fragment). Result: **554 fragments have no gateway route tail**, and — more important — several
"registered" routes are empty stubs from E-127/E-129 (`DEFAULT_DATA`, empty strings), which behave exactly like a
missing route to the native client.

Two caveats stated explicitly:
- The `BRM/<Class>/<Method>` family is served by the wildcard RPC dispatchers
  (`/admin/API/BRM/:ns/:fn`, `/brms/api/v{1.0,1.1}/BRM/:ns/:cls/:fn` → `brmRpcHandler`), so a missing literal string
  does not prove a missing handler; only the explicitly handled methods are real.
- `devicesManager/*` and `DMS/Ptz/*` are registered by **E-127 P0** as `DEFAULT_DATA` stubs (see
  `src/e127-p0-coverage.js:9-40`), i.e. present-but-empty.

### 3.1 Missing / stub-only endpoints that matter for Monitoring Center → Live View → Playback

| # | Endpoint (DPSDK literal, VA) | Gateway state | Why it matters |
|---|---|---|---|
| 1 | `realmonitor/uri` `0x180c97df0` | **registered but EMPTY** — `src/e129-p1-coverage.js:42` returns `{uri:'', url:''}` | This *is* `Dpsdk::CRestLogicalImplVSL::StartRealPlay` (§1.4). An empty `url` = no live tile. Must return the 11-key DTO of §1.5. |
| 2 | `realmonitor/snapshot/` `0x180c99538` | **no route** (only `realmonitor.snapshot` in the E-135 RPC catalog) | Snapshot button / thumbnail strip in Live View (`Media.RealMonitor.Snapshot`). |
| 3 | `playback/uri` `0x180c97c00` + `SS/Playback/StartPlaybackByTime`/`ByFile` | **stub with `url:''`** (`e129-p1-coverage.js:43,57,58`) | Historical playback never starts a stream. |
| 4 | `download/uri` `0x180c97cf0`, `record/downalod/uri` `0x180c97d70` (sic, Dahua typo) | **no route** | Playback download / clip export. |
| 5 | `ptz/preset/goto/channels/` `0x180c98568`, `ptz/preset/channels/` `0x180c98468`, `ptz/location/channels/` `0x180c98368`, `ptz/arrange/channels/` `0x180c98420`, `ptz/fi/focus/` `0x180c98818`, `ptz/fi/iris/` `0x180c98850`, `dpsdkPtz/ptz` `0x180c80238`, `dpsdkPtz/ptzZoomMax` `0x180c80300` | **no route** (the `DMS/Ptz/*` RPC equivalents are E-127 stubs) | PTZ pad/presets on the live tile; without it the whole PTZ panel is dead. |
| 6 | `record/records` `0x180c97aa8`, `record/records/daily` `0x180c97a20`, `record/queryLockInfos` `0x180c989c8`, `record/locking/channels/` `0x180c97ae8`, `record/unlocking/channels/` `0x180c97b70`, `record/pluseRecord/` `0x180c98a10`, `record/status/channels/` `0x180c979a0` | **no route** (only `SS/Record/QueryRecord(s)`, `LockRecord`, `UnlockRecord`, `QueryLock` exist) | Playback timeline/search + record locking. |
| 7 | `SS/Record/GetAlarmRecords` `0x180c99348`, `SS/Record/GetChannelMonthRecordStatus` `0x180c95730`, `SS/Record/QueryLockInfos` `0x180c97018`, `SS/Tag/SaveRecordTag` `0x180c99128`, `SS/Tag/QueryRecordTags` `0x180c99218`, `SS/Tag/DeleteRecordTag` `0x180c991a0` | **no route** | Playback calendar (month status), alarm markers, bookmarks/tags. |
| 8 | `record/smart-analyze/frame|start|stop` `0x180c81760`/`0x180c815d8`/`0x180c81660` | **no route** | Playback smart search (intelligent frame extraction). |
| 9 | `monitor/view/upgrade` `0x180ca45a8`, `tvwall/status` `0x180c9d610`, `tvwall/wall` `0x180c9d560`, `tvwall/wall/` `0x180c9d6f0`, `tvwall/del/` `0x180c9d680`, `tvwall/nameRepeat` `0x180c9d780`, `tvwall/printDecoder` `0x180c9d3c0`, `vms/tvWall/capacity/` `0x180c98320`, `vms/tvWall/openWindows/` `0x180c982d8`, `vms/tvWallTask` `0x180c98020`, `BRM/TvWall/{Get,Save,Delete}UserTvWallTask*`, `vsl/tvwall/getTvWallTaskInfo` `0x180c98098` | partial (generic `tvWalls`/`tvwall/page`; task/status/decoder paths missing) | Video wall: open windows, capacity, decoder print, per-user wall tasks. |
| 10 | `devicesManager/deviceTree` `0x180ca34c8`, `devicesManager/devicesInfo` `0x180ca3558`, `devicesManager/deviceAllOrg`, `devicesManager/collection/channels` `0x180ca3a10`, `devicesManager/collection/batchDelete`, `devicesManager/devicesGroup/{org}`, `devicesManager/devices/offlineReasons` | E-127 **stubs** (empty) | The REST-side Resources tree (§2 of the contract map). The gateway serves `tree/*` and `/admin/API/tree/*` properly; the `devicesManager/*` REST mirrors are empty. |
| 11 | `BRM/Device/GetMediaVK`-family REST twins: `BRM/Device/GetCurrentMediaVK` `0x180c94af0`, `BRM/Device/GetMediaVKs` `0x180c94b70` | RPC methods handled in `index.js:1081-1087`; REST literals absent | Stream decryption keys — needed for VK-encrypted media. |
| 12 | `snapshotList/` `0x180c995e0`, `link-record-channel/list` `0x180c993f0`, `/quota/*-record-quota/status` `0x180c9cba8`/`0x180c9cc48`/`0x180c9ccf0`, `/record-plan/list` `0x180c9afe8`, `/motion-detection-record-plan/list` `0x180c9b070`, `record-plan/execute/status/list` `0x180c9ceb0`, `device/device-record-wholeness/config` `0x180c81ea8`, `v1.1/storage/plan/record-plan{,/page,/channel/list,/status}` `0x180c9b8e0`… | **no route** | Storage-plan sub-tabs (recording plan per channel, quotas, record wholeness). |

Non-media families also absent (lower priority): streams/attendance/survey-group/parking-lot/case-library/vtalk/
`v1.1/domain*`, `v1.1/license/*` mutations, `v1.1/storage/disk/*` (RAID/format), `v1.1/backup-restore/*`,
`v1.1/log/*` export/count, `/audio/file/*`, `/bayonetServer/*`, `/dev/ubskey`, `v1.1/acs/*`, `v1.1/shop/*`.

---

## 4. Server-side `DPSDK.dll` (11,388,424 B) — what differs (optional item)

`C:\Users\bruno\Downloads\dssv2-setup\dssserver-analysis\unpack-inner-1376402688\DPSDK.dll`. Method: `srv-diff.mjs`
(PE-agnostic ASCII string inventory, presence/absence). **`[strings-only]`** — no decompiler pass on this build.

| Literal | client | server |
|---|---|---|
| `Media.RealMonitor.Uri` | Y | **Y** |
| `MediaRealMonitorUri` (functionCode id) | Y | **–** |
| `realmonitor/uri`, `realmonitor/snapshot/`, `playback/uri`, `download/uri`, `record/downalod/uri` | Y | **Y** |
| response keys `connectType`,`protocol`,`trackId`,`token`,`stunPort`,`stunEnable`,`session`,`minRate` | Y | **Y** |
| `rtspUrls`, `rtspUrl` | Y | **–** |
| `urlType`, `scheme` | Y | **Y** |
| `DPSDK_SetRtspThreadWaitTime`, `threadWaitTime` | Y | **Y** |
| `rtspTimeout` | Y | **–** |
| `RTP/AVP/TCP; interleaved=0-1`, `…;unicast;interleaved=%d-%d;mode=play`, `Dahua Rtsp Client/2.0` | Y | **Y** |
| `Refusing to issue an RTSP SETUP without a Transport: header.`, `Got a blank Session ID`, `RTSP CSeq mismatch or invalid CSeq`, `Unable to read the CSeq header: [%s]` | Y | **Y** |
| `eventCenter/messages/subscribeAddress` | Y | **–** |
| `allowRetry` | Y | **Y** |

Reading: the server build carries the **same** media-URI contract (same `realmonitor/*` REST paths, same eleven
response keys, same live555-derived RTSP client with identical CSeq/Session/Transport guards) and therefore the same
SETUP response requirements. What it does **not** contain is the client-only side: the `MediaRealMonitorUri`
functionCode id, the device/channel `rtspUrls` DTO keys and `rtspTimeout`. That is consistent with the split proven in
§1: the *client* parses `rtspUrls` from device DTOs and issues `realmonitor/uri`; the *server* only produces the
eleven-key URI response. No extra fields are required of us by the server build.

---

## 5. Server implementation actions (ordered)

1. **`GET {brms|videoService}/…/realmonitor/uri` must return the real URL, not `''`.** Replace the E-129 stub
   (`src/e129-p1-coverage.js:42`) with the §1.5 payload: eleven **string** keys, `url` = dialable MediaMTX/gateway RTSP
   URL for the requested `channelId`, `port` numeric (`"9100"`), `ip` = media host, `token`/`session`/`trackId`
   numeric strings, `protocol`/`connectType` numeric, `stunEnable`/`stunPort` `"0"`, `minRate` `""`.
2. **Echo the request**: `channelId` selects the stream, `subType` = `streamType-1`, `scheme` is `RTSP`
   (`"RTSPS"`-equivalent request uses `urlType:"2"`), `duration` is `"600"`. The URL must not carry `token=`/`trackID=`.
3. **Answer SETUP within 1 s** (default `RtspThreadWaitTime = 1` second, hard-coded image default, `*1000` for ms);
   the client does **not** retry, so one slow response = one failed tile. If longer patience is needed, serve
   `threadWaitTime` in device config (`0x180c3f128`) — the only supported knob.
4. **Implement `realmonitor/snapshot/`** (Live View snapshots) next; then **`playback/uri` + `SS/Playback/*` with a
   real `url`** (currently a stub with `url:''`), then `download/uri` + `record/downalod/uri`.
5. **PTZ**: register `ptz/preset/goto/channels/`, `ptz/preset/channels/`, `ptz/location/channels/`,
   `ptz/arrange/channels/`, `ptz/fi/{focus,iris}/`, `dpsdkPtz/ptz`, `dpsdkPtz/ptzZoomMax` (the `DMS/Ptz/*` stubs alone
   leave the PTZ pad inert).
6. **Playback record APIs**: `record/records`, `record/records/daily`, `record/queryLockInfos`,
   `record/{locking,unlocking}/channels/`, `record/status/channels/`, `SS/Record/GetAlarmRecords`,
   `SS/Record/GetChannelMonthRecordStatus`, `SS/Tag/*`.
7. **`devicesManager/*` REST mirrors** currently E-127 stubs — serve the same payloads as `tree/*` /
   `/admin/API/tree/*` so the REST-tree caller sees data.
8. **Video wall**: `vms/tvWall{,s}`, `vms/tvWall/{capacity,openWindows,operation}/`, `vms/tvWallTask`,
   `tvwall/{status,wall,del,nameRepeat,printDecoder}`, `BRM/TvWall/*UserTvWallTask*`, `vsl/tvwall/getTvWallTaskInfo`.
9. **Media VK over REST** (`BRM/Device/GetCurrentMediaVK`, `GetMediaVKs`) — already handled as RPC; add the REST
   literals so a REST-transport client gets keys before RTSP.
10. Keep the SETUP 200 contract of `RTSP_URLS_DTO_SHAPE.md` §6.3 unchanged (CSeq echoed, non-empty stable `Session:`,
    `Transport: …interleaved=a-b`) — the server build enforces the identical checks (§4).

---

## 6. Evidence index

| Claim | Tool | Address |
|---|---|---|
| one xref each for `MediaRealMonitorUri` / `Media.RealMonitor.Uri` | `xrefs` | `0x1806800f4`, `0x180680101` |
| request descriptor (`GET`, 9 string keys, slot roles) | `procedure_pseudo_code` | `0x18067fea0` |
| request serializer (query string from `DAT_180f76928`) | `procedure_pseudo_code` | `0x18067fc60` |
| slot `0xc` is HTTP Digest auth, not a parser | `procedure_pseudo_code` | `0x18074e3c0` |
| descriptor destructor | `procedure_pseudo_code` | `0x18067fdb0` |
| **response DTO: 11 string keys, size 0x58** | `procedure_pseudo_code` | **`0x180680310`** |
| key string bytes for `ip` / `port` / `url` | `read_bytes` | `0x180caf7cc`, `0x180cbaf04`, `0x180caf99c` |
| response→play-params mapping (base +0x58) | `procedure_pseudo_code` | `0x180236060` |
| `StartRealPlay` request fill + `realmonitor/uri` path | `procedure_pseudo_code` + strings | `0x1802359f0`, `0x180c97df0` |
| `Start` forwards `*(this+0x2c)` | `procedure_pseudo_code` | `0x180849bd0` |
| ctor writes `+0x2c` | `procedure_pseudo_code` | `0x18084fcf0` |
| default global value = 1 | `read_bytes` | `0x180f55894` (`01 00 00 00`) |
| `SetRtspThreadWaitTime` accepts only > 1 | `procedure_pseudo_code` | `0x1800099c0` |
| wait is seconds, `*1000` → ms | `procedure_pseudo_code` | `0x1808895f0` |
| single connect attempt, no retry loop | `procedure_pseudo_code` | `0x180849a60` |
| no RTSP retry literal; only libcurl/`allowRetry` | `search_strings` | `0x180c648f0`, `0x180cdde28` |
| gateway route/stub inventory | `routecmp3.mjs` + `grep` | `src/e127-p0-coverage.js`, `src/e129-p1-coverage.js:42-61`, `src/index.js:1081` |
| server-build string diff | `srv-diff.mjs` | `dssserver-analysis\unpack-inner-1376402688\DPSDK.dll` |

### Residual unknowns
1. `connectType` / `protocol` **numeric values** the client expects (read as `atoi` ints; no enum table found in
   `FUN_180236060`). Our gateway currently assumes `1`; needs a live-trace confirmation.
2. Whether the DSS UI reaches live video through this VSL REST path or through the device-DTO `rtspUrls` path for the
   first frame — both exist; §1.5 makes the REST path correct regardless.
3. `threadWaitTime` carrier endpoint (device config vs environment) was not enumerated in this pass — the default (1 s)
   is what we size against.
