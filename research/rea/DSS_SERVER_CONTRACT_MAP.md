# DSS Server Contract Map — REA reverse engineering of the official Dahua DSS Client

Target binary: `C:\Users\bruno\Downloads\dssv2-setup\dssclient-extracted\DPSDK.dll`
- SHA-256: `ce43c8b799505f0f2a45c02639f892a426233ad40960d3696cb6150bfccc0d47`
- Size: 17,078,880 bytes · PE32+ (x86_64) · ImageBase `0x180000000` · 1,363 exports
- Sections: `.text@0x1000  .rdata@0xbe7000  .data@0xefa000  .pdata@0xf81000  .tls@0x105b000  .rsrc@0x105c000  .reloc@0x105d000`
  (section VAs above are RVAs as reported by the PE header parser; all absolute VAs in this document are `ImageBase + RVA` and were computed by script, never by hand.)

Companion binaries inspected by string inventory: `MainFormPlugin.dll` (UI/PluginFactory layer), `dslalien.dll`
(a second copy of the same live555-derived RTSP stack — useful cross-check), `configsdk.dll`, `netsdk.dll`.

> Methodology note (repo rule): every address and offset in this document was produced by `node .mjs`
> scripts (`strings.mjs`, `allstrings.mjs`, `range.mjs`, `q.mjs`, `dirscan.mjs`) that parse the PE header and
> convert file-offset → RVA → VA. No hex/offset arithmetic was performed by hand.
> Where a claim is string-inventory evidence only (no decompilation yet) it is marked **[strings-only]**.
> Ghidra decompiler dossiers are marked **[ghidra]** and carry the function address.

---

## 1. Video transport — RTSP SETUP / PLAY contract  ⭐ (blocking issue)

### 1.1 The client does NOT synthesise an RTSP URL

**[strings-only]** Critical finding: `DPSDK.dll` contains **no `rtsp://` literal, no `/cam/realmonitor` literal and
no `9100` literal**. The RTSP URL the client dials is **entirely server-supplied**. The only URL-ish pieces that
exist in the binary are:

| VA | String | Meaning |
|---|---|---|
| `0x180cd77b0` | `MediaRealMonitorUri` | functionCode id of the REST call that returns the live URL |
| `0x180cd77c8` | `Media.RealMonitor.Uri` | topic/function name form of the same call |
| `0x180cdbfc0` | `rtspUrls` | plural URL field parsed from the response |
| `0x180cdbfd0` | `rtspUrl` | singular URL field parsed from the response |
| `0x180caf99c` | `url` | base URL field |
| `0x180cd7798` | `subType` | stream sub-type field |
| `0x180cd77a0` | `urlType` | URL type discriminator field |
| `0x180cd77a8` | `scheme` | URL scheme field |
| `0x180cd77e0` | `resource` | resource identifier field |
| `0x180cdb870` | `enableRtspTls` | RTSPS enable flag on the device record |
| `0x180cdb630` | `outRtspPort` | outbound RTSP port on the device record |
| `0x180cc7678` | `rtspport` | lowercase variant used on the device/SNMP record |

`range.mjs 0x180cd7400 0x180cd8700` shows these keys live in the **DTO field-name pool**, immediately adjacent to
`Account.User.GetMenuRights`, `Storage.Record.GetPlaybackUri`, `Media.RealMonitor.Snapshot`… i.e. these are
JSON keys of the DTOs the client parses. `url2` does **not** exist as a literal anywhere in `DPSDK.dll`
(verified by full-inventory regex `url2` → 0 hits), so any server emitting an `url2` field is emitting a field the
client never reads.

**Server implementation action:** the gateway must return the complete, dialable RTSP URL in the
`Media.RealMonitor.Uri` response. The client will not prepend `rtsp://`, will not add `:9100`, and will not add
`/cam/realmonitor`. Port 9100 must be baked into the returned URL/port pair by us.

### 1.1b Which key wins: `rtspUrls` before `rtspUrl`

**[script-computed]** `xref.mjs` on the three URL field VAs locates the response parser:

| Field VA | Referencing code | Enclosing function |
|---|---|---|
| `rtspUrls` `0x180cdbfc0` | `0x1806d69dc` and `0x1806dbf2c` | `0x1806d5eb0`, `0x1806db570` |
| `rtspUrl` `0x180cdbfd0` | `0x1806d6a1b` and `0x1806dbf6b` | `0x1806d5eb0`, `0x1806db570` |
| `urlType` `0x180cd77a0` | `0x180680060`, `0x1806808f0` | `0x18067fea0`, `0x180680730` |
| `scheme` `0x180cd77a8` | `0x1806800c0`, `0x180680910` | `0x18067fea0`, `0x180680730` |

In both parser functions the **plural `rtspUrls` is read at a strictly lower address than the singular `rtspUrl`**
(`0x1806d69dc` < `0x1806d6a1b`, and `0x1806dbf2c` < `0x1806dbf6b`), i.e. the array form is evaluated first and the
singular form is the fallback.

**Server implementation action:** return `rtspUrls` as an **array of objects** (the primary form) and also a
compatible singular `rtspUrl` as fallback. `url` is a *different* field used by many other DTOs (24 referrers)
and must not be relied on to carry the live stream URL. `urlType` and `scheme` are read by a separate function pair
(`0x18067fea0` / `0x180680730`) — they select the URL variant/scheme, so they must agree with the URL we return.

### 1.2 Which URL the client dials — the exact hand-off fields

**[strings-only]** The RTSP engine receives exactly three transport-relevant values, confirmed by the failure log
format string:

```
0x180ca9460  "Real Stream Start Failed iRet[%d]! iMediaSessionID = %d, strCameraId %s strURL %s
              mediaType: %d strTrackID %s streamType %d strToken %s"
```

and for two-way audio:

```
0x180cba2a0  "Talk Start Failed iRet[%d]! iMediaSessionID = %d, strDevId %s strUrl %s
              nTalkType: %d nTalkBit %d nAudioType %d strToken %s"
```

So the live-play start path is `DPSDK_StartRealPlay` / `DPSDK_StartRealPlayEx` →
`DPSDK_StartMediaRealPlay` → media session open with **(strURL, strTrackID, strToken, mediaType, streamType)**.

**Server implementation action:** the URI response must give us all five: a dialable `url`/`rtspUrl`,
a `trackId`, a `token`, plus `mediaType`/`streamType` discriminators. If `token` or `trackId` is missing the
client still issues SETUP but builds a malformed request URL (see 1.4), which manifests as a SETUP timeout.

### 1.3 URL assembly by the client — the exact query-string appenders

**[strings-only]** `range.mjs 0x180c02f00 0x180c04800` (region `.rdata` immediately after
`RTSPSDK::CRTSPBaseClient::ConnectServer`) yields the URL-composition templates:

| VA | Format |
|---|---|
| `0x180c04178` | `%s%stoken=%s%s` |
| `0x180c04188` | `&trackID=%s` |
| `0x180c04198` | `trackID=%s` |
| `0x180c04130` | `%s&vcsvideocodec=%s&vcsresolution=%s&vcsfps=%d&vcsbps=%d&usedvcs=%d%s` |
| `0x180c03bc8` | `clock=%s-%s` |
| `0x180c03bd8` | `byte=%llu-` |
| `0x180c03be8` | `npt=%llu-%llu` |

**Reading:** the client takes the server URL and appends `token=<token>` (the first `%s` is the base URL, the second
`%s` is the separator — `?` or `&` depending on whether the base URL already contains `?`), then appends
`&trackID=<trackId>`. The `vcs*` suffix is only added when "usedvcs" is set (transcoded stream).

**Server implementation action:** the URL we return must be tolerant of `?`/`&` appending. Do **not** return a URL
whose path requires a `?` we already consumed, and do not percent-encode the token in a way the client's raw
`token=%s` append would double-encode. Return the base without `token=`/`trackID=` already present.

### 1.4 The RTSP request set the client actually emits

**[strings-only]** All in `RTSPSDK::CRTSPBaseClient::SendRTSPMessage` region (`.rdata` `0x180c039e0`–`0x180c03cd0`),
one log line per method — these are the exact methods our RTSP listener must answer:

| VA | Log line | Method |
|---|---|---|
| `0x180c03a60` | `[DPSDK] OPTION iMediaSessionID = %d, http->url = %s, http->userAgent = %s` | `OPTIONS` |
| `0x180c039f0` | `[DPSDK] DESCRIBE iMediaSessionID = %d, http->url = %s, http->userAgent = %s, http->accept = %s` | `DESCRIBE` |
| `0x180c03c78` | `[DPSDK] SETUP iMediaSessionID = %d, http->transport = %s` | `SETUP` |
| `0x180c03b70` | `[DPSDK] PLAY iMediaSessionID = %d, http->scale = %s, http->speed = %s, http->range = %s` | `PLAY` |
| `0x180c03c20` | `[DPSDK] PAUSE iMediaSessionID = %d` | `PAUSE` |
| `0x180c03af0` | `[DPSDK] SEEK_FILE iMediaSessionID = %d, http->range = %s` | `PLAY` + `Range: clock=` |
| `0x180c03b30` | `[DPSDK] SEEK_TIME iMediaSessionID = %d, http->range = %s` | `PLAY` + `Range: npt=` |
| `0x180c03ac8` | `[DPSDK] TEARDOWN iMediaSessionID = %d` | `TEARDOWN` |

Fixed header values:

| VA | String | Where used |
|---|---|---|
| `0x180c03ab0` | `Dahua Rtsp Client/2.0` | `User-Agent` on every request |
| `0x180c03a50` | `DPSDK` | `Accept` value seen in the DESCRIBE log (`http->accept`) |
| `0x180c64198` | `Accept: application/sdp` | DESCRIBE default when no override |
| `0x180c640f0` | `CSeq: %ld` | every request |
| `0x180c641f8` | `Transport: %s` | SETUP |
| `0x180c640d0` | `Session: %s` | SETUP/PLAY/PAUSE/TEARDOWN after SETUP |
| `0x180c62a80`/`0x180c5aa98` | `RTSP/1.0` | request line protocol |
| `0x180c640e0` | `%s %s RTSP/1.0` | request-line builder |
| `0x180c5ac88` | `RTSP/1.0 %d %s` | response status-line parser |
| `0x180c03848` | `User-DefCode:` | proprietary header the parser recognises |
| `0x180c03858` | `Location:` | parser recognises Location (redirect/302 handling) |

**Server implementation action:** answer `OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY` and be ready for
`PAUSE`/`TEARDOWN`. Any 4xx/5xx or silence on `OPTIONS`/`DESCRIBE` aborts the chain before SETUP is ever sent —
that also looks like "SETUP timed out" from the user's point of view.

### 1.5 Transport header — interleaved TCP vs UDP, exact literals

**[strings-only]** `range.mjs 0x180c02f00 0x180c04800` — the complete Transport template pool
(`0x180c03ed8`–`0x180c040d0`):

```
0x180c03ed8  RTP/AVP/DHTP;unicast
0x180c03ef0  RTP/AVP/TCP; interleaved=0-1                 ← note the SPACE after the semicolon
0x180c03f10  RTP/AVP/GBTP; interleaved=0-1
0x180c03f30  RTP/AVP/UDP;unicast;client_port=%d-%d
0x180c03f58  RTP/AVP/GBTCP;unicast%s
0x180c03f70  PGSP/AVP;unicast%s
0x180c03f88  RTP/AVP/GBTP;unicast%s
0x180c03fa0  NONE/AVP/TCP;unicast%s
0x180c03fb8  NONE/AVP/TCP;unicast
0x180c03fd0  RTP/AVP/SIP;unicast%s
0x180c03fe8  NONE/AVP/UDP;unicast%s
0x180c04000  RTP/AVP/UDP;unicast%s
0x180c04018  ;destination=%s;client_port=%d-%d
0x180c04040  NONE/AVP/UDP;multicast
0x180c04058  RTP/AVP/UDP;multicast
0x180c04070  DH/RTP/TCP;unicast;interleaved=%d-%d;mode=play
0x180c040a0  RTP/AVP/TCP;unicast;interleaved=%d-%d;mode=play
```

Plus the playback/download modifiers appended to the base transport in the same region:

```
0x180c03cb8  %s;playmode=download;device_domain_id=%s
0x180c03ce8  %s;playmode=download;tcpmode=passive;device_domain_id=%s
0x180c03d28  %s;playmode=download;tcpmode=active;device_domain_id=%s
0x180c03d60  %s;playmode=download
0x180c03d78  %s;playmode=download;tcpmode=passive
0x180c03da0  %s;playmode=download;tcpmode=active
0x180c03dc8  %s;playmode=playback;device_domain_id=%s
0x180c03df8  %s;playmode=playback;tcpmode=passive;device_domain_id=%s
0x180c03e38  %s;playmode=playback;tcpmode=active;device_domain_id=%s
0x180c03e70  %s;playmode=playback
0x180c03e88  %s;playmode=playback;tcpmode=passive
0x180c03eb0  %s;playmode=playback;tcpmode=active
```

**Reading:** for live view the client's default is **interleaved TCP** — `RTP/AVP/TCP; interleaved=0-1` (or
`RTP/AVP/TCP;unicast;interleaved=%d-%d;mode=play` when it needs explicit channel numbers). UDP is available
(`RTP/AVP/UDP;unicast;client_port=%d-%d`, with optional `;destination=%s`) but is not the default. The `DHTP`,
`GBTP`, `PGSP`, `SIP`, `NONE` prefixes are alternates selected by `sdkMsg.m_transModel` / `rtpHeadType`
(log format `0x180c040d0`: `sdkMsg.bStandard = %d,sdkMsg.enableEx = %d,sdkMsg.rtpHeadType=%d,nRtpPort=%d,m_transModel=%d`).

**Server implementation action (this is the likely root cause of the live failure):**
1. The client will almost always ask for **TCP interleaved** with a literal space (`Transport: RTP/AVP/TCP; interleaved=0-1`).
   Our RTSP handler must accept that exact string — including the space after the semicolon — and must not require
   `unicast` to be present.
2. The server's `200 OK` to SETUP must echo a `Transport:` header carrying `interleaved=<a>-<b>`. If we omit
   `interleaved=`, the live555 layer cannot bind the interleaved channels and the session never reaches `PLAY`
   → client reports a SETUP timeout.
3. If we answer with a UDP-only transport, the client has no UDP sockets bound (it chose TCP), so the session
   stalls the same way.

### 1.6 Response-side validation the client enforces (these produce SETUP failures)

**[strings-only]** live555-derived error strings inside `DPSDK.dll` (also present in `dslalien.dll` at the same
offsets +0x0 — same library):

| VA | String | Contract |
|---|---|---|
| `0x180c641b8` | `Refusing to issue an RTSP SETUP without a Transport: header.` | client-side guard — we must advertise support, client only sends Transport if a transport template was selected |
| `0x180c64208` | `Refusing to issue an RTSP request [%s] without a session ID.` | after SETUP, every request needs `Session:` — so our SETUP response **must** return `Session: <id>` |
| `0x180c64310` | `Got RTSP Session ID Line [%s], but wanted ID [%s]` | if we return a session id the client does not expect, the response is rejected |
| `0x180c64348` | `Got a blank Session ID` | `Session:` header must have a non-empty value |
| `0x180c64370` | `Unable to read the CSeq header: [%s]` | every response **must** echo the request `CSeq` |
| `0x180c5c2a8` | `RTSP CSeq mismatch or invalid CSeq` | echoed CSeq mismatch ⇒ response discarded ⇒ timeout |
| `0x180c63fb8` | `The CSeq of this request %ld did not match the response %ld` | same |
| `0x180c642a0` | `Unable to read the interleaved parameter from Transport header: [%s]` | our SETUP 200 must contain parseable `interleaved=` |
| `0x180c5b3a8` | `rtsp pdu len too large, drop!` | response must not exceed the client's PDU limit |
| `0x180c5c290` | `RTSP session error` | generic |

**Server implementation action:** implement a strict RTSP responder:
`CSeq` echoed verbatim (decimal, no sign), `Session:` non-empty and stable for the session lifetime,
`Transport:` echoed with both channel numbers, `RTSP/1.0 200 OK` status line, and `Content-Length` present on
any body (`0x180c23498 Content-Length: %d`). Also handle `OPTIONS` `Public:` listing
(`0x180c5a818 Session`, `0x180c5a820 RTP-Info`, `0x180c5a82c Range`, `0x180c5a838 Content-Base` are all parsed).

### 1.7 Timeouts and retry knobs

**[strings-only]** Timeout-relevant surfaces:

| VA | String / symbol | Meaning |
|---|---|---|
| `0x180ef7e9d` | `DPSDK_SetRtspThreadWaitTime` (export) | the public API that sets the RTSP thread wait time |
| `0x180c03028` | `[DPSDK] MediaSessionID=[%d], RtspThreadWaitTime = %d` | the value actually applied per media session |
| `0x180c02f90` | `[DPSDK] MediaSessionID=[%d], ConnectServer IP=[%s], PORT=[%d], ConnectRet=[%d]` | TCP connect result — **the first thing to read in the client log** |
| `0x180c034b8` | `Check connection failed -- MediaSessionID:%d, IP :%s, Port: %d` | connection watchdog |
| `0x180c034f8` | `MediaSessionID = %d, ConnectServer %s, time:%u` | connect timing |
| `0x180c03558` | `MediaSessionID = %d, CheckConnection %s, time:%u` | keepalive timing |
| `0x180c03060` | `RTSPSDK::CRTSPBaseClient::Start` | thread entry — spawns connect + watchdog |
| `0x180c03528` | `RTSPSDK::CRTSPBaseClient::CheckConnection` | periodic keepalive (`OPTIONS` or `GET_PARAMETER`) |
| `0x180ef7df1` | `DPSDK_SetPlaybackTimeoutByDevice` (export) | playback-specific timeout |
| `0x180c3f248` | `rtspTimeout` | device-side RTSP timeout config tag |
| `0x180c009b0` / `0x180c00978` | `[PSDK] OnSetupResponse success! iMediaSessionID = %d` / `... failed[%d]!` | **the SETUP verdict log line** |
| `0x180c01c48` | `[PSDK] OnPlayResponse success! iMediaSessionID = %d` | PLAY verdict |

**Diagnosis recipe for "RTSP SETUP timed out."**
1. `ConnectRet` at `0x180c02f90` must be success. If the gateway returns a URL whose host:port is not reachable,
   this is where it fails, not at SETUP.
2. If `[DPSDK] SETUP ...` is never logged, the chain died at `OPTIONS`/`DESCRIBE` — check our `DESCRIBE` SDP
   (`Accept: application/sdp`) and `OPTIONS` `Public:` reply.
3. If `[DPSDK] SETUP ...` **is** logged and `OnSetupResponse failed[%d]` follows, the cause is one of the §1.6
   validation rules (almost always a missing/incorrect `Transport: ...interleaved=a-b` echo, or a missing
   `Session:` header).
4. If neither line appears, the socket was closed mid-handshake — check `Send packet failed` at
   `0x180c03990` / `0x180c04780`.

**Server implementation action:** emit the RTSP handler so that SETUP is answered in < 1 s with a transport echo.
Do not hold the SETUP response while waiting for the upstream camera — reply with the transport echo first,
then bridge media.

### 1.8 The exact functions that drive the handshake — recovered addresses

**[script-computed]** `xref.mjs` scans `.text` for RIP-relative `LEA r64,[rip+disp32]`
(`REX.W 8D /r` with `mod=00, rm=101`) whose resolved target equals a specific `.rdata` string VA, then walks back
to the nearest ≥2-byte `0xCC` padding run to derive the enclosing function start. Results, each prologue verified
by hex dump (`hex.mjs`):

| Address | Function | Evidence (referenced strings) | Prologue |
|---|---|---|---|
| `0x180849a60` | `RTSPSDK::CRTSPBaseClient::ConnectServer` | `0x180c02f90` `ConnectServer IP=[%s], PORT=[%d], ConnectRet=[%d]` @ `0x180849b8b`; `0x180c03000` symbol string @ `0x180849b71` | `4C 8B DC 53 56 48 81 EC A8 00 00 00` (`mov r11,rsp; push rbx,rsi; sub rsp,0xA8`) |
| `0x180849bd0` | `RTSPSDK::CRTSPBaseClient::Start` | `0x180c03060` symbol @ `0x180849bf7`; `0x180c03028` `RtspThreadWaitTime = %d` @ `0x180849c1c` | — |
| **`0x180852190`** | **`RTSPSDK::CRTSPBaseClient::SendRTSPMessage`** — builds and sends every RTSP request | SETUP log `0x180c03c78` @ `0x18085300a`; `Dahua Rtsp Client/2.0` `0x180c03ab0` @ `0x180853b10`,`0x180853c3f`; DESCRIBE log `0x180c039f0` @ `0x180853ccc`; `RTP/AVP/TCP; interleaved=0-1` `0x180c03ef0` @ `0x180852b70`; `RTP/AVP/TCP;unicast;interleaved=%d-%d;mode=play` `0x180c040a0` @ `0x1808527a2`; `RTP/AVP/UDP;unicast;client_port=%d-%d` `0x180c03f30` @ `0x180852b19`; `%s%stoken=%s%s` `0x180c04178` @ `0x180852538`,`0x180852638`,`0x1808526ce`; `vcs…` `0x180c04130` @ `0x1808525de`; transport-mode log `0x180c040d0` @ `0x18085273d` | `40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC F0 01 00 00` (`push rbp,rsi,rdi,r12-r15; sub rsp,0x1F0`) |
| `0x18084d8a0` | `RTSPSDK::CRTSPBaseClient::CheckConnection` | `0x180c03528` symbol @ `0x18084db51`,`0x18084dc51`,`0x18084dcd1` | `48 8B C4 57 41 54 41 55 41 56 41 57 48 81 EC A0 01 00 00` (`mov rax,rsp; push rdi,r12-r15; sub rsp,0x1A0`) |
| `0x18085a620` | `RTSPSDK::CRTSPSBaseClient::SendRTSPMessage` (RTSPS/TLS twin) | same string set: `0x180c03ef0` @ `0x18085afed`, `0x180c03f30` @ `0x18085af96`, `0x180c04178` @ `0x18085a9ee`,`0x18085ab00`,`0x18085aba8`, `0x180c03ab0` @ `0x18085bfc9`,`0x18085c101`, `0x180c039f0` @ `0x18085c18e` | — |
| `0x1808586d0` | `CRTSPSBaseClient::ConnectServer` | `0x180c02f90` @ `0x1808588fe` | — |
| `0x180839600` | `CRTSPEntity*::OnSetupResponse` (live entity) | `0x180c009b0` `OnSetupResponse success! iMediaSessionID = %d` @ `0x1808399bd` | — |
| `0x180841d40` | `OnSetupResponse` variant (`CRTSPEntityPB` playback) | `0x180c009b0` @ `0x180842361` | — |
| `0x180843520` | `OnSetupResponse` variant (3rd entity) | `0x180c009b0` @ `0x1808438fa` | — |

**Contract reading of `0x180852190`:** the single function that both **chooses the Transport string** and
**assembles the request URL** is `CRTSPBaseClient::SendRTSPMessage`. It:
1. picks a transport template from the pool by `sdkMsg.m_transModel` / `rtpHeadType` / `nRtpPort`
   (log at `0x18085273d` prints `sdkMsg.bStandard, enableEx, rtpHeadType, nRtpPort, m_transModel`),
2. appends `token=<token>` and `&trackID=<trackId>` to the server-supplied URL (`0x180852538`–`0x1808526ce`),
3. optionally appends the `vcs*` transcode parameters (`0x1808525de`),
4. sets `User-Agent: Dahua Rtsp Client/2.0` (`0x180853b10`) and issues the method.

**Server implementation action:** because the transport is chosen client-side from the *server-provided* URL/port
pairing and the `trackId`/`token` values, the server must return a URL that (a) already carries the correct host and
port (9100 for the DSS media service), (b) can accept `?token=` or `&token=` appending, and (c) pairs with a
`trackId` that the RTSP listener recognises in the `trackID=` query parameter. If the RTSP listener we run does not
tolerate `token=`/`trackID=` query params on the SETUP URL, or answers on a different port than the URL, SETUP never
completes → "RTSP SETUP timed out".

### 1.9 RTSP engine structure (for deeper follow-up)

Class map recovered from RTTI strings in `.rdata` (`q.mjs dpsdk-all.tsv "^\.\?AV"`):

- Clients: `RTSPSDK::CRTSPBaseClient`, `RTSPSDK::CRTSPSBaseClient` (RTSPS, TLS variant — see `0x180c77130`
  `[PSDK]SetSSLInfo  SSLEnable = [%d] RTSPSEnable = [%d] CertificatePath = [%s] UnSSLPort = [%d]`)
- Entities: `CRTSPEntityReal` (live), `CRTSPEntityPB` (playback), `CRTSPEntityTalk` (two-way audio),
  `CRTSPEntityVtCall`, `CRTSPEntityBayPic`, `CRTSPSBaseEntity`/`CRTSPSRealEntity`
- Units/drivers: `CRTSPTCPUnit`, `CRTSPTCPBayPicDriver`, `CRTSPUDPUnit`, `CRTSPMulticastUnit`,
  `CRTSPTCPDriver`, `CRTSPUDPDriver`, `CRTSPMulticastUDPDriver`, `CRTSPStdTCPUnit`
- Sessions: `RTSPSDK::RealSession`, `PlaybackSession`, `TalkSession`, `BroadcastSession`,
  `VtAudioSession`, `VtVideoSession`, `BayPicSession`
- A second, independent stack: `dsl::DRtspClient` / `dsl::DRtspSession` (`0x180c59ec0`, `0x180c5b390`)
  with its own `RTSP/1.0`, `CSeq: `, `Session: ` handling — used by the media/playback path.

`Cannot see xref-level detail yet` — **superseded by §1.8**, which lists the recovered function addresses.

### 1.10 What is still unknown (residual unknowns)

1. **Exact default value of `RtspThreadWaitTime`** — it is a runtime parameter (`DPSDK_SetRtspThreadWaitTime`),
   not a literal in `.rdata`. Its default is set in `CRTSPBaseClient::Start` @ `0x180849bd0`, which needs a
   decompiler pass. `[unknown]`
2. **Which of `url` / `rtspUrl` / `rtspUrls` wins** — *partially resolved in §1.1b*: the RTSP URL parser at
   `0x1806d5eb0` / `0x1806db570` reads `rtspUrls` (array) before `rtspUrl` (singular). What still needs a
   decompiler is whether a non-empty array suppresses the singular entirely, and how `urlType`/`scheme`
   (`0x18067fea0` / `0x180680730`) filter the array. `[unknown → partially resolved]`
3. **Whether `connectType` (`0x180cd4bb8`) selects TCP vs UDP** or only P2P-vs-direct. It sits in a device DTO
   cluster (`BRMS.Device.GetP2PConnectType`, `0x180cd83d0`), so it likely means direct/P2P/relay rather than
   RTSP transport. `[unknown]` — transport is chosen from `m_transModel`/`rtpHeadType` (§1.8).
4. **The literal UI string the operator saw.** No binary contains "RTSP SETUP timed out."; the message is either
   produced by our harness or by a translation catalogue (`.qm`) not shipped as plain strings. Diagnose from the
   client log instead (`[PSDK] OnSetupResponse`).

---

## 2. Device tree payloads — Monitoring Center → Resources

### 2.1 `dspStatus` does not exist

**[strings-only, exhaustive negative]** A `dirscan.mjs` pass over **every** `.dll`/`.exe` in the DSS Client
distribution (100+ files, ASCII + UTF-16LE) for `dspStatus|dspstatus` returned **0 hits**. The client never reads a
`dspStatus` key.

**Server implementation action:** stop emitting `dspStatus`. The client's status keys are `onlineStatus`,
`syncChannelStauts` (sic — note the client's own typo), `intelliState`, `deviceStatus`, `channelStatus`,
`alarmStatus`/`byPassStatus`/`faultStatus` (alarm-host only) and the enum `State`. Removing `dspStatus` cannot
break the client; supplying it is dead weight.

### 2.2 Tree function codes (the calls the Resources panel makes)

**[script-computed]** from `data/functioncodes.tsv` (1,043 pairs extracted):

| functionCode id | topic | id VA |
|---|---|---|
| `BRMSTreeGetGradeDeviceTree` | `BRMS.Tree.GetGradeDeviceTree` | `0x180cdbd28` |
| `BRMSTreeGetFullGradeDeviceTree` | `BRMS.Tree.GetFullGradeDeviceTree` | `0x180cdca70` |
| `BRMSTreeGetDeviceTree` | `BRMS.Tree.GetDeviceTree` | `0x180cdd278` |
| `BRMSTreeSearchGradeDeviceTreeWithListMode` | `BRMS.Tree.SearchGradeDeviceTreeWithListMode` | `0x180cdcd30` |
| `BRMSTreeSearchFullGradeDeviceTreeWithListMode` | `BRMS.Tree.SearchFullGradeDeviceTreeWithListMode` | `0x180cdc790` |
| `ResourcesTreeGetDeviceTree` | `Resource.Tree.GetDeviceTree` | `0x180cdef20` |
| `DevicesManagerCollectionChannelsQuery` | `DevicesManager.Collection.ChannelsQuery` | `0x180cdf508` |
| `DevicesManagerCollectionBatchDelete` | `DevicesManager.Collection.BatchDelete` | `0x180cdeea0` |

Public C API entry points (exports): `DPSDK_GetGradeDeviceTree` (`0x180ef483f`), `DPSDK_GetFullGradeDeviceTree`
(`0x180ef4773`), `DPSDK_SearchGradeDeviceTree` (`0x180ef782e`), `DPSDK_SearchFullGradeDeviceTree` (`0x180ef780e`),
`DPSDK_GetDeviceTreeInfo` (`0x180ef423e`), `DPSDK_GetPersonOrgTree` (`0x180ef5450`).

Internal wiring (from `range.mjs 0x180ca3400 0x180ca3700`):

```
0x180ca3428  Dpsdk::CRestLogical::GetAllOrg              -> 0x180ca3448  devicesManager/deviceAllOrg
0x180ca34a0  Dpsdk::CRestLogical::GetDeviceByLayered     -> 0x180ca34c8  devicesManager/deviceTree
                                                         0x180ca34e8  tree/search
0x180ca3538  Dpsdk::CRestLogical::GetDevice              -> 0x180ca3558  tree/devices
                                                         0x180ca3568  devicesManager/devicesInfo
0x180ca35c0  Dpsdk::CRestLogical::GetDeviceListByOrg
0x180ca3628  Dpsdk::CRestLogical::GetOrgInfo            -> 0x180ca3648  devicesManager/devicesGroup/
                                                         0x180ca3668  root
0x180ca36a8  Dpsdk::CRestLogical::CreateOrg
```

**Server implementation action:** implement at minimum `devicesManager/deviceTree`, `tree/search`,
`tree/devices`, `devicesManager/devicesInfo`, `devicesManager/deviceAllOrg`. `GetOrgInfo` builds its path as
`devicesManager/devicesGroup/` + `root` or an org code — so `/devicesManager/devicesGroup/{orgCode}` must return a
single org node.

### 2.3 Tree node keys — the exact field-name set

**[script-computed]** `range.mjs 0x180cdbc80 0x180cdbe60` — the field pool that sits between
`BRMSTreeGetGradeDeviceTree` and `BRMSResourceBindingBatchDeleteChannelRelations`:

| VA | Key | Meaning |
|---|---|---|
| `0x180cdbd68` | `organizations` | array of org nodes (children of an org) |
| `0x180cdbd78` | `checked` | boolean — tri-state checkbox state |
| `0x180cdbd80` | `hasChild` | **boolean — MUST be present on every node** |
| `0x180cdbd90` | `deviceCapability` | device capability mask |
| `0x180cdbda8` | `channelRemoteType` | channel remote/cascade type |
| `0x180cdbdc0` | `inputAlarmType` | alarm input type |

Full node namespace assembled from `q.mjs` over the whole DTO pool (`0x180cae400`–`0x180cb1200`, `0x180cafd00`+):

**Org / tree node (`DeviceOrgTreeVo`)**

| Key | VA |
|---|---|
| `orgCode` | `0x180cae960` |
| `orgName` | `0x180cae968` |
| `parentOrgCode` | `0x180cae978` |
| `sort` | `0x180cae988` |
| `remark` | `0x180cae970` |
| `domainId` | `0x180cae990` |
| `orgType` | `0x180cde7e0` |
| `orgId` | `0x180caf9cc` |
| `unitType` / `unitTypeName` | `0x180cae6d0` / `0x180cdbba0` |
| `unitSeq` / `unitName` | `0x180cae6c8` / `0x180cdb300` |
| `hasChild` / `checked` | `0x180cdbd80` / `0x180cdbd78` |
| `organizations` | `0x180cdbd68` |
| `devices` | `0x180c76d90` |
| `channels` | `0x180c76ea8` |
| `unitTypes` | `0x180cdbc68` |

**Device node (`DeviceTreeVo`)**

| Key | VA |
|---|---|
| `deviceCode` | `0x180cae708` |
| `deviceName` | `0x180cae420` |
| `deviceType` | `0x180cafa40` |
| `deviceCategory` | `0x180caf0a8` |
| `deviceIp` / `devicePort` | `0x180caebd8` / `0x180caebe8` |
| `deviceSn` | `0x180cdac20` |
| `deviceModel` / `deviceModelStr` | `0x180ccaad8` / `0x180caeb98` |
| `deviceStatus` | `0x180cdcd20` |
| `deviceOrgCode` | `0x180cd5a58` |
| `deviceOnlineTimeSync` | `0x180cd5830` |
| `onlineStatus` | `0x180cae908` |
| `intelliState` | `0x180cae928` |
| `sleepMode` | `0x180cae948` |
| `offlineReason` | `0x180cae8f8` |
| `offlineReasonCode` / `offlineReasonDesc` | `0x180cdba98` / `0x180cdba80` |
| `channelNum` / `channelCount` | `0x180cbaf20` / `0x180cd4530` |
| `channelInfos` / `channelExtList` | `0x180cb14e8` / `0x180cbb1a0` |
| `deviceCapabilities` | `0x180cdbc08` |
| `manufacturer` / `deviceManufacturer` | `0x180caeb48` / `0x180cce218` |
| `protocol` / `streamProtocol` | `0x180caeb18` / `0x180caeb28` |

**Channel node (`ChannelVo`)**

| Key | VA |
|---|---|
| `channelId` | `0x180cae568` |
| `channelName` | `0x180cae578` |
| `channelCode` | `0x180caf520` |
| `channelSeq` | `0x180cae6b8` |
| `channelType` | `0x180caee78` |
| `channelSubtype` | `0x180caee88` (also truncated alias `channelSubty` at `0x180caffd8`) |
| `channelStatus` | `0x180ccc080` |
| `channelSn` | `0x180cdb578` |
| `channelIp` / `channelMac` | `0x180cdb2f0` / `0x180cdb728` |
| `channelRemoteType` | `0x180cdbda8` |
| `channelCapabilities` | `0x180cdbbf0` |
| `channelExt` | `0x180cdb6b8` |
| `subType` | `0x180cd7798` |
| `streamType` | `0x180cae548` |

### 2.4 The paging envelope

**[script-computed]** The client's paged-result keys, at their VAs:

| Key | VA | Note |
|---|---|---|
| `pageNo` | `0x180cb07a4` | request + response page index |
| `pageSize` | `0x180cb07b0` | page size (also lowercase variant `pagesize` @ `0x180cc9cc8`) |
| `results` | `0x180cb07d0` | **the array the client iterates** |
| `totalCount` | `0x180cafd70` | total rows |
| `total` | `0x180cb02e8` | alias |
| `count` | `0x180cb0b48` | alias |
| `currentPage` | `0x180cc9620` | alias |
| `finished` | `0x180cb07c0` | completion flag |
| `data` | `0x180caf7c4` | outer payload key |
| `errorCode` | `0x180caf088` | |
| `code` | `0x180caeb04` | |
| `result` | `0x180cb09cc` | |
| `params` | `0x180c97404` | request payload key |
| `msg` (as `Msg`) | `0x180c7c1f4` | |

**Server implementation action:** paged tree answers must look like
`{ code, msg, data: { pageNo, pageSize, totalCount, results: [ …nodes… ] } }` with the node keys of §2.3.
Per repo rule (AGENTS.md §2) **counters and sort values must be strings** (`"1"`, `"0"`, `"86"`) — the C++
matchers do no coercion; `hasChild`/`checked` are the exceptions that are read as booleans.

---

## 3. Server API surface

### 3.1 Service base paths (the router table)

**[script-computed]** `range.mjs 0x180c7f018 0x180c7f180` — the literal list of service prefixes the client will
route to, followed by the two API versions:

```
0x180c7f018 /videoService        0x180c7f108 /otms/api
0x180c7f028 /faceService         0x180c7f118 /obms/api
0x180c7f038 /accessControlServer 0x180c7f128 /ipms/api
0x180c7f050 /PermissionProxy/v1  0x180c7f138 /omms/api
0x180c7f068 /alarmhost/v1        0x180c7f148 /cfgs/api
0x180c7f078 /vehicleServer       0x180c7f158 /iams/api
0x180c7f088 /emapService         0x180c7f168 /erms/api
0x180c7f098 /psib                0x180c7f174 "v1.0"
0x180c7f0a0 /alarmProcess        0x180c7f17c "v1.1"
0x180c7f0b0 /admin/API
0x180c7f0bc /OBMS
0x180c7f0c8 /brms/api
0x180c7f0d8 /OTMS/API
0x180c7f0e8 /ecos/api
0x180c7f0f8 /emap/api
```

Note `0x180c7f5f8 /ci/` and `0x180c7f600 /IPMS/API/` (uppercase variants used by specific calls), and
`0x180c905d8 api/v1.1/acs/record/offline/synchronize` (no leading slash — path concatenation exists).

**Server implementation action:** the gateway must accept the paths with **and** without the version segment,
case-sensitively distinguishing `/OBMS` vs `/obms/api`, `/OTMS/API` vs `/otms/api`. Our current gateway only serving
`/brms/api` explains any secondary endpoint misses.

### 3.2 Function-code registry (complete, machine-readable)

1043 `functionCode` → `topic` pairs, written to **`research/rea/data/functioncodes.tsv`**. Distribution by service
prefix:

| Prefix | Count | Prefix | Count |
|---|---|---|---|
| `BRMS` | 519 | `IPMS` | 86 |
| `Express` | 149 | `OBMS` | 70 |
| `VSL` | 38 | `BRM` | 33 |
| `DMS` | 18 | `Access` | 17 |
| `SS` | 16 | `Storage` | 11 |
| `Account` | 10 | `EMAP` | 10 |
| `Resource` | 10 | `IAMS` | 8 |
| `Intelligence` | 8 | `AR` | 7 |
| `ERMS` | 6 | `OMMS` | 5 |
| `VMS` | 5 | `MTS` | 4 |
| `Media` | 3 | `CFGS`, `Ci`, `DevicesManager`, `IVS`, `PTS` | 2 / 2 / 2 / 1 / 2 |

946 REST path fragments → **`research/rea/data/rest-paths.txt`**.

### 3.3 High-value rows (URL · method · request · response · source)

Method inference: `Dpsdk::CRestLogical::*Get*` = GET/`POST` with `params` body; `*Create*`/`*Update*`/
`*Add*`/`*Delete*`/`*Batch*` are POST. The client's REST layer (`CDpsdkManager_Rest.cpp`,
`RestLogical.cpp`, `RestLogic_Definition.cpp` — source paths at `0x180c7e388`, `0x180c7f1b0`, `0x180c7ed70`)
always sends `params` as the body key.

| URL | Method | Request fields | Response fields | Source |
|---|---|---|---|---|
| `/brms/api/v1.1/account/initialize/status` | GET | — | `code`,`msg`,`data` | `Dpsdk::CDpsdkManager::GetUserPWDState`, path @ `0x180c7e500` |
| `/brms/api/v1.1/account/initialize` | POST | `pInitializeInfo` | `code`,`msg` | `InitializeAccount` @ `0x180c7ea30` |
| `/brms/api/v1.1/account/security/question/list` | GET | — | question list | `GetUserQuestionList` @ `0x180c7e988` |
| `/brms/api/v1.1/account/security/question/answer` | POST | `pAnswerList` | `code` | `VerifyQuestionAnswer` @ `0x180c7ead8` |
| `/brms/api/v1.1/account/security/public-key/generate` | POST/GET | — | RSA `-----BEGIN PUBLIC KEY-----` PEM | `UpdatePublicKey` @ `0x180c7eb78` |
| `/brms/api/v1.1/account/security/password/forgot/guide` | POST | `pForgotPwdGuideInfo` | `code` | `GuideForgotPassword` @ `0x180c7e5b8` |
| `/brms/api/v1.1/account/mail/verify/code/generate` | POST | `pGetVertifyCodeInfo` | `code` | `GetMailVertifyCode` @ `0x180c7e700` |
| `/brms/api/v1.1/account/mail/verify/code/check` | POST | `pCheckVertifyCodeInfo` | `code` | `CheckMailVertifyCode` @ `0x180c7e800` |
| `/brms/api/v1.1/account/security/password/retrieve-by-mail` | POST | `pUpdatePWDbyMailInfo` | `code` | `VertifyUpdatePWDByMail` @ `0x180c7e8b8` |
| `/brms/api/v1.1/account/security/password/retrieve` | POST | `pUserPassword` | `code` | `VerifyUpdatePWD` @ `0x180c7ec08` |
| `/brms/api/v1.1/account/authorize/password/change` | POST | `pUserPassword` | `code` | `ChangeAccountUserPassword` @ `0x180c7ecb8` |
| `Account.User.FirstLogin` | POST | `loginName`,`loginPass`,`loginType` | `token`,`userId` (+ RSA challenge) | `Dpsdk::CRestLogical::LoginFirstTime` `0x180ca2e20`; ids @ `0x180cdf5c0` |
| `Account.User.SecondLogin` | POST | encrypted challenge (`PrivateDecrypt` client-side) | `token`,`userId` | `LoginSecondTime` `0x180ca2fc8`; id @ `0x180cdf888` |
| `/cfgs/api/v1.1/system/environment/runtime/check` | GET | — | `code` | `CheckRuntimeEnvironment` @ `0x180c7f530` |
| `v1.1/config/server/time` | GET | — | `systemTime` | `Dpsdk::CRestLogical::SyncTime` @ `0x180c7fe68` |
| `v1.1/definition/stream-type/list` | GET | — | `pStreamTypes` | `GetSteamTypes` @ `0x180c7ee50` |
| `v1.1/definition/channel-capability/list` | GET | — | `pChnlCapabilities` | `GetChannelCapabilities` @ `0x180c7ef00` |
| `v1.1/definition/device-type/list` | GET | — | `pDeviceTypes` | `GetDeviceTypes` @ `0x180c7efb0` |
| `v1.1/definition/record-storage-position/list` | GET | — | `pStoragePositions` | `GetRecordStoragePositions` @ `0x180c7eda0` |
| `devicesManager/deviceTree` + `tree/search` | POST | tree filter (`unitTypes`,`channelTypes`,`deviceCategories`,`deviceTypes`,`sourceTypes`,`inputAlarmTypes`,`serverCodes`,`filterEmptyDevice`,`addTypes`,`excludeDeviceTypes`,`excludeDeviceCategories`,`channelSubtypes`,`channelRemoteTypes`,`cameraTypes`,`protocolTypes`,`deviceCapabilities`,`channelCapabilities`,`inputAlarmType`… — all @ `0x180cdbc78`–`0x180cdbd10`) | `organizations`/`devices`/`channels` tree with `hasChild`,`checked` | `Dpsdk::CRestLogical::GetDeviceByLayered` @ `0x180ca34a0` |
| `tree/devices` | POST | device filter | device node array | `GetDevice` @ `0x180ca3538` |
| `devicesManager/devicesInfo` | POST | `deviceCodes[]` | device detail (`deviceIp`,`devicePort`,`userName`,`password`,`protocol`,`streamProtocol`,`encrypType`,`manufacturer`) | `GetDevice` @ `0x180ca3558`; fields @ `0x180caeb04`–`0x180caeb74` |
| `devicesManager/deviceAllOrg` | GET | — | org list | `GetAllOrg` @ `0x180ca3448` |
| `devicesManager/devicesGroup/{orgCode\|root}` | GET | — | org node | `GetOrgInfo` @ `0x180ca3648` |
| `Media.RealMonitor.Uri` | POST | `resource`/`channelId` + `subType`,`urlType`,`scheme` | **`url`/`rtspUrl`/`rtspUrls`, `trackId`, `token`** | ids @ `0x180cd77b0`/`0x180cd77c8`; keys `0x180cdbfc0`,`0x180cdbfd0`,`0x180caf99c`,`0x180cd77a0`,`0x180cd77a8`,`0x180cd7798`,`0x180cd77e0` |
| `Media.RealMonitor.Snapshot` | POST | channel + type | picture | ids @ `0x180cd8410`/`0x180cd8430` |
| `/videoService/eventCenter/messages/subscribe` | POST | `subscribeAddress`,`subscribeAddrType`,`subscribeUser`,`subscribePassword`,`initMessageId` | `SubscribeID` | `0x180cbd490`; fields @ `0x180cd8010`–`0x180cd8070`, `0x180caf300` |
| `eventCenter/messages/subscribeAddress` | POST | same | subscription address | `0x180c97e98` |
| `BRM/User/GetChannelsCount` | POST | — | `count` | `GetChannelsCount` @ `0x180c7f638` |
| `account/user/level` | GET | — | user level | `GetUserLevel` @ `0x180c7f6f8` |
| `BRM/Time/SyncServerTime` | POST | — | server time | `GetSyncServerTime` @ `0x180c7ff80` |
| `v1.1/device/{code}/timing` | POST | timing | `code` | `DeviceTiming` @ `0x180c80018` |
| `v1.1/config/device-login-model` | GET/POST | `deviceLoginModel` | model | `GetDeviceLoginModel` @ `0x180c800a0` |
| `v1.1/config/interface/common/timeout` | GET | — | timeout config | `QueryInterfaceCommonTimeout` @ `0x180c801a8` |
| `dpsdkPtz/ptz`, `dpsdkPtz/ptzZoomMax` | POST | PTZ cmd | ptz info | `GetPtzInfo` `0x180c80238`, `GetPtzZoomMax` `0x180c80300` |
| `devicesManager/devices/{code}/webTunnel` | GET | — | tunnel info | `BRMS.Device.GetDeviceWebTunnel` @ `0x180cdbab0` |
| `/brms/api/v1.1/license/express-to-pro/active/file/export` | POST | — | file | `0x180ca67f0` |
| `/web/authorization` | POST | — | web auth | `Dpsdk::CRestLogical::GetWebAuthorization` @ `0x180ca0e98` |

### 3.4 Envelope and auth headers

- Envelope keys: `code`, `msg`/`Msg`, `result`, `data`, `params`, `errorCode`.
- Login returns `token`; the client then sends it as a header on every call. The literal header format is not a
  plain string in this DLL — `Dpsdk::CDpsdkManager::GetWebAuthorization` (`0x180ca0e68`) and
  `DPSDK_GetWebAuthorization` (`0x180ef631c`) wrap it; `Authorization: Bearer %s` (`0x180c672d0`) and
  `Authorization: WSSE profile="UsernameToken"` (`0x180ce1658`) exist for the web/portal paths.
  **Note:** this is `[strings-only]`; exact header name for the BRMS REST calls needs a decompiler pass on
  `CDpsdkManager_Rest.cpp` helpers.
- Relogin: `DPSDK_Relogin` (`0x180ef72fd`), `DPSDK_ReloginByToken` (`0x180ef730b`),
  `DPSDK_SeverOffByTokenLogin` (`0x180ef8083`); client logs `Post Relogin Task` / `Start to relogin` /
  `User is ready to relogin.token is empty` (`0x180c76778`, `0x180c76970`, `0x180c76790`).

**Server implementation action:** two-phase login must be implemented — `Account.User.FirstLogin` returns a
challenge/token, `Account.User.SecondLogin` receives the RSA-encrypted secret and returns the final `token`
(`Login PSDKAPI_REQUEST success, token = %s, user id = %s` @ `0x180ca2ff0`). A server that only implements a single
login will fail the client's `LoginSecondTime` step.

---

## 4. NOTIFY topics (message-broker subscriptions)

**[script-computed]** 89 `notify*` topics extracted → **`research/rea/data/notify-topics.txt`**. All live in
`.rdata` `0x180c72c28`–`0x180c76388`. The ones that matter for the current work:

| Topic | VA | Why it matters |
|---|---|---|
| `vms.notifyDeviceStatus` | `0x180c72d58` | device online/offline — the tree refresh trigger |
| `vms.notifyDevChannelStatus` | `0x180c72d70` | channel status |
| `brms.notifyChannelStatuses` | `0x180c72d90` | batch channel statuses |
| `brms.notifyChannelCapabilities` | `0x180c72db0` | capability refresh |
| `vms.notifyChannelIntelliState` | `0x180c72dd0` | `intelliState` field source |
| `vms.notifyDeviceOffline` | `0x180c72df0` | |
| **`vms.notifyMediaVK`** | `0x180c737a0` | **media VK delivery (`vkId`/`vkValue`, `0x180cb0c64`/`0x180cb0c70`) — stream decryption keys** |
| `vms.notifyUserTokenExpiration` | `0x180c72c28` | token expiry → forces relogin |
| `vms.notifyUserRole` | `0x180c72d40` | |
| `vms.notifyAlarms` / `brms.notifyAlarms` | `0x180c72eb8` / `0x180c72e48` | alarm push |
| `vms.notifySyncTime` | `0x180c72f88` | clock sync |
| `vms.notify.resourceBinding` | `0x180c73720` | resource binding change |
| `vms.notifyMenuRightChanged` | `0x180c737b8` | menu rights |

Subscription plumbing: `Dpsdk::CDpsdkCore::SetMQTopic` (`0x180c76710`), `DPSDK_SetMQTopic` (`0x180ef7d35`),
`Dpsdk::CDpsdkManager::SubscribeMspMessage` (`0x180c7b7c8`), `SubscribeHumanTraffic` (`0x180c7b878`),
`SubscribeActualGpsConfig` (`0x180c7b6c8`), `SubscribeVehicleAlarmConfig` (`0x180c7bab0`);
`Dpsdk::CDpsdkCore::HandleUpdateTokenNotify` (`0x180c76dc0`) consumes token-refresh messages.

**Server implementation action:** publish `vms.notifyDeviceStatus`, `vms.notifyDevChannelStatus` and
`vms.notifyMediaVK` on the ActiveMQ topic namespace, and implement
`POST /videoService/eventCenter/messages/subscribe` returning a `SubscribeID`. Without `vms.notifyMediaVK` a
VK-encrypted stream cannot be decrypted even when RTSP negotiates successfully.

---


| UTC timestamp | Action |
|---|---|
| 2026-11-12T04:00Z | `binary_session` → no target open. Located `DPSDK.dll` at `C:\Users\bruno\Downloads\dssv2-setup\dssclient-extracted\DPSDK.dll` (17,078,880 B) and a server-side copy under `dssserver-analysis\unpack-inner-1376402688` (11,388,424 B, not used this pass). |
| 2026-11-12T04:01Z | `open_binary` DPSDK.dll → sha256 `ce43c8b7…0d47`, PE x86_64. |
| 2026-11-12T04:01Z | `search_strings "SETUP timed out"` and `search_strings "RTSP"` → Ghidra provider timeout at 330,000 ms startup deadline (target too large). No partial results returned. |
| 2026-11-12T04:01Z | `update_analysis_settings ghidra.startup_timeout_ms = 1800000` (applies at next startup). |
| 2026-11-12T04:02Z | Built `strings.mjs` / `allstrings.mjs` / `range.mjs` / `q.mjs` / `dirscan.mjs` in the session scratchpad (PE-aware offset→RVA→VA). |
| 2026-11-12T04:02Z | `dirscan.mjs` over all 100+ client DLLs/EXEs for `timed out|timeout` → **no literal "RTSP SETUP timed out."** anywhere; the closest UI strings are `MainFormPlugin.dll 0x180661f10 "Request timed out."`, `0x18067b860 "Request video data timed out"`, `0x18067b8a8 "Device connection timed out."`. Conclusion: the phrase the operator sees is a paraphrase/harness message, not a client literal — diagnose via the `[PSDK] OnSetupResponse` log line instead. |
| 2026-11-12T04:02Z | `dirscan.mjs` for `SETUP timed|RTSP SETUP` → only `Refusing to issue an RTSP SETUP without a Transport: header.` in DPSDK.dll and dslalien.dll. |
| 2026-11-12T04:03Z | Full ordered string inventory: DPSDK.dll 554,521 strings, MainFormPlugin.dll 185,157 strings. |
| 2026-11-12T04:03Z | `range.mjs 0x180cd7400–0x180cd8700` → `Media.RealMonitor.Uri` DTO key cluster (rtspUrl/url/urlType/scheme/subType/resource). |
| 2026-11-12T04:04Z | `range.mjs 0x180c02f00–0x180c04800` → full Transport template pool, User-Agent, RTSP method log lines, token/trackID appenders. |
| 2026-11-12T04:04Z | `inspect_native_exports` DPSDK.dll → 1,363 exports; RTSP-related exports enumerated (`DPSDK_SetRtspThreadWaitTime`, `DPSDK_StartRealPlay(Ex)`, `DPSDK_StopMediaRealPlay`, …). |
| 2026-11-12T04:05Z | Section 1 of this report written. |
| 2026-11-12T04:06Z | `range.mjs 0x180cae400–0x180caeb00` → device/tree/alarm DTO field pool (`orgCode`,`deviceCode`,`unitType`,`sort`,`hasChild`…). |
| 2026-11-12T04:06Z | `dirscan.mjs` over all client binaries for `dspStatus` → **0 hits** (exhaustive negative, §2.1). |
| 2026-11-12T04:07Z | `range.mjs 0x180cdbc80–0x180cdbe60` → tree response keys (`organizations`,`checked`,`hasChild`,`deviceCapability`,`channelRemoteType`,`inputAlarmType`). |
| 2026-11-12T04:07Z | Paging envelope keys located (`pageNo` `0x180cb07a4`, `pageSize` `0x180cb07b0`, `results` `0x180cb07d0`, `totalCount` `0x180cafd70`). |
| 2026-11-12T04:08Z | `range.mjs 0x180c7f018–0x180c7f180` → **service base path router table** (22 prefixes + `v1.0`/`v1.1`). |
| 2026-11-12T04:08Z | `range.mjs 0x180ca3400–0x180ca3700` → device-tree REST wiring (`devicesManager/deviceTree`, `tree/search`, `tree/devices`, `devicesManager/devicesInfo`, `devicesManager/devicesAllOrg`, `devicesManager/devicesGroup/`). |
| 2026-11-12T04:09Z | `pair.mjs` → **1,043 functionCode↔topic pairs**; written to `research/rea/data/functioncodes.tsv`. |
| 2026-11-12T04:09Z | `artifacts.mjs` → `research/rea/data/functioncodes.tsv` (1,043), `rest-paths.txt` (946), `notify-topics.txt` (89 notify topics after filtering 458 prefix matches). |
| 2026-11-12T04:10Z | Built `xref.mjs` (RIP-relative `LEA` scanner + function-start recovery via `0xCC` padding) and `hex.mjs` (VA→hexdump). |
| 2026-11-12T04:10Z | `xref.mjs` on RTSP symbol/log strings → `CRTSPBaseClient::ConnectServer` `0x180849a60`, `::Start` `0x180849bd0`, **`::SendRTSPMessage` `0x180852190`**, `::CheckConnection` `0x18084d8a0`, `CRTSPSBaseClient::SendRTSPMessage` `0x18085a620`, `CRTSPSBaseClient::ConnectServer` `0x1808586d0`, three `OnSetupResponse` entities `0x180839600` / `0x180841d40` / `0x180843520`. |
| 2026-11-12T04:11Z | `hex.mjs` verified all four prologues as MSVC x64 function entries (`SendRTSPMessage` frame = `sub rsp,0x1F0`). |
| 2026-11-12T04:11Z | `xref.mjs` on Transport templates → transport selection and URL/token/trackID assembly are both inside `0x180852190` (`RTP/AVP/TCP; interleaved=0-1` @ `0x180852b70`, `%s%stoken=%s%s` @ `0x180852538`/`0x180852638`/`0x1808526ce`). |
| 2026-11-12T04:12Z | `xref.mjs` on `rtspUrls`/`rtspUrl`/`urlType`/`scheme` → URL response parsers `0x1806d5eb0`, `0x1806db570`, `0x18067fea0`, `0x180680730`; plural read precedes singular (§1.1b). |
| 2026-11-12T04:12Z | NOTIFY topic inventory extracted (89 topics, `.rdata 0x180c72c28–0x180c76388`), incl. `vms.notifyMediaVK` (stream VK keys). |
| 2026-11-12T04:13Z | Sections 2, 3, 4 and residual-unknown list written; report finalised for this pass. |

### Not done in this pass / next steps

- **Ghidra decompiler dossiers not obtained.** Two attempts at `search_strings` on this 17,078,880-byte DLL hit the
  Ghidra startup deadline (first 330,000 ms). `ghidra.startup_timeout_ms` is now set to 1,800,000 ms at runtime, so
  a fresh `open_binary` + query should succeed. Recommended targets for the next pass, in order:
  `0x180852190` (`SendRTSPMessage` — transport branch + URL assembly), `0x180849bd0` (`Start` — the
  `RtspThreadWaitTime` default), `0x1806d5eb0` (`Media.RealMonitor.Uri` response parser — `rtspUrls` vs `rtspUrl`
  precedence), `0x180839600` (`OnSetupResponse` — which RTSP failure codes map to which client error).
- **Method verb confirmation.** GET vs POST for the 1,043 function codes was inferred from naming; the REST layer's
  request builder needs one decompiler pass to confirm.
- **Exact auth header name** for BRMS REST calls (§3.4) is still `[strings-only]`.
- **`MainFormPlugin.dll` not analysed** beyond string inventory — the RTSP handshake lives entirely in
  `DPSDK.dll`; `MainFormPlugin.dll` only surfaces the UI messages (`Request video data timed out`
  @ `0x18067b860`, `Device connection timed out.` @ `0x18067b8a8`, `Request timed out.` @ `0x180661f10`).
- **Server-side `DPSDK.dll`** at `C:\Users\bruno\Downloads\dssv2-setup\dssserver-analysis\unpack-inner-1376402688\DPSDK.dll`
  (11,388,424 B) is a *different, smaller* build and was **not** opened; it may reveal the server's own
  contract implementation and is a high-value follow-up.

