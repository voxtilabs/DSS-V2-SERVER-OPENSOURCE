# E-160 — "Channel &lt;name&gt; No permissions of sub stream 1." — the exact client check

Target: `C:\DSS\DSS Client\PluginFactory.dll` (35,558,496 B, PE32+ x86-64, ImageBase **0x180000000**,
SHA-256 `5107e73e8bf6002355a000004206c5dce784ad9536ad0bfd00ead6d728a4f2a4`), read-only.
Method: PE section/`.pdata`/import/EAT parsing + Capstone linear disassembly (Ghidra import of the 35 MB
DLL exceeded the 330 s REA startup deadline; `.pdata` gives exact `RUNTIME_FUNCTION` bounds, so decompilation
was not required to recover the condition — see §8).

---

## 0. Answer in three lines

1. **Condition** — `MonitorUI::CEventInfoPreviewWnd::OpenPreview()` raises the toast when the caller asks for
   stream type **2** (= "Sub Stream 1") **and** the per-channel stream-availability integer held at
   `channelInfo + 0x160` is **< 2**. The sibling check for sub stream 2 is `< 3`.
   Both come from the client's own cached channel model, **not** from `MTS/Video.StartVideo`.
2. **Why StartVideo=1000 / `DPSDK_StartRealPlayEx`=0 changes nothing** — the check runs *before* the play call,
   and when it fails the client silently rewrites the stream type to **1 (main)** and plays anyway. The media
   layer therefore reports success while the tile shows the warning.
3. **What the server must send** — the channel node must declare the highest permitted stream as
   **1-based 1/2/3** (`1`=main only, `2`=+sub stream 1, `3`=+sub stream 2). In the channel-tree DTO that value
   is the **`streamType`** key, and the open-source gateway currently hard-codes `streamType: '1'`
   (§6). Set it to `"3"` (minimum `"2"`).

---

## 1. Locating the literal (file offset → VA)

| item | value |
|---|---|
| literal offset given | `26026032` = **0x18D2030** |
| section | `.rdata` (rawptr 0x181C600, RVA 0x181E000) |
| **VA** | **0x1818D3A30** (`0x180000000 + 0x18D3A30`) |
| SHA of that window | `No permissions of sub stream 1.\0` |

Bytes around it (`.rdata` string pool, `.` = NUL):

```
... LinkDefalut.png | CEventLinkInfoWnd | No permissions of sub stream 1. | %1 %2 %3 |
    No sub stream 2 permission. | OpenPreview Failed,Ret=%d ChannelId=%s |
    EventCenterUI::CEventLinkInfoWnd::OpenPreview |
    ...\code_path\APPCOMPO__8cce2e\src\EventCenterUI\UI\RealEvent\LinkMaterial\EventLinkInfoWnd.cpp
```

The `%1 %2 %3` right after it is the Qt `QString::arg` template used to build the toast
(`"Channel" + " " + <channelName> + " " + <message>`), which is exactly the string the operator sees.

## 2. All code references to the literal (5 copies, one per preview window class)

`lea r8,[0x1818D3A30]` sites (RIP-relative scan of `.text`), each inside a distinct `OpenPreview` clone:

| site VA | enclosing function (`.pdata`) |
|---|---|
| `0x1804376A0` | `0x1804374B0-0x180437C4B` (EventCenterUI path, has both toasts) |
| `0x1806A45D3` | `0x1806A4130-0x1806A47F6` |
| `0x18082BADF` | `0x18082B690-0x18082BDCE` |
| `0x181145760` | `0x181145470-0x181145C5C` |
| **`0x1811E922C`** | **`0x1811E9070-0x1811E953B`** = `MonitorUI::CEventInfoPreviewWnd::OpenPreview` |

`No sub stream 2 permission.` (VA `0x1818D3A68`) is referenced at `0x1804379AA`, `0x18082B98C`, `0x1811458AD`
— the same function family, one extra stream level.

Identity of the Monitoring Center copy is proven by its own log strings:

```
0x1811E9488  lea rax,[0x1818D3A90] "OpenPreview Failed,Ret=%d ChannelId=%s"
0x1811E94A1  lea r9, [0x181AEFE50] "MonitorUI::CEventInfoPreviewWnd::OpenPreview"
0x1811E94AE  lea rdx,[0x181AEFE90] "...\src\UI\MonitorUI\UI\EventInfoView\EventInfoPreviewWnd.cpp"
0x1811E94A8  mov r8d, 0x67                 ; __LINE__ 103
```

## 3. The function, decompiled by hand (0x1811E9070)

Signature (from the prologue and the tail call):

```c
int MonitorUI::CEventInfoPreviewWnd::OpenPreview(
        CInterfaceSetManager* self,   // rcx -> r15
        int      chIndex,             // edx -> r13d
        QString* channelId,           // r8  -> rsi
        int      streamType,          // r9d -> edi     <-- 1=main, 2=sub1, 3=sub2
        int      arg5)                // [rbp+0x2B0] -> r12d
```

Relevant part (annotated, addresses verbatim):

```c
  if (!self->mgr40) return -3;                                   // 0x1811E90B8
  IGroupManager* gm = self->mgr40->GetGroupManager();   // IAT 0x1821E51C8
  if (!gm) return -3;
  IUserManager*  um = self->mgr40->GetUserManager();    // IAT 0x1821E5350  (null-checked only)
  if (!um) return -3;
  gm->vfunc_0x18(&obj, arg5);                            // 0x1811E9100  -> obj at [rbp-0x40]
  if (!obj) return -3;                                   // 0x1811E910B
  if (!self->m?38) return -3;                            // 0x1811E9116
  ... build QString channelId ...

  if (streamType != 2) goto do_play;                     // 0x1811E9165  cmp edi,2 / jne 0x1811E93AC
  /* ---- sub stream 1 requested: ask the group model for the channel's stream info ---- */
  ChannelStreamInfo info;                                // 0x1811E916E, ctor 0x1800330CD, sizeof = 0x210
  int sz = 0x210;                                        // 0x1811E9178
  bool ok = obj->vfunc_0xD8(&channelIdQString, &info, &sz);   // 0x1811E91A6
  if (!ok)                    goto do_play;               // 0x1811E91EE  test bl,bl / je 0x1811E939C
  if (info.field_0x160 >= 2)  goto do_play;               // 0x1811E91F6  cmp [rbp+0x180],2 / jge 0x1811E939C
  /* ----------------------------  TOAST  ---------------------------- */
  msg  = QMetaObject::tr("Channel");                      // 0x1811E920B "Channel"
  perm = QMetaObject::tr("No permissions of sub stream 1.");   // 0x1811E922C
  text = QString("%1 %2 %3").arg(msg).arg(channelName).arg(perm);   // 0x1811E9256
  DSGUI::DSMessageNotify::Instance()
        .AddTextNotification(text, false, false, false);  // 0x1811E9358 (non-modal toast)
  streamType = 1;                                         // 0x1811E9375  mov edi,1
do_play:
  info dtor;                                              // 0x1811E93A3
  ... build request, then:
  ret = StartPlay(self->m?38, chIndex, name, streamType /*r9d*/, &str);   // 0x1811E9423 -> 0x18000F704
  if (ret) log("OpenPreview Failed,Ret=%d ChannelId=%s");  // 0x1811E946C..0x1811E94A1
  return ret;                                             // 0 success, 0xFFFFFFFD (-3) on early failures
```

`info` lives at `rbp+0x20`; the compared dword is at `rbp+0x180` ⇒ **`info + 0x160`**.

**Exact condition (sub stream 1):**

```
streamTypeRequested == 2                       // 0x1811E9165   (else the check is skipped entirely)
&& obj->GetChannelStreamInfo(channelId,&info,sizeof(info)) != false     // 0x1811E91A6
&& *(int*)((char*)&info + 0x160) < 2           // 0x1811E91F6   <-- the value the server controls
   -> toast "Channel <name> No permissions of sub stream 1." and play MAIN stream
```

**Exact condition (sub stream 2), same family at `0x180437976`:**

```
streamTypeRequested == 3 && *(int*)(info + 0x160) < 3
   -> toast "Channel <name> No sub stream 2 permission."
```

The `info` object is not a DPSDK JSON DTO (§5), it is the client's per-channel **graded** channel record
(`GroupLogical::GradeChnInfo`-style, 0x210 B) served by `IGroupManager` — i.e. the same data the
device/view tree was built from. That is why a correct `Video.StartVideo` (code 1000, full
`RealTimeVideoVo`) and `DPSDK_StartRealPlayEx()==0` do not affect it: the decision is taken from cached
tree data **before** the play call.

## 4. What the number 2 / 3 means (proof of the 1-based stream numbering)

`UICommonModule.dll`, label switch for the stream selector:

```
0x180712F55  cmp dword ptr [rsp+0x24], 2
0x180712F5A  jne 0x180712FE2
0x180712F7C  lea rdx,[0x1809F5278] "Sub Stream 1"
```

⇒ the client's internal stream type is **1 = Main Stream, 2 = Sub Stream 1, 3 = Sub Stream 2**
(the same file also holds `"Main Stream"`, `"Sub Stream 2"`, `"Select Stream"`). Therefore the field at
`+0x160` is the **number of streams available to this user for this channel**, equivalently "highest stream
type":

| `+0x160` | meaning | sub1 toast | sub2 toast |
|---|---|---|---|
| 1 | main only | **YES** | YES |
| 2 | main + sub stream 1 | no | **YES** |
| 3 | main + sub 1 + sub 2 | no | no |

The operator's symptom (toast on every click, tile still plays, `StartRealPlayEx` = 0) means the client is
holding **1** for the channel and falling back to main stream.

## 5. What does *not* feed it (ruled out explicitly)

* **`MTS/Video.StartVideo` / `RealTimeVideoVo`** — the check precedes the call; the response cannot make the
  toast disappear (`DPSDK_StartRealPlayEx`=0 is expected and irrelevant).
* **A DPSDK JSON DTO bound at offset 0x160** — exhaustively enumerated every field descriptor registered by
  DPSDK's schema registrar (`FUN_1807512d0`, 16 114 call sites): the only fields landing at `+0x160` in the
  whole SDK are `orgCode` / `domainId` / `lEdChannelCount`-style members of unrelated VOs. There is **no**
  `streamNum` / `subStreamNum` / `streamCount` / `*SubStream*` key anywhere in the client string pools
  (DPSDK.dll, PluginFactory.dll, UICommonModule.dll, MainFormPlugin.dll, CommonData.dll). So the value is
  computed by the client from the channel node it already has, not parsed from a bespoke counter field.
* **`DPSDK_*` return codes / function codes** — no function-code comparison exists on this path. The
  catalog codes (8 liveView, 17 livePreview …) gate *whether the channel appears at all*, not the stream level.

## 6. The channel-node field: `streamType` — exact JSON to return

The channel-tree DTO (`ChannelNodeVo`) is built by DPSDK descriptor `FUN_1806d3310`; its keys are

```
checked, capability, domainId, deviceType, deviceCapability, pId, status, channelRemoteType,
inputAlarmType, channelName, streamType, channelType, unitType, channelSubtype, orgCode,
channelId, deviceCategory, cameraType
```

`streamType` is the **only** per-channel stream datum that exists in the channel node, and it is exactly the
value the client needs to answer "may this user open sub stream 1/2". Today our gateway emits a constant
`'1'`:

* `poc/dss-v2-harness/brms-gateway/src/e029-spa-contracts.js:146` → `streamType: String(channel.streamType || '1')`
* `poc/dss-v2-harness/brms-gateway/src/e124-grade-tree.js:60` → `streamType: '1'`

⇒ every channel advertises "main stream only" ⇒ `+0x160 == 1` ⇒ **sub stream 1 toast on every click**.

**Required change** — one field, in every channel node of the device/view/grade tree (and of the channel
list VO), value as a **string** (all keys in this DTO are strings; a numeric JSON int does not bind):

```json
{
  "channelId": "1000013$1$0$0",
  "pId": "1000013",
  "channelName": "Camara 1",
  "unitType": "1",
  "channelType": "1",
  "channelSubtype": "0",
  "channelRemoteType": "0",
  "cameraType": "1",
  "checked": "1",
  "orgCode": "001001",
  "deviceType": "1",
  "deviceCategory": "1",
  "deviceCapability": "1024",
  "capability": "0",
  "status": "1",
  "domainId": "",
  "inputAlarmType": "",
  "streamType": "3"
}
```

* `"streamType": "3"` → main + sub stream 1 + sub stream 2 (no toast at any level). **This is the value to ship.**
* `"streamType": "2"` → clears the **sub stream 1** toast; the sub stream 2 toast would still fire.
* `"1"` (current) → both toasts; `"0"` → treated as "no stream".

Notes
* Value must be a **string** (`"3"`), consistent with every other key of `ChannelNodeVo` (E-095 lesson).
* Emit it in **all** node producers (`/brms/api/v1.1/tree/...`, `/monitor/view/view-tree` channel nodes,
  `BRMS.Tree.GetFullGradeDeviceTree`, search variants), otherwise the Monitoring Center may keep a cached
  copy with `"1"` after a partial refresh.
* If `streamType` is already `"3"` and the toast persists, the count is being derived from the number of
  declared sub streams instead (device record `channelNum` / `rtspUrls[]` with `streamType` `"0"`+`"1"`);
  in that case expose ≥ 2 entries in the channel's `rtspUrls` and 2 sub streams in the device/channel config.

### Decisive 60-second verification (no rebuild needed)

Hook the compare and read the integer the client actually holds:

```js
// frida -f DSSClient.exe -l chk.js
const M = Module.getBaseAddress('PluginFactory.dll');
Interceptor.attach(M.add(0x11E91F6), {           // cmp dword ptr [rbp+0x180], 2
  onEnter() { this.v = this.context.rbp.add(0x180).readS32(); },
  onLeave() { console.log('streamAvail =', this.v); }
});
```

Change only `streamType` on the wire (`"1"` → `"3"`), click the tile:
`streamAvail` must go `1 → 3` and the toast disappears. If `streamAvail` stays `1` while the JSON already
says `"3"`, the client cache is stale (relogin) or the field is not bound (wrong node/endpoint) — both are
visible with this hook alone.

## 7. The 394 duplicate device nodes (plausible mechanism, not proven in this pass)

394 = **2 × 197** — i.e. the two real channels repeated ~197 times each, which is the signature of an
**append-only tree plus repeated population**, not of per-stream node creation:

* The native tree never de-duplicates and never re-parents: `CreateChildItem` (`UICommonModule.dll`
  `0x1804F2200`) hangs **every** element of `organizations[]`/`devices[]`/`channels[]` as a direct child via
  `QStandardItem::appendRows` (already documented in `e124-grade-tree.js` §E-140). Duplicate `channelId`
  values in the payload ⇒ duplicate nodes, one per occurrence.
* Every `NotifyGroupManagerState` / `SignalNotifyGroupManagerState` / `HandleAddViewFloder` notification
  (device status, view-share, favourite) re-runs that population for the same channel set, so a server that
  repeats the same device/channel under several org nodes **or** pushes periodic notifications multiplies
  the visible entries. 2 channels × 197 repeats = 394.
* Mitigation mirrors E-140: scope each tree response to the requested `orgCode`, emit each `channelId` once,
  and do not list the same channel both in `channels[]` and in `windowData[]` of the view tree.

This is a hypothesis backed by the arithmetic and by the known append-without-dedupe behaviour; it was not
proven by a live capture in this pass.

## 8. Method, evidence trail and limitations

* `PluginFactory.dll` is 35 MB; REA's Ghidra import exceeded the 330 000 ms startup deadline (no OOM
  confirmed). Rizin/kuna are unavailable on this host (`capability_unavailable`), so the pass used:
  PE section table (`off→VA`), `.pdata` `RUNTIME_FUNCTION` merge (exact function bounds), `.idata` import
  resolution (gave `IGroupManager`/`IUserManager`, `QString`, `DSMessageNotify::AddTextNotification`,
  `DPrintLog::Log`) and Capstone 5.0.7 linear disassembly with RIP-target string annotation.
* Scratchpad scripts: `pe.py` (sections/off→VA), `pdx.py` (function disassembly + `.pdata`), `iat2.py`
  (IAT → `module!mangled_name`), `xrefkey.py` (string→code xrefs), `reg2.py` (DPSDK DTO field descriptors).
* Confidence: **condition, thresholds, argument gating, fallback-to-main and toast composition: certain**
  (read directly from code). **Value semantics (1/2/3, 1-based): certain** (label switch).
  **Identity of the server key as `streamType`: high but inferred** — the field is computed client-side from
  the cached channel node, and `streamType` is the only per-channel stream datum in that node; §6's Frida hook
  turns this into a measurement.
* Nothing under `C:\DSS` was modified; all artifacts were written to the session scratchpad.
