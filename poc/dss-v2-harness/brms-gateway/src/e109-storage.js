// ===== E-109: server list + storage endpoints (client FALLBACK hits) =======
//
// Live evidence (historical [FALLBACK] harvest, 2026-11-07): the real client
// requested these and they reached the generic catch-all:
//   GetServersList                -> v1.1/server/list            (@0xc913a8)
//   GetPageDeviceStoragePositionList -> v1.1/storage/position/device/page (@0xc991d5)
//   GetLocalDiskList              -> v1.1/storage/disk/local-disk/list (@0xc987cd)
//   GetNetDiskList                -> v1.1/storage/disk/net-disk/list   (@0xc9843d)
//   GetDiskGroupList              -> v1.1/storage/group/list    (@0xc98d75)
// (tree/orgs|devices|channels GET, system/network/list, config/ai/privacy,
// updateToken were historical FALLBACKs already fixed by E-025/E-107.)
//
// Shapes are supersets with STRING counters (E-095 lesson) and the devices
// come from the live registry, so the Storage pages list REAL rows instead
// of the benign catch-all envelope.

import { DEVICE_REGISTRY, allChannels } from './e025-devices.js';
import { deviceOrgCode, orgName } from './e041-orgs.js';
import fs from 'node:fs';

const LOCAL_SERVER_CODE = 'video#local';

function dataDir() {
  for (const d of ['/app/data', process.env.GATEWAY_DATA_DIR || '', '.'] ) {
    try { if (d && fs.existsSync(d)) return d; } catch { /* keep looking */ }
  }
  return '.';
}

// GetServersList: the video server that owns every device record. The client
// uses serverCode as the storage scope for the disk endpoints.
export function buildServerListPayload() {
  const list = [{
    serverCode: LOCAL_SERVER_CODE,
    serverName: 'Video Server',
    serverType: '1',
    ip: process.env.PUBLIC_HOST || '10.10.20.120',
    port: '9100',
    status: '1', online: '1', isOnline: '1',
    isLocal: '1', local: '1',
    deviceCount: String(DEVICE_REGISTRY.size),
    orgCode: '001',
    createTime: '2026-01-01 00:00:00', modifyTime: '2026-01-01 00:00:00'
  }];
  return {
    list, results: list, items: list, pageData: list, serverList: list,
    total: String(list.length), totalCount: String(list.length),
    pageNo: '1', pageSize: '100', pageCount: '1'
  };
}

// E-141: server/video/list (REA rea-media-path-noroute.md §5.3) is the main
// source of the client's TCP candidates. FUN_18025fdf0 expects per entry
// url[250] @+0x44 + ip[64] @+0x04 (stride 0x13a). The candidate MUST be the
// DSS/media server (same host as the login/StartVideo url => octet distance 0);
// never publish a camera IP here.
export function buildVideoServerListPayload() {
  const host = process.env.PUBLIC_HOST || '127.0.0.1';
  const rtspPort = process.env.RTSP_PORT || '9100';
  const httpsPort = process.env.HTTPS_PORT || '1443';
  const url = `rtsp://${host}:${rtspPort}`;
  const list = [{
    serverCode: LOCAL_SERVER_CODE,
    serverName: 'Video Server',
    ip: host,
    port: Number(rtspPort),
    portStr: String(rtspPort),
    httpsPort: Number(httpsPort),
    url,
    rtspUrl: url,
    status: '1', online: '1', isOnline: '1', serviceStatus: 'online',
    isLocal: '1', local: '1', locale: '', uiBufLen: '0'
  }];
  return {
    list, servers: list, results: list, items: list, pageData: list, serverList: list,
    serverCode: LOCAL_SERVER_CODE, serverName: 'Video Server', locale: '', uiBufLen: '0',
    total: String(list.length), totalCount: String(list.length),
    pageNo: '1', pageSize: '100', pageCount: '1'
  };
}

// GetPageDeviceStoragePositionList: devices with their storage/record state.
export function buildStoragePositionDevicePagePayload(query = {}) {
  const q = (k) => String(query?.[k] ?? '').trim();
  const page = Math.max(1, Number(q('page') || 1) || 1);
  const pageSize = Math.max(1, Number(q('pageSize') || 20) || 20);
  const kw = q('keyword').toLowerCase();
  let rows = [...DEVICE_REGISTRY.values()].filter((d) =>
    !kw || String(d.deviceName || '').toLowerCase().includes(kw) || String(d.deviceCode || '').toLowerCase().includes(kw));
  const total = rows.length;
  rows = rows.slice((page - 1) * pageSize, page * pageSize).map((d) => ({
    deviceCode: d.deviceCode, deviceId: d.deviceId || d.deviceCode, deviceName: d.deviceName,
    orgCode: deviceOrgCode(d), orgName: orgName(deviceOrgCode(d)),
    serverCode: d.serverCode || LOCAL_SERVER_CODE,
    channelNum: String(allChannels().filter((c) => c.deviceCode === d.deviceCode).length),
    recordStatus: '1', storagePosition: 'local', position: 'local',
    status: '1', online: d.online ? '1' : '0'
  }));
  return {
    pageData: rows, list: rows, results: rows, items: rows, deviceList: rows,
    total: String(total), totalCount: String(total),
    pageNo: String(page), page: String(page), pageSize: String(pageSize),
    pageCount: String(Math.max(1, Math.ceil(total / pageSize)))
  };
}

// GetLocalDiskList: the REAL data volume of the server (statfs on /app/data).
export function buildLocalDiskListPayload() {
  let totalKb = '0', freeKb = '0', usedKb = '0';
  try {
    const st = fs.statfsSync(dataDir());
    const total = Number(st.blocks) * Number(st.bsize) / 1024;
    const free = Number(st.bfree) * Number(st.bsize) / 1024;
    totalKb = String(Math.floor(total)); freeKb = String(Math.floor(free)); usedKb = String(Math.floor(total - free));
  } catch { /* volume unknown - honest zeros */ }
  const list = [{
    diskId: '1', diskCode: 'local-disk-1', diskName: 'Local Disk',
    serverCode: LOCAL_SERVER_CODE, diskType: 'local', type: 'local',
    status: '1', online: '1', isLocal: '1',
    totalSpace: totalKb, freeSpace: freeKb, usedSpace: usedKb,
    usedPercent: totalKb === '0' ? '0' : String(Math.floor((Number(usedKb) / Number(totalKb)) * 100)),
    path: dataDir(), createTime: '2026-01-01 00:00:00'
  }];
  return {
    list, results: list, items: list, diskList: list, localDiskList: list, pageData: list,
    total: String(list.length), totalCount: String(list.length),
    pageNo: '1', pageSize: '100', pageCount: '1'
  };
}

// GetNetDiskList: no network disks configured - explicit empty (not catch-all).
// E-112: the client's netDisk packet reads `abnormityType` (observed as
// "Invalid key: [abnormityType]") - carried at root for every row the client
// would materialize.
export function buildNetDiskListPayload() {
  return {
    list: [], results: [], items: [], diskList: [], netDiskList: [], pageData: [],
    abnormityType: '0',
    total: '0', totalCount: '0', pageNo: '1', pageSize: '100', pageCount: '1'
  };
}

// GetDiskGroupList: no disk groups configured - explicit empty.
export function buildDiskGroupListPayload() {
  return {
    list: [], results: [], items: [], groupList: [], diskGroupList: [], pageData: [],
    total: '0', totalCount: '0', pageNo: '1', pageSize: '100', pageCount: '1'
  };
}
