// ===== E-129: P1 residual REST coverage (REA report ses_e45812db8ffe07Z4sg36E7wf46) =====
// 32 P1 literals (login/password-recovery, domain/license, server status,
// alarm-host, monitor URIs, p2p) with the descriptor keys the client validates
// (IsKeyValid) so no ErrorId 3101 toast. Same multi-root registration as E-127.
import { urlsFor, DEFAULT_DATA } from './e127-p0-coverage.js';

// base path (no leading slash, no trailing slash) -> payload data
const P1 = {
  // login / password recovery (DPSDK 0x0C7CBB8-0x0C7D2B8, 0x0C9DC38, 0x0C967F0)
  'account/security/password/forgot/guide': { ...DEFAULT_DATA, guide: '', steps: [], retrieveWays: [] },
  'account/mail/verify/code/generate': { ...DEFAULT_DATA, success: true, sendResult: '1', verifyCode: '' },
  'account/mail/verify/code/check': { ...DEFAULT_DATA, success: true, verifyCode: '', checked: '1' },
  'account/security/password/retrieve-by-mail': { ...DEFAULT_DATA, success: true, retrieveWays: [], mailServiceReady: '0' },
  'account/security/question/answer': { ...DEFAULT_DATA, success: true, unlockRemainTime: '0' },
  'account/security/question/reset': { ...DEFAULT_DATA, success: true },
  'account/security/password/retrieve': { ...DEFAULT_DATA, success: true, newPassword: '', retrieveWays: [] },
  'account/authorize/password/change': { ...DEFAULT_DATA, success: true, oldPassword: '0', newPassword: '' },
  'accounts/client/data': { ...DEFAULT_DATA, randomKey: '', deviceTypeName: '', protocolTypeName: '' },
  // domain / license (0x0C9C668-0x0CA5270)
  'domain': { ...DEFAULT_DATA, orgs: [], list: [], results: [], orgCode: '', parentCode: '', parentName: '', isParent: '0' },
  'domain/page': { ...DEFAULT_DATA, pageData: [], orgs: [] },
  'license': { ...DEFAULT_DATA, licenseKey: '', licenseKeys: [], oldLicenseKeys: [], expireTime: '', expireRemainDays: '0', activeUrl: '', secretKey: '', keyCode: '' },
  'license/active': { ...DEFAULT_DATA, success: true, licenseKey: '', expireTime: '', expireRemainDays: '0' },
  'license/care/active': { ...DEFAULT_DATA, success: true, careKeys: [], careRemainDays: '0', exceedItems: [] },
  // server status / home (0x0C919E8-0x0CA6328)
  'server/allServiceStatus': { ...DEFAULT_DATA, serverStatus: '1', serviceStatus: [], subServerIds: [], backupServerIds: [], switchType: '0' },
  'server/functions': { ...DEFAULT_DATA, functionCodes: [], frameInfos: [], msgNum: '0' },
  'server/pic/list': { ...DEFAULT_DATA, list: [], results: [], detectionImageUrl: '' },
  'server/page': { ...DEFAULT_DATA, pageData: [], list: [] },
  'server/switch': { ...DEFAULT_DATA, success: true, switchType: '0', sourceServerId: '', targetServerId: '' },
  'server/main/server-name': { ...DEFAULT_DATA, serverName: 'BRMS-LAB', registerIp: '', enableEdit: '0' },
  // alarm-host / alarm config (0x0C82628-0x0C846C8)
  'alarmHosts/config': { ...DEFAULT_DATA, alarmConfigurations: [], alarmCount: '0', minTime: '', maxTime: '' },
  'alarm-host/device/area/fetch/batch/list': { ...DEFAULT_DATA, list: [], results: [], items: [] },
  'alarm-host/device/operate/batch': { ...DEFAULT_DATA, success: true, failedIds: [] },
  'alarm-host/alarm-out/channel/list': { ...DEFAULT_DATA, list: [], results: [], bindChannels: [] },
  'alarm-host/alarm-signal/channel/list': { ...DEFAULT_DATA, list: [], results: [], linkChannels: [] },
  'alarm-type/soft-trigger/list': { ...DEFAULT_DATA, list: [], results: [], alarmConfigurations: [] },
  'alarm/combination/rule/list': { ...DEFAULT_DATA, list: [], results: [] },
  'config/alarm/handle/comment': { ...DEFAULT_DATA, success: true },
  // monitor URIs (0x0C963F0-0x0C90898)
  'realmonitor/uri': { ...DEFAULT_DATA, uri: '', url: '' },
  'playback/uri': { ...DEFAULT_DATA, uri: '', url: '' },
  'capture/getCaptureChnByUserId': { ...DEFAULT_DATA, list: [], results: [] },
  'resource/videoRealation': { ...DEFAULT_DATA, list: [], results: [] },
  // p2p (0x0C81358, 0x0C97C78)
  'p2p/info': { ...DEFAULT_DATA, connectType: '0', p2pStatus: '0', status: '0', serverCode: '', globalStatus: '0' },
  'p2p/connect-type': { ...DEFAULT_DATA, connectType: '0', p2pStatus: '0', status: '0', serverCode: '', globalStatus: '0' }
};

export function registerP1Coverage(app, envelope) {
  let added = 0, skipped = 0;
  for (const [p, data] of Object.entries(P1)) {
    for (const url of urlsFor(p)) {
      const variants = p.endsWith('/') ? [url + '/:id', url] : [url];
      for (const u of variants) {
        for (const method of ['GET', 'POST']) {
          try {
            app[method.toLowerCase()](u, async () => envelope(data));
            added++;
          } catch { skipped++; }
        }
      }
    }
  }
  console.log(`[E129-P1] registered=${added} skipped(dup/conflict)=${skipped}`);
}
