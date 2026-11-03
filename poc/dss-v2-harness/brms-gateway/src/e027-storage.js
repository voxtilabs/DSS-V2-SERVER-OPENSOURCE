// ===== E-027: STORAGE PLAN / SS RECORD CONTRACT =====
//
// Routes served for the Storage Plan tab (menuCode 003005), built from the
// production bundle evidence (real-useDeviceApi.js) and the SSRecordController
// contract (EV-037). Channel plan-config default is "not configured"; when the
// operator sets a plan the usable template is stored per channelCode.

// channelId -> plan template. A plan keeps the day-of-week schedule and the
// recording mode used by NVMS/Playback (NORMAL_RECORD "1", MOTION_DETECTION "83").
const CHANNEL_PLANS = new Map();

// E-029: the Storage Plan LIST pages (record-plan/page and
// motion-detection-record-plan/page) enumerate the plans that actually exist -
// nothing is invented, an unconfigured channel simply is not in the list.
export function listChannelPlans(kind) {
  const rows = [];
  for (const [channelId, plan] of CHANNEL_PLANS) {
    if (plan?.kind && plan.kind !== kind) continue;
    rows.push({
      id: plan.id || `${channelId}-${kind}`,
      channelId,
      channelCode: channelId,
      channelName: plan.channelName || channelId,
      deviceCode: plan.deviceCode || channelId.split('$')[0],
      deviceName: plan.deviceName || '',
      orgCode: plan.orgCode || '001',
      orgName: plan.orgName || 'Current Site',
      position: plan.position ?? '1',
      code: plan.code,
      name: plan.name || '24x7 schedule',
      streamType: plan.streamType ?? 1,
      recordType: plan.recordType ?? 1,
      enable: plan.enable ?? 1,
      remark: plan.remark || '',
      kind: plan.kind || kind
    });
  }
  return rows;
}

// E-029: the tree/table label for the storage position filter (1 central, 2 device).
export const STORAGE_POSITION_NAMES = { '1': 'Central Storage', '2': 'Device Storage' };

function planTemplate(prefix) {
  // Default template: 24x7 normal recording; enableWeekday/days flags per slice.
  const period = [];
  for (let i = 0; i < 7; i++) {
    period.push({ weekday: String(i + 1), enable: 1, timeSlices: [{ timeSliceStart: '00:00:00', timeSliceEnd: '23:59:59' }] });
  }
  return {
    code: `${prefix}-PLAN-DEFAULT`,
    name: '24x7 schedule',
    enable: 1,
    planPeriod: period,
    planWeekDays: [1, 2, 3, 4, 5, 6, 7],
    recordType: 1,
    streamType: 0,
    scheduleType: 0
  };
}

// The SPA batch-asks which channels have any plan configured:
// POST /brms/api/v1.1/storage/plan/channel/plan-config-status/fetch/batch/list
export function buildPlanConfigStatusPayload(body = {}) {
  const inputs = Array.isArray(body.channels) ? body.channels
    : Array.isArray(body.channelIds) ? body.channelIds
      : Array.isArray(body.list) ? body.list
        : (body.channelId ? [body.channelId] : []);
  const items = inputs.map((c) => {
    const id = typeof c === 'object' ? (c.channelId || c.code || c) : c;
    const configured = CHANNEL_PLANS.has(id);
    return {
      channelId: id,
      channelCode: id,
      configured,
      status: configured ? 1 : 0,
      configStatus: configured ? 1 : 0,
      errorMessage: ''
    };
  });
  const results = items.length ? items
    : [...CHANNEL_PLANS.keys()].map((id) => ({ channelId: id, channelCode: id, configured: true, status: 1, configStatus: 1, errorMessage: '' }));
  return { results, list: results, items, total: results.length };
}

// GET/PUT /brms/api/v1.{0,1}/storage/plan/channel/{channelCode}/new-device-record-plan
export function getChannelRecordPlan(channelCode) {
  const tpl = CHANNEL_PLANS.get(channelCode) || planTemplate(channelCode || 'CH');
  return {
    channelId: channelCode,
    channelCode,
    ...tpl
  };
}

export function setChannelRecordPlan(channelCode, body = {}) {
  const prev = CHANNEL_PLANS.get(channelCode);
  const tpl = { ...(prev || planTemplate(channelCode || 'CH')), ...body, channelId: channelCode, channelCode };
  CHANNEL_PLANS.set(channelCode, tpl);
  return getChannelRecordPlan(channelCode);
}

// POST /brms/api/v1.0/SS/Record/QueryRecord  (RequestInfo<RecordQueryXo>)
export function buildSSQueryRecordPayload(body = {}) {
  const xo = body.data || body.xo || body;
  const keyword = xo.keyword || '';
  const self = new Date().toISOString();
  const channelId = o1(xo.channelId) || o1(xo.channelCode) || '';
  return {
    desc: 'Success',
    total: 0,
    results: [],
    list: [],
    items: [],
    pageNo: Number(xo.pageNo) || 1,
    pageSize: Number(xo.pageSize) || 30,
    recordingTimeList: [],
    statisticsList: [],
    channelId,
    keyword,
    createTime: self
  };
}
function o1(v) { return v == null ? '' : String(v); }

// Start/Stop/Lock/Unlock/Delete Record — plain success contracts.
export function buildSSRecordActionPayload() {
  return { desc: 'Success', success: true, results: [] };
}
