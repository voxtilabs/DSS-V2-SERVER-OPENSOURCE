// ===== E-025: LAUNCHER PAGE WITH THE REAL QT/CEF BRIDGE =====
//
// The launcher page is what the DSS Client renders in its embedded CEF browser
// (CefRender.exe + libcef). E-025 recovered the exact bridge from the shipped
// client - it is NOT `window.webAPICaller` (that is only the *inbound* half)
// and it is not any invented API:
//
//  1. CefRender.exe injects a V8 extension (found verbatim in its strings):
//       var ClientObject; if (!ClientObject) ClientObject = {};
//       (function () {
//         ClientObject.MainCall = function (method, param, callbackName) {
//           native function MainCall(method, param, callbackName);
//           return MainCall(method, param, callbackName);
//         };
//       })();
//     -> window.ClientObject.MainCall(method, param, callbackName)
//
//  2. web -> native param is a JSON *string* (the real app serializes it:
//     `d = null!=n && ""!==n ? gf(n) ? n : JSON.stringify(n) : ""`).
//
//  3. native -> web: `window.webAPICaller('<callbackName|action>', '<json>')`
//     (literal JS found in PluginFactory.dll / UICommonModule.dll strings:
//     "window.webAPICaller('%1','%2')"). The payload is a JSON string.
//
//  4. TOKEN: the production launcher ALWAYS asks the native for the token when
//     the URL carries none:
//       const l = nt(location.href); let c; l.token || (c = await be());
//       ke(token, l.token || c.token); ke(resourceToken, ...);
//     with `be` = getToken = blurringPromisifyClientApiCall("getToken") ->
//     ClientObject.MainCall('getToken', '', cbId) and the native replies
//     webAPICaller(cbId, {token, resourceToken}).
//     (E-024/E-022 pages only listened for a Qt push of `updateToken`, which
//     never happens on boot -> "init error ... 401 (token=no)").
//
//  5. MODULE HAND-OFF: a tile click calls the native module switcher
//     (PluginFactory.dll, CWebBusinessControl::OnMainCall -> "switchMenuTab",
//      parsing menuCode / pluginName / menuName / externData):
//       ClientObject.MainCall('switchMenuTab',
//         JSON.stringify({menuCode, pluginName, menuName, externData}), cbId)
//     Other native methods in the same dispatcher: openVedio, openRecord,
//     closeWebPage, addSite, delSite, clientCallback.
//
// This page registers window.webAPICaller itself (the real app only does it
// when window.top === window.self), so it works both inside the client and in
// a plain browser for verification.

// Menu codes below are the REAL 158-code set harvested from the client's
// leveldb cache (000003.ldb) and the client menu catalog (E-022/E-023).
const TILE_REGISTRY = {
  // 001000 - Resource Management (NATIVE QT PLUGINS - pluginName left empty
  // so the client native dispatcher resolves by menuCode only; invented
  // pluginNames made the client open the wrong module, e.g. IA instead of Device).
  '001001': { name: 'Device', icon: '\uD83D\uDDA5', moduleName: 'Device Management', moduleCode: '001001', pluginName: '' },
  '001002': { name: 'User', icon: '\uD83D\uDC64', moduleName: 'User Management', moduleCode: '001002', pluginName: '' },
  '001003': { name: 'Storage', icon: '\uD83D\uDCBE', moduleName: 'Storage Management', moduleCode: '001003', pluginName: '' },
  // 002000 - Monitoring Center
  '002001': { name: 'Monitoring Center', icon: '\uD83D\uDCF9', moduleName: 'Monitoring Center', moduleCode: '002001', pluginName: '' },
  '002002': { name: 'E-Map', icon: '\uD83D\uDDFA', moduleName: 'E-Map', moduleCode: '002002', pluginName: '' },
  '002003': { name: 'Base Info', icon: '\uD83D\uDCCB', moduleName: 'Base Info', moduleCode: '002003', pluginName: '' },
  '002004': { name: 'Control Library', icon: '\uD83D\uDCDA', moduleName: 'Control Library', moduleCode: '002004', pluginName: '' },
  '002005': { name: 'Access Control', icon: '\uD83D\uDEAA', moduleName: 'Access Control', moduleCode: '002005', pluginName: '' },
  '002006': { name: 'Video Intercom', icon: '\uD83D\uDCDE', moduleName: 'Video Intercom', moduleCode: '002006', pluginName: '' },
  '002007': { name: 'Attendance', icon: '\uD83D\uDCC5', moduleName: 'Attendance', moduleCode: '002007', pluginName: '' },
  '002008': { name: 'Visitor', icon: '\uD83D\uDC65', moduleName: 'Visitor Management', moduleCode: '002008', pluginName: '' },
  '002009': { name: 'Parking Lot', icon: '\uD83D\uDEB6', moduleName: 'Parking Lot', moduleCode: '002009', pluginName: '' },
  '002010': { name: 'Intelligence Analysis', icon: '\uD83E\uDDE0', moduleName: 'Intelligence Analysis', moduleCode: '002010', pluginName: '' },
  '002011': { name: 'Record Plan', icon: '\uD83D\uDCF9', moduleName: 'Record Plan', moduleCode: '002011', pluginName: '' },
  '002012': { name: 'Maintenance Config', icon: '\uD83D\uDD27', moduleName: 'Maintenance Config', moduleCode: '002012', pluginName: '' },
  '002013': { name: 'TV Wall', icon: '\uD83D\uDDA5', moduleName: 'TV Wall', moduleCode: '002013', pluginName: '' },
  '002015': { name: 'Visual Tracking', icon: '\uD83C\uDDAF', moduleName: 'Visual Tracking', moduleCode: '002015', pluginName: '' },
  // 003000 - System / Cascade
  '003001': { name: 'Cascade', icon: '\uD83D\uDD17', moduleName: 'Cascade', moduleCode: '003001', pluginName: '' },
  '003002': { name: 'License', icon: '\uD83D\uDCDC', moduleName: 'License', moduleCode: '003002', pluginName: '' },
  '003003': { name: 'System Config', icon: '\u2699', moduleName: 'System Config', moduleCode: '003003', pluginName: '' },
  '003004': { name: 'Backup', icon: '\uD83D\uDCBD', moduleName: 'Backup', moduleCode: '003004', pluginName: '' },
  '003005': { name: 'Third Party', icon: '\uD83D\uDD0C', moduleName: 'Third Party', moduleCode: '003005', pluginName: '' },
  // 004000 - Web modules (rendered inside the CEF page, no native hand-off)
  '004002': { name: 'Search Center', icon: '\uD83D\uDD0D', moduleName: 'Search Center', moduleCode: '004002', pluginName: '', path: '/deepXplore' },
  '004003': { name: 'DeepXplore', icon: '\uD83D\uDD2C', moduleName: 'DeepXplore', moduleCode: '004003', pluginName: '', path: '/deepXplore/explorer' },
  '004004': { name: 'Maintenance Center', icon: '\uD83D\uDEE0', moduleName: 'Maintenance Center', moduleCode: '004004', pluginName: '', path: '/maintenance' },
  '004005': { name: 'Access Center', icon: '\uD83C\uDFE2', moduleName: 'Access Center', moduleCode: '004005', pluginName: '', path: '/accessCenter' },
  '004006': { name: 'Entrance Center', icon: '\uD83D\uDEAA', moduleName: 'Entrance Center', moduleCode: '004006', pluginName: '', path: '/entranceCenter' },
  '004007': { name: 'Intelligence Center', icon: '\uD83E\uDDE0', moduleName: 'Intelligence Center', moduleCode: '004007', pluginName: '', path: '/intelligenceCenter' },
  '004008': { name: 'Face Recognition', icon: '\uD83D\uDC64', moduleName: 'Face Recognition', moduleCode: '004008', pluginName: '', path: '/faceRecognition' },
  // 010000 - Logs & Records
  '010001': { name: 'Logs', icon: '\uD83D\uDCDD', moduleName: 'Logs', moduleCode: '010001', pluginName: '' },
  '010002': { name: 'Record Download', icon: '\u2B07', moduleName: 'Record Download', moduleCode: '010002', pluginName: '' },
  // 011000 - Web Applications
  '011001': { name: 'Web Apps', icon: '\uD83C\uDF10', moduleName: 'Web Applications', moduleCode: '011001', pluginName: '', path: '/webApps' }
};

const MODULE_PREFIXES = ['001001', '002001', '003001', '004002', '010001', '011001'];

const PAGE = `<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>DSS Client - Launcher</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f6fa;min-height:100vh;padding:20px}
    .container{max-width:1200px;margin:0 auto}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #e1e4e8}
    .title{font-size:24px;font-weight:600;color:#1a1a2e}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
    .tile{background:#fff;border:1px solid #e1e4e8;border-radius:8px;padding:20px;cursor:pointer;transition:all .2s;display:flex;flex-direction:column;align-items:center;text-align:center}
    .tile:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.1);border-color:#1890ff}.icon{width:48px;height:48px;margin-bottom:12px;display:flex;align-items:center;justify-content:center;background:#f0f5ff;border-radius:8px;color:#1890ff;font-size:24px}.name{font-size:14px;font-weight:500}.code{font-size:11px;color:#8c9196;margin-top:4px;font-family:monospace}
    .status{margin-top:24px;padding:16px;background:#fff;border:1px solid #e1e4e8;border-radius:8px;font-size:13px;color:#595d64;white-space:pre-wrap}
    .bridge{margin-top:8px;font-family:monospace;font-size:12px;color:#4b5563}
  </style>
</head><body>
  <div class="container">
    <div class="header"><div class="title">DSS Launcher</div></div>
    <div class="grid" id="grid"></div>
    <div class="status" id="status">Loading modules...</div>
    <div class="bridge" id="bridge"></div>
  </div>
  <script>
  // ===== E-025: QT/CEF BRIDGE (evidence in e025-launcher-page.js) =====
  (function () {
    var REGISTRY = ${JSON.stringify(TILE_REGISTRY)};
    var PREFIXES = ${JSON.stringify(MODULE_PREFIXES)};

    // ---- native bridge detection (CefRender.exe injected ClientObject) ----
    function hasNative() {
      try {
        return !!window.ClientObject && typeof window.ClientObject.MainCall === 'function';
      } catch (e) { return false; }
    }

    var callbacks = {};
    var cbSeq = 0;

    // web -> native. param is a JSON string exactly like the real app sends.
    function mainCall(method, paramObj, cb) {
      if (!hasNative()) { if (cb) cb(null); return; }
      var cbId = 'cb_' + (++cbSeq) + '_' + Date.now();
      if (cb) callbacks[cbId] = cb;
      try {
        var param;
        if (paramObj === undefined || paramObj === null) param = '';
        else if (typeof paramObj === 'string') param = paramObj;
        else param = JSON.stringify(paramObj);
        window.ClientObject.MainCall(method, param, cbId);
      } catch (e) {
        console.log('[native] MainCall failed:', method, String(e));
        delete callbacks[cbId];
        if (cb) cb(null);
      }
      // A hung native call must never block the launcher.
      setTimeout(function () { if (callbacks[cbId]) { delete callbacks[cbId]; if (cb) cb(null); } }, 4000);
    }

    // ---- native -> web dispatcher (window.webAPICaller('%1','%2')) --------
    window.webAPICaller = function (action, payload) {
      var data = payload;
      if (typeof data === 'string' && data.length) {
        try { data = JSON.parse(data); } catch (e) { /* keep the raw string */ }
      }
      console.log('[webAPICaller]', action, data);
      var cb = callbacks[action];
      if (cb) {
        delete callbacks[action];
        cb(data || {});
        return;
      }
      handleNativeEvent(action, data || {});
    };

    function handleNativeEvent(action, data) {
      switch (action) {
        case 'updateToken':
        case 'updateSiteToken':
          if (data && (data.token || data.resourceToken)) {
            localStorage.setItem('token', data.token || data.resourceToken);
            localStorage.setItem('resourceToken', data.resourceToken || data.token);
          }
          break;
        case 'menuRightsChange':
          renderTiles();
          break;
        case 'devInfoChange':
        case 'devStateChange':
        case 'alarmMessage':
        case 'notifyClientState':
          console.log('[native event]', action, data);
          break;
        default:
          console.log('[unhandled native call]', action, data);
      }
    }

    // ---- token: ask the NATIVE first (real launcher contract), then retry --
    function getToken(cb) {
      var local = localStorage.getItem('token');
      if (local) {
        cb({ token: local, resourceToken: localStorage.getItem('resourceToken') || local });
        return;
      }
      if (!hasNative()) { cb(null); return; }
      setStatus('Waiting for the client token (native getToken)...');
      mainCall('getToken', '', function (res) {
        if (res && (res.token || res.resourceToken)) {
          localStorage.setItem('token', res.token || res.resourceToken);
          localStorage.setItem('resourceToken', res.resourceToken || res.token);
          if (res.language) localStorage.setItem('language', res.language);
          if (res.userId) localStorage.setItem('userId', res.userId);
          if (res.skin) localStorage.setItem('skin', res.skin);
          if (res.displaytimezone) localStorage.setItem('displaytimezone', res.displaytimezone);
          cb(res);
        } else {
          cb(null);
        }
      });
    }

    function setStatus(text) { document.getElementById('status').textContent = text; }
    function setBridge(text) { document.getElementById('bridge').textContent = text; }

    function request(path, method, body) {
      var token = localStorage.getItem('token') || '';
      var headers = { 'Content-Type': 'application/json' };
      if (token) headers['X-Subject-Token'] = token;
      return fetch(path, { method: method || 'GET', headers: headers, body: body ? JSON.stringify(body) : undefined })
        .then(function (res) {
          return res.text().then(function (txt) {
            var json = null;
            try { json = JSON.parse(txt); } catch (e) { /* non-JSON */ }
            return { status: res.status, json: json };
          });
        });
    }

    function init() {
      setBridge('bridge: ' + (hasNative() ? 'native (ClientObject.MainCall)' : 'offline (no ClientObject)'));
      getToken(function (token) {
        var hasToken = !!(token && (localStorage.getItem('token') || '').length);
        if (!hasToken) {
          setStatus('No token available yet. The client will push updateToken after login; modules will refresh automatically.\\nBridge: ' + (hasNative() ? 'native' : 'browser'));
          renderTiles();
          return;
        }
        // E-025: GET tree routes now exist (they used to 404 -> fallback).
        request('/brms/api/v1.0/tree/orgs', 'GET')
          .then(function () { return request('/brms/api/v1.0/tree/devices', 'GET'); })
          .then(function () { return request('/brms/api/v1.0/tree/channels', 'GET'); })
          .then(function () { return request('/brms/api/v1.0/accounts/current', 'GET'); })
          .then(function () {
            setStatus('Ready - ' + new Date().toLocaleTimeString() + ' (token present)');
            renderTiles();
          })
          .catch(function (e) {
            setStatus('Bootstrap incomplete: ' + (e && e.message ? e.message : e) + ' (token=' + (hasToken ? 'yes' : 'no') + ')');
            renderTiles();
          });
      });
    }

    function parseMenuRights() {
      try { return JSON.parse(localStorage.getItem('menuRights')) || {}; }
      catch (e) { return {}; }
    }

    function renderTiles() {
      var mr = parseMenuRights();
      var rights = mr.menuRights || [];
      var forbidden = mr.forbiddenMenus || [];
      var allowed = rights.filter(function (c) { return forbidden.indexOf(c) === -1; });
      var grid = document.getElementById('grid');
      grid.innerHTML = '';
      var shown = {};
      var seen = {};
      for (var i = 0; i < allowed.length; i++) {
        var code = allowed[i];
        var prefix = code.slice(0, 6);
        if (PREFIXES.indexOf(prefix) !== -1 && !shown[prefix]) {
          shown[prefix] = 1;
          addTile(REGISTRY[prefix] || { name: prefix, icon: '\uD83D\uDCE6', moduleName: prefix, moduleCode: prefix, pluginName: '' }, prefix);
        }
      }
      for (var j = 0; j < allowed.length; j++) {
        var c2 = allowed[j];
        if (REGISTRY[c2] && PREFIXES.indexOf(c2.slice(0, 6)) === -1 && !seen[c2]) {
          seen[c2] = 1;
          addTile(REGISTRY[c2], c2);
        }
      }
      if (!grid.children.length) {
        grid.innerHTML = '<div style="grid-column:1/-3;text-align:center;color:#8c9196;padding:40px">No modules available (menuRights not injected by the client)</div>';
      }
    }

    // Native module hand-off: switchMenuTab (PluginFactory.dll OnMainCall).
    function switchMenuTab(info, code) {
      var payload = {
        menuCode: code,
        pluginName: info.pluginName || '',
        menuName: info.moduleName || info.name || '',
        externData: '{}'
      };
      console.log('[switchMenuTab]', JSON.stringify(payload));
      mainCall('switchMenuTab', payload, function () {});
    }

    function addTile(info, code) {
      var grid = document.getElementById('grid');
      var div = document.createElement('div');
      div.className = 'tile';
      div.innerHTML = '<div class="icon">' + info.icon + '</div><div class="name">' + info.name + '</div><div class="code">' + code + '</div>';
      div.addEventListener('click', function (e) {
        e.preventDefault();
        console.log('Tile clicked:', code, info);
        // Web modules (have a path) -> navigate inside the CEF page.
        // Native QT modules (no path) -> hand off to the client via
        // switchMenuTab with menuCode + menuName (pluginName left empty so
        // the native dispatcher resolves by menuCode; invented pluginNames
        // were opening the wrong module, e.g. IA instead of Device Config).
        if (info.path) {
          window.location.hash = '#/entry/' + code;
        } else {
          switchMenuTab(info, code);
        }
      });
      grid.appendChild(div);
    }

    window.addEventListener('storage', function (e) {
      if (e.key === 'menuRights') renderTiles();
      if (e.key === 'token') init();
    });

    init();
  })();
  <\/script></body></html>`;

export const LAUNCHER_PAGE_HTML = PAGE;
export default PAGE;
