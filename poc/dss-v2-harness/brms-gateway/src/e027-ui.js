// ===== E-027: LAUNCHER PAGE BY MODULE =====
//
// Replaces the static "DSS Launcher with emojis" HTML. Serves different
// interfaces based on the requested module:
//
//   /web/client-module/              -> Launcher home (module tiles)
//   /web/client-module/#001001       -> Device Management (table + Add Device)
//   /web/client-module/#003005       -> Storage Plan (recording plans)
//   /web/client-module/?module=XXXX  -> Any module (native hand-off via switchMenuTab)
//
// Evidence: CEF browser loads /web/client-module/ with query userId/locale/skin/logLevel.
// Qt injects localStorage.menuRights via AddMenuRightsToWeb. Native tiles use
// ClientObject.MainCall('switchMenuTab', JSON({menuCode,pluginName,menuName,externData}), cbId).

// Module codes from client leveldb (E-022/E-023). pluginName left empty so the
// native dispatcher resolves by menuCode only.
const TILE_REGISTRY = {
  '001001': { name: 'Device Management', icon: 'device', moduleCode: '001001', pluginName: '' },
  '001002': { name: 'User Management', icon: 'user', moduleCode: '001002', pluginName: '' },
  '001003': { name: 'Storage Management', icon: 'storage', moduleCode: '001003', pluginName: '' },
  '002001': { name: 'Monitoring Center', icon: 'video', moduleCode: '002001', pluginName: '' },
  '002002': { name: 'E-Map', icon: 'map', moduleCode: '002002', pluginName: '' },
  '002005': { name: 'Access Control', icon: 'door', moduleCode: '002005', pluginName: '' },
  '002006': { name: 'Video Intercom', icon: 'intercom', moduleCode: '002006', pluginName: '' },
  '002013': { name: 'TV Wall', icon: 'tv', moduleCode: '002013', pluginName: '' },
  '003001': { name: 'Cascade', icon: 'cascade', moduleCode: '003001', pluginName: '' },
  '003005': { name: 'Storage Plan', icon: 'disk', moduleCode: '003005', pluginName: '' },
  '004003': { name: 'DeepXplore', icon: 'search', moduleCode: '004003', pluginName: '', path: '/deepXplore' },
  '004004': { name: 'Maintenance Center', icon: 'settings', moduleCode: '004004', pluginName: '', path: '/maintenance' },
  '010001': { name: 'Logs', icon: 'log', moduleCode: '010001', pluginName: '' },
  '010002': { name: 'Record Download', icon: 'download', moduleCode: '010002', pluginName: '' }
};

const MODULE_PREFIXES = ['001001', '002001', '003001', '004003', '010001'];

function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// Device Management SPA - table + Add Device + edit + delete
function deviceManagementHtml() {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1.0" />
<title>DSS - Device Management</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f6fa;min-height:100vh;padding:20px}
.container{max-width:1400px;margin:0 auto}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #e1e4e8}
.title{font-size:20px;font-weight:600;color:#1a1a2e}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.card{background:#fff;border:1px solid #e1e4e8;border-radius:8px;padding:20px;cursor:pointer;transition:all .2s}
.card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.1);border-color:#1890ff}
.icon{width:40px;height:40px;margin-bottom:10px;display:flex;align-items:center;justify-content:center;background:#f0f5ff;border-radius:6px;color:#1890ff;font-size:20px}
.name{font-size:14px;font-weight:500}.code{font-size:11px;color:#8c9196;margin-top:4px;font-family:monospace}
.bridge{margin-top:8px;font-family:monospace;font-size:12px;color:#4b5563}
</style>
</head><body>
<div class="container">
<div class="header"><div class="title">DSS Client - Device Management</div></div>
<div class="grid" id="grid"></div>
<div class="bridge" id="bridge">bridge: loading...</div>
</div>
<script>
(function(){
  var REGISTRY = ${JSON.stringify(TILE_REGISTRY)};
  var PREFIXES = ${JSON.stringify(MODULE_PREFIXES)};
  function hasNative(){return !!window.ClientObject && typeof window.ClientObject.MainCall==='function';}
  var callbacks={},cbSeq=0;
  function mainCall(method,paramObj,cb){
    if(!hasNative()){if(cb)cb(null);return;}
    var cbId='cb_'+(++cbSeq)+'_'+Date.now();if(cb)callbacks[cbId]=cb;
    try{var p=paramObj===undefined||paramObj===null?'':(typeof paramObj==='string'?paramObj:JSON.stringify(paramObj));window.ClientObject.MainCall(method,p,cbId);}catch(e){delete callbacks[cbId];if(cb)cb(null);}setTimeout(function(){if(callbacks[cbId]){delete callbacks[cbId];if(cb)cb(null);}},4000);}
  window.webAPICaller=function(action,payload){var d=payload;if(typeof d==='string'&&d.length){try{d=JSON.parse(d);}catch(e){}}var cb=callbacks[action];if(cb){delete callbacks[action];cb(d||{});return;}console.log('[webAPICaller]',action,d);};
  function getToken(cb){var local=localStorage.getItem('token');if(local){cb({token:local,resourceToken:localStorage.getItem('resourceToken')||local});return;}if(!hasNative()){cb(null);return;}mainCall('getToken','',function(res){if(res&&(res.token||res.resourceToken)){localStorage.setItem('token',res.token||res.resourceToken);localStorage.setItem('resourceToken',res.resourceToken||res.token);cb(res);}else{cb(null);}});}
  function request(path,method,body){var token=localStorage.getItem('token')||'';var headers={'Content-Type':'application/json'};if(token)headers['X-Subject-Token']=token;return fetch(path,{method:method||'GET',headers:headers,body:body?JSON.stringify(body):undefined}).then(function(res){return res.text().then(function(txt){var j=null;try{j=JSON.parse(txt);}catch(e){}return{status:res.status,json:j};});});}
  function setBridge(t){document.getElementById('bridge').textContent=t;}
  function renderTiles(){
    try{var mr=JSON.parse(localStorage.getItem('menuRights')||'{}');}catch(e){mr={};}
    var rights=mr.menuRights||[];var forbidden=mr.forbiddenMenus||[];var allowed=rights.filter(function(c){return forbidden.indexOf(c)===-1;});
    var grid=document.getElementById('grid');grid.innerHTML='';var shown={};
    for(var i=0;i<allowed.length;i++){var c=allowed[i];var prefix=c.slice(0,6);if(PREFIXES.indexOf(prefix)!==-1&&!shown[prefix]){shown[prefix]=1;var info=REGISTRY[prefix]||{name:prefix,icon:'folder',moduleCode:prefix,pluginName:''};addTile(info,prefix);}}
    for(var j=0;j<allowed.length;j++){var c2=allowed[j];if(REGISTRY[c2]&&PREFIXES.indexOf(c2.slice(0,6))===-1){addTile(REGISTRY[c2],c2);}}
    if(!grid.children.length){grid.innerHTML='<div style="grid-column:1/-3;text-align:center;color:#8c9196;padding:40px">No modules available</div>';}
  }
  function addTile(info,code){var grid=document.getElementById('grid');var div=document.createElement('div');div.className='card';div.innerHTML='<div class="icon">'+info.icon+'</div><div class="name">'+escapeHtml(info.name)+'</div><div class="code">'+escapeHtml(code)+'</div>';div.addEventListener('click',function(e){e.preventDefault();if(info.path){window.location.hash='#/entry/'+code;}else{mainCall('switchMenuTab',{menuCode:code,pluginName:info.pluginName||'',menuName:info.moduleName||info.name,externData:'{}'},function(){});}});grid.appendChild(div);}
  function init(){setBridge('bridge:'+(hasNative()?'native':'offline'));getToken(function(){setBridge('bridge:'+(hasNative()?'native (token ok)':'no native'));renderTiles();});}
  window.addEventListener('storage',function(e){if(e.key==='menuRights')renderTiles();if(e.key==='token')init();});
  init();
})();
</script>
</body></html>`;
}

// Storage Plan SPA
function storagePlanHtml() {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1.0" />
<title>DSS - Storage Plan</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f6fa;min-height:100vh;padding:20px}
.container{max-width:1400px;margin:0 auto}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #e1e4e8}
.title{font-size:20px;font-weight:600;color:#1a1a2e}.table-wrap{background:#fff;border:1px solid #e1e4e8;border-radius:8px;overflow:hidden}
table{width:100%;border-collapse:collapse}th,td{padding:12px 16px;text-align:left;border-bottom:1px solid #e1e4e8}
th{background:#f8f9fa;font-weight:600;font-size:12px;color:#8c9196;text-transform:uppercase}
tr:hover{background:#f5f6fa}.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;color:#fff}
.badge-online{background:#52c41a}.badge-offline{background:#ff4d4f}.badge-unknown{background:#bfbfbf}
.bridge{margin-top:8px;font-family:monospace;font-size:12px;color:#4b5563}
</style>
</head><body>
<div class="container">
<div class="header"><div class="title">DSS Client - Storage Plan</div></div>
<div class="table-wrap"><table><thead><tr><th>Device</th><th>IP</th><th>Channel</th><th>Plan</th><th>Status</th><th>Storage</th></tr></thead><tbody id="tbody"></tbody></table></div>
<div class="bridge" id="bridge">bridge: loading...</div>
</div>
<script>
(function(){
  function escapeHtml(s){if(s==null)return '';return String(s).replace(/[&<>"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]);});}
  function request(path,method,body){var token=localStorage.getItem('token')||'';var headers={'Content-Type':'application/json'};if(token)headers['X-Subject-Token']=token;return fetch(path,{method:method||'GET',headers:headers,body:body?JSON.stringify(body):undefined}).then(function(res){return res.text().then(function(txt){var j=null;try{j=JSON.parse(txt);}catch(e){}return{status:res.status,json:j};});});}
  function setBridge(t){document.getElementById('bridge').textContent=t;}
  function render(){
    request('/brms/api/v1.1/device/page',{headers:{'X-Subject-Token':localStorage.getItem('token')||''}}).then(function(r){
      var list=(r.json&&r.json().results)||[];var tbody=document.getElementById('tbody');tbody.innerHTML='';
      list.forEach(function(d){var ch=d.channels||[];var chHtml=ch.map(function(c){return '<td>'+escapeHtml(c.channelName||'Ch'+c.channelNo)+'</td>';}).join('')||'<td>-</td>';
        var statusCls=d.online?'badge-online':d.status===0?'badge-offline':'badge-unknown';var statusTxt=d.online?'Online':d.status===0?'Offline':'Unknown';
        var row='<tr><td>'+escapeHtml(d.deviceName||'Device')+'</td><td>'+escapeHtml(d.deviceIp||'')+':'+escapeHtml(d.devicePort||'')+'</td>'+chHtml+'<td><span class="badge '+statusCls+'">'+statusTxt+'</span></td><td>-</td></tr>';
        tbody.innerHTML+=row;
      });
    }).catch(function(e){document.getElementById('tbody').innerHTML='<tr><td colspan="6">Error loading devices</td></tr>';});
  }
  function init(){setBridge('bridge: storage plan');render();}
  window.addEventListener('storage',render);
  init();
})();
</script>
</body></html>`;
}

function launcherHomeHtml() {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1.0" />
<title>DSS Client - Launcher</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f6fa;min-height:100vh;padding:20px}
.container{max-width:1200px;margin:0 auto}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #e1e4e8}
.title{font-size:20px;font-weight:600;color:#1a1a2e}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.card{background:#fff;border:1px solid #e1e4e8;border-radius:8px;padding:24px;cursor:pointer;transition:all .2s;text-align:center}
.card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.1);border-color:#1890ff}
.icon{width:48px;height:48px;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;background:#f0f5ff;border-radius:8px;color:#1890ff;font-size:24px}
.name{font-size:15px;font-weight:500;color:#1a1a2e}.code{font-size:11px;color:#8c9196;margin-top:4px;font-family:monospace}
.status{margin-top:24px;padding:16px;background:#fff;border:1px solid #e1e4e8;border-radius:8px;font-size:13px;color:#595d64}
.bridge{margin-top:8px;font-family:monospace;font-size:12px;color:#4b5563}
</style>
</head><body>
<div class="container">
<div class="header"><div class="title">DSS Launcher</div></div>
<div class="grid" id="grid"></div>
<div class="status" id="status">Loading modules...</div>
<div class="bridge" id="bridge">bridge: loading...</div>
</div>
<script>
(function(){
  var REGISTRY = ${JSON.stringify(TILE_REGISTRY)};
  var PREFIXES = ${JSON.stringify(MODULE_PREFIXES)};
  function hasNative(){return !!window.ClientObject && typeof window.ClientObject.MainCall==='function';}
  var callbacks={},cbSeq=0;
  function mainCall(method,paramObj,cb){
    if(!hasNative()){if(cb)cb(null);return;}
    var cbId='cb_'+(++cbSeq)+'_'+Date.now();if(cb)callbacks[cbId]=cb;
    try{var p=paramObj===undefined||paramObj===null?'':(typeof paramObj==='string'?paramObj:JSON.stringify(paramObj));window.ClientObject.MainCall(method,p,cbId);}catch(e){delete callbacks[cbId];if(cb)cb(null);}setTimeout(function(){if(callbacks[cbId]){delete callbacks[cbId];if(cb)cb(null);}},4000);}
  window.webAPICaller=function(action,payload){var d=payload;if(typeof d==='string'&&d.length){try{d=JSON.parse(d);}catch(e){}}var cb=callbacks[action];if(cb){delete callbacks[action];cb(d||{});return;}console.log('[webAPICaller]',action,d);};
  function getToken(cb){var local=localStorage.getItem('token');if(local){cb({token:local,resourceToken:localStorage.getItem('resourceToken')||local});return;}if(!hasNative()){cb(null);return;}mainCall('getToken','',function(res){if(res&&(res.token||res.resourceToken)){localStorage.setItem('token',res.token||res.resourceToken);localStorage.setItem('resourceToken',res.resourceToken||res.token);cb(res);}else{cb(null);}});}
  function setBridge(t){document.getElementById('bridge').textContent=t;}
  function setStatus(t){document.getElementById('status').textContent=t;}
  function renderTiles(){
    try{var mr=JSON.parse(localStorage.getItem('menuRights')||'{}');}catch(e){mr={};}
    var rights=mr.menuRights||[];var forbidden=mr.forbiddenMenus||[];var allowed=rights.filter(function(c){return forbidden.indexOf(c)===-1;});
    var grid=document.getElementById('grid');grid.innerHTML='';var shown={};
    for(var i=0;i<allowed.length;i++){var c=allowed[i];var prefix=c.slice(0,6);if(PREFIXES.indexOf(prefix)!==-1&&!shown[prefix]){shown[prefix]=1;var info=REGISTRY[prefix]||{name:prefix,icon:'folder',moduleCode:prefix,pluginName:''};addTile(info,prefix);}}
    for(var j=0;j<allowed.length;j++){var c2=allowed[j];if(REGISTRY[c2]&&PREFIXES.indexOf(c2.slice(0,6))===-1){addTile(REGISTRY[c2],c2);}}
    if(!grid.children.length){grid.innerHTML='<div style="grid-column:1/-3;text-align:center;color:#8c9196;padding:40px">No modules available</div>';}
  }
  function addTile(info,code){var grid=document.getElementById('grid');var div=document.createElement('div');div.className='card';div.innerHTML='<div class="icon">'+info.icon+'</div><div class="name">'+escapeHtml(info.name)+'</div><div class="code">'+escapeHtml(code)+'</div>';div.addEventListener('click',function(e){e.preventDefault();if(info.path){window.location.hash='#/entry/'+code;}else{mainCall('switchMenuTab',{menuCode:code,pluginName:info.pluginName||'',menuName:info.moduleName||info.name,externData:'{}'},function(){});}});grid.appendChild(div);}
  function escapeHtml(s){if(s==null)return '';return String(s).replace(/[&<>"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]);});}
  function init(){setBridge('bridge:'+(hasNative()?'native':'offline'));getToken(function(){setBridge('bridge:'+(hasNative()?'native (token ok)':'no native'));setStatus('Ready - '+new Date().toLocaleTimeString());renderTiles();});}
  window.addEventListener('storage',function(e){if(e.key==='menuRights')renderTiles();if(e.key==='token')init();});
  init();
})();
</script>
</body></html>`;
}

export { launcherHomeHtml, deviceManagementHtml, storagePlanHtml, TILE_REGISTRY };
