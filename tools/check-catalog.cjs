let s = '';
process.stdin.on('data', (d) => { s += d; });
process.stdin.on('end', () => {
  const j = JSON.parse(s);
  const d = j.data || {};
  const rows = d.pageData || d.list || [];
  console.log('total:', d.total, 'rows:', rows.length);
  for (const r of rows) console.log(' -', r.deviceCode, '|', r.deviceName, '| status=' + r.status, '| deviceStatus=' + r.deviceStatus, '| online=' + r.online);
});
