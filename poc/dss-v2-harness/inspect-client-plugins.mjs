// E-022 Objective 1: inspect DSS Client local plugin/menu configs and logs.
// Reports the module registry files + today's log lines with filter/permission hints.
// Usage: node inspect-client-plugins.mjs
import fs from 'node:fs';
import path from 'node:path';

const roots = [
  'C:/DSS/DSS Client',
  'C:/Users/bruno/AppData/Local/dahua',
];
const CONFIG_EXT = new Set(['.xml', '.ini', '.cfg', '.json']);
const today = new Date(); today.setHours(0, 0, 0, 0);

function walk(dir, depth = 0, out = []) {
  if (depth > 6) return out;
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name.startsWith('$')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, depth + 1, out);
    else out.push(p);
  }
  return out;
}

function head(s, n) { return s.length <= n ? s : s.slice(0, n) + `...(+${s.length - n})`; }

const all = roots.flatMap((r) => walk(r));
const cfg = all.filter((p) => CONFIG_EXT.has(path.extname(p).toLowerCase()) && fs.statSync(p).size < 40 * 1024 * 1024);

console.log('=== CONFIG FILES (name-keyword filtered) ===');
const kw = /(plugin|module|menu|function|license|client|service|config|atom|launcher)/i;
let shown = 0;
for (const p of cfg) {
  const rel = p.replace(/^C:\/(Users\/bruno\/)?/i, '');
  const want = kw.test(path.basename(p));
  if (!want) continue;
  let size = 0; try { size = fs.statSync(p).size; } catch {}
  console.log(`${rel} (${size}b)`);
  if (size <= 120 * 1024 && shown < 14) {
    try {
      const t = fs.readFileSync(p, 'latin1').replace(/\u0000/g, '');
      // print only interesting lines to keep output bounded
      const lines = t.split(/\r?\n/).filter((l) => /(module|plugin|menu|function|license|id=|name=|code=|right|launcher|title|url)/i.test(l) && l.trim().length > 0);
      const keep = lines.slice(0, 60);
      if (keep.length) { console.log(keep.map((l) => '  ' + head(l.trim(), 180)).join('\n')); shown++; }
    } catch { /* binary-ish */ }
  }
}

console.log('\n=== TODAYS LOG FILES ===');
const logs = all.filter((p) => /\.(log|txt)$/i.test(path.extname(p)) && fs.statSync(p).mtime > today);
for (const p of logs.slice(0, 24)) {
  let size = 0; try { size = fs.statSync(p).size; } catch {}
  console.log(`${p} (${size}b, ${fs.statSync(p).mtime.toTimeString().slice(0, 8)})`);
}

console.log('\n=== TODAY LOG HITS (menu/module/license/version/plugin/forbidden) ===');
for (const p of logs.slice(0, 10)) {
  try {
    const size = fs.statSync(p).size;
    const fd = fs.openSync(p, 'r');
    const start = size > 512 * 1024 ? size - 512 * 1024 : 0;
    const buf = Buffer.alloc(size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    fs.closeSync(fd);
    const text = buf.toString('latin1');
    const lines = text.split(/\r?\n/).filter((l) => /(menu|module|license|version|plugin|forbidden|right|function|view)?(menu|module|license|plugin|forbidden|right)/i.test(l) && /(menu|module|license|plugin|forbidden|right|function)/i.test(l));
    const hits = lines.slice(-90);
    if (hits.length) {
      console.log(`--- ${path.basename(p)} (${hits.length} hits) ---`);
      for (const h of hits) console.log('  ' + head(h.trim(), 260));
    }
  } catch { /* unreadable */ }
}
