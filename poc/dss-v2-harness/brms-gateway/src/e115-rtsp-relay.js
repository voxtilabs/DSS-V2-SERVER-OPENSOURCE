// ===== E-115: RTSP relay (Dahua handshake <-> MediaMTX/gortsplib) =========
//
// Root cause found by the live video-chain QA (2026-11-07, pcap
// "CAPTURA FILTRADA DSS.pcapng"): the real DSS Client speaks RTSP with
//   User-Agent: DSSCClient, absolute URI, Transport: RTP/AVP/TCP;unicast;
//   interleaved=0-1, and the sequence SETUP -> PLAY -> TEARDOWN ON THE SAME
//   URL, with ZERO DESCRIBE/OPTIONS.
// MediaMTX (gortsplib) instead requires SETUP with the track control
// (/trackID=0) and PLAY on the base URL:
//   SETUP base?token=            -> 400 "invalid SETUP path"
//   SETUP base/trackID=0 + PLAY base -> 200/200, RTP flows (verified)
// So a relay in front of MediaMTX is REQUIRED for Live View:
//   - accept the client's aggregated SETUP/PLAY on the base URL,
//   - split it upstream into SETUP <path>/trackID=0 + PLAY <path>,
//   - rewrite interleaved channels (client 0-1 <-> upstream 2-3),
//   - carry the upstream Session id and the token validation.
//
// Listens on RTSP_PORT (9100) inside the gateway; the compose must publish
// 9100 from the gateway and REMOVE the mediamtx 9100 host mapping.

import net from 'node:net';

const CRLF = '\r\n';

export function parseRtspUrl(raw) {
  // rtsp://host:port/path?query  (absolute form the DSS client uses)
  try {
    const u = new URL(raw);
    return { path: u.pathname.replace(/^\/+/, ''), query: u.search };
  } catch {
    // relative form: path?query RTSP/1.0
    const m = String(raw).split('?');
    return { path: m[0].replace(/^\/*/, ''), query: m[1] ? '?' + m[1] : '' };
  }
}

function parseInterleavedChannel(transportHeader) {
  const m = /interleaved\s*=\s*(\d+)(?:-(\d+))?/i.exec(transportHeader || '');
  if (!m) return null;
  return { from: Number(m[1]), to: m[2] ? Number(m[2]) : Number(m[1]) };
}

export function rewriteTransport(header, from, to) {
  return header.replace(/interleaved\s*=\s*\d+(?:-\d+)?/i, `interleaved=${from}-${to}`);
}

// Extract track controls from an SDP body: [{control, mime}]
export function parseSdpControls(sdp) {
  const out = [];
  let cur = null;
  for (const line of String(sdp).split(/\r?\n/)) {
    if (line.startsWith('m=')) { cur = { mline: line, control: null, mime: line.slice(2).split(' ')[0] }; out.push(cur); }
    else if (cur && /^a=control:/i.test(line)) cur.control = line.slice(10).trim();
  }
  return out;
}

export function startRtspRelay({ port, upstreamHost = 'mediamtx', upstreamPort = 8554, validateToken }) {
  const sdpCache = new Map(); // path -> {controls, at}
  const UP_CH = { from: 2, to: 3 }; // upstream interleaved channels we ask for
  const CL_CH = { from: 0, to: 1 }; // channels the DSS client uses

  async function upstreamDescribe(path) {
    const hit = sdpCache.get(path);
    if (hit && Date.now() - hit.at < 60000) return hit;
    const sdp = await new Promise((resolve, reject) => {
      const c = net.connect(upstreamPort, upstreamHost, () => {
        c.write(`DESCRIBE rtsp://${upstreamHost}:${upstreamPort}/${path} RTSP/1.0${CRLF}CSeq: 1${CRLF}Accept: application/sdp${CRLF}${CRLF}`);
      });
      let buf = '';
      const timer = setTimeout(() => { c.destroy(); reject(new Error('describe timeout')); }, 5000);
      c.on('data', (d) => {
        buf += d.toString('latin1');
        const i = buf.indexOf(CRLF + CRLF);
        if (i !== -1) {
          const head = buf.slice(0, i);
          const cl = /Content-Length:\s*(\d+)/i.exec(head);
          const body = buf.slice(i + 4, i + 4 + (cl ? Number(cl[1]) : 0));
          clearTimeout(timer); c.destroy(); resolve(body);
        }
      });
      c.on('error', (e) => { clearTimeout(timer); reject(e); });
    });
    const controls = parseSdpControls(sdp);
    sdpCache.set(path, { controls, at: Date.now() });
    return { controls };
  }

  const server = net.createServer((client) => {
    const clientKey = `${client.remoteAddress}:${client.remotePort}`;
    let up = null;
    let upReady = false;
    const pending = []; // client messages buffered until upstream is connected
    let basePath = '';
    let upSession = null; // Session id from the upstream SETUP response
    let cseq = 1;

    function log(...a) { console.log('[E115-RTSP]', clientKey, ...a); }

    function connectUpstream() {
      up = net.connect(upstreamPort, upstreamHost, () => {
        upReady = true;
        log('upstream connected');
        while (pending.length) {
          const m = pending.shift();
          handleClientMessage(m.method, m.url, m.headers, m.raw);
        }
      });
      up.on('error', (e) => { log('upstream error', e.message); try { client.destroy(); } catch {} });
      up.on('close', () => { upReady = false; try { client.destroy(); } catch {} });
      let ubuf = Buffer.alloc(0);
      up.on('data', (d) => {
        ubuf = Buffer.concat([ubuf, d]);
        // pump: interleaved frames ($) and text responses
        for (;;) {
          if (ubuf.length < 4) return;
          if (ubuf[0] === 0x24) {
            const len = ubuf.readUInt16BE(2);
            if (ubuf.length < 4 + len) return;
            const ch = ubuf[1];
            const payload = ubuf.subarray(4, 4 + len);
            ubuf = ubuf.subarray(4 + len);
            // remap upstream channel back to the client channel
            const out = ch === UP_CH.from ? CL_CH.from : (ch === UP_CH.to ? CL_CH.to : ch);
            client.write(Buffer.concat([Buffer.from([0x24, out]), (() => { const b = Buffer.alloc(2); b.writeUInt16BE(len, 0); return b; })(), payload]));
          } else {
            const i = ubuf.indexOf(CRLF + CRLF);
            if (i === -1) return;
            const head = ubuf.slice(0, i).toString('latin1');
            let cl = /Content-Length:\s*(\d+)/i.exec(head);
            let bodyLen = cl ? Number(cl[1]) : 0;
            if (ubuf.length < i + 4 + bodyLen) return;
            const body = ubuf.subarray(i + 4, i + 4 + bodyLen);
            ubuf = ubuf.subarray(i + 4 + bodyLen);
            let outHead = head;
            // capture the upstream Session id (PLAY/TEARDOWN need it, and the
            // Dahua client may not echo it back)
            const sessM = /Session:\s*([^\r\n;]+)/i.exec(outHead);
            if (sessM && /Transport:\s*/i.test(outHead)) upSession = sessM[1].trim();
            // rewrite the upstream Transport back to the client's channels
            const tr = /Transport:\s*(.+)/i.exec(outHead);
            if (tr) outHead = outHead.replace(/Transport:\s*.+/i, 'Transport: ' + rewriteTransport(tr[1], CL_CH.from, CL_CH.to));
            client.write(outHead + CRLF + CRLF);
            if (body.length) client.write(body);
          }
        }
      });
    }

    function upstreamSend(msg) { if (up && upReady) up.write(msg); }

    async function handleClientMessage(method, rawUrl, headers, raw) {
      if (!up || !upReady) { pending.push({ method, url: rawUrl, headers, raw }); return; }
      if (method === 'OPTIONS') {
        // answer locally (the DSS client sends none, but others might)
        client.write(`RTSP/1.0 200 OK${CRLF}CSeq: ${headers.cseq || cseq++}${CRLF}Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, OPTIONS, GET_PARAMETER, SET_PARAMETER${CRLF}${CRLF}`);
        return;
      }
      if (method === 'DESCRIBE') {
        const p = parseRtspUrl(rawUrl);
        const upUrl = `rtsp://${upstreamHost}:${upstreamPort}/${p.path}${p.query}`;
        const c = cseq++;
        up.write(`DESCRIBE ${upUrl} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}Accept: application/sdp${CRLF}User-Agent: DSSCClient${CRLF}${CRLF}`);
        return;
      }
      if (method === 'SETUP') {
        const p = parseRtspUrl(rawUrl);
        basePath = p.path || basePath;
        const token = decodeURIComponent((p.query.match(/token=([^&]*)/) || [])[1] || '');
        if (validateToken) validateToken(token, basePath, clientKey);
        let controls = [];
        try { controls = (await upstreamDescribe(basePath)).controls; } catch (e) { log('describe failed', e.message); }
        // track control: the client's URL control if it carries one, else the
        // first media track from our upstream DESCRIBE (Dahua sends none).
        const urlControl = p.path.includes('/') ? p.path.split('/').slice(1).join('/') : null;
        const control = urlControl || controls.find((c) => /^(video|H265|H264)/i.test(c.mime || ''))?.control || controls[0]?.control || 'trackID=0';
        const upUrl = `rtsp://${upstreamHost}:${upstreamPort}/${basePath}/${control}`;
        const c = cseq++;
        const transport = headers.transport || 'RTP/AVP/TCP;unicast;interleaved=0-1';
        const upTransport = rewriteTransport(transport, UP_CH.from, UP_CH.to);
        up.write(`SETUP ${upUrl} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}Transport: ${upTransport}${CRLF}User-Agent: DSSCClient${CRLF}${CRLF}`);
        log('SETUP', basePath, '->', control);
        return;
      }
      if (method === 'PLAY' || method === 'RECORD' || method === 'PAUSE') {
        const p = parseRtspUrl(rawUrl);
        const c = cseq++;
        const sess = headers.session || upSession;
        const sessionH = sess ? `${CRLF}Session: ${sess}` : '';
        const rangeH = headers.range ? `${CRLF}Range: ${headers.range}` : '';
        up.write(`${method} rtsp://${upstreamHost}:${upstreamPort}/${p.path || basePath} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}User-Agent: DSSCClient${sessionH}${rangeH}${CRLF}${CRLF}`);
        log(method, p.path || basePath, 'session=' + (sess || 'none'));
        return;
      }
      if (method === 'TEARDOWN') {
        const p = parseRtspUrl(rawUrl);
        const c = cseq++;
        const sess = headers.session || upSession;
        const sessionH = sess ? `${CRLF}Session: ${sess}` : '';
        up.write(`TEARDOWN rtsp://${upstreamHost}:${upstreamPort}/${p.path || basePath} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}User-Agent: DSSCClient${sessionH}${CRLF}${CRLF}`);
        setTimeout(() => { try { up.destroy(); } catch {} try { client.destroy(); } catch {} }, 250);
        log('TEARDOWN');
        return;
      }
      // GET_PARAMETER / SET_PARAMETER / unknown -> 200 locally
      client.write(`RTSP/1.0 200 OK${CRLF}CSeq: ${headers.cseq || cseq++}${CRLF}${CRLF}`);
    }

    let cbuf = Buffer.alloc(0);
    client.on('data', (d) => {
      cbuf = Buffer.concat([cbuf, d]);
      for (;;) {
        if (cbuf.length < 4) return;
        if (cbuf[0] === 0x24) {
          const len = cbuf.readUInt16BE(2);
          if (cbuf.length < 4 + len) return;
          const ch = cbuf[1];
          const payload = cbuf.subarray(4, 4 + len);
          cbuf = cbuf.subarray(4 + len);
          if (up && upReady) {
            const out = ch === CL_CH.from ? UP_CH.from : (ch === CL_CH.to ? UP_CH.to : ch);
            up.write(Buffer.concat([Buffer.from([0x24, out]), (() => { const b = Buffer.alloc(2); b.writeUInt16BE(len, 0); return b; })(), payload]));
          }
        } else {
          const i = cbuf.indexOf(CRLF + CRLF);
          if (i === -1) return;
          const head = cbuf.slice(0, i).toString('latin1');
          const cl = /Content-Length:\s*(\d+)/i.exec(head);
          const bodyLen = cl ? Number(cl[1]) : 0;
          if (cbuf.length < i + 4 + bodyLen) return;
          const body = cbuf.subarray(i + 4, i + 4 + bodyLen).toString('latin1');
          cbuf = cbuf.subarray(i + 4 + bodyLen);
          const lines = head.split(CRLF);
          const first = lines[0].split(' ');
          const method = first[0];
          const url = first.slice(1, -1).join(' ');
          const headers = {};
          for (const l of lines.slice(1)) {
            const j = l.indexOf(':');
            if (j > 0) headers[l.slice(0, j).trim().toLowerCase()] = l.slice(j + 1).trim();
          }
          headers.cseq = (Number((/cseq:\s*(\d+)/i.exec(head) || [])[1]) || cseq++);
          handleClientMessage(method, url, headers, head + CRLF + CRLF + body);
        }
      }
    });
    client.on('error', () => {});
    client.on('close', () => { try { up && up.destroy(); } catch {} });
    if (!up) connectUpstream();
  });

  server.listen(port, () => console.log(`[E115-RTSP] relay listening on ${port} -> ${upstreamHost}:${upstreamPort}`));
  server.on('error', (e) => console.error('[E115-RTSP] listen error', e.message));
  return server;
}
