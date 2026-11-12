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
import { createDhavState, wrapWithDhav } from './e155-dhav.js';
import { rtpToAnnexB } from './e156-rtp-depacket.js';

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
    // E-150 (pcap of the REAL Dahua server, 9100): the client's live555 player
    // expects the Dahua session metadata on every 200:
    //   SETUP: Server, Session:<id>;timeout=60, Transport:...interleaved=a-b;ssrc=<hex>,
    //          x-dynamic-rate: 1
    //   PLAY : Server, Session:<id>, RTP-Info: url=;seq=..;rtptime=..;ssrc=..,
    //          Range: npt=0.000000-
    // MediaMTX (gortsplib) sends none of that, so the client kept "loading"
    // forever although RTP was flowing. We synthesize the Dahua headers and
    // align the RTP SSRC with the one we advertise.
    let clientSsrc = null;
    let pendingPlay = null; // legacy (unused after E-153)
    let clientSession = null; // session id we advertise to the client
    let queuedPlay = null; // client PLAY waiting for the upstream SETUP answer
    // E-155: the DSS media pipeline only accepts the Dahua private RTP payload
    // container ("DHAV"); MediaMTX delivers plain H.264/H.265. Set RELAY_DHAV=0
    // to disable the wrapping (diagnostics).
    const dhav = process.env.RELAY_DHAV === '0' ? null : createDhavState();
    const cseqMethod = new Map(); // upstream CSeq -> method

    function ssrcHex() {
      if (clientSsrc === null) clientSsrc = Math.floor(Math.random() * 0xffffffff) >>> 0;
      return clientSsrc.toString(16).toUpperCase().padStart(8, '0');
    }

    function replyPlay(clientSeq) {
      // E-153: answer PLAY immediately. The real Dahua server itself returns
      // seq=0;rtptime=0 in many sessions, so waiting for the first RTP frame
      // (the old behaviour) only risked the client's 1 s timeout.
      client.write(`RTSP/1.0 200 OK${CRLF}CSeq: ${clientSeq}${CRLF}Server: Dahua Rtsp Server/2.0${CRLF}Session: ${clientSession || ''}${CRLF}RTP-Info: url=;seq=0;rtptime=0;ssrc=${ssrcHex()}${CRLF}Range: npt=0.000000-${CRLF}${CRLF}`);
    }

    function sendUpstreamPlay(path, clientCseq) {
      const c = cseq++;
      noteCseq(c, Number(clientCseq)); cseqMethod.set(c, 'PLAY');
      const sessionH = upSession ? `${CRLF}Session: ${upSession}` : '';
      up.write(`PLAY rtsp://${upstreamHost}:${upstreamPort}/${path || basePath} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}User-Agent: Dahua Rtsp Client/2.0${sessionH}${CRLF}${CRLF}`);
      log('PLAY upstream', path || basePath, 'session=' + (upSession || 'none'), 'cseq', c, '<-', clientCseq);
    }

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
            let payload = Buffer.from(ubuf.subarray(4, 4 + len));
            ubuf = ubuf.subarray(4 + len);
            // E-150: the first RTP frame carries the seq/rtptime the PLAY 200
            // must advertise. Hold the PLAY response until it arrives (or the
            // fallback timer fires) so the client never sees RTP before the
            // RTP-Info that describes it.
            if (ch === UP_CH.from && payload.length >= 12) {
              // advertise and emit the same SSRC so the player can correlate
              if (clientSsrc !== null) payload.writeUInt32BE(clientSsrc >>> 0, 8);
              // E-155/E-156: the Dahua pipeline needs the DHAV container, whose
              // body must be an Annex-B bitstream. MediaMTX forwards the
              // camera's RFC 7798/6184 framing (AP/FU/STAP-A), so convert it.
              if (dhav) {
                const ab = rtpToAnnexB(payload.subarray(12), dhav);
                if (!ab || !ab.length) continue;
                payload = Buffer.concat([payload.subarray(0, 12), wrapWithDhav(ab, dhav)]);
              }
            }
            // remap upstream channel back to the client channel
            const out = ch === UP_CH.from ? CL_CH.from : (ch === UP_CH.to ? CL_CH.to : ch);
            client.write(Buffer.concat([Buffer.from([0x24, out]), (() => { const b = Buffer.alloc(2); b.writeUInt16BE(payload.length, 0); return b; })(), payload]));
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
            const status = Number((/^RTSP\/1\.0 (\d+)/.exec(head) || [])[1] || 0);
            // E-145: echo the CLIENT's CSeq (never the relay's upstream one).
            const csM = /CSeq:\s*(\d+)/i.exec(outHead);
            const upSeq = csM ? Number(csM[1]) : null;
            const clientSeq = upSeq !== null ? cseqMap.get(upSeq) : undefined;
            if (upSeq !== null && clientSeq !== undefined) outHead = outHead.replace(/CSeq:\s*\d+/i, 'CSeq: ' + clientSeq);
            const method = upSeq !== null ? cseqMethod.get(upSeq) : undefined;
            if (status === 200 && method === 'SETUP') {
              // E-153: the client was already answered immediately; here we
              // only capture the upstream session id and flush a queued PLAY.
              const sessM = /Session:\s*([^\r\n;]+)/i.exec(outHead);
              if (sessM) upSession = sessM[1].trim();
              if (queuedPlay) {
                const q = queuedPlay;
                queuedPlay = null;
                sendUpstreamPlay(q.path, q.clientCseq);
              }
            } else if (status === 200 && method === 'PLAY') {
              // already answered immediately (RTP-Info zeros are accepted by
              // the Dahua client, as the production capture shows)
            } else if (status >= 400 && (method === 'SETUP' || method === 'PLAY')) {
              // upstream rejected after we had already answered the client:
              // drop the connection so the player reports a clean failure
              // instead of receiving a stray gortsplib 400.
              log('upstream rejected', method, status, '|', outHead.split('\r\n').slice(0, 3).join(' / '), '|', body.toString('latin1').slice(0, 200));
              try { client.destroy(); } catch {}
            } else {
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
        }
      });
    }

    function upstreamSend(msg) { if (up && upReady) up.write(msg); }

    async function handleClientMessage(method, rawUrl, headers, raw) {
      if (!up || !upReady) { pending.push({ method, url: rawUrl, headers, raw }); return; }
      if (method === 'OPTIONS') {
        // Match the real server: echo the public method list and the session.
        const sessH = upSession ? `${CRLF}Session: ${upSession}` : '';
        client.write(`RTSP/1.0 200 OK${CRLF}CSeq: ${headers.cseq || cseq++}${CRLF}Server: Dahua Rtsp Server/2.0${sessH}${CRLF}Public: OPTIONS,DESCRIBE,SETUP,PLAY,PAUSE,TEARDOWN,SET_PARAMETER,GET_PARAMETER${CRLF}${CRLF}`);
        return;
      }
      if (method === 'DESCRIBE') {
        const p = parseRtspUrl(rawUrl);
        const upUrl = `rtsp://${upstreamHost}:${upstreamPort}/${p.path}${p.query}`;
        const c = cseq++;
        noteCseq(c, Number(headers.cseq)); cseqMethod.set(c, method);
        up.write(`DESCRIBE ${upUrl} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}Accept: application/sdp${CRLF}User-Agent: Dahua Rtsp Client/2.0${CRLF}${CRLF}`);
        return;
      }
      if (method === 'SETUP') {
        const p = parseRtspUrl(rawUrl);
        basePath = p.path || basePath;
        const token = decodeURIComponent((p.query.match(/token=([^&]*)/) || [])[1] || '');
        if (validateToken) validateToken(token, basePath, clientKey);
        // E-153: the Dahua client waits ~1 s (RtspThreadWaitTime default 1) for
        // the SETUP reply. The old code awaited an upstream DESCRIBE first and
        // timed out on a cold MediaMTX path ("Operation failed"). Answer the
        // client IMMEDIATELY with our own session id and run the upstream
        // SETUP asynchronously; the PLAY is queued until upstream answers.
        if (!clientSession) clientSession = String(2000000000000 + Math.floor(Math.random() * 899999999999));
        const urlControl = p.path.includes('/') ? p.path.split('/').slice(1).join('/') : null;
        const control = urlControl || 'trackID=0';
        const upUrl = `rtsp://${upstreamHost}:${upstreamPort}/${basePath}/${control}`;
        const c = cseq++;
        noteCseq(c, Number(headers.cseq)); cseqMethod.set(c, method);
        // E-154: the DSS client sends "RTP/AVP/TCP; interleaved=0-1;playmode=playback".
        // gortsplib rejects the unknown `playmode` parameter with 400, so the
        // upstream transport is always rebuilt in its exact accepted form.
        const upTransport = `RTP/AVP/TCP;unicast;interleaved=${UP_CH.from}-${UP_CH.to}`;
        up.write(`SETUP ${upUrl} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}Transport: ${upTransport}${CRLF}User-Agent: Dahua Rtsp Client/2.0${CRLF}${CRLF}`);
        client.write(`RTSP/1.0 200 OK${CRLF}CSeq: ${headers.cseq}${CRLF}Server: Dahua Rtsp Server/2.0${CRLF}Session: ${clientSession};timeout=60${CRLF}Transport: RTP/AVP/TCP;unicast;interleaved=${CL_CH.from}-${CL_CH.to};ssrc=${ssrcHex()}${CRLF}x-dynamic-rate: 1${CRLF}${CRLF}`);
        log('SETUP', basePath, '->', control, 'cseq', c, '<-', headers.cseq, '(immediate)');
        return;
      }
      if (method === 'PLAY' || method === 'RECORD' || method === 'PAUSE') {
        const p = parseRtspUrl(rawUrl);
        if (method !== 'PAUSE' && !upSession) {
          // upstream SETUP not answered yet (usually <100 ms): queue the PLAY
          queuedPlay = { path: p.path || basePath, clientCseq: headers.cseq };
          log('PLAY queued until upstream SETUP');
          return;
        }
        const c = cseq++;
        noteCseq(c, Number(headers.cseq)); cseqMethod.set(c, method);
        // E-154: the client only knows OUR session id; the upstream must get
        // MediaMTX's own session. Using headers.session first made gortsplib
        // answer 400 "session not found" to every PLAY.
        const sess = upSession || headers.session;
        const sessionH = sess ? `${CRLF}Session: ${sess}` : '';
        const rangeH = headers.range ? `${CRLF}Range: ${headers.range}` : '';
        up.write(`${method} rtsp://${upstreamHost}:${upstreamPort}/${p.path || basePath} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}User-Agent: Dahua Rtsp Client/2.0${sessionH}${rangeH}${CRLF}${CRLF}`);
        if (method === 'PLAY') replyPlay(headers.cseq);
        log(method, p.path || basePath, 'session=' + (sess || 'none'), 'cseq', c, '<-', headers.cseq, '(immediate)');
        return;
      }
      if (method === 'TEARDOWN') {
        const p = parseRtspUrl(rawUrl);
        const c = cseq++;
        noteCseq(c, Number(headers.cseq)); cseqMethod.set(c, method);
        if (pendingPlay) { clearTimeout(pendingPlay.timer); pendingPlay = null; }
        // E-154: upstream must receive ITS session id, not the client's.
        const sess = upSession || headers.session;
        const sessionH = sess ? `${CRLF}Session: ${sess}` : '';
        up.write(`TEARDOWN rtsp://${upstreamHost}:${upstreamPort}/${p.path || basePath} RTSP/1.0${CRLF}CSeq: ${c}${CRLF}User-Agent: Dahua Rtsp Client/2.0${sessionH}${CRLF}${CRLF}`);
        setTimeout(() => { try { up.destroy(); } catch {} try { client.destroy(); } catch {} }, 250);
        log('TEARDOWN');
        return;
      }
      // GET_PARAMETER / SET_PARAMETER / unknown -> 200 locally
      client.write(`RTSP/1.0 200 OK${CRLF}CSeq: ${headers.cseq || cseq++}${CRLF}${CRLF}`);
    }

    let cbuf = Buffer.alloc(0);
    // E-145 (REA DSS_SERVER_CONTRACT_MAP §1.6): the client DISCARDS any RTSP
    // reply whose CSeq is not the one it sent ("RTSP CSeq mismatch or invalid
    // CSeq" -> the user sees "RTSP SETUP timed out"). The relay used its own
    // upstream counter and forwarded MediaMTX's CSeq verbatim, so every reply
    // was dropped. Keep a per-connection map upstreamCSeq -> clientCSeq and
    // rewrite the echoed header back to the client's value.
    const cseqMap = new Map();
    function noteCseq(upstreamCseq, clientCseq) {
      if (Number.isFinite(upstreamCseq) && Number.isFinite(clientCseq)) cseqMap.set(upstreamCseq, clientCseq);
      if (cseqMap.size > 256) cseqMap.delete(cseqMap.keys().next().value);
    }
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
    client.on('close', () => {
      if (pendingPlay) { clearTimeout(pendingPlay.timer); pendingPlay = null; }
      try { up && up.destroy(); } catch {}
    });
    if (!up) connectUpstream();
  });

  server.listen(port, () => console.log(`[E115-RTSP] relay listening on ${port} -> ${upstreamHost}:${upstreamPort}`));
  server.on('error', (e) => console.error('[E115-RTSP] listen error', e.message));
  return server;
}
