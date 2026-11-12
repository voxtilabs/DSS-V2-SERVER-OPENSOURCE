// E-115: RTSP relay test - simulates the Dahua client pattern
// (SETUP + PLAY on the SAME url, interleaved TCP, zero DESCRIBE) against a
// fake gortsplib-style upstream that demands SETUP <path>/trackID=0.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { parseSdpControls, parseRtspUrl, rewriteTransport, startRtspRelay, dahuaUrlToMediaMtxPath, buildDahuaMonitorPath } from '../e115-rtsp-relay.js';

test('E-115 pure helpers', () => {
  assert.deepEqual(parseRtspUrl('rtsp://10.10.20.120:9100/cam_X?token=abc'), { path: 'cam_X', query: '?token=abc' });
  assert.deepEqual(parseRtspUrl('cam_X?token=abc'), { path: 'cam_X', query: '?token=abc' });
  assert.equal(rewriteTransport('RTP/AVP/TCP;unicast;interleaved=0-1', 2, 3), 'RTP/AVP/TCP;unicast;interleaved=2-3');
  const sdp = 'v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\na=control:trackID=0\r\n';
  const c = parseSdpControls(sdp);
  assert.equal(c.length, 1);
  assert.equal(c[0].control, 'trackID=0');
  assert.match(c[0].mime, /video/);
});

test('E-165 Dahua monitor URL <-> MediaMTX path', () => {
  // the production URL from research/rea/E151_REAL_RTSP_CAPTURE.md
  const real = 'mediaServer/monitor/param/cameraid=1000013%240%26substream=1';
  assert.equal(dahuaUrlToMediaMtxPath(real), 'cam_1000013');
  // our encoder shape (channelId D0238JDG3016$1$0$0 -> seq 0)
  const built = buildDahuaMonitorPath('D0238JDG3016', '0', '2');
  assert.equal(built, 'mediaServer/monitor/param/cameraid=D0238JDG3016%240%26substream=2');
  assert.equal(dahuaUrlToMediaMtxPath(built), 'cam_D0238JDG3016');
  // generic paths are untouched (the relay falls back to them)
  assert.equal(dahuaUrlToMediaMtxPath('cam_D0238JDG3016'), null);
  // absolute form, exactly what the client sends on SETUP
  const u = parseRtspUrl('rtsp://127.0.0.1:9199/mediaServer/monitor/param/cameraid=D0238JDG3016%240%26substream=2?token=abc');
  assert.equal(dahuaUrlToMediaMtxPath(u.path), 'cam_D0238JDG3016');
});

test('E-115 relay: Dahua SETUP+PLAY same url gets RTP from gortsplib-style upstream', async () => {
  // ---- fake upstream (MediaMTX-like): DESCRIBE returns SDP; SETUP only
  // accepts <path>/trackID=0; PLAY only accepts the base <path>.
  const upstream = net.createServer((c) => {
    let buf = Buffer.alloc(0);
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (buf.length < 4) return;
        if (buf[0] === 0x24) {
          const len = buf.readUInt16BE(2);
          if (buf.length < 4 + len) return;
          buf = buf.subarray(4 + len); // upstream ignores client channels
          continue;
        }
        const i = buf.indexOf('\r\n\r\n');
        if (i === -1) return;
        const head = buf.slice(0, i).toString();
        buf = buf.subarray(i + 4);
        const [method, url] = head.split('\r\n')[0].split(' ').filter((x, idx, a) => idx !== a.length - 1);
        const cseq = (/CSeq:\s*(\d+)/i.exec(head) || [])[1] || '1';
        if (method === 'DESCRIBE') {
          const sdp = 'v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\na=control:trackID=0\r\n';
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nContent-Type: application/sdp\r\nContent-Length: ${sdp.length}\r\n\r\n${sdp}`);
        } else if (method === 'SETUP') {
          if (!url.includes('/trackID=0')) {
            c.write(`RTSP/1.0 400 Bad Request\r\nCSeq: ${cseq}\r\n\r\ninvalid SETUP path`);
            return;
          }
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nSession: ABC123\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3\r\n\r\n`);
        } else if (method === 'PLAY') {
          if (url.includes('/trackID=')) {
            c.write(`RTSP/1.0 400 Bad Request\r\nCSeq: ${cseq}\r\n\r\npath has changed`);
            return;
          }
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nSession: ABC123\r\nRTP-Info: url=rtsp://up/${encodeURIComponent(url)}\r\n\r\n`);
          // one interleaved RTP frame on upstream channel 2 -> must arrive on client channel 0
          const rtp = Buffer.from([0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
          c.write(Buffer.concat([Buffer.from([0x24, 0x02]), (() => { const b = Buffer.alloc(2); b.writeUInt16BE(rtp.length, 0); return b; })(), rtp]));
        } else if (method === 'TEARDOWN') {
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nSession: ABC123\r\n\r\n`);
          c.destroy();
        } else {
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\n\r\n`);
        }
      }
    });
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const upPort = upstream.address().port;
  const relay = startRtspRelay({ port: 0, upstreamHost: '127.0.0.1', upstreamPort: upPort });
  await new Promise((r) => relay.once('listening', r));
  const relayPort = relay.address().port;

  const result = await new Promise((resolve, reject) => {
    const cl = net.connect(relayPort, '127.0.0.1', () => {
      // the Dahua pattern: SETUP and PLAY with the SAME absolute url
      cl.write(`SETUP rtsp://10.10.20.120:${relayPort}/cam_X?token=abc RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\nUser-Agent: DSSCClient\r\n\r\n`);
    });
    let buf = Buffer.alloc(0);
    let got = { setup: null, play: null, rtp: 0 };
    const timer = setTimeout(() => { cl.destroy(); resolve(got); }, 4000);
    cl.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (buf.length < 4) return;
        if (buf[0] === 0x24) {
          const len = buf.readUInt16BE(2);
          if (buf.length < 4 + len) return;
          const ch = buf[1];
          buf = buf.subarray(4 + len);
          if (ch === 0) got.rtp++;
          continue;
        }
        const i = buf.indexOf('\r\n\r\n');
        if (i === -1) return;
        const head = buf.slice(0, i).toString();
        const cl2 = /Content-Length:\s*(\d+)/i.exec(head);
        const bl = cl2 ? Number(cl2[1]) : 0;
        if (buf.length < i + 4 + bl) return;
        buf = buf.subarray(i + 4 + bl);
        const status = Number((/RTSP\/1\.0 (\d+)/.exec(head) || [])[1]);
        if (/CSeq: 1/.test(head)) { got.setup = status; if (status === 200) cl.write(`PLAY rtsp://10.10.20.120:${relayPort}/cam_X?token=abc RTSP/1.0\r\nCSeq: 2\r\nSession: ABC123\r\nUser-Agent: DSSCClient\r\n\r\n`); else { clearTimeout(timer); reject(new Error('SETUP rejected: ' + head.split('\r\n')[0])); } }
        if (/CSeq: 2/.test(head)) { got.play = status; cl.write(`TEARDOWN rtsp://10.10.20.120:${relayPort}/cam_X RTSP/1.0\r\nCSeq: 3\r\nSession: ABC123\r\n\r\n`); }
      }
    });
    cl.on('error', () => {});
  });
  assert.equal(result.setup, 200, 'SETUP accepted on the base url');
  assert.equal(result.play, 200, 'PLAY accepted on the SAME base url');
  assert.ok(result.rtp >= 1, 'RTP frames reach the client on channel 0');
  relay.close();
  upstream.close();
});

test('E-155 DHAV wrapper: magic, class, recordLen, extraLen and Annex-B preserved', async () => {
  const { wrapWithDhav, isDhav, createDhavState } = await import('../e155-dhav.js');
  // H.265 sample: start code + VPS NAL (type 32 -> 0x40 0x01)
  const nal = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0c, 0x01]), Buffer.alloc(100, 0xaa)]);
  const st = createDhavState();
  const out = wrapWithDhav(nal, st);
  assert.equal(out.slice(0, 4).toString('latin1'), 'DHAV');
  assert.equal(out[4], 0xFC, 'class video');
  const extraLen = out[22];
  assert.ok(extraLen === 12 || extraLen === 8, 'extraLen is the TLV block length');
  const recordLen = out.readUInt32LE(12);
  assert.equal(recordLen, 24 + extraLen + nal.length + 8, 'recordLen = 24 + extra + NAL + 8');
  assert.equal(out.readUInt32LE(8), 0, 'first counter is 0');
  assert.ok(out.readUInt32LE(16) > 1700000000, 'unix seconds');
  // body is the untouched Annex-B NAL, followed by the 8 trailing bytes
  assert.deepEqual(out.slice(24 + extraLen, 24 + extraLen + nal.length), nal);
  assert.equal(out.length, 24 + extraLen + nal.length + 8);
  // idempotent on an already-wrapped payload
  const again = wrapWithDhav(out, st);
  assert.equal(again, out);
  assert.ok(isDhav(out));
  // counter increments per frame
  const second = wrapWithDhav(nal, st);
  assert.equal(second.readUInt32LE(8), 1, 'counter increments');
});

test('E-156 RTP -> Annex-B depacketizer (H.265 AP/FU + H.264 STAP-A/FU-A)', async () => {
  const { rtpToAnnexB, depacketizeH265, depacketizeH264 } = await import('../e156-rtp-depacket.js');
  // Real AP captured from the EBA camera (H.265 type 48):
  //   60 01 | 00 03 46 01 30 | 00 08 4e 01 01 03 ff ff 6e 80
  const ap = Buffer.from('600100034601300008 4e010103ffff6e80'.replace(/ /g, ''), 'hex');
  const st = { codec: null };
  const out = rtpToAnnexB(ap, st);
  assert.equal(st.codec, 'h265', 'AP identifies H.265');
  assert.deepEqual(out, Buffer.from('0000000146 0130 00000001 4e010103ffff6e80'.replace(/ /g, ''), 'hex'), 'AP NALs become Annex-B');
  // FU start (62 01 | 81 | data) -> start code + rebuilt NAL header + data
  const fuStart = Buffer.from('62 01 81 d0 10 fd 90'.replace(/ /g, ''), 'hex');
  const s2 = depacketizeH265(fuStart, {});
  assert.deepEqual(s2, Buffer.from('00000001 0201 d010fd90'.replace(/ /g, ''), 'hex'), 'FU start rebuilt');
  // FU middle -> raw continuation, no start code
  const fuMid = Buffer.from('62 01 41 aabb'.replace(/ /g, ''), 'hex');
  assert.deepEqual(depacketizeH265(fuMid, {}), Buffer.from('aabb', 'hex'), 'FU middle is a continuation');
  // H.264 STAP-A (24) and FU-A (28)
  const stap = Buffer.from('18 0003 460130'.replace(/ /g, ''), 'hex');
  assert.deepEqual(depacketizeH264(stap, {}), Buffer.from('00000001 460130'.replace(/ /g, ''), 'hex'), 'STAP-A');
  const fua = Buffer.from('7c 85 05aabb'.replace(/ /g, ''), 'hex');
  assert.deepEqual(depacketizeH264(fua, {}), Buffer.from('00000001 6505aabb'.replace(/ /g, ''), 'hex'), 'FU-A start');
});

test('E-158 parameter sets from the MediaMTX SDP (sprop-vps/sps/pps -> Annex-B)', async () => {
  const { parameterSetsFromSdp } = await import('../e156-rtp-depacket.js');
  const sdp = 'v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n' +
    'a=fmtp:96 sprop-pps=RAHA98DMkA==; sprop-sps=QgEBAWAAAAMAkAAAAwAAAwB4oAPAgBEHy5ZdKQhGRdUMBAQAAAMABAAAAwBRgBd5RAAO4IAAHcEx; sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwB4lwJA\r\n';
  const out = parameterSetsFromSdp(sdp);
  assert.ok(out && out.length > 20, 'parameter sets built');
  // three start codes, VPS first
  const starts = [];
  for (let i = 0; i + 3 < out.length; i++) if (out[i] === 0 && out[i + 1] === 0 && out[i + 2] === 0 && out[i + 3] === 1) starts.push(i);
  assert.equal(starts.length, 3, 'VPS + SPS + PPS start codes');
  assert.equal(out[starts[0] + 4], 0x40, 'VPS NAL type 32');
  assert.equal(out[starts[1] + 4], 0x42, 'SPS NAL type 33');
  assert.equal(out[starts[2] + 4], 0x44, 'PPS NAL type 34');
  assert.equal(parameterSetsFromSdp('v=0\r\n'), null, 'no fmtp -> null');
});

test('E-145 relay echoes the CLIENT CSeq (REA: mismatch -> reply discarded -> SETUP timeout)', async () => {
  // The DSS client starts its CSeq wherever it wants (observed 1, 7, 41...).
  // DPSDK.dll (live555 strings 0x180c64370 / 0x180c5c2a8) DISCARDS any reply
  // whose CSeq != the request's, which the user sees as "RTSP SETUP timed out".
  // The relay therefore must map its own upstream counter back to the client's.
  const upstream = net.createServer((c) => {
    let buf = Buffer.alloc(0);
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (buf.length < 4) return;
        if (buf[0] === 0x24) {
          const len = buf.readUInt16BE(2);
          if (buf.length < 4 + len) return;
          buf = buf.subarray(4 + len);
          continue;
        }
        const i = buf.indexOf('\r\n\r\n');
        if (i === -1) return;
        const head = buf.slice(0, i).toString();
        buf = buf.subarray(i + 4);
        const [method, url] = head.split('\r\n')[0].split(' ').filter((x, idx, a) => idx !== a.length - 1);
        const cseq = (/CSeq:\s*(\d+)/i.exec(head) || [])[1] || '1';
        if (method === 'DESCRIBE') {
          const sdp = 'v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\na=control:trackID=0\r\n';
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nContent-Type: application/sdp\r\nContent-Length: ${sdp.length}\r\n\r\n${sdp}`);
        } else if (method === 'SETUP') {
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nSession: SESS42\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3\r\n\r\n`);
        } else if (method === 'PLAY') {
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nSession: SESS42\r\n\r\n`);
          // one RTP frame so the relay can emit the PLAY 200 with RTP-Info
          const rtp = Buffer.from([0x80, 0x60, 0x12, 0x34, 0x00, 0x00, 0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF]);
          c.write(Buffer.concat([Buffer.from([0x24, 0x02]), (() => { const b = Buffer.alloc(2); b.writeUInt16BE(rtp.length, 0); return b; })(), rtp]));
        } else if (method === 'TEARDOWN') {
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nSession: SESS42\r\n\r\n`);
          c.destroy();
        } else {
          c.write(`RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\n\r\n`);
        }
      }
    });
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const upPort = upstream.address().port;
  const relay = startRtspRelay({ port: 0, upstreamHost: '127.0.0.1', upstreamPort: upPort });
  await new Promise((r) => relay.once('listening', r));
  const relayPort = relay.address().port;

  const seen = await new Promise((resolve) => {
    const cl = net.connect(relayPort, '127.0.0.1', () => {
      // non-1 CSeq values on purpose; the transport is the exact client literal
      cl.write(`SETUP rtsp://10.10.20.120:${relayPort}/cam_Y?token=abc RTSP/1.0\r\nCSeq: 41\r\nTransport: RTP/AVP/TCP; interleaved=0-1\r\nUser-Agent: Dahua Rtsp Client/2.0\r\n\r\n`);
    });
    let buf = Buffer.alloc(0);
    const out = { setupCSeq: null, playCSeq: null, transport: null, session: null, setupHead: '', playHead: '' };
    const timer = setTimeout(() => { cl.destroy(); resolve(out); }, 6000);
    cl.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (buf.length < 4) return;
        if (buf[0] === 0x24) {
          const len = buf.readUInt16BE(2);
          if (buf.length < 4 + len) return;
          buf = buf.subarray(4 + len);
          continue;
        }
        const i = buf.indexOf('\r\n\r\n');
        if (i === -1) return;
        const head = buf.slice(0, i).toString();
        buf = buf.subarray(i + 4);
        const cs = Number((/CSeq:\s*(\d+)/i.exec(head) || [])[1]);
        if (/200/.test(head.split('\r\n')[0]) && cs === 41 && out.setupCSeq === null) {
          out.setupCSeq = cs;
          out.setupHead = head;
          out.transport = (/Transport:\s*(.+)/i.exec(head) || [])[1] || null;
          out.session = (/Session:\s*([^\r\n;]+)/i.exec(head) || [])[1] || null;
          cl.write(`PLAY rtsp://10.10.20.120:${relayPort}/cam_Y?token=abc RTSP/1.0\r\nCSeq: 42\r\nSession: ${out.session}\r\nUser-Agent: Dahua Rtsp Client/2.0\r\n\r\n`);
        } else if (cs === 42) {
          out.playCSeq = cs;
          out.playHead = head;
          clearTimeout(timer);
          cl.write(`TEARDOWN rtsp://10.10.20.120:${relayPort}/cam_Y RTSP/1.0\r\nCSeq: 43\r\nSession: ${out.session}\r\n\r\n`);
          cl.destroy();
          resolve(out);
        }
      }
    });
    cl.on('error', () => {});
  });

  assert.equal(seen.setupCSeq, 41, 'SETUP response echoes the client CSeq 41');
  assert.equal(seen.playCSeq, 42, 'PLAY response echoes the client CSeq 42');
  assert.ok(seen.session && seen.session.length > 0, 'SETUP returns a non-empty Session');
  assert.ok(/interleaved=0-1/.test(seen.transport || ''), 'Transport echoed with the client interleaved channels');
  // E-150: the Dahua session metadata the production client expects
  assert.match(seen.setupHead, /Server: Dahua Rtsp Server\/2\.0/i, 'SETUP carries the Dahua server id');
  assert.match(seen.setupHead, /Session: \S+;timeout=60/i, 'SETUP Session has ;timeout=60');
  assert.match(seen.transport || '', /;ssrc=[0-9A-F]{8}/i, 'SETUP Transport advertises ssrc');
  assert.match(seen.setupHead, /x-dynamic-rate: 1/i, 'SETUP advertises x-dynamic-rate');
  assert.match(seen.playHead, /RTP-Info: url=;seq=\d+;rtptime=\d+;ssrc=[0-9A-F]{8}/i, 'PLAY RTP-Info carries seq/rtptime/ssrc');
  assert.match(seen.playHead, /Range: npt=0\.000000-/i, 'PLAY carries Range npt');
  relay.close();
  upstream.close();
});
