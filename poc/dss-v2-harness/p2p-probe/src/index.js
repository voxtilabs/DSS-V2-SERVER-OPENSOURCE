import crypto from 'node:crypto';
import { createConnection } from 'node:net';

const EASY4IP_HOST = process.env.EASY4IP_HOST || 'www.easy4ip.com';
const EASY4IP_PORT = parseInt(process.env.EASY4IP_PORT || '443');
const SN = process.env.SN || '';
const USER = process.env.USER || '';
const PASS = process.env.PASS || '';

function log(...a) { console.log('[P2P-PROBE]', new Date().toISOString(), ...a); }

async function soapGetDeviceByDevSequence(sn) {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns2:getDeviceByDevSequence xmlns:ns2="http://webservice.ddns.dahua.com/">
      <devSequence>${sn}</devSequence>
    </ns2:getDeviceByDevSequence>
  </soap:Body>
</soap:Envelope>`;
  return new Promise((resolve, reject) => {
    const req = crypto.createConnection({ host: EASY4IP_HOST, port: EASY4IP_PORT }, () => {
      req.write(`POST /ws/getDeviceByDevSequence HTTP/1.1\r\nHost: ${EASY4IP_HOST}\r\nContent-Type: text/xml; charset=utf-8\r\nSOAPAction: "getDeviceByDevSequence"\r\nContent-Length: ${Buffer.byteLength(xml)}\r\n\r\n${xml}`);
    });
    let data = '';
    req.on('data', d => data += d);
    req.on('end', () => resolve(data));
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('timeout')));
  });
}

async function httpGetDeviceInfo(easy4ipUrl) {
  return new Promise((resolve, reject) => {
    const url = new URL(easy4ipUrl);
    const req = crypto.createConnection({ host: url.hostname, port: url.port || 443 }, () => {
      req.write(`GET ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nConnection: close\r\n\r\n`);
    });
    let data = '';
    req.on('data', d => data += d);
    req.on('end', () => resolve(data));
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('timeout')));
  });
}

async function touHandshake(relayHost, relayPort, localPort) {
  // This is a stub for PTCP/Tou handshake per EV-031 (DHProxyClientAddPortEx)
  // Real implementation would use the P2PDll exports or reimplemented PTCP protocol
  log('TOU handshake stub - would connect to', relayHost, relayPort, 'and map local port', localPort);
  return { success: true, localPort };
}

async function main() {
  if (!SN) { log('Usage: SN=<serial> USER=<user> PASS=<pass> node src/index.js'); process.exit(1); }
  log('Starting P2P probe for SN:', SN);
  
  // Step 1: Easy4IP SOAP lookup (EV-032)
  try {
    const soapResp = await soapGetDeviceByDevSequence(SN);
    log('SOAP response length:', soapResp.length);
    // Parse for easy4ipcloud URL, relay host, etc.
  } catch (e) { log('SOAP failed:', e.message); }
  
  // Step 2: Easy4IP HTTP/JSON device info (EV-032)
  // Step 3: PTCP/Tou handshake (EV-031)
  // Step 4: Local port forward verification
  
  log('Probe complete (stub). Full implementation requires reimplementation of PTCP/Tou per ADR-0009.');
}

main().catch(e => { log('Fatal:', e); process.exit(1); });