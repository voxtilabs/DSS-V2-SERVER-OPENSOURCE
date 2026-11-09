import { parse } from 'pcap-parser';
import fs from 'node:fs';

const PCAP_FILE = 'CAPTURA FILTRADA DSS.pcapng';

console.log('=== Analyzing Production PCAPNG ===\n');

let packetCount = 0;
let conversations = new Map();
let tlsPorts = new Set();
let sipPackets = [];
let udp41641 = [];
let rtspPackets = [];
let rtpPackets = [];
let certInfo = null;

async function analyze() {
  const parser = parse(PCAP_FILE);
  
  for await (const packet of parser) {
    packetCount++;
    
    if (!packet.header || !packet.data) continue;
    
    const eth = packet.data;
    if (!eth.payload) return;
    
    const ip = eth.payload;
    if (!ip || !ip.payload) return;
    
    const srcIp = ip.srcaddr;
    const dstIp = ip.dstaddr;
    const proto = ip.protocol;
    
    // Track conversations
    const convKey = `${srcIp}:${dstIp}:${proto}`;
    if (!conversations.has(convKey)) {
      conversations.set(convKey, { count: 0, bytes: 0, ports: new Set() });
    }
    const conv = conversations.get(convKey);
    conv.count++;
    conv.bytes += packet.header.capturedLength;
    
    if (ip.payload && (ip.payload.dport || ip.payload.sport)) {
      const sport = ip.payload.sport || 0;
      const dport = ip.payload.dport || 0;
      conv.ports.add(sport);
      conv.ports.add(dport);
    }
    
    // TLS ports
    if ((ip.payload.dport === 9443 || ip.payload.sport === 9443) ||
        (ip.payload.dport === 1443 || ip.payload.sport === 1443)) {
      tlsPorts.add(ip.payload.dport);
      tlsPorts.add(ip.payload.sport);
    }
    
    // SIP on UDP 5080
    if (proto === 17 && (ip.payload.dport === 5080 || ip.payload.sport === 5080)) {
      if (ip.payload.payload) {
        const sipData = ip.payload.payload.toString('utf8', 0, Math.min(ip.payload.payload.length, 2000));
        if (sipData.includes('SIP/2.0') || sipData.includes('REGISTER') || sipData.includes('SIP/')) {
          sipPackets.push({
            srcIp, dstIp, sport: ip.payload.sport, dport: ip.payload.dport,
            data: sipData.substring(0, 500),
            timestamp: packet.header.timestampSeconds + packet.header.timestampMicroseconds / 1e6
          });
        }
      }
    }
    
    // UDP 41641
    if (proto === 17 && (ip.payload.dport === 41641 || ip.payload.sport === 41641)) {
      if (ip.payload.payload) {
        udp41641.push({
          srcIp, dstIp, sport: ip.payload.sport, dport: ip.payload.dport,
          payloadHex: ip.payload.payload.toString('hex').substring(0, 200),
          timestamp: packet.header.timestampSeconds + packet.header.timestampMicroseconds / 1e6
        });
      }
    }
    
    // RTSP on 9100 or 554
    if (proto === 6 && (ip.payload.dport === 9100 || ip.payload.sport === 9100 || 
                        ip.payload.dport === 554 || ip.payload.sport === 554)) {
      if (ip.payload.payload) {
        const rtspData = ip.payload.payload.toString('utf8', 0, Math.min(ip.payload.payload.length, 2000));
        if (rtspData.includes('RTSP/1.0') || rtspData.includes('OPTIONS') || 
            rtspData.includes('DESCRIBE') || rtspData.includes('SETUP') ||
            rtspData.includes('PLAY') || rtspData.includes('TEARDOWN')) {
          rtspPackets.push({
            srcIp, dstIp, sport: ip.payload.sport, dport: ip.payload.dport,
            data: rtspData.substring(0, 500),
            timestamp: packet.header.timestampSeconds + packet.header.timestampMicroseconds / 1e6
          });
        }
      }
    }
    
    // Potential RTP (heuristic: high ports, payload looks like RTP)
    if (proto === 17 && ip.payload.dport > 10000 && ip.payload.payload) {
      const payload = ip.payload.payload;
      if (payload.length >= 12 && (payload[0] === 0x80 || payload[0] === 0x81)) {
        rtpPackets.push({
          srcIp, dstIp, sport: ip.payload.sport, dport: ip.payload.dport,
          payloadHex: payload.toString('hex').substring(0, 100),
          timestamp: packet.header.timestampSeconds + packet.header.timestampMicroseconds / 1e6
        });
      }
    }
    
    // Look for certificate info in TLS handshake
    if (proto === 6 && (ip.payload.dport === 9443 || ip.payload.sport === 9443)) {
      if (ip.payload.payload && ip.payload.payload.length > 4) {
        const payload = ip.payload.payload;
        if (payload.length > 10 && payload[0] === 0x16 && payload[1] === 0x03) {
          const dataStr = payload.toString('utf8', 0, Math.min(payload.length, 5000));
          if (dataStr.includes('System CA') || dataStr.includes('System CA Service')) {
            certInfo = dataStr.substring(0, 2000);
          }
        }
      }
    }
  }
  
  console.log('\n=== ANALYSIS COMPLETE ===');
  console.log(`Total packets: ${packetCount}`);
  console.log(`\n--- Conversations (${conversations.size}) ---`);
  for (const [key, val] of conversations.entries()) {
    console.log(`${key}: ${val.count} packets, ${val.bytes} bytes, ports: ${Array.from(val.ports).join(', ')}`);
  }
  
  console.log('\n--- TLS Ports ---');
  console.log(Array.from(tlsPorts).join(', '));
  
  console.log('\n--- SIP Packets (UDP 5080) ---');
  console.log(`Count: ${sipPackets.length}`);
  sipPackets.slice(0, 10).forEach(p => {
    console.log(`${p.srcIp}:${p.sport} -> ${p.dstIp}:${p.dport} @ ${new Date(p.timestamp * 1000).toISOString()}`);
    console.log(`  ${p.data.substring(0, 200)}...`);
  });
  
  console.log('\n--- UDP 41641 Packets ---');
  console.log(`Count: ${udp41641.length}`);
  udp41641.slice(0, 10).forEach(p => {
    console.log(`${p.srcIp}:${p.sport} -> ${p.dstIp}:${p.dport} @ ${new Date(p.timestamp * 1000).toISOString()}`);
    console.log(`  Payload: ${p.payloadHex}...`);
  });
  
  console.log('\n--- RTSP Packets ---');
  console.log(`Count: ${rtspPackets.length}`);
  rtspPackets.slice(0, 10).forEach(p => {
    console.log(`${p.srcIp}:${p.sport} -> ${p.dstIp}:${p.dport} @ ${new Date(p.timestamp * 1000).toISOString()}`);
    console.log(`  ${p.data.substring(0, 200)}...`);
  });
  
  console.log('\n--- RTP Packets ---');
  console.log(`Count: ${rtpPackets.length}`);
  rtpPackets.slice(0, 10).forEach(p => {
    console.log(`${p.srcIp}:${p.sport} -> ${p.dstIp}:${p.dport} @ ${new Date(p.timestamp * 1000).toISOString()}`);
    console.log(`  Payload: ${p.payloadHex}...`);
  });
  
  if (certInfo) {
    console.log('\n--- Certificate Info ---');
    console.log(certInfo);
  }
  
  // Save summary to file
  const summary = {
    packetCount,
    conversations: Array.from(conversations.entries()).map(([k, v]) => ({
      key: k,
      count: v.count,
      bytes: v.bytes,
      ports: Array.from(v.ports)
    })),
    tlsPorts: Array.from(tlsPorts),
    sipPackets: sipPackets.slice(0, 50),
    udp41641: udp41641.slice(0, 50),
    rtspPackets: rtspPackets.slice(0, 50),
    rtpPackets: rtpPackets.slice(0, 50)
  };
  fs.writeFileSync('pcap-analysis-summary.json', JSON.stringify(summary, null, 2));
  console.log('\nSummary saved to pcap-analysis-summary.json');
}

analyze().catch(console.error);