import forge from 'node-forge';
import fs from 'node:fs';
import path from 'node:path';

const CERTS_DIR = path.resolve('poc/dss-v2-harness/certs');

if (!fs.existsSync(CERTS_DIR)) {
  fs.mkdirSync(CERTS_DIR, { recursive: true });
}

console.log('Generating certificates with node-forge...');

// 1. Generate Root CA (System CA)
const rootCAKeys = forge.pki.rsa.generateKeyPair(2048);
const rootCA = forge.pki.createCertificate();
rootCA.publicKey = rootCAKeys.publicKey;
rootCA.serialNumber = '01';
rootCA.validity.notBefore = new Date('2024-06-22');
rootCA.validity.notAfter = new Date('2034-06-20');
rootCA.setSubject([{ name: 'commonName', value: 'System CA' }]);
rootCA.setIssuer([{ name: 'commonName', value: 'System CA' }]);
rootCA.setExtensions([
  { name: 'basicConstraints', cA: true },
  { name: 'keyUsage', keyCertSign: true, cRLSign: true },
  { name: 'subjectKeyIdentifier' }
]);
rootCA.sign(rootCAKeys.privateKey, forge.md.sha256.create());

const rootCAKeyPem = forge.pki.privateKeyToPem(rootCAKeys.privateKey);
const rootCACertPem = forge.pki.certificateToPem(rootCA);

fs.writeFileSync(path.join(CERTS_DIR, 'ca-key.pem'), rootCAKeyPem);
fs.writeFileSync(path.join(CERTS_DIR, 'ca-cert.pem'), rootCACertPem);
console.log('Root CA (System CA) generated');

// 2. Generate Server Cert for 1443 (signed by System CA)
const serverKeys = forge.pki.rsa.generateKeyPair(2048);
const serverCert = forge.pki.createCertificate();
serverCert.publicKey = serverKeys.publicKey;
serverCert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
serverCert.validity.notBefore = new Date();
serverCert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
serverCert.setSubject([{ name: 'commonName', value: '10.10.20.120' }]);
serverCert.setIssuer([{ name: 'commonName', value: 'System CA' }]);
serverCert.setExtensions([
  { name: 'basicConstraints', cA: false },
  { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
  { name: 'extKeyUsage', serverAuth: true },
  { name: 'subjectAltName', altNames: [{ type: 2, value: '10.10.20.120' }, { type: 7, ip: '10.10.20.120' }] },
  { name: 'subjectKeyIdentifier' }
]);
serverCert.sign(rootCAKeys.privateKey, forge.md.sha256.create());

const serverKeyPem = forge.pki.privateKeyToPem(serverKeys.privateKey);
const serverCertPem = forge.pki.certificateToPem(serverCert);

fs.writeFileSync(path.join(CERTS_DIR, 'key.pem'), serverKeyPem);
fs.writeFileSync(path.join(CERTS_DIR, 'cert.pem'), serverCertPem);
console.log('Server cert for 1443 generated');

// 3. Generate Server Cert for 9443 (System CA Service - exact production match)
const serverKeys2 = forge.pki.rsa.generateKeyPair(2048);
const serverCert2 = forge.pki.createCertificate();
serverCert2.publicKey = serverKeys2.publicKey;
serverCert2.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
serverCert2.validity.notBefore = new Date('2024-06-22');
serverCert2.validity.notAfter = new Date('2034-06-20');
serverCert2.setSubject([{ name: 'commonName', value: 'System CA Service' }]);
serverCert2.setIssuer([{ name: 'commonName', value: 'System CA' }]);
serverCert2.setExtensions([
  { name: 'basicConstraints', cA: false },
  { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
  { name: 'extKeyUsage', serverAuth: true },
  { name: 'subjectAltName', altNames: [{ type: 2, value: '10.10.20.120' }, { type: 7, ip: '10.10.20.120' }] },
  { name: 'subjectKeyIdentifier' }
]);
serverCert2.sign(rootCAKeys.privateKey, forge.md.sha256.create());

const serverKey2Pem = forge.pki.privateKeyToPem(serverKeys2.privateKey);
const serverCert2Pem = forge.pki.certificateToPem(serverCert2);

// Write separate key files for each certificate
fs.writeFileSync(path.join(CERTS_DIR, 'key.pem'), forge.pki.privateKeyToPem(serverKeys.privateKey));
fs.writeFileSync(path.join(CERTS_DIR, 'cert.pem'), serverCertPem);
console.log('Server cert for 1443 generated');

fs.writeFileSync(path.join(CERTS_DIR, 'key_9443.pem'), forge.pki.privateKeyToPem(serverKeys2.privateKey));
fs.writeFileSync(path.join(CERTS_DIR, 'cert_9443.pem'), serverCert2Pem);
console.log('Server cert for 9443 (System CA Service) generated');

console.log('\nAll certificates generated in', CERTS_DIR);
console.log('Files:');
fs.readdirSync(CERTS_DIR).forEach(f => console.log('  ', f));