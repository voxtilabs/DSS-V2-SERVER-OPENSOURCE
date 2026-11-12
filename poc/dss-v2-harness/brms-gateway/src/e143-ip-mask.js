// ===== E-143a: never leak the camera's internal IP through tree payloads =====
//
// The real camera (e.g. D0238JDG3016 at 192.168.0.238) lives server-side only.
// Every tree node that carries deviceIp/ipcIp must show the gateway address
// (PUBLIC_HOST) instead — the media path is already server-provided
// (rtsp://PUBLIC_HOST:9100/...), so the client never needs the camera address.
//
// Live evidence (2026-11-11): deviceOrg (5 occurrences) and tree/devices
// (12 occurrences) payloads exposed 192.168.0.238 to the client.
// Scope: tree emitters only (e037 native tree, e124 grade tree, e139 paged
// tree). Admin/device-management endpoints keep the real IP — those are the
// operator's own views, not client-facing tree data.

export const PUBLIC_DEVICE_IP = process.env.PUBLIC_HOST || '10.10.20.120';

/**
 * Tree-payload view of a device IP: always the gateway, never the camera.
 * Empty stays empty (same contract as before for IP-less devices).
 */
export function maskDeviceIp(device) {
  const raw = String(device?.deviceIp || '').trim();
  return raw ? PUBLIC_DEVICE_IP : '';
}
