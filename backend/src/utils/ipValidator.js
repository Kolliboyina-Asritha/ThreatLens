import net from 'net';

/**
 * Checks if a given hostname is a valid IPv4 address.
 * @param {string} hostname
 * @returns {boolean}
 */
export const isIPv4Address = (hostname) => {
  if (!hostname || typeof hostname !== 'string') return false;
  
  // Clean brackets if any
  const cleanHost = hostname.replace(/^\[|\]$/g, '').trim();
  
  // Standard IPv4 regex: 4 decimal octets 0-255
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;
  if (!ipv4Regex.test(cleanHost)) return false;
  
  return net.isIPv4(cleanHost);
};

/**
 * Checks if a given hostname is a valid IPv6 address.
 * @param {string} hostname
 * @returns {boolean}
 */
export const isIPv6Address = (hostname) => {
  if (!hostname || typeof hostname !== 'string') return false;
  const cleanHost = hostname.replace(/^\[|\]$/g, '').trim();
  return net.isIPv6(cleanHost);
};

/**
 * Checks if a given hostname is an IP address (IPv4 or IPv6).
 * @param {string} hostname
 * @returns {boolean}
 */
export const isIPAddress = (hostname) => {
  return isIPv4Address(hostname) || isIPv6Address(hostname);
};
