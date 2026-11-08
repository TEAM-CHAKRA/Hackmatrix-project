import crypto from 'node:crypto';

/**
 * Format current date as YYYYMMDD
 */
function getFormattedDate() {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const day = String(now.getUTCDate()).padStart(2, '0');
  return `${year}${month}${day}`;
}

/**
 * Generate 16 random hex characters using crypto.randomBytes
 */
function getRandomHex(bytes = 8) {
  return crypto.randomBytes(bytes).toString('hex').toUpperCase();
}

/**
 * Generate investigation ID: INV-YYYYMMDD-<16hex>
 * e.g., INV-20261107-7F3A2C9D1E4B8A5F
 */
export function generateInvestigationId() {
  return `INV-${getFormattedDate()}-${getRandomHex(8)}`;
}

/**
 * Generate community report ID: CR-YYYYMMDD-<16hex>
 * e.g., CR-20261107-A91B3C4D5E6F7A8B
 */
export function generateCommunityId() {
  return `CR-${getFormattedDate()}-${getRandomHex(8)}`;
}

