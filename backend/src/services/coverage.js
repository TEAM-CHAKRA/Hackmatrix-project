import {
  URL_CHECK_IDS,
  MESSAGE_CHECK_IDS,
  COMPLETED_COVERAGE_STATUSES,
} from '../config/constants.js';

/**
 * Calculate investigation check coverage.
 * 
 * Rules:
 * - Only statuses in COMPLETED_COVERAGE_STATUSES ('completed', 'no_match', 'match_found') count as completed.
 * - 'unavailable', 'error', 'not_checked' (or omitted checks) never count and are never treated as clean.
 * - Total expected checks: 6 for 'url', 4 for 'message'.
 * 
 * @param {object} params
 * @param {'url' | 'message'} [params.type='url']
 * @param {Array<{ id: string, status: string }>} [params.checks=[]]
 * @returns {{ completed: number, total: number, missing: string[] }}
 */
export function calculateCoverage({ type = 'url', checks = [] } = {}) {
  const expectedCheckIds = type === 'message' ? MESSAGE_CHECK_IDS : URL_CHECK_IDS;
  const total = expectedCheckIds.length;

  const checksMap = new Map();
  for (const check of checks) {
    if (check && check.id) {
      checksMap.set(check.id, check.status);
    }
  }

  const missing = [];
  let completed = 0;

  for (const checkId of expectedCheckIds) {
    const status = checksMap.get(checkId);
    if (status && COMPLETED_COVERAGE_STATUSES.includes(status)) {
      completed++;
    } else {
      missing.push(checkId);
    }
  }

  return {
    completed,
    total,
    missing,
  };
}

