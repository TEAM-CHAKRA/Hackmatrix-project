import { useCallback, useEffect, useRef, useState } from 'react';
import { getInvestigation } from '../services/api.js';

const POLL_MS = 1200;
const MAX_POLL_MS = 3 * 60 * 1000;

/** Fetches a report and polls while it is still processing. */
export function useInvestigation(id) {
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const startedRef = useRef(Date.now());

  const load = useCallback(async () => {
    try {
      const data = await getInvestigation(id);
      setReport(data.report);
      setError(null);
      return data.report;
    } catch (err) {
      setError(err);
      return null;
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    let cancelled = false;
    let timer;
    startedRef.current = Date.now();
    setLoading(true);
    setReport(null);
    setError(null);

    const tick = async () => {
      const r = await load();
      if (cancelled) return;
      if (r && r.status === 'processing') {
        if (Date.now() - startedRef.current > MAX_POLL_MS) {
          setError(new Error('The investigation is taking longer than expected. Refresh to check again.'));
          return;
        }
        timer = setTimeout(tick, POLL_MS);
      }
    };
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [id, load]);

  return { report, setReport, error, loading, reload: load };
}
