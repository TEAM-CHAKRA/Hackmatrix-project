import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

/**
 * "Scan Now": open /scanner and focus the investigation input.
 * A fresh timestamp in router state means clicking it while already on
 * /scanner still triggers the focus (the Scanner page listens for it).
 */
export function useScanNow() {
  const navigate = useNavigate();
  return useCallback(() => {
    navigate('/scanner', { state: { focusScanner: Date.now() } });
  }, [navigate]);
}
