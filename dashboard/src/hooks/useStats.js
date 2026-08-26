// src/hooks/useStats.js — Polls /api/stats every 30 seconds

import { useState, useEffect, useCallback } from 'react';
import { getStats } from '../api/client';

export function useStats(pollMs = 30000) {
  const [stats, setStats]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState(null);

  const fetch = useCallback(async () => {
    try {
      setError(null);
      const data = await getStats();
      setStats(data);
    } catch (e) {
      setError('Failed to load stats. Is the backend running?');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
    const id = setInterval(fetch, pollMs);
    return () => clearInterval(id);
  }, [fetch, pollMs]);

  return { stats, loading, error, refetch: fetch };
}
