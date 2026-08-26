// src/hooks/useDetections.js — Fetches and paginates detections

import { useState, useEffect, useCallback } from 'react';
import { getDetections } from '../api/client';

export function useDetections({ page = 1, limit = 15, level = null } = {}) {
  const [data, setData]       = useState([]);
  const [pagination, setPag]  = useState({ total: 0, totalPages: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, limit };
      if (level) params.level = level;
      const res = await getDetections(params);
      setData(res.data || []);
      setPag(res.pagination || { total: 0, totalPages: 0 });
      setError(null);
    } catch (e) {
      setError('Failed to load detections.');
    } finally {
      setLoading(false);
    }
  }, [page, limit, level]);

  useEffect(() => { fetch(); }, [fetch]);

  return { data, pagination, loading, error, refetch: fetch };
}
