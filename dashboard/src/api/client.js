// src/api/client.js — Axios instance with base URL

import axios from 'axios';

const client = axios.create({
  baseURL: '/api',   // Vite proxy forwards to http://localhost:5000/api
  timeout: 10000
});

// ── Helpers ───────────────────────────────────────────────────────
export const getStats      = () => client.get('/stats').then(r => r.data.data);
export const getDetections = (params = {}) => client.get('/detections', { params }).then(r => r.data);
export const getDomain     = (domain) => client.get(`/detections/${domain}`).then(r => r.data);
export const submitReport  = (payload) => client.post('/report', payload).then(r => r.data);
export const submitFeedback = (payload) => client.post('/feedback', payload).then(r => r.data);

export default client;
