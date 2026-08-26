// src/pages/DomainLookup.jsx — Search any domain for its detection history

import { useState } from 'react';
import { getDomain } from '../api/client';
import RiskBadge from '../components/RiskBadge';
import ScoreBar from '../components/ScoreBar';

export default function DomainLookup() {
  const [query, setQuery]   = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoad]  = useState(false);
  const [error, setError]   = useState(null);

  const search = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoad(true);
    setError(null);
    setResult(null);
    try {
      const data = await getDomain(query.trim().toLowerCase().replace(/https?:\/\//, ''));
      setResult(data);
    } catch {
      setError('Domain not found or backend error.');
    } finally {
      setLoad(false);
    }
  };

  return (
    <div className="page-content">
      <div className="section-header">
        <div>
          <div className="section-title">Domain Lookup</div>
          <div className="section-subtitle">Check detection history for any domain</div>
        </div>
      </div>

      {/* Search Form */}
      <div className="card" style={{ marginBottom: 20 }}>
        <form onSubmit={search} style={{ display: 'flex', gap: 12 }}>
          <div className="search-bar" style={{ flex: 1, marginBottom: 0 }}>
            <span className="search-icon">🌐</span>
            <input
              placeholder="Enter domain (e.g. paypal-verify.tk)…"
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-refresh" style={{ padding: '8px 20px' }}>
            {loading ? '…' : 'Search'}
          </button>
        </form>
      </div>

      {/* Result */}
      {error && (
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <div className="empty-title">No results</div>
          <div className="empty-sub">{error}</div>
        </div>
      )}

      {result && (
        <>
          {/* Summary Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 20 }}>
            {[
              { label: 'Total Hits',   value: result.summary?.totalHits,  icon: '📊', color: '#00d4aa' },
              { label: 'Avg Score',    value: result.summary?.avgScore,   icon: '📈', color: '#f0b429' },
              { label: 'High Risk',    value: result.summary?.highRisk,   icon: '⛔', color: '#ff4d6d' },
            ].map(item => (
              <div key={item.label} className="card" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <span style={{ fontSize: 28 }}>{item.icon}</span>
                <div>
                  <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', fontWeight: 600 }}>{item.label}</div>
                  <div style={{ fontSize: 28, fontWeight: 800, color: item.color }}>{item.value ?? 0}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Detection rows */}
          {result.data?.length > 0 ? (
            <div className="card">
              <div className="section-title" style={{ marginBottom: 16 }}>
                Detection History — <span style={{ color: '#00d4aa' }}>{result.domain}</span>
              </div>
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>URL</th>
                      <th>Risk</th>
                      <th>Score</th>
                      <th>Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.data.map(d => (
                      <tr key={d._id}>
                        <td><div className="cell-url" title={d.url}>{d.url}</div></td>
                        <td><RiskBadge level={d.riskLevel} /></td>
                        <td><ScoreBar score={d.riskScore} /></td>
                        <td><span className="cell-time">{new Date(d.createdAt).toLocaleDateString()}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-icon">🛡️</div>
              <div className="empty-title">No history for this domain</div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
