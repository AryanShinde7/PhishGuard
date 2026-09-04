// src/pages/DomainLookup.jsx — Search any domain for its detection history

import { useState } from 'react';
import { getDomain } from '../api/client';
import RiskBadge from '../components/RiskBadge';
import ScoreBar from '../components/ScoreBar';
import {
  Globe, Search, AlertTriangle, ShieldCheck,
  BarChart2, TrendingUp, ShieldX
} from 'lucide-react';

export default function DomainLookup() {
  const [query, setQuery]   = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoad]  = useState(false);
  const [error, setError]   = useState(null);

  const search = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoad(true); setError(null); setResult(null);
    try {
      const data = await getDomain(query.trim().toLowerCase().replace(/https?:\/\//, ''));
      setResult(data);
    } catch {
      setError('Domain not found or backend error.');
    } finally {
      setLoad(false);
    }
  };

  const summaryCards = result ? [
    { label: 'Total Hits', value: result.summary?.totalHits, Icon: BarChart2,  color: '#2F4157' },
    { label: 'Avg Score',  value: result.summary?.avgScore,  Icon: TrendingUp, color: '#D99000' },
    { label: 'High Risk',  value: result.summary?.highRisk,  Icon: ShieldX,    color: '#DC3B3B' },
  ] : [];

  return (
    <div className="page-content">
      <div className="section-header">
        <div>
          <div className="section-title">Domain Lookup</div>
          <div className="section-subtitle">Check detection history and threat intelligence for any domain</div>
        </div>
      </div>

      {/* Search Form */}
      <div className="card" style={{ marginBottom: 20 }}>
        <form onSubmit={search} style={{ display: 'flex', gap: 12 }}>
          <div className="search-bar" style={{ flex: 1, marginBottom: 0 }}>
            <Globe size={15} strokeWidth={1.75} className="search-icon" />
            <input
              placeholder="Enter domain (e.g. paypal-verify.tk)…"
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-primary" style={{ padding: '9px 22px' }}>
            {loading
              ? <div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
              : <><Search size={14} strokeWidth={2} /> Search</>
            }
          </button>
        </form>
      </div>

      {/* No Result */}
      {error && (
        <div className="empty-state">
          <AlertTriangle size={38} strokeWidth={1.5} className="empty-icon-svg" />
          <div className="empty-title">No results</div>
          <div className="empty-sub">{error}</div>
        </div>
      )}

      {result && (
        <>
          {/* Summary Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 20 }}>
            {summaryCards.map(item => (
              <div key={item.label} className="card" style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '18px 20px' }}>
                <item.Icon size={26} strokeWidth={1.5} style={{ color: item.color, flexShrink: 0 }} />
                <div>
                  <div style={{ fontSize: 11, color: '#8BA5B5', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.5px', marginBottom: 2 }}>
                    {item.label}
                  </div>
                  <div style={{ fontSize: 28, fontWeight: 800, color: item.color, letterSpacing: '-1px' }}>
                    {item.value ?? 0}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Detection rows */}
          {result.data?.length > 0 ? (
            <div className="card">
              <div className="section-title" style={{ marginBottom: 14 }}>
                Detection History —{' '}
                <span style={{ color: '#567C8E', fontWeight: 500 }}>{result.domain}</span>
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
              <ShieldCheck size={38} strokeWidth={1.5} className="empty-icon-svg" />
              <div className="empty-title">No history for this domain</div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
