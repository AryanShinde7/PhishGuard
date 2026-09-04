// src/pages/Detections.jsx — Paginated detection history table

import { useState } from 'react';
import { useDetections } from '../hooks/useDetections';
import RiskBadge from '../components/RiskBadge';
import ScoreBar from '../components/ScoreBar';
import { Search, RefreshCw, AlertTriangle, ShieldCheck } from 'lucide-react';

const LEVELS = ['All', 'HIGH RISK', 'SUSPICIOUS', 'SAFE'];

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function Detections() {
  const [page, setPage]      = useState(1);
  const [levelFilter, setLF] = useState(null);
  const [search, setSearch]  = useState('');

  const { data, pagination, loading, error, refetch } = useDetections({
    page, limit: 15, level: levelFilter
  });

  const filtered = search
    ? data.filter(d => d.url.includes(search) || d.domain.includes(search))
    : data;

  return (
    <div className="page-content">
      <div className="section-header">
        <div>
          <div className="section-title">Detection History</div>
          <div className="section-subtitle">{pagination.total} total records</div>
        </div>
        <button className="btn-refresh" onClick={refetch}>
          <RefreshCw size={14} strokeWidth={2} />
          Refresh
        </button>
      </div>

      {/* Search */}
      <div className="search-bar">
        <Search size={15} strokeWidth={1.75} className="search-icon" />
        <input
          placeholder="Search by URL or domain…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {/* Level filter pills */}
      <div className="filter-row">
        {LEVELS.map(l => (
          <button
            key={l}
            className={`filter-pill ${(l === 'All' ? !levelFilter : levelFilter === l) ? 'active' : ''}`}
            onClick={() => { setLF(l === 'All' ? null : l); setPage(1); }}
          >
            {l}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="card">
        {loading ? (
          <div className="spinner-wrap"><div className="spinner" /></div>
        ) : error ? (
          <div className="empty-state">
            <AlertTriangle size={38} strokeWidth={1.5} className="empty-icon-svg" />
            <div className="empty-title">Could not load detections</div>
            <div className="empty-sub">{error}</div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <ShieldCheck size={38} strokeWidth={1.5} className="empty-icon-svg" />
            <div className="empty-title">No detections found</div>
            <div className="empty-sub">
              {search ? 'Try a different search term.' : 'Start browsing with the extension to populate detections.'}
            </div>
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Risk</th>
                  <th>Score</th>
                  <th>URL Flags</th>
                  <th>Page Flags</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(d => (
                  <tr key={d._id}>
                    <td>
                      <div className="cell-domain" title={d.url}>{d.domain}</div>
                      <div className="cell-url" title={d.url}>{d.url}</div>
                    </td>
                    <td><RiskBadge level={d.riskLevel} /></td>
                    <td><ScoreBar score={d.riskScore} /></td>
                    <td>
                      <div className="flags-cell">
                        {(d.urlFlags || []).slice(0, 2).map(f => (
                          <span key={f} className="flag-chip url" title={f}>
                            {f.replace(/_/g,' ').toLowerCase()}
                          </span>
                        ))}
                        {(d.urlFlags || []).length > 2 && (
                          <span className="flag-chip url">+{d.urlFlags.length - 2}</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="flags-cell">
                        {(d.domFlags || []).slice(0, 2).map(f => (
                          <span key={f} className="flag-chip dom" title={f}>
                            {f.replace(/_/g,' ').toLowerCase()}
                          </span>
                        ))}
                        {(d.domFlags || []).length > 2 && (
                          <span className="flag-chip dom">+{d.domFlags.length - 2}</span>
                        )}
                      </div>
                    </td>
                    <td><span className="cell-time">{timeAgo(d.createdAt)}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pagination.totalPages > 1 && (
          <div className="pagination">
            <button className="page-btn" disabled={page === 1} onClick={() => setPage(p => p - 1)}>‹</button>
            <span className="page-info">Page {page} of {pagination.totalPages}</span>
            <button className="page-btn" disabled={page >= pagination.totalPages} onClick={() => setPage(p => p + 1)}>›</button>
          </div>
        )}
      </div>
    </div>
  );
}
