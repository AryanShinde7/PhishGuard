// src/pages/Overview.jsx — Live stats + charts

import { useStats } from '../hooks/useStats';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';

const COLORS = ['#ff4d6d', '#f0b429', '#22c55e'];

function StatCard({ label, value, icon, type, sub }) {
  return (
    <div className={`stat-card ${type}`}>
      <div className="stat-header">
        <span className="stat-label">{label}</span>
        <span className="stat-icon">{icon}</span>
      </div>
      <div className="stat-value">{value ?? '—'}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#0e1525', border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: 8, padding: '8px 14px', fontSize: 13
    }}>
      <div style={{ color: 'rgba(255,255,255,0.5)', marginBottom: 4 }}>{label}</div>
      <div style={{ color: '#00d4aa', fontWeight: 700 }}>{payload[0].value} detections</div>
    </div>
  );
};

export default function Overview() {
  const { stats, loading, error, refetch } = useStats(30000);

  const pieData = stats ? [
    { name: 'High Risk',  value: stats.highRiskCount   || 0 },
    { name: 'Suspicious', value: stats.suspiciousCount || 0 },
    { name: 'Safe',       value: stats.safeCount       || 0 },
  ] : [];

  const total = stats?.totalScanned || 0;

  return (
    <div className="page-content">
      {/* Header */}
      <div className="section-header">
        <div>
          <div className="section-title">Dashboard Overview</div>
          <div className="section-subtitle">
            {stats?.generatedAt
              ? `Last updated: ${new Date(stats.generatedAt).toLocaleTimeString()}`
              : 'Loading live data...'}
          </div>
        </div>
        <button className="btn-refresh" onClick={refetch}>↻ Refresh</button>
      </div>

      {/* Stat Cards */}
      {loading ? (
        <div className="spinner-wrap"><div className="spinner" /></div>
      ) : error ? (
        <div className="empty-state">
          <div className="empty-icon">⚠️</div>
          <div className="empty-title">Backend Unreachable</div>
          <div className="empty-sub">{error}</div>
        </div>
      ) : (
        <>
          <div className="stats-grid">
            <StatCard label="Total Scanned"  value={total}                    icon="🔍" type="total" sub="All time detections" />
            <StatCard label="High Risk"      value={stats?.highRiskCount}     icon="⛔" type="high"  sub={total ? `${Math.round((stats.highRiskCount/total)*100)}% of total` : ''} />
            <StatCard label="Suspicious"     value={stats?.suspiciousCount}   icon="⚠️" type="susp"  sub={total ? `${Math.round((stats.suspiciousCount/total)*100)}% of total` : ''} />
            <StatCard label="Safe"           value={stats?.safeCount}         icon="✓"  type="safe"  sub={total ? `${Math.round((stats.safeCount/total)*100)}% of total` : ''} />
          </div>

          {/* Charts */}
          <div className="charts-row">
            {/* Area chart — detections per day */}
            <div className="card">
              <div className="section-header" style={{ marginBottom: 16 }}>
                <div className="section-title">Detections — Last 7 Days</div>
              </div>
              {stats?.detectionsByDay?.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={stats.detectionsByDay} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#00d4aa" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#00d4aa" stopOpacity={0}   />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                    <XAxis dataKey="date" tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 11 }} />
                    <YAxis tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 11 }} allowDecimals={false} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="count" stroke="#00d4aa" strokeWidth={2} fill="url(#grad)" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty-state">
                  <div className="empty-icon">📈</div>
                  <div className="empty-title">No data yet</div>
                  <div className="empty-sub">Detections will appear here as the extension scans pages.</div>
                </div>
              )}
            </div>

            {/* Pie chart — risk distribution */}
            <div className="card">
              <div className="section-title" style={{ marginBottom: 16 }}>Risk Distribution</div>
              {total > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80}
                      paddingAngle={3} dataKey="value">
                      {pieData.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}
                    </Pie>
                    <Legend
                      formatter={(val) => <span style={{ color: 'rgba(255,255,255,0.6)', fontSize: 12 }}>{val}</span>}
                    />
                    <Tooltip
                      formatter={(v) => [v, 'Detections']}
                      contentStyle={{ background: '#0e1525', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }}
                      labelStyle={{ color: 'white' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty-state" style={{ padding: '24px' }}>
                  <div className="empty-icon">🥧</div>
                  <div className="empty-sub">No detections yet</div>
                </div>
              )}
            </div>
          </div>

          {/* Top Flags This Week */}
          <div className="card">
            <div className="section-title" style={{ marginBottom: 16 }}>🏆 Top Triggered Flags — This Week</div>
            {stats?.topFlagsThisWeek?.length > 0 ? (
              <div className="flag-list">
                {stats.topFlagsThisWeek.map((item, i) => (
                  <div key={item.flag} className="flag-row">
                    <span className="flag-rank">#{i + 1}</span>
                    <span className="flag-name">{item.flag.replace(/_/g, ' ')}</span>
                    <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%', borderRadius: 4,
                        background: `linear-gradient(90deg, #00d4aa, #a855f7)`,
                        width: `${Math.min(100, (item.count / (stats.topFlagsThisWeek[0]?.count || 1)) * 100)}%`,
                        transition: 'width 0.8s ease'
                      }} />
                    </div>
                    <span className="flag-count">{item.count}×</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state" style={{ padding: '20px' }}>
                <div className="empty-sub">No flag data for this week yet.</div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
