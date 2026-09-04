// src/pages/Overview.jsx — Live stats + charts

import { useStats }      from '../hooks/useStats';
import { useDetections } from '../hooks/useDetections';
import RiskBadge         from '../components/RiskBadge';
import ScoreBar          from '../components/ScoreBar';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend,
  PieChart, Pie, Cell
} from 'recharts';
import {
  ScanLine, ShieldX, TriangleAlert, ShieldCheck,
  AlertTriangle, TrendingUp, ArrowUpRight, ExternalLink
} from 'lucide-react';

/* ── Palette tokens (match CSS variables) ─────────────── */
const C = {
  navy:  '#2F4157',
  blue:  '#567C8E',
  red:   '#DC3B3B',
  amber: '#D99000',
  green: '#16A477',
  muted: '#8BA5B5',
  border:'#C7D9E5',
  bg:    '#F3F6F9',
};

/* ── Mini sparkline bar heights for stat cards ─────────── */
const SPARK = [3, 5, 4, 7, 6, 8, 10, 7, 9, 12, 10, 14];

function SparkBars() {
  const max = Math.max(...SPARK);
  return (
    <div className="stat-bars">
      {SPARK.map((h, i) => (
        <div
          key={i}
          className={`stat-bar ${i === SPARK.length - 1 ? 'active' : ''}`}
          style={{ height: `${(h / max) * 100}%` }}
        />
      ))}
    </div>
  );
}

/* ── Stat Card ─────────────────────────────────────────── */
function StatCard({ label, value, Icon, type, sub }) {
  return (
    <div className={`stat-card ${type}`}>
      <div className="stat-card-top">
        <div>
          <div className="stat-label">{label}</div>
          <div className="stat-value">{value ?? '—'}</div>
          {sub && (
            <div className="stat-sub">
              <span className="change-up">
                <ArrowUpRight size={11} strokeWidth={2.5} />
                {sub}
              </span>
            </div>
          )}
        </div>
        <div className="stat-icon-wrap">
          <Icon size={20} strokeWidth={1.75} />
        </div>
      </div>
      <SparkBars />
    </div>
  );
}

/* ── Custom Chart Tooltip ──────────────────────────────── */
const ChartTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#fff', border: `1px solid ${C.border}`,
      borderRadius: 8, padding: '10px 14px', fontSize: 12,
      boxShadow: '0 4px 16px rgba(47,65,87,0.12)'
    }}>
      <div style={{ color: C.muted, marginBottom: 6, fontWeight: 600 }}>{label}</div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color: p.color, fontWeight: 700, display: 'flex', justifyContent: 'space-between', gap: 16 }}>
          <span>{p.name}</span>
          <span>{p.value}</span>
        </div>
      ))}
    </div>
  );
};

/* ── Pie Legend ────────────────────────────────────────── */
function PieLegendRow({ color, name, value, total }) {
  const pct = total ? Math.round((value / total) * 100) : 0;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
      <span style={{ width: 10, height: 10, borderRadius: '50%', background: color, flexShrink: 0 }} />
      <span style={{ flex: 1, fontSize: 13, color: C.navy }}>{name}</span>
      <span style={{ fontSize: 13, fontWeight: 700, color: C.navy, minWidth: 28, textAlign: 'right' }}>{value}</span>
      <span style={{ fontSize: 12, color: C.muted, minWidth: 40, textAlign: 'right' }}>{pct}%</span>
    </div>
  );
}

/* ── Time formatter ────────────────────────────────────── */
function timeAgo(iso) {
  const d = new Date(iso);
  const m = Math.floor((Date.now() - d) / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return d.toLocaleDateString('en-IN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/* ════════════════════════════════════════════════════════ */
export default function Overview() {
  const { stats, loading, error } = useStats(30000);
  const { data: recentScans }     = useDetections({ page: 1, limit: 6, level: null });

  if (loading) return <div className="spinner-wrap"><div className="spinner" /></div>;

  if (error) return (
    <div className="page-content">
      <div className="empty-state">
        <AlertTriangle size={40} strokeWidth={1.5} className="empty-icon-svg" />
        <div className="empty-title">Backend Unreachable</div>
        <div className="empty-sub">{error}</div>
      </div>
    </div>
  );

  const total      = stats?.totalScanned    || 0;
  const highCount  = stats?.highRiskCount   || 0;
  const suspCount  = stats?.suspiciousCount || 0;
  const safeCount  = stats?.safeCount       || 0;

  /* Pie data */
  const pieData = [
    { name: 'High Risk',  value: highCount,  color: C.red   },
    { name: 'Suspicious', value: suspCount,  color: C.amber },
    { name: 'Safe',       value: safeCount,  color: C.green },
  ];

  /* Line chart — transform detectionsByDay into per-risk counts if available */
  const lineData = (stats?.detectionsByDay || []).map(d => ({
    date: d.date,
    Safe:       d.safe       ?? 0,
    Suspicious: d.suspicious ?? 0,
    'High Risk': d.highRisk  ?? d.count ?? 0,
  }));

  /* Top flags */
  const topFlags   = stats?.topFlagsThisWeek || [];
  const maxFlagCnt = topFlags[0]?.count || 1;

  return (
    <div className="page-content">

      {/* ── Stat Cards ────────────────────────────────────────── */}
      <div className="stats-grid">
        <StatCard
          label="Total Scanned"
          value={total}
          Icon={ScanLine}
          type="total"
          sub={total ? '+12% from last week' : null}
        />
        <StatCard
          label="High Risk"
          value={highCount}
          Icon={ShieldX}
          type="high"
          sub={total ? `+${Math.round((highCount / total) * 100)}% of total` : null}
        />
        <StatCard
          label="Suspicious"
          value={suspCount}
          Icon={TriangleAlert}
          type="susp"
          sub={total ? `+${Math.round((suspCount / total) * 100)}% of total` : null}
        />
        <StatCard
          label="Safe"
          value={safeCount}
          Icon={ShieldCheck}
          type="safe"
          sub={total ? `+${Math.round((safeCount / total) * 100)}% of total` : null}
        />
      </div>

      {/* ── Charts Row ────────────────────────────────────────── */}
      <div className="charts-row">

        {/* Line Chart — Detections last 7 days */}
        <div className="card">
          <div className="section-header" style={{ marginBottom: 18 }}>
            <div className="section-title">Detections — Last 7 Days</div>
          </div>
          {lineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={210}>
              <LineChart data={lineData} margin={{ top: 4, right: 8, left: -24, bottom: 0 }}>
                <CartesianGrid strokeDasharray="4 4" stroke={C.border} />
                <XAxis dataKey="date" tick={{ fill: C.muted, fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: C.muted, fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} />
                <Legend
                  wrapperStyle={{ fontSize: 12, paddingTop: 12 }}
                  formatter={v => <span style={{ color: C.blue, fontWeight: 500 }}>{v}</span>}
                />
                <Line type="monotone" dataKey="Safe"       stroke={C.green} strokeWidth={2} dot={{ r: 3, fill: C.green }} activeDot={{ r: 5 }} />
                <Line type="monotone" dataKey="Suspicious" stroke={C.amber} strokeWidth={2} dot={{ r: 3, fill: C.amber }} activeDot={{ r: 5 }} />
                <Line type="monotone" dataKey="High Risk"  stroke={C.red}   strokeWidth={2} dot={{ r: 3, fill: C.red   }} activeDot={{ r: 5 }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: 32 }}>
              <TrendingUp size={36} strokeWidth={1.5} className="empty-icon-svg" />
              <div className="empty-sub">Detections will appear here as the extension scans pages.</div>
            </div>
          )}
        </div>

        {/* Donut Pie — Risk Distribution */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 16 }}>Risk Distribution</div>
          {total > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%" cy="50%"
                    innerRadius={50} outerRadius={72}
                    paddingAngle={3}
                    dataKey="value"
                    startAngle={90} endAngle={-270}
                  >
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle"
                    style={{ fontSize: 22, fontWeight: 800, fill: C.navy }}>
                    {total}
                  </text>
                  <text x="50%" y="62%" textAnchor="middle" dominantBaseline="middle"
                    style={{ fontSize: 10, fill: C.muted, fontWeight: 500 }}>
                    Total
                  </text>
                </PieChart>
              </ResponsiveContainer>
              <div style={{ marginTop: 8 }}>
                {pieData.map(d => (
                  <PieLegendRow key={d.name} color={d.color} name={d.name} value={d.value} total={total} />
                ))}
              </div>
            </>
          ) : (
            <div className="empty-state" style={{ padding: 24 }}>
              <div className="empty-sub">No detections yet</div>
            </div>
          )}
        </div>
      </div>

      {/* ── Bottom Row ────────────────────────────────────────── */}
      <div className="bottom-row">

        {/* Recent Scans */}
        <div className="card">
          <div className="section-header" style={{ marginBottom: 12 }}>
            <div className="section-title">Recent Scans</div>
            <button className="view-all-link">
              View All <ArrowUpRight size={13} strokeWidth={2} />
            </button>
          </div>
          {recentScans?.length > 0 ? (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>URL / Domain</th>
                    <th>Result</th>
                    <th>Risk Score</th>
                    <th>Reason</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map(d => (
                    <tr key={d._id}>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <ExternalLink size={12} strokeWidth={1.75} style={{ color: C.muted, flexShrink: 0 }} />
                          <div>
                            <div className="cell-domain">{d.domain}</div>
                            <div className="cell-url">{d.url}</div>
                          </div>
                        </div>
                      </td>
                      <td><RiskBadge level={d.riskLevel} /></td>
                      <td><ScoreBar score={d.riskScore} /></td>
                      <td>
                        <span style={{ fontSize: 12, color: C.blue }}>
                          {d.urlFlags?.[0]?.replace(/_/g, ' ') || d.domFlags?.[0]?.replace(/_/g, ' ') || '—'}
                        </span>
                      </td>
                      <td><span className="cell-time">{timeAgo(d.createdAt)}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state" style={{ padding: 24 }}>
              <div className="empty-sub">No recent scans yet.</div>
            </div>
          )}
        </div>

        {/* Detection Categories */}
        <div className="card">
          <div className="section-header" style={{ marginBottom: 16 }}>
            <div className="section-title">Detection Categories</div>
            <span style={{ fontSize: 11.5, color: C.muted, fontWeight: 500 }}>Last 7 Days</span>
          </div>
          {topFlags.length > 0 ? (
            <div className="flag-list">
              {topFlags.slice(0, 8).map((item, i) => (
                <div key={item.flag} className="flag-row">
                  <span className="flag-name">
                    {item.flag.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                  </span>
                  <div className="flag-track">
                    <div
                      className="flag-fill"
                      style={{ width: `${Math.min(100, (item.count / maxFlagCnt) * 100)}%` }}
                    />
                  </div>
                  <span className="flag-count">{item.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state" style={{ padding: 20 }}>
              <div className="empty-sub">No flag data for this week yet.</div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
