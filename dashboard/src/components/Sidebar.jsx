// src/components/Sidebar.jsx
import { LayoutDashboard, ShieldAlert, MessageSquare, Globe, Shield } from 'lucide-react';

const NAV = [
  { id: 'overview',   label: 'Overview',      Icon: LayoutDashboard },
  { id: 'detections', label: 'Detections',    Icon: ShieldAlert },
  { id: 'feedback',   label: 'Feedback',      Icon: MessageSquare },
  { id: 'lookup',     label: 'Domain Lookup', Icon: Globe },
];

export default function Sidebar({ active, onNav }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">
          <Shield size={18} strokeWidth={2} />
        </div>
        <span className="logo-text">PhishGuard</span>
      </div>

      <nav className="sidebar-nav">
        {NAV.map(({ id, label, Icon }) => (
          <button
            key={id}
            className={`nav-item ${active === id ? 'active' : ''}`}
            onClick={() => onNav(id)}
          >
            <Icon size={18} strokeWidth={1.75} className="nav-icon" />
            {label}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        CYB02 · SIH 2026<br />PhishGuard v0.1.0
      </div>
    </aside>
  );
}
