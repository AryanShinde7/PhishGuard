// src/components/Sidebar.jsx

import { useState } from 'react';

const NAV = [
  { id: 'overview',   label: 'Overview',    icon: '📊' },
  { id: 'detections', label: 'Detections',  icon: '🔍' },
  { id: 'feedback',   label: 'Feedback',    icon: '💬' },
  { id: 'lookup',     label: 'Domain Lookup', icon: '🌐' },
];

export default function Sidebar({ active, onNav }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">🛡️</div>
        <span className="logo-text">PhishGuard</span>
      </div>

      <nav className="sidebar-nav">
        {NAV.map(item => (
          <button
            key={item.id}
            className={`nav-item ${active === item.id ? 'active' : ''}`}
            onClick={() => onNav(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        SIH 2026 · CYB02<br />PhishGuard v0.1.0
      </div>
    </aside>
  );
}
