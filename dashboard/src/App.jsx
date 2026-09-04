// src/App.jsx — Root application with sidebar navigation

import { useState } from 'react';
import Sidebar    from './components/Sidebar';
import Overview   from './pages/Overview';
import Detections from './pages/Detections';
import Feedback   from './pages/Feedback';
import DomainLookup from './pages/DomainLookup';
import { RefreshCw, Settings } from 'lucide-react';

const PAGE_TITLES = {
  overview:   { title: 'Dashboard', sub: 'Monitor and analyze phishing threats detected by PhishGuard.' },
  detections: { title: 'Detections', sub: 'Paginated history of all scanned URLs and their risk results.' },
  feedback:   { title: 'Feedback', sub: 'Submit corrections to improve PhishGuard detection accuracy.' },
  lookup:     { title: 'Domain Lookup', sub: 'Check detection history and threat intelligence for any domain.' },
};

export default function App() {
  const [page, setPage] = useState('overview');
  const meta = PAGE_TITLES[page];

  const renderPage = () => {
    switch (page) {
      case 'overview':   return <Overview />;
      case 'detections': return <Detections />;
      case 'feedback':   return <Feedback />;
      case 'lookup':     return <DomainLookup />;
      default:           return <Overview />;
    }
  };

  return (
    <div className="layout">
      <Sidebar active={page} onNav={setPage} />

      <div className="main">
        {/* Topbar */}
        <header className="topbar">
          <div className="topbar-left">
            <div className="topbar-title">{meta.title}</div>
            <div className="topbar-subtitle">{meta.sub}</div>
          </div>
          <div className="topbar-right">
            <div className="live-badge">
              <span className="live-dot" />
              LIVE
            </div>
            <button className="btn-refresh" onClick={() => window.location.reload()}>
              <RefreshCw size={13} strokeWidth={2} />
              Refresh
            </button>
            <div className="user-badge">
              <div className="user-avatar">CY</div>
              CYB02
              <Settings size={13} strokeWidth={1.75} style={{ color: '#8BA5B5' }} />
            </div>
          </div>
        </header>

        {/* Page */}
        {renderPage()}
      </div>
    </div>
  );
}
