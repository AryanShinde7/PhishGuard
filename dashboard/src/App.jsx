// src/App.jsx — Root application with sidebar navigation

import { useState } from 'react';
import Sidebar    from './components/Sidebar';
import Overview   from './pages/Overview';
import Detections from './pages/Detections';
import Feedback   from './pages/Feedback';
import DomainLookup from './pages/DomainLookup';

const PAGE_TITLES = {
  overview:   'Dashboard',
  detections: 'Detections',
  feedback:   'Feedback',
  lookup:     'Domain Lookup',
};

export default function App() {
  const [page, setPage] = useState('overview');

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
          <div className="topbar-title">
            🛡️ PhishGuard <span>/ {PAGE_TITLES[page]}</span>
          </div>
          <div className="topbar-right">
            <div className="live-badge">
              <span className="live-dot" />
              LIVE
            </div>
          </div>
        </header>

        {/* Page */}
        {renderPage()}
      </div>
    </div>
  );
}
