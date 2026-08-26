// src/pages/Feedback.jsx — Submit feedback and view feedback stats

import { useState } from 'react';
import { submitFeedback } from '../api/client';

const TYPES = [
  { id: 'suspicious',     label: '🚨 Mark as Suspicious',    color: '#ff4d6d' },
  { id: 'safe',           label: '✅ Mark as Safe',           color: '#22c55e' },
  { id: 'false_positive', label: '🔄 False Positive',         color: '#f0b429' },
  { id: 'false_negative', label: '🔴 False Negative (Missed)', color: '#a855f7' },
];

export default function Feedback() {
  const [url, setUrl]             = useState('');
  const [type, setType]           = useState('');
  const [comment, setComment]     = useState('');
  const [sending, setSending]     = useState(false);
  const [success, setSuccess]     = useState('');
  const [error, setError]         = useState('');

  const submit = async (e) => {
    e.preventDefault();
    if (!url || !type) { setError('URL and feedback type are required.'); return; }
    setSending(true);
    setError('');
    setSuccess('');
    try {
      const res = await submitFeedback({ url, feedbackType: type, comment });
      setSuccess(res.message);
      setUrl(''); setType(''); setComment('');
    } catch {
      setError('Failed to submit. Make sure the backend is running.');
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="page-content">
      <div className="section-header">
        <div>
          <div className="section-title">Submit Feedback</div>
          <div className="section-subtitle">Help improve PhishGuard's detection accuracy</div>
        </div>
      </div>

      <div className="card" style={{ maxWidth: 600 }}>
        <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>

          {/* URL */}
          <div>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Page URL *
            </label>
            <div className="search-bar" style={{ marginBottom: 0 }}>
              <span className="search-icon">🌐</span>
              <input
                type="url"
                placeholder="https://example.com/login"
                value={url}
                onChange={e => setUrl(e.target.value)}
                required
              />
            </div>
          </div>

          {/* Feedback Type */}
          <div>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Feedback Type *
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {TYPES.map(t => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setType(t.id)}
                  style={{
                    padding: '10px 14px',
                    borderRadius: 8,
                    border: `1px solid ${type === t.id ? t.color : 'rgba(255,255,255,0.08)'}`,
                    background: type === t.id ? `${t.color}18` : 'transparent',
                    color: type === t.id ? t.color : 'rgba(255,255,255,0.5)',
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    fontFamily: 'inherit',
                    textAlign: 'left',
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {/* Comment */}
          <div>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Comment (optional)
            </label>
            <textarea
              rows={3}
              placeholder="Additional context about why you're reporting this page…"
              value={comment}
              onChange={e => setComment(e.target.value)}
              maxLength={500}
              style={{
                width: '100%',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 8,
                padding: '10px 14px',
                color: 'rgba(255,255,255,0.9)',
                fontSize: 14,
                fontFamily: 'inherit',
                resize: 'vertical',
                outline: 'none',
              }}
            />
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginTop: 4, textAlign: 'right' }}>
              {comment.length}/500
            </div>
          </div>

          {/* Alerts */}
          {error && (
            <div style={{ padding: '10px 14px', background: 'rgba(255,77,109,0.1)', border: '1px solid rgba(255,77,109,0.25)', borderRadius: 8, color: '#ff4d6d', fontSize: 13 }}>
              ⚠️ {error}
            </div>
          )}
          {success && (
            <div style={{ padding: '10px 14px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: 8, color: '#22c55e', fontSize: 13 }}>
              ✅ {success}
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={sending}
            style={{
              padding: '12px',
              background: 'linear-gradient(135deg, #00d4aa, #a855f7)',
              border: 'none',
              borderRadius: 8,
              color: 'white',
              fontWeight: 700,
              fontSize: 14,
              cursor: sending ? 'not-allowed' : 'pointer',
              opacity: sending ? 0.7 : 1,
              fontFamily: 'inherit',
              transition: 'opacity 0.2s',
            }}
          >
            {sending ? 'Sending…' : '📤 Submit Feedback'}
          </button>
        </form>
      </div>
    </div>
  );
}
