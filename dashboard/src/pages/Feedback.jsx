// src/pages/Feedback.jsx — Submit feedback

import { useState } from 'react';
import { submitFeedback } from '../api/client';
import {
  ShieldAlert, ShieldCheck, RefreshCcw, CircleX,
  Globe, Send, CheckCircle, AlertCircle
} from 'lucide-react';

const TYPES = [
  { id: 'suspicious',     label: 'Mark as Suspicious',     Icon: ShieldAlert,  color: '#DC3B3B', bg: '#FEF1F1', border: '#F5C6C6' },
  { id: 'safe',           label: 'Mark as Safe',            Icon: ShieldCheck,  color: '#16A477', bg: '#EAF8F3', border: '#A8DFC9' },
  { id: 'false_positive', label: 'False Positive',          Icon: RefreshCcw,   color: '#D99000', bg: '#FFF8E6', border: '#F5DFA0' },
  { id: 'false_negative', label: 'False Negative (Missed)', Icon: CircleX,      color: '#567C8E', bg: '#E3ECF2', border: '#C7D9E5' },
];

export default function Feedback() {
  const [url, setUrl]         = useState('');
  const [type, setType]       = useState('');
  const [comment, setComment] = useState('');
  const [sending, setSending] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError]     = useState('');

  const submit = async (e) => {
    e.preventDefault();
    if (!url || !type) { setError('URL and feedback type are required.'); return; }
    setSending(true); setError(''); setSuccess('');
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

  const labelStyle = {
    display: 'block', fontSize: 11, fontWeight: 600,
    color: '#8BA5B5', marginBottom: 8,
    textTransform: 'uppercase', letterSpacing: '0.6px'
  };

  return (
    <div className="page-content">
      <div className="section-header">
        <div>
          <div className="section-title">Submit Feedback</div>
          <div className="section-subtitle">Help improve PhishGuard's detection accuracy</div>
        </div>
      </div>

      <div className="card" style={{ maxWidth: 580 }}>
        <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* URL */}
          <div>
            <label style={labelStyle}>Page URL *</label>
            <div className="search-bar" style={{ marginBottom: 0 }}>
              <Globe size={15} strokeWidth={1.75} className="search-icon" />
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
            <label style={labelStyle}>Feedback Type *</label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {TYPES.map(t => {
                const selected = type === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setType(t.id)}
                    style={{
                      padding: '10px 14px',
                      borderRadius: 8,
                      border: `1px solid ${selected ? t.color : '#C7D9E5'}`,
                      background: selected ? t.bg : '#F3F6F9',
                      color: selected ? t.color : '#567C8E',
                      fontSize: 13, fontWeight: 600,
                      cursor: 'pointer', transition: 'all 0.18s',
                      fontFamily: 'Inter, sans-serif', textAlign: 'left',
                      display: 'flex', alignItems: 'center', gap: 8,
                    }}
                  >
                    <t.Icon size={15} strokeWidth={1.75} />
                    {t.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Comment */}
          <div>
            <label style={labelStyle}>Comment (optional)</label>
            <textarea
              rows={3}
              placeholder="Additional context about why you're reporting this page…"
              value={comment}
              onChange={e => setComment(e.target.value)}
              maxLength={500}
              style={{
                width: '100%', background: '#F3F6F9',
                border: '1px solid #C7D9E5', borderRadius: 8,
                padding: '10px 14px', color: '#2F4157',
                fontSize: 13.5, fontFamily: 'Inter, sans-serif',
                resize: 'vertical', outline: 'none',
                transition: 'border-color 0.18s',
              }}
              onFocus={e => e.target.style.borderColor = '#567C8E'}
              onBlur={e => e.target.style.borderColor = '#C7D9E5'}
            />
            <div style={{ fontSize: 11, color: '#8BA5B5', marginTop: 4, textAlign: 'right' }}>
              {comment.length}/500
            </div>
          </div>

          {/* Alerts */}
          {error && (
            <div style={{
              padding: '10px 14px', background: '#FEF1F1',
              border: '1px solid #F5C6C6', borderRadius: 8,
              color: '#DC3B3B', fontSize: 13,
              display: 'flex', alignItems: 'center', gap: 8
            }}>
              <AlertCircle size={15} strokeWidth={1.75} />
              {error}
            </div>
          )}
          {success && (
            <div style={{
              padding: '10px 14px', background: '#EAF8F3',
              border: '1px solid #A8DFC9', borderRadius: 8,
              color: '#16A477', fontSize: 13,
              display: 'flex', alignItems: 'center', gap: 8
            }}>
              <CheckCircle size={15} strokeWidth={1.75} />
              {success}
            </div>
          )}

          {/* Submit */}
          <button type="submit" disabled={sending} className="btn-primary">
            <Send size={15} strokeWidth={1.75} />
            {sending ? 'Sending…' : 'Submit Feedback'}
          </button>
        </form>
      </div>
    </div>
  );
}
