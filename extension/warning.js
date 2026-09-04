/**
 * warning.js — Logic & Interactivity for PhishGuard Interstitial Block Page
 */

'use strict';

document.addEventListener('DOMContentLoaded', () => {
  // Extract query parameters
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url') || '';
  const initialScore = parseInt(params.get('score'), 10) || 75;
  const initialLevel = params.get('level') || 'HIGH RISK';
  
  let initialReasons = [];
  try {
    const rawReasons = params.get('reasons');
    if (rawReasons) {
      initialReasons = JSON.parse(decodeURIComponent(rawReasons));
    }
  } catch (e) {
    console.warn('[PhishGuard Warning] Could not parse query reasons:', e);
  }

  // DOM Elements
  const targetUrlText = document.getElementById('targetUrlText');
  const copyUrlBtn = document.getElementById('copyUrlBtn');
  const copyBtnText = document.getElementById('copyBtnText');
  const goBackBtn = document.getElementById('goBackBtn');
  const viewDetailsBtn = document.getElementById('viewDetailsBtn');
  const detailsPanel = document.getElementById('detailsPanel');
  const riskBadge = document.getElementById('riskBadge');
  const scoreValueBadge = document.getElementById('scoreValueBadge');
  const scoreBarFill = document.getElementById('scoreBarFill');
  const mlCard = document.getElementById('mlCard');
  const mlProbBadge = document.getElementById('mlProbBadge');
  const mlModelVal = document.getElementById('mlModelVal');
  const reasonsContainer = document.getElementById('reasonsContainer');
  const advancedToggle = document.getElementById('advancedToggle');
  const advancedBody = document.getElementById('advancedBody');
  const proceedAnywayBtn = document.getElementById('proceedAnywayBtn');
  const reportFalsePositiveBtn = document.getElementById('reportFalsePositiveBtn');

  // Render initial basic state
  if (targetUrl) {
    targetUrlText.textContent = targetUrl;
  } else {
    targetUrlText.textContent = 'Unknown or invalid destination URL';
  }

  renderScoreAndLevel(initialScore, initialLevel);
  renderReasons(initialReasons);

  // Request rich cached evaluation from background service worker
  if (targetUrl && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'GET_WARNING_DATA',
      url: targetUrl
    }, (response) => {
      if (chrome.runtime.lastError || !response || !response.evaluation) {
        console.log('[PhishGuard Warning] No background cache found, using query params');
        return;
      }

      const evalData = response.evaluation;
      const risk = evalData.risk || {};
      const finalScore = risk.score !== undefined ? risk.score : initialScore;
      const finalLevel = risk.level || initialLevel;
      const breakdown = risk.breakdown || [];
      const mlAnalysis = risk.mlAnalysis || evalData.backendResult?.mlAnalysis;

      renderScoreAndLevel(finalScore, finalLevel);

      // Render breakdown list
      if (breakdown.length > 0) {
        renderReasons(breakdown.map(b => ({
          text: b.description || b.flag,
          points: b.points,
          source: b.source
        })));
      }

      // Render ML statistics if present
      if (mlAnalysis && mlAnalysis.probability !== undefined) {
        const pct = (mlAnalysis.probability * 100).toFixed(1);
        mlProbBadge.textContent = `${pct}% Phishing Probability`;
        mlProbBadge.className = 'metric-badge danger';
        if (mlAnalysis.model) {
          mlModelVal.textContent = mlAnalysis.model;
        }
      } else {
        mlProbBadge.textContent = 'Rule-based heuristic';
        mlProbBadge.className = 'metric-badge ml';
      }
    });
  }

  // ── Functions ──────────────────────────────────────────────────────────────

  function renderScoreAndLevel(score, level) {
    scoreValueBadge.textContent = `${score} / 100`;
    scoreBarFill.style.width = `${Math.min(100, Math.max(10, score))}%`;
    
    if (score >= 60) {
      riskBadge.textContent = 'CRITICAL PHISHING THREAT';
      riskBadge.style.background = 'linear-gradient(90deg, #dc2626, #991b1b)';
    } else {
      riskBadge.textContent = `${level} THREAT`;
    }
  }

  function renderReasons(reasons) {
    reasonsContainer.innerHTML = '';

    if (!reasons || reasons.length === 0) {
      // Default security notices if no granular flags were passed
      const defaults = [
        { text: 'Unverified or deceptive domain structure mimicking trusted entities', points: 20 },
        { text: 'Elevated phishing indicators detected by PhishGuard heuristic engine', points: 15 },
        { text: 'Insecure transport or potential credential harvesting risk', points: 15 }
      ];
      reasons = defaults;
    }

    reasons.forEach(r => {
      const item = document.createElement('div');
      item.className = 'reason-item';

      const iconSvg = `
        <svg class="reason-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
      `;

      const text = typeof r === 'string' ? r : (r.text || r.description || JSON.stringify(r));
      const points = typeof r === 'object' && r.points ? `+${r.points} pts` : '';

      item.innerHTML = `
        ${iconSvg}
        <span class="reason-text">${escapeHtml(text)}</span>
        ${points ? `<span class="reason-tag">${escapeHtml(points)}</span>` : ''}
      `;

      reasonsContainer.appendChild(item);
    });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ── Event Listeners ────────────────────────────────────────────────────────

  // "Go Back to Safety" Button
  if (goBackBtn) {
    goBackBtn.addEventListener('click', () => {
      // If the browser has back history, navigate back
      if (window.history.length > 1) {
        window.history.back();
      } else {
        // No history (e.g. opened directly in new tab or window)
        window.location.href = 'https://www.google.com';
      }
    });
  }

  // "Copy URL" Button
  if (copyUrlBtn) {
    copyUrlBtn.addEventListener('click', async () => {
      if (!targetUrl) return;
      try {
        await navigator.clipboard.writeText(targetUrl);
        if (copyBtnText) copyBtnText.textContent = 'Copied!';
        setTimeout(() => {
          if (copyBtnText) copyBtnText.textContent = 'Copy';
        }, 2000);
      } catch (e) {
        console.error('Failed to copy URL:', e);
      }
    });
  }

  // Proceed Anyway (Bypass)
  if (proceedAnywayBtn) {
    proceedAnywayBtn.addEventListener('click', () => {
      if (!targetUrl) return;

      const confirmed = window.confirm(
        '⚠️ SECURITY WARNING:\n\n' +
        'Are you sure you want to bypass PhishGuard protection and open this website?\n\n' +
        'This website has been identified as high-risk phishing and may attempt to steal your passwords or sensitive information.'
      );

      if (confirmed) {
        chrome.runtime.sendMessage({
          type: 'BYPASS_WARNING',
          url: targetUrl
        }, () => {
          // Navigate to the target URL now that bypass is granted
          window.location.href = targetUrl;
        });
      }
    });
  }

  // Report False Positive
  if (reportFalsePositiveBtn) {
    reportFalsePositiveBtn.addEventListener('click', () => {
      if (!targetUrl) return;

      reportFalsePositiveBtn.disabled = true;
      reportFalsePositiveBtn.textContent = 'Submitting...';

      let targetHostname = '';
      try {
        targetHostname = new URL(targetUrl).hostname;
      } catch {
        targetHostname = targetUrl;
      }

      chrome.runtime.sendMessage({
        type: 'USER_REPORT',
        url: targetUrl,
        domain: targetHostname,
        reportType: 'FALSE_POSITIVE',
        riskScore: initialScore,
        riskLevel: initialLevel
      }, () => {
        reportFalsePositiveBtn.textContent = '✓ Reported as False Positive';
        reportFalsePositiveBtn.style.color = '#34d399';
      });
    });
  }
});
