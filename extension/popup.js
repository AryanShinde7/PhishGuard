/**
 * popup.js — PhishGuard Extension Popup Controller
 *
 * Phase 4: Warning UI & Interactive Safety Actions
 * - Renders dynamic Safe, Suspicious, and High-Risk UI states
 * - Provides non-technical plain language warnings & advisories
 * - "Return to Safety" navigation action for high-risk targets
 * - Collapsible diagnostic accordion
 */

'use strict';

import { analyzeUrl } from './urlAnalyzer.js';
import { calculateRisk } from './riskEngine.js';

// ── DOM references ────────────────────────────────────────────────────────────
const siteDomain            = document.getElementById('siteDomain');
const siteUrl               = document.getElementById('siteUrl');
const riskBadge             = document.getElementById('riskBadge');
const riskLabel             = document.getElementById('riskLabel');
const scoreNum              = document.getElementById('scoreNum');
const scoreBarFill          = document.getElementById('scoreBarFill');
const warningBanner         = document.getElementById('warningBanner');
const bannerIcon            = document.getElementById('bannerIcon');
const bannerTitle           = document.getElementById('bannerTitle');
const bannerDesc            = document.getElementById('bannerDesc');
const safetyActions         = document.getElementById('safetyActions');
const btnReturnSafety       = document.getElementById('btnReturnSafety');
const btnProceedAnyway      = document.getElementById('btnProceedAnyway');
const btnToggleDiagnostics  = document.getElementById('btnToggleDiagnostics');
const diagnosticTitle       = document.getElementById('diagnosticTitle');
const diagnosticCollapse    = document.getElementById('diagnosticCollapse');
const reasonsList           = document.getElementById('reasonsList');
const btnReport             = document.getElementById('btnReport');
const btnSafe               = document.getElementById('btnSafe');

let activeTabId = null;

// ── Helpers ───────────────────────────────────────────────────────────────────

function truncateUrl(url, maxLen = 46) {
  return url.length > maxLen ? url.slice(0, maxLen) + '…' : url;
}

/**
 * Animate numeric counter smoothly
 */
function animateScore(targetScore, duration = 400) {
  const start = 0;
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - (1 - progress) * (1 - progress);
    const current = Math.round(start + (targetScore - start) * ease);
    scoreNum.textContent = current;

    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      scoreNum.textContent = targetScore;
    }
  }
  requestAnimationFrame(update);
}

/**
 * Render Warning Banner state based on Risk Tier
 */
function updateWarningState(risk) {
  warningBanner.className = `warning-banner ${risk.levelKey}`;

  if (risk.level === 'SAFE') {
    bannerIcon.textContent  = '✓';
    bannerTitle.textContent = 'Standard Web Domain';
    bannerDesc.textContent  = 'No anomalous URL structures or spoofing patterns detected. Safe to browse.';
    safetyActions.classList.add('hidden');
  } else if (risk.level === 'SUSPICIOUS') {
    bannerIcon.textContent  = '⚠';
    bannerTitle.textContent = 'Caution: Suspicious Signals';
    bannerDesc.textContent  = 'Unusual domain structure or keywords detected. Avoid entering sensitive passwords or financial details.';
    safetyActions.classList.add('hidden');
  } else {
    // HIGH RISK
    bannerIcon.textContent  = '⛔';
    bannerTitle.textContent = 'Critical Phishing Danger';
    bannerDesc.textContent  = 'Strong characteristics of credential theft or brand spoofing. Do not interact with this page!';
    safetyActions.classList.remove('hidden');
  }
}

/**
 * Render diagnostic reasons and point breakdown
 */
function renderBreakdown(riskResult) {
  reasonsList.innerHTML = '';
  const breakdown = riskResult.breakdown || [];
  const count = breakdown.length;

  diagnosticTitle.textContent = `Diagnostic Indicators (${count})`;

  if (count === 0) {
    const li = document.createElement('li');
    li.innerHTML = '<span class="reason-icon">🛡️</span><span>Clean baseline. No anomalous URL heuristics triggered.</span>';
    reasonsList.appendChild(li);
    return;
  }

  const iconMap = {
    BRAND_IMPERSONATION: '🎭',
    IP_HOST: '🖧',
    AT_SYMBOL: '⚠️',
    INSECURE_HTTP: '🔓',
    PUNYCODE_HOMOGRAPH: '🔤',
    SUSPICIOUS_KEYWORDS: '🔍',
    SUSPICIOUS_TLD: '🚩',
    EXCESSIVE_SUBDOMAINS: '🌐',
    EXCESSIVE_HYPHENS: '🔗',
    REDIRECT_IN_PATH: '🔀',
    LONG_URL: '📏',
    LONG_HOSTNAME: '📏'
  };

  breakdown.forEach((item) => {
    const li = document.createElement('li');
    const icon = iconMap[item.flag] || '⚠️';
    li.innerHTML = `
      <span class="reason-icon">${icon}</span>
      <span>${item.description.replace(/\(\+\d+\s+pts\)/, '')}</span>
      <span class="pts-tag">+${item.points} pts</span>
    `;
    reasonsList.appendChild(li);
  });
}

/**
 * Update UI for browser internal system pages
 */
function handleSpecialPage(url) {
  siteDomain.textContent = 'Internal Browser Page';
  siteUrl.textContent    = url;
  riskBadge.className    = 'risk-badge safe';
  riskLabel.textContent  = '✓  Safe (System)';
  scoreNum.textContent   = '0';
  scoreBarFill.style.width = '0%';
  scoreBarFill.style.background = '#22c55e';
  
  warningBanner.className = 'warning-banner safe';
  bannerIcon.textContent  = '✓';
  bannerTitle.textContent = 'Internal System URL';
  bannerDesc.textContent  = 'Native browser environment. No security risks present.';
  safetyActions.classList.add('hidden');

  diagnosticTitle.textContent = 'Diagnostic Indicators (0)';
  reasonsList.innerHTML = '<li><span class="reason-icon">🛡️</span><span>System page — exempt from external evaluation.</span></li>';
}

// ── Main Controller ───────────────────────────────────────────────────────────
async function init() {
  let tabs;
  try {
    tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch (err) {
    bannerDesc.textContent = 'Error accessing active tab.';
    console.error('[PhishGuard] tabs.query error:', err);
    return;
  }

  const tab = tabs[0];
  if (!tab || !tab.url) {
    siteDomain.textContent = 'No Active Tab';
    siteUrl.textContent    = '—';
    bannerDesc.textContent = 'Unable to read current URL.';
    return;
  }

  activeTabId = tab.id;
  const url = tab.url;

  // Handle internal browser URLs
  if (url.startsWith('chrome://') || url.startsWith('edge://') ||
      url.startsWith('about:')    || url.startsWith('chrome-extension://')) {
    handleSpecialPage(url);
    return;
  }

  // 1. Run URL Analysis
  const analysis = analyzeUrl(url);

  // 2. Compute Transparent Risk Score
  const risk = calculateRisk(analysis);

  // 3. Render Site Info
  siteDomain.textContent = analysis.hostname || 'Unknown Target';
  siteUrl.textContent    = truncateUrl(url);

  // 4. Update Risk Badge & Theme
  riskBadge.className = `risk-badge ${risk.levelKey}`;
  riskLabel.textContent = `${risk.level === 'SAFE' ? '✓' : risk.level === 'SUSPICIOUS' ? '⚠' : '✕'}  ${risk.level}`;

  // 5. Update Warning Banner Card
  updateWarningState(risk);

  // 6. Animate Score Meter & Counter
  animateScore(risk.score);
  scoreBarFill.style.width = `${Math.max(4, risk.score)}%`;
  scoreBarFill.style.background = risk.color;

  // 7. Render Breakdown List
  renderBreakdown(risk);

  // 8. Sync state with background worker
  try {
    chrome.runtime.sendMessage({
      type: 'ANALYZE_URL',
      url: url,
      tabId: tab.id
    });
  } catch (e) {
    // Worker silent catch
  }

  // ── Action Handlers ──────────────────────────────────────────────────────────

  // Return to Safety Action
  btnReturnSafety.addEventListener('click', async () => {
    if (activeTabId) {
      await chrome.tabs.update(activeTabId, { url: 'https://www.google.com' });
      window.close();
    }
  });

  // Dismiss Safety Banner Action
  btnProceedAnyway.addEventListener('click', () => {
    safetyActions.classList.add('hidden');
    bannerDesc.textContent = 'Proceeding with caution. Avoid entering sensitive passwords or payment details.';
  });

  // Collapsible Diagnostics Accordion
  btnToggleDiagnostics.addEventListener('click', () => {
    const isExpanded = btnToggleDiagnostics.getAttribute('aria-expanded') === 'true';
    btnToggleDiagnostics.setAttribute('aria-expanded', !isExpanded);
    diagnosticCollapse.classList.toggle('collapsed', isExpanded);
  });

  // User Reporting Handlers
  btnReport.addEventListener('click', () => {
    chrome.runtime.sendMessage({
      type: 'USER_REPORT',
      url,
      domain: analysis.hostname,
      riskScore: risk.score,
      riskLevel: risk.level,
      reportType: 'suspicious',
    });
    btnReport.textContent = 'Reported ✓';
    btnReport.disabled    = true;
    bannerDesc.textContent = 'Thank you! Threat report logged for community review.';
  });

  btnSafe.addEventListener('click', () => {
    chrome.runtime.sendMessage({
      type: 'USER_REPORT',
      url,
      domain: analysis.hostname,
      riskScore: risk.score,
      riskLevel: risk.level,
      reportType: 'safe',
    });
    btnSafe.textContent = 'Marked Safe ✓';
    btnSafe.disabled    = true;
    bannerDesc.textContent = 'Feedback saved! Domain noted as benign.';
  });
}

// ── Entry point ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
