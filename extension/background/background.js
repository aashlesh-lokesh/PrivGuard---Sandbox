/**
 * PrivGuard Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 * - Badge updates (colour + text based on risk level)
 * - Extension lifecycle management
 * - Context menu for manual page scan
 * - Image OCR relay (content script → background → content script)
 * - Installation / onboarding
 */

'use strict';

/* ═══════════════════════════════════════════════════════════════
   BADGE COLOURS
   ═══════════════════════════════════════════════════════════════ */
const BADGE_COLORS = {
  CRITICAL: '#D63031',
  HIGH:     '#E17055',
  MEDIUM:   '#FDCB6E',
  LOW:      '#00B894',
  NONE:     '#636E72',
};

/* ═══════════════════════════════════════════════════════════════
   MESSAGE HANDLING
   ═══════════════════════════════════════════════════════════════ */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {
    case 'PG_UPDATE_BADGE':
      updateBadge(sender.tab?.id, msg);
      break;

    case 'PG_STATE_UPDATE':
      // Forward state update from content script to popup (if open)
      // The popup also listens via chrome.runtime.onMessage
      break;

    case 'PG_SCAN_IMAGE':
      // For now, respond that OCR in background is not available
      // (OCR via Tesseract.js needs a full page context)
      sendResponse({ findings: [], score: 0, riskLevel: 'NONE' });
      return true; // async response
  }
});

/* ═══════════════════════════════════════════════════════════════
   BADGE
   ═══════════════════════════════════════════════════════════════ */
function updateBadge(tabId, { score, riskLevel, findingsCount }) {
  if (!tabId) return;

  const text = findingsCount > 0 ? String(findingsCount) : '';
  const color = BADGE_COLORS[riskLevel] || BADGE_COLORS.NONE;

  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeTextColor({ color: '#FFFFFF', tabId });

  // Update tooltip
  const title = findingsCount > 0
    ? `PrivGuard: ${findingsCount} finding${findingsCount > 1 ? 's' : ''} (Score: ${score})`
    : 'PrivGuard: No issues detected';
  chrome.action.setTitle({ title, tabId });
}

/* ═══════════════════════════════════════════════════════════════
   CONTEXT MENU
   ═══════════════════════════════════════════════════════════════ */
chrome.runtime.onInstalled.addListener((details) => {
  // Create context menu
  chrome.contextMenus.create({
    id: 'pg-scan-selection',
    title: '🛡️ PrivGuard: Scan selected text',
    contexts: ['selection'],
  });

  chrome.contextMenus.create({
    id: 'pg-scan-page',
    title: '🛡️ PrivGuard: Scan this page',
    contexts: ['page'],
  });

  // Show welcome on first install
  if (details.reason === 'install') {
    chrome.storage.local.set({ pgEnabled: true, pgInstallDate: Date.now() });
  }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab?.id) return;

  if (info.menuItemId === 'pg-scan-selection') {
    // Send selected text to content script for analysis
    chrome.tabs.sendMessage(tab.id, {
      type: 'PG_SCAN_TEXT',
      text: info.selectionText,
    });
  } else if (info.menuItemId === 'pg-scan-page') {
    chrome.tabs.sendMessage(tab.id, {
      type: 'PG_REQUEST_STATE',
    });
  }
});

/* ═══════════════════════════════════════════════════════════════
   TAB EVENTS — reset badge when navigating
   ═══════════════════════════════════════════════════════════════ */
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ text: '', tabId });
    chrome.action.setTitle({ title: 'PrivGuard', tabId });
  }
});

/* ═══════════════════════════════════════════════════════════════
   LIFECYCLE LOG
   ═══════════════════════════════════════════════════════════════ */
console.log('[PrivGuard] Background service worker loaded.');
