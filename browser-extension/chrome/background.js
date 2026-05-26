// MV3 service worker. Holds the report blob and answers queries from
// the content script / popup.
//
// The user loads a JSON report (the file wpsecscan writes to
// ~/.wpsecscan/reports/) via the popup. We keep it in chrome.storage.local
// indexed by hostname so different sites' reports don't bleed.

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'load_report') {
    chrome.storage.local.set({['report_' + msg.host]: msg.report}, () => {
      sendResponse({ok: true});
    });
    return true;
  }
  if (msg.type === 'get_report') {
    chrome.storage.local.get('report_' + msg.host, (items) => {
      sendResponse(items['report_' + msg.host] || null);
    });
    return true;
  }
});
