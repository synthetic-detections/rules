// Legitimate StreamSaver.js download page (should NOT match).
// Uses a ServiceWorker and octet-stream download the normal way, but has none
// of the SourTrade config-assembly shape (no /config build instructions, no
// standaloneUrl, no Bun/AES-CTR in-browser PE assembly) and not the full
// campaign message triple.
import streamSaver from 'streamsaver';

async function saveReport(rows) {
  const fileStream = streamSaver.createWriteStream('report.csv', { size: undefined });
  const writer = fileStream.getWriter();
  const enc = new TextEncoder();
  for (const r of rows) {
    await writer.write(enc.encode(r.join(',') + '\n'));
  }
  await writer.close();
}

// registers streamsaver's mitm service worker for same-origin download delivery
navigator.serviceWorker.register('/StreamSaver/sw.js');
document.getElementById('dl').addEventListener('click', () => saveReport(window.__rows || []));
