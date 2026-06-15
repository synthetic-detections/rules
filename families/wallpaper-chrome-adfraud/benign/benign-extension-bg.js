// Benign extension service worker — should NOT match any rule
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.tabs.create({ url: "https://example.com/welcome" });
  }
});

chrome.runtime.setUninstallURL("https://example.com/feedback");

chrome.storage.local.get("settings", (result) => {
  console.log("Settings loaded:", result);
});
