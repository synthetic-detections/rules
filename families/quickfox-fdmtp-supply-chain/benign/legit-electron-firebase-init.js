// Benign Electron renderer bootstrap that legitimately loads the Firebase
// compat SDKs and checks a helper process. Structurally similar to a loader
// (Firebase SDK filenames + a process check) but carries none of the campaign
// anchors. Must NOT match the LoaderShape rule.

import { initializeApp } from "https://www.gstatic.com/firebasejs/firebase-app-compat.js";
import "https://www.gstatic.com/firebasejs/firebase-analytics-compat.js";

const app = initializeApp({
  apiKey: "AIzaSyDEMO",
  projectId: "my-desktop-app",
});

// Legit crash-reporter helper presence check
function helperRunning(name) {
  return window.processList && window.processList.includes(name);
}

if (helperRunning("updater.exe")) {
  console.log("auto-updater active");
}
