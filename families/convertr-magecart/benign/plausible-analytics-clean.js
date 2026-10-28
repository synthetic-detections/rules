// Plausible Analytics - lightweight web analytics
// https://plausible.io
(function(){
  "use strict";
  var location = window.location;
  var document = window.document;
  var scriptEl = document.currentScript;
  var endpoint = scriptEl.getAttribute("data-api") || new URL(scriptEl.src).origin + "/api/event";
  function trigger(eventName, options) {
    var payload = {
      n: eventName,
      u: location.href,
      d: scriptEl.getAttribute("data-domain"),
      r: document.referrer || null,
      w: window.innerWidth
    };
    var request = new XMLHttpRequest();
    request.open("POST", endpoint, true);
    request.setRequestHeader("Content-Type", "text/plain");
    request.send(JSON.stringify(payload));
  }
  var lastPage;
  function page() {
    if (lastPage === location.pathname) return;
    lastPage = location.pathname;
    trigger("pageview");
  }
  var history = window.history;
  if (history.pushState) {
    var originalPushState = history.pushState;
    history.pushState = function() {
      originalPushState.apply(this, arguments);
      page();
    };
    window.addEventListener("popstate", page);
  }
  page();
})();
