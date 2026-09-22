// legitimate async widget loader
(function () {
  var s = document.createElement("script");
  s.src = "https://cdn.jsdelivr.net/npm/some-widget@1.2.3/dist/widget.min.js";
  s.async = true;
  (document.head || document.documentElement).appendChild(s);
})();
