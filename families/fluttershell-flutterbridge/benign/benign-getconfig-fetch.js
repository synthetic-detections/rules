// Ordinary SPA config loader — /getConfig is a common endpoint name.
export async function loadConfig() {
  const r = await fetch("/getConfig", { credentials: "include" });
  if (!r.ok) throw new Error("config load failed");
  return r.json();
}
