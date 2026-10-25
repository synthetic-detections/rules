Benign test corpus for k0t / Stray Cat rules.

Rule 1 (AdaptixC2 beacon) requires co-occurrence of AdaptixC2 strings
AND campaign-specific infrastructure IPs/domains. Generic AdaptixC2
documentation or GitHub source code should NOT match, because the
infrastructure strings won't co-occur.

Rule 2 (IOC co-occurrence) requires >=2 indicators. A file containing
only one domain or one hash should not trigger.

Suggested benign files:
- AdaptixC2 GitHub README (contains "adaptixc2" but no campaign infra)
- MeshCentral documentation (contains "meshcentral" but not the specific
  campaign subdomains)
- Generic FortiGate security advisory text
