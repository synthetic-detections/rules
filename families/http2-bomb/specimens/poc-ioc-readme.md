# HTTP/2 Bomb — public PoC references

- Codex / Calif.io writeup: <https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb>
- PoC repository: <https://github.com/califio/publications/tree/main/MADBugs/http2-bomb>
- CVE for Apache httpd: **CVE-2026-49975** (fix in `mod_http2 v2.0.41`)
- Researcher: Quang Luong (with Jun Rong, Duc Phan)
- Apache committer who shipped the same-day fix: Stefan Eissing

Affected default configs: nginx, Apache httpd, Microsoft IIS, Envoy, Cloudflare Pingora.
