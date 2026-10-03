/*
   DirtyBlanket — self-propagating npm worm, 2026-10-03
   -----------------------------------------------------
   Compromise via typosquatting npm packages impersonating Express.js and
   React (xeprews, express-javascript, express-nodejs, react-nodejs, exprdd,
   exprrdd, exptrdd, exptred, exptredd). Published under the "dirtyblanket"
   npm account (contact: [email protected]). Payload chain: malicious
   preinstall/postinstall scripts download linux.sh → drops systemd-fontd
   ELF binary (fake systemd service "systemd-fontd") → Tor C2 on
   s5n2uyo6gb6dhirsm5pihwohi6e7ayrwojx4xjow4cqabmbowpezenid.onion:80.
   Propagation: SSH key theft, AUR package poisoning, npm token hijack.
   Node.js binary downloaded from Internet Archive Wayback Machine. Code
   hosted on Codeberg under account "hellscripter" (repo: install-scripts).

   Related families: [[chaindrop-npm-worm]], [[ironworm-npm-worm]],
   [[miasma-redhat-npm]].

   Rule 1 — behavioural: npm manifest carrying a DirtyBlanket typosquat
            package name + lifecycle hook wiring.
   Rule 2 — IOC sweep: Tor C2, Codeberg account, fake service name,
            download infra, campaign email (co-occurrence guarded).
   Rule 3 — specimen pin: SHA-256 pins for the linux.sh dropper and
            systemd-fontd binary, plus heuristic fallback.

   Sources:
     https://safedep.io/dirtyblanket-express-impersonation-npm/
*/

import "hash"

rule DirtyBlanket_NpmManifest
{
    meta:
        description = "npm package.json carrying a DirtyBlanket typosquat package name with a lifecycle hook — worm dropper"
        author      = "synthetic-detections"
        date        = "2026-10-03"
        severity    = "critical"
        family      = "dirtyblanket-npm-worm"
        reference   = "https://safedep.io/dirtyblanket-express-impersonation-npm/"
    strings:
        // Structural anchors — must be a package.json
        $pkg_name    = "\"name\""
        $pkg_scripts = "\"scripts\""
        // DirtyBlanket typosquat package names — globally unique identifiers.
        // Each one impersonates a legitimate npm package.
        $typo1       = "\"xeprews\""
        $typo2       = "\"express-javascript\""
        $typo3       = "\"express-nodejs\""
        $typo4       = "\"react-nodejs\""
        $typo5       = "\"exprdd\""
        $typo6       = "\"exprrdd\""
        $typo7       = "\"exptrdd\""
        $typo8       = "\"exptred\""
        $typo9       = "\"exptredd\""
        // Lifecycle hooks — the worm uses preinstall or postinstall
        $hook1       = "\"preinstall\""
        $hook2       = "\"postinstall\""
    condition:
        $pkg_name and
        $pkg_scripts and
        any of ($typo*) and
        any of ($hook*) and
        filesize < 128KB
}

rule DirtyBlanket_IOC
{
    meta:
        description = "DirtyBlanket IOC sweep — Tor C2, Codeberg infra, fake systemd service, campaign email, Wayback download"
        author      = "synthetic-detections"
        date        = "2026-10-03"
        severity    = "high"
        family      = "dirtyblanket-npm-worm"
        reference   = "https://safedep.io/dirtyblanket-express-impersonation-npm/"
    strings:
        // Globally unique campaign indicators — safe to fire standalone
        $tor_c2   = "s5n2uyo6gb6dhirsm5pihwohi6e7ayrwojx4xjow4cqabmbowpezenid" nocase
        $email    = "dirtyblanket@proton.me" nocase
        // Campaign-level tokens — unique enough in cluster
        $codeberg = "hellscripter"
        $svc_name = "systemd-fontd"
        $npm_acct = "dirtyblanket"
        // Infrastructure indicators — need co-occurrence
        $wayback  = "web.archive.org"
        $aur      = ".pkg.tar.zst"
        $ssh_prop = ".ssh/authorized_keys"
    condition:
        // The Tor C2 onion address or campaign email are globally unique
        // Otherwise require co-occurrence: fake service name + another
        // campaign indicator (Codeberg account or npm account)
        // Propagation cluster: SSH + AUR + Wayback download infra
        // together with at least one campaign anchor
        (
            any of ($tor_c2, $email) or
            $svc_name and any of ($codeberg, $npm_acct) or
            $wayback and $ssh_prop and $aur and any of ($svc_name, $codeberg, $npm_acct)
        ) and
        filesize < 50MB
}

rule DirtyBlanket_Specimen
{
    meta:
        description = "DirtyBlanket specimen pin — SHA-256 for linux.sh dropper and systemd-fontd binary"
        author      = "synthetic-detections"
        date        = "2026-10-03"
        severity    = "critical"
        family      = "dirtyblanket-npm-worm"
        reference   = "https://safedep.io/dirtyblanket-express-impersonation-npm/"
    strings:
        $tor_c2 = "s5n2uyo6gb6dhirsm5pihwohi6e7ayrwojx4xjow4cqabmbowpezenid"
        $svc    = "systemd-fontd"
    condition:
        // Exact SHA-256 pins for the known specimens (zero-FP)
        // linux.sh dropper
        // systemd-fontd ELF binary
        // Heuristic fallback: small shell script or ELF carrying the Tor C2
        // onion address and the fake service name
        hash.sha256(0, filesize) == "65f0a95b24e30305146346cbc2452cfabadab9e1ca35053e1134b67c38919577" or hash.sha256(0, filesize) == "2c9dbc14809f1e1aebda114194368b002acf74c8760b88fc101f625d179793c2" or $tor_c2 and $svc and filesize < 1MB
}
