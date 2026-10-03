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
        $pkg_name    = "\"name\"" ascii
        $pkg_scripts = "\"scripts\"" ascii

        // DirtyBlanket typosquat package names — globally unique identifiers.
        // Each one impersonates a legitimate npm package.
        $typo1  = "\"xeprews\"" ascii
        $typo2  = "\"express-javascript\"" ascii
        $typo3  = "\"express-nodejs\"" ascii
        $typo4  = "\"react-nodejs\"" ascii
        $typo5  = "\"exprdd\"" ascii
        $typo6  = "\"exprrdd\"" ascii
        $typo7  = "\"exptrdd\"" ascii
        $typo8  = "\"exptred\"" ascii
        $typo9  = "\"exptredd\"" ascii

        // Lifecycle hooks — the worm uses preinstall or postinstall
        $hook1 = "\"preinstall\"" ascii
        $hook2 = "\"postinstall\"" ascii

    condition:
        filesize < 128KB
        and $pkg_name
        and $pkg_scripts
        and any of ($typo*)
        and any of ($hook*)
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
        $tor_c2    = "s5n2uyo6gb6dhirsm5pihwohi6e7ayrwojx4xjow4cqabmbowpezenid" ascii nocase
        $email     = "dirtyblanket@proton.me" ascii nocase

        // Campaign-level tokens — unique enough in cluster
        $codeberg  = "hellscripter" ascii
        $svc_name  = "systemd-fontd" ascii
        $npm_acct  = "dirtyblanket" ascii

        // Infrastructure indicators — need co-occurrence
        $wayback   = "web.archive.org" ascii
        $aur       = ".pkg.tar.zst" ascii
        $ssh_prop  = ".ssh/authorized_keys" ascii

    condition:
        filesize < 50MB
        and (
            // The Tor C2 onion address or campaign email are globally unique
            any of ($tor_c2, $email)
            or
            // Otherwise require co-occurrence: fake service name + another
            // campaign indicator (Codeberg account or npm account)
            (
                $svc_name
                and any of ($codeberg, $npm_acct)
            )
            or
            // Propagation cluster: SSH + AUR + Wayback download infra
            // together with at least one campaign anchor
            (
                $wayback and $ssh_prop and $aur
                and any of ($svc_name, $codeberg, $npm_acct)
            )
        )
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
        $tor_c2   = "s5n2uyo6gb6dhirsm5pihwohi6e7ayrwojx4xjow4cqabmbowpezenid" ascii
        $svc      = "systemd-fontd" ascii

    condition:
        // Exact SHA-256 pins for the known specimens (zero-FP)
        hash.sha256(0, filesize) == "65f0a95b24e30305146346cbc2452cfabadab9e1ca35053e1134b67c38919577"  // linux.sh dropper
        or hash.sha256(0, filesize) == "2c9dbc14809f1e1aebda114194368b002acf74c8760b88fc101f625d179793c2"  // systemd-fontd ELF binary
        // Heuristic fallback: small shell script or ELF carrying the Tor C2
        // onion address and the fake service name
        or (
            filesize < 1MB
            and $tor_c2
            and $svc
        )
}
