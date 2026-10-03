/*
   Miasma — Mini Shai-Hulud npm worm against @redhat-cloud-services
   ----------------------------------------------------------------
   Disclosed 2026-06-01 (Wiz, Aikido, Snyk, JFrog); Red Hat confirmed
   2026-06-02 via RHSB-2026-006 — root cause was a hijacked GitHub
   account, which then drove the CI/CD pipeline to publish trojanised
   versions via OIDC.

   32 packages, 96 versions, ~80-117k weekly downloads. preinstall script
   executes a heavily obfuscated index.js whose payload sweeps GitHub
   Actions secrets, AWS/GCP/Azure credentials, Vault tokens, Kubernetes
   kubeconfigs, npm/PyPI publish tokens, SSH keys, GPG keys, and .env
   files. Payload is uniquely-encrypted per infection — hash IOCs are
   not durable.

   Lineage: derivative of the Mini Shai-Hulud worm open-sourced by
   TeamPCP, with cosmetic Dune → Greek-mythology rebranding ("spartan"
   markers, repo description "Miasma: The Spreading Blight"). Researchers
   explicitly caveat that this is TTP overlap rather than confirmed
   attribution.

   Rule 1 — obfuscated index.js behavioural: eval() + ROT-decode helper
            + GCP UA + size-band on the unusually large payload file.
   Rule 2 — package.json scope+preinstall pin: any @redhat-cloud-services
            package.json wired to run a preinstall on index.js.
   Rule 3 — IOC sweep: 32 affected package names, "spartan" / "Miasma:
            The Spreading Blight" themed strings, the GCP UA fingerprint.

   Sibling family: [[ironworm-npm-worm]] — Rust+eBPF evolution of the
   same supply-chain playbook.

   Sources:
     https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages
     https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm
     https://snyk.io/blog/miasma-supply-chain-attack-malicious-code-redhat-cloud-services-npm-packages/
     https://access.redhat.com/security/vulnerabilities/RHSB-2026-006
*/

rule Miasma_ObfuscatedIndexJS {
    meta:
        description = "Heavily obfuscated index.js payload pattern used by Miasma — eval + ROT-decoding + Google API UA + credential-sweep target list"
        author = "synthetic-detections"
        date = "2026-06-05"
        severity = "critical"
        family = "miasma-redhat-npm"
        reference = "https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages"
    strings:
        // eval() over a decoded string — the headline obfuscation tell
        $eval_call = /eval\s*\(\s*[A-Za-z_$][\w$]{0,32}\s*\)/
        // ROT-13 / ROT-N character-rotation helpers (Wiz: "ROT-based decoding")
        $rot_helper_a = /String\.fromCharCode\s*\([^)]{0,80}\+\s*1?3\s*\)/
        $rot_helper_b = /charCodeAt\s*\([^)]{0,40}\)\s*[-+]\s*1?3\b/
        // Distinctive GCP UA observed in Miasma traffic
        $gcp_ua = "google-api-nodejs-client/7.0.0 gl-node/20.11.0 gccl/7.0.0"
        // Credential-sweep target tokens — at least two co-occurring
        // indicate the payload is hunting cloud secrets, not legitimate
        // service-account use.
        $cred_aws = "AWS_ACCESS_KEY_ID"
        $cred_gcp = "GOOGLE_APPLICATION_CREDENTIALS"
        $cred_az = "AZURE_CLIENT_SECRET"
        $cred_npm = "NPM_TOKEN"
        $cred_gha = "ACTIONS_RUNTIME_TOKEN"
        $cred_vault = "VAULT_TOKEN"
        $cred_kube = "/.kube/config"
        $cred_ssh = "/.ssh/"
    condition:
        $eval_call and ($gcp_ua or any of ($rot_helper_a, $rot_helper_b) and 3 of ($cred_aws, $cred_gcp, $cred_az, $cred_npm, $cred_gha, $cred_vault, $cred_kube, $cred_ssh)) and filesize > 32KB and filesize < 5MB
}

rule Miasma_NpmPackageManifest {
    meta:
        description = "package.json under @redhat-cloud-services scope wired to run index.js as a preinstall hook — the Miasma delivery shape"
        author = "synthetic-detections"
        date = "2026-06-05"
        severity = "critical"
        family = "miasma-redhat-npm"
        reference = "https://access.redhat.com/security/vulnerabilities/RHSB-2026-006"
    strings:
        $scope = "@redhat-cloud-services/"
        $pkg_scripts = "\"scripts\""
        $pkg_preinst = "\"preinstall\""
        $preinst_idx = /"preinstall"\s*:\s*"[^"]{0,40}(node\s+)?\.?\/?index\.js[^"]{0,40}"/
    condition:
        $scope and $pkg_scripts and $pkg_preinst and $preinst_idx and filesize < 256KB
}

rule Miasma_IOC {
    meta:
        description = "Static IOC sweep — 32 @redhat-cloud-services package coordinates, Miasma/spartan thematic strings, GCP user-agent fingerprint"
        author = "synthetic-detections"
        date = "2026-06-05"
        severity = "high"
        family = "miasma-redhat-npm"
        reference = "https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages"
    strings:
        // Campaign / rebranding markers (Dune → Greek mythology cosmetic shift)
        $theme_miasma = "Miasma: The Spreading Blight" nocase
        $theme_spartan = "spartan" nocase
        $gcp_ua = "google-api-nodejs-client/7.0.0 gl-node/20.11.0 gccl/7.0.0"
        // Affected npm package coordinates under @redhat-cloud-services scope.
        // A representative subset — Wiz's full table lists 32 packages / 96
        // versions; matching any one is sufficient for the IOC sweep.
        $pkg01 = "@redhat-cloud-services/frontend-components"
        $pkg02 = "@redhat-cloud-services/rbac-client"
        $pkg03 = "@redhat-cloud-services/chrome"
        $pkg04 = "@redhat-cloud-services/frontend-components-utilities"
        $pkg05 = "@redhat-cloud-services/frontend-components-notifications"
        $pkg06 = "@redhat-cloud-services/host-inventory"
        $pkg07 = "@redhat-cloud-services/insights-common-typescript"
        $pkg08 = "@redhat-cloud-services/types"
        // Specific vulnerable version pins reported by Wiz
        $ver1 = "frontend-components@7.7.2"
        $ver2 = "frontend-components@7.7.3"
        $ver3 = "frontend-components@7.7.5"
        $ver4 = "rbac-client@9.0.3"
        $ver5 = "rbac-client@9.0.4"
        $ver6 = "rbac-client@9.0.6"
        $ver7 = "chrome@2.3.1"
    condition:
        // Verbatim campaign phrase or fingerprint — high-confidence
        // Or a specific known-bad version pin
        // Or "spartan" marker co-occurring with at least one package name
        // (raw "spartan" alone is a noisy English word)
        // NOTE: bare @redhat-cloud-services package *names* are not IOCs
        // on their own — any legitimate consumer app or lockfile lists
        // several of them. Detection here requires a compromised version
        // pin ($ver*), a campaign theme, or the GCP UA fingerprint.
        ($theme_miasma or $gcp_ua or any of ($ver*) or $theme_spartan and any of ($pkg*)) and filesize < 50MB
}
