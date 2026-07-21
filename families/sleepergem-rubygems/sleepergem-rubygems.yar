/*
   SleeperGem — malicious RubyGems dropping a persistent developer-machine backdoor
   (reported 2026-07-20; StepSecurity / The Hacker News — unattributed)
   -----------------------------------------------------------------------
   A Ruby-ecosystem supply-chain cluster. Three gems were published to the
   public RubyGems registry between 2026-07-18 and 2026-07-19:
     - git_credential_manager        (2.8.0, 2.8.1, 2.8.2, 2.8.3)
     - Dendreo                       (1.1.3, 1.1.4)
     - fastlane-plugin-run_tests_firebase_testlab
   They impersonate legitimate tooling and stage a second payload from
   attacker infrastructure.

   Defining tradecraft (this is what the rules anchor on, NOT the gem names,
   which collide with legitimate projects):
     - CI-EVASION: the loader inspects CI/CD environment markers
       (GITHUB_ACTIONS, GITLAB_CI, CI, RUNNER_*) and DECLINES to detonate on
       build systems / sandboxes, firing only on a real developer host.
     - Native daemon dropped under ~/.local/share/gcm/ .
     - Persistence via a cron job AND a systemd user/service unit.
     - Privilege artifact: a setuid-root shell planted at
       /usr/local/sbin/ping6 .
     - Second-stage fetch of an additional payload from a remote server.

   Because "git_credential_manager", "fastlane-plugin-*", and "Dendreo" are
   also names of / adjacent to real software, the IOC rule requires the gem
   name to CO-OCCUR with a malicious version pin or a payload artifact, and
   the behavioral rule keys on the drop-path + setuid-shell + CI-evasion
   combination rather than any single generic token.

   Rule 1 — Behavioral (critical): the backdoor's drop/persist/evade combo.
   Rule 2 — IOC (high): gem names + malicious version pins + drop paths, guarded.
   Rule 3 — Specimen pin (critical): the malicious gemspec/extension shape.

   Sources:
     https://www.stepsecurity.io/blog/sleepergem-compromised-rubygems-drop-persistent-backdoor
     https://thehackernews.com/2026/07/sleepergem-uses-three-malicious.html
     https://www.developer-tech.com/news/sleepergem-rubygems-attack-evades-ci-to-hit-developer-laptops/

   Related: [[vitevenom-npm-blockchain-c2]] [[ironworm-npm-worm]]
            [[famous-chollima-packagist]] — 2026 registry supply-chain wave.
*/

rule SleeperGem_Backdoor_Behavior
{
    meta:
        description = "SleeperGem RubyGems backdoor behavior — CI-evasion env checks + ~/.local/share/gcm daemon drop + cron/systemd persistence + setuid /usr/local/sbin/ping6 shell + second-stage fetch"
        author      = "synthetic-detections"
        date        = "2026-07-21"
        severity    = "critical"
        family      = "sleepergem-rubygems"
        reference   = "https://www.stepsecurity.io/blog/sleepergem-compromised-rubygems-drop-persistent-backdoor"

    strings:
        // Drop path for the native daemon
        $gcm_dir   = ".local/share/gcm" ascii wide nocase

        // Privilege artifact — setuid root shell
        $setuid6   = "/usr/local/sbin/ping6" ascii wide nocase

        // CI/CD evasion — only detonate off a build system
        $ci_gha    = "GITHUB_ACTIONS" ascii wide
        $ci_glci   = "GITLAB_CI" ascii wide
        $ci_runner = "RUNNER_OS" ascii wide
        $ci_ci     = "ENV['CI']" ascii wide nocase

        // Persistence
        $persist_cron    = "crontab" ascii wide nocase
        $persist_systemd = "systemctl" ascii wide nocase
        $persist_unit    = ".service" ascii wide nocase

        // Second-stage staging / exec primitives seen in the loader
        $fetch1    = "Net::HTTP" ascii wide
        $fetch2    = "open-uri" ascii wide nocase
        $chmod_suid= "chmod" ascii wide nocase
        $spawn     = "Process.detach" ascii wide nocase

    condition:
        filesize < 5MB
        and (
            // Core signature: the daemon drop path OR the setuid shell path —
            // both are highly specific to this backdoor.
            (
                any of ($gcm_dir, $setuid6)
                and (
                    any of ($ci_gha, $ci_glci, $ci_runner, $ci_ci)
                    or any of ($persist_cron, $persist_systemd)
                )
            )
            or
            // Alternate: CI-evasion decision + persistence + a staging/exec
            // primitive co-occurring (the loader's shape without needing the
            // exact drop path literal).
            (
                any of ($ci_gha, $ci_glci, $ci_runner, $ci_ci)
                and any of ($persist_cron, $persist_systemd, $persist_unit)
                and any of ($fetch1, $fetch2)
                and any of ($chmod_suid, $spawn, $setuid6, $gcm_dir)
            )
        )
}

rule SleeperGem_Malicious_Gem_IOC
{
    meta:
        description = "SleeperGem IOC — the three trojanised gems + malicious version pins, guarded by co-occurrence with a malicious version or a payload drop-path so legitimate same-named projects do not match"
        author      = "synthetic-detections"
        date        = "2026-07-21"
        severity    = "high"
        family      = "sleepergem-rubygems"
        reference   = "https://thehackernews.com/2026/07/sleepergem-uses-three-malicious.html"

    strings:
        // Gem names (individually collide with legit software -> guarded below)
        $gem_gcm    = "git_credential_manager" ascii wide nocase
        $gem_dendreo= "Dendreo" ascii wide
        $gem_fl     = "fastlane-plugin-run_tests_firebase_testlab" ascii wide nocase

        // Malicious version pins
        $v_gcm_280  = "2.8.0" ascii wide
        $v_gcm_281  = "2.8.1" ascii wide
        $v_gcm_282  = "2.8.2" ascii wide
        $v_gcm_283  = "2.8.3" ascii wide
        $v_den_113  = "1.1.3" ascii wide
        $v_den_114  = "1.1.4" ascii wide

        // Payload artifacts that confirm maliciousness
        $gcm_dir    = ".local/share/gcm" ascii wide nocase
        $setuid6    = "/usr/local/sbin/ping6" ascii wide nocase

    condition:
        filesize < 5MB
        and (
            // A payload artifact alone is a strong signal
            any of ($gcm_dir, $setuid6)
            or
            // A named gem pinned to a known-malicious version
            (
                ($gem_gcm and any of ($v_gcm_280, $v_gcm_281, $v_gcm_282, $v_gcm_283))
                or ($gem_dendreo and any of ($v_den_113, $v_den_114))
            )
            or
            // Any named gem co-occurring with a payload artifact
            (
                any of ($gem_gcm, $gem_dendreo, $gem_fl)
                and any of ($gcm_dir, $setuid6)
            )
        )
}

rule SleeperGem_Malicious_Gemspec_Specimen
{
    meta:
        description = "SleeperGem specimen pin — malicious gemspec/native-extension shape that fetches a second stage and installs the gcm daemon + setuid shell during gem install"
        author      = "synthetic-detections"
        date        = "2026-07-21"
        severity    = "critical"
        family      = "sleepergem-rubygems"
        reference   = "https://www.stepsecurity.io/blog/sleepergem-compromised-rubygems-drop-persistent-backdoor"

    strings:
        $spec       = "Gem::Specification.new" ascii wide
        $ext        = "extensions" ascii wide nocase
        $extconf    = "extconf.rb" ascii wide nocase

        $gcm_dir    = ".local/share/gcm" ascii wide nocase
        $setuid6    = "/usr/local/sbin/ping6" ascii wide nocase
        $ci_gha     = "GITHUB_ACTIONS" ascii wide
        $ci_glci    = "GITLAB_CI" ascii wide
        $fetch1     = "Net::HTTP" ascii wide
        $fetch2     = "open-uri" ascii wide nocase

    condition:
        filesize < 2MB
        and ($spec or $ext or $extconf)
        and any of ($gcm_dir, $setuid6)
        and any of ($ci_gha, $ci_glci)
        and any of ($fetch1, $fetch2)
}
