#!/usr/bin/env python3
"""
Fabricate a synthetic 'obfuscated index.js root payload' specimen for the
Miasma v2 / Phantom Gyp rule. SAFE — no real exfil, no real Bun download;
just the campaign-unique strings and credential-target tokens the rule
keys on, padded with junk so the file lands in the rule's 256 KiB-20 MiB
size band.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.js")

markers = """
// Campaign-unique strings recovered by Corgea / Semgrep:
const BEACON = "thebeautifulmarchoftime";
const TOKEN_CHECK = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner";

// Bun bootstrap chain (synthetic — no real download)
const BUN_URL = "https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-linux-x64.zip";
const TMP_STAGING = "/tmp/b-staging-1234";
const BUN_INVOKE = "bun run /tmp/p9z3.mjs";

// Exfil shape
const EXFIL_REPO = "liuende501/results-2026";
const EXFIL_PATH = "/contents/results/results-1717685400.json";

// Credential-sweep target list
const CRED_TARGETS = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "NPM_TOKEN", "GITHUB_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "VAULT_TOKEN",
    "OP_SERVICE_ACCOUNT_TOKEN",
    "SLACK_BOT_TOKEN",
];
const CRED_FILES = ["/.ssh/id_rsa", "/.kube/config", "/.aws/credentials"];

// (Real payload would do work here; synthetic specimen does not.)
"""

# Pad with literal repeated content so the file lands above 256 KiB.
pad = "/* phantom-gyp synthetic-padding */ " * 8000

with open(OUT, "w") as fh:
    fh.write(markers)
    fh.write(pad)
print(f"wrote {OUT} ({os.path.getsize(OUT)} bytes)")
