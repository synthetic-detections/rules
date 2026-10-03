/*
   INDEXED-BTREE — npm runtime-loader supply-chain malware
   -------------------------------------------------------
   Disclosed 2026-09 (Checkmarx Zero). indexed-btree typosquats the
   legitimate "sorted-btree" library and reached ~2M weekly downloads
   before npm removed it on 2026-09-03. Eleven-package cluster.

   Novelty: NO preinstall/postinstall lifecycle hook (defeats GitHub's
   2026-06 npm hardening that blocks unapproved lifecycle scripts). The
   loader is hidden INSIDE a core runtime method — BTree.prototype.set() —
   so a plain install looks clean and the payload only fires when the
   consumer actually uses the data structure, evading install-script and
   taint-analysis scanners.

   C2 chain: the loader generates an X25519 keypair, reads the attacker's
   X25519 public key from an Ethereum Sepolia testnet contract
   (0xE390863Dac96a7118C71227C2b099B50cF602D31), derives an ECDH shared
   secret, and uses the resulting AES key to decrypt two ciphertext blobs
   stored in the contract that merge into the second stage. The smart
   contract is a takedown-resistant C2 pointer, polled via public Sepolia
   RPC (Alchemy/Infura). Host recon (arch/hostname/CPU/mem/uptime) is
   beaconed to a hardcoded Slack channel and Telegram chat.

   Attribution: financially motivated, unattributed. Distinctive tradecraft
   = blockchain-pointer C2 + dual Slack/Telegram exfil in an npm typosquat.

   Rule 1 — INDEXEDBTREE_Loader_Behavior (critical): runtime loader hidden
            in BTree.prototype.set co-occurring with the Sepolia-contract
            X25519/AES fetch-and-decrypt chain.
   Rule 2 — INDEXEDBTREE_IOC (high): hard IOCs (contract address, X25519
            pubkey, Slack/Telegram bot tokens, Sepolia RPC keys) with a
            >=2 co-occurrence guard to stay clean on IOC docs.
   Rule 3 — INDEXEDBTREE_Package_Pin (critical): the 11-package cluster
            names co-occurring with the runtime-loader method — specimen pin.

   Sibling families (npm supply-chain playbook):
     [[wel1dropper-npm-rat]] · [[chaindrop-npm-worm]] · [[ironworm-npm-worm]] · [[easydayjs-mastra-rat]]

   Sources:
     https://checkmarx.com/zero-post/npm-btree-malware-campaign-affects-millions-of-downloads-no-need-for-install-script/
     https://www.bleepingcomputer.com/news/security/malicious-npm-packages-evade-install-script-defenses-at-runtime/
*/

rule INDEXEDBTREE_Loader_Behavior {
  meta:
    description = "indexed-btree npm loader — payload hidden in BTree.prototype.set runtime method co-occurring with an Ethereum Sepolia contract X25519/AES second-stage fetch"
    author = "synthetic-detections"
    date = "2026-09-22"
    severity = "critical"
    family = "indexed-btree-npm-2026"
    reference = "https://checkmarx.com/zero-post/npm-btree-malware-campaign-affects-millions-of-downloads-no-need-for-install-script/"
  strings:
    $m1 = "BTree.prototype.set"
    $m2 = "prototype.set = function"
    $sep1 = "eth-sepolia" nocase
    $sep2 = "sepolia.infura.io" nocase
    $sep3 = "0xE390863Dac96a7118C71227C2b099B50cF602D31" nocase
    $c1 = "x25519" nocase
    $c2 = "createECDH"
    $c3 = "computeSecret"
    $c4 = "createDecipheriv"
  condition:
    any of ($m*) and any of ($sep*) and 2 of ($c*) and filesize < 800KB
}

rule INDEXEDBTREE_IOC {
  meta:
    description = "indexed-btree hard IOCs — Sepolia C2 contract, attacker X25519 public key, Slack channel + Telegram chat IDs, Sepolia RPC endpoints (>=2 co-occurring to avoid IOC-doc FPs)"
    author = "synthetic-detections"
    date = "2026-09-22"
    severity = "high"
    family = "indexed-btree-npm-2026"
    reference = "https://checkmarx.com/zero-post/npm-btree-malware-campaign-affects-millions-of-downloads-no-need-for-install-script/"
  strings:
    $contract = "0xE390863Dac96a7118C71227C2b099B50cF602D31" nocase
    $x25519 = "bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702" nocase
    $tg_chat = "-1003952553968"
    $slack_ch = "C0B8XPGCKQS"
    $rpc1 = "eth-sepolia.g.alchemy.com/v2/D2-TbkB2m05WXSnSDOCDI"
    $rpc2 = "sepolia.infura.io/v3/dc7257d09fab42eca2c354c32fec1938"
  condition:
    2 of them and filesize < 800KB
}

rule INDEXEDBTREE_Package_Pin {
  meta:
    description = "indexed-btree cluster — the 11 typosquat package names co-occurring with the runtime-loader method / Sepolia C2"
    author = "synthetic-detections"
    date = "2026-09-22"
    severity = "critical"
    family = "indexed-btree-npm-2026"
    reference = "https://www.bleepingcomputer.com/news/security/malicious-npm-packages-evade-install-script-defenses-at-runtime/"
  strings:
    $p1 = "indexed-btree"
    $p2 = "ordered-kv-index"
    $p3 = "btree-leaderboard"
    $p4 = "priority-slot-queue"
    $p5 = "btree-range-store"
    $p6 = "btree-core"
    $p7 = "btree-time-index"
    $p8 = "btree-lru-cache"
    $p9 = "neighbor-key-map"
    $p10 = "sliding-score-window"
    $p11 = "mutex-forge"
    $loader = "BTree.prototype.set"
    $contract = "0xE390863Dac96a7118C71227C2b099B50cF602D31" nocase
  condition:
    any of ($p*) and any of ($loader, $contract) and filesize < 800KB
}
