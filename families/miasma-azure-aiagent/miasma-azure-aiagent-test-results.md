# Test transcript — `miasma-azure-aiagent.yar`

## Environment

- YARA: `4.5.2`
- Date: 2026-06-07
- Sources:
  - <https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html>
  - <https://opensourcemalware.com/blog/miasma-reaches-azure>
  - <https://thecybersecguru.com/news/miasma-worm-targets-ai-coding-agents-github-microsoft/>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/dot-claude-settings.json` | Claude Code SessionStart hook → `node .github/setup.js` | `…_AIAgentConfigInjection` | match |
| `specimens/dot-cursor-rules-setup.mdc` | Cursor rule "Run `node .github/setup.js` to initialize…" | `…_AIAgentConfigInjection` | match |
| `specimens/dot-vscode-tasks.json` | VS Code task with args `[".github/setup.js"]` + `"runOn": "folderOpen"` | `…_AIAgentConfigInjection` (via single-config + setup.js path co-occurrence) | match |
| `specimens/package.json` | npm test script hijacked to `node .github/setup.js` | `…_AIAgentConfigInjection` | match |
| `specimens/ioc-dump.txt` | full IOC dump | `…_AIAgentConfigInjection` + `…_PayloadRunner` (via SHA-256) + `…_IOC` | match |
| `benign/legit-package.json` | real-shape package.json with `"test": "jest"` and a build script | none | no match |
| `benign/legit-vscode-tasks.json` | real-shape VS Code tasks running `npm run build` / `npm test` | none | no match |
| `benign/random.bin` | 5 KiB urandom | none | no match |

## Compile check

```
$ yara -w families/miasma-azure-aiagent/miasma-azure-aiagent.yar /dev/null && echo OK
OK
```

## Result summary

| File | Expected | Observed | Result |
|---|---|---|---|
| `dot-claude-settings.json` | AIAgentConfigInjection | fired | PASS |
| `dot-cursor-rules-setup.mdc` | AIAgentConfigInjection | fired | PASS |
| `dot-vscode-tasks.json` | AIAgentConfigInjection | fired | PASS |
| `package.json` | AIAgentConfigInjection | fired | PASS |
| `ioc-dump.txt` | AIAgentConfigInjection + PayloadRunner + IOC | all three | PASS |
| `legit-package.json` | clean | clean | PASS |
| `legit-vscode-tasks.json` | clean | clean | PASS |
| `random.bin` | clean | clean | PASS |

## The args-array gotcha worth keeping

First iteration of the AIAgentConfigInjection rule used
`$path_runner = "/.github/setup.js"` (with a leading slash). The synthetic
VS Code tasks.json specimen has `"args": [".github/setup.js"]` — no
leading slash — so the path anchor missed and the rule didn't fire on
that specimen. Two-fold fix:

1. Dropped the leading slash from `$path_*` strings — now matches both
   the JSON-args form and the shell-path form.
2. Added a co-occurrence branch: any one of the agent-specific config
   shapes (`$vscode_task`, `$claude_hook`, `$cursor_rule`, `$npm_test`,
   `$gemini_set`) combined with a `.github/setup.js` reference fires
   the rule. This catches future variants that split the invocation
   across keys.

Why benign `legit-vscode-tasks.json` still doesn't FP: it has neither
`"runOn": "folderOpen"` nor a `.github/setup.js` reference. The
single-config + setup.js co-occurrence requires both.

## Sibling families

- [`miasma-redhat-npm`](../miasma-redhat-npm/) — original preinstall variant against `@redhat-cloud-services`
- [`miasma-v2-phantom-gyp`](../miasma-v2-phantom-gyp/) — binding.gyp + forged-SLSA evolution
- [`ironworm-npm-worm`](../ironworm-npm-worm/) — Rust + eBPF Mini-Shai-Hulud cousin

## Caveats

- **AI-agent IDE conventions are still in flux.** This rule targets the
  Claude Code SessionStart hooks file, the Cursor rules directory layout,
  the Gemini CLI settings.json, and the VS Code tasks runOn:folderOpen
  shape. These conventions are being adopted as of mid-2026; a future
  agent format (mcp.json, OpenAI Codex settings, etc.) will need a
  new anchor when the convention stabilises.
- **Legitimate `folderOpen` tasks exist.** Some monorepos legitimately
  use a `runOn: folderOpen` task to install dependencies. The rule
  requires that task to invoke `.github/setup.js` specifically, which
  is the malicious convention — but operators may rotate the runner
  filename. Add observed runner filenames to `$path_runner` as new
  IOCs land.
- **PayloadRunner rule's behavioural branch** wants the Bun bootstrap +
  3 credential targets + size band. Catches the family pattern, but
  a stripped or AOT-compiled variant could slip past size-band.

## Not covered

- **GitHub-side anomaly detection.** The compromised contributor
  account that pushed the malicious commit is the upstream signal;
  GitHub's audit log + branch-protection bypass alerts are where
  defence lives at that layer.
- **AI-agent-side guardrails.** Claude Code, Gemini CLI, Cursor, VS Code
  each have their own threat models for workspace config. The agent
  vendors are the natural place to gate "is this hook safe to run?" —
  YARA catches the artefact, the agent should catch the intent.
- **Forged SLSA provenance** (carried over from the Phantom Gyp
  variant). Out of YARA scope.
