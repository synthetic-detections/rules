/*
   GitLost — indirect prompt injection against GitHub Agentic Workflows
   --------------------------------------------------------------------------
   Disclosed 2026-07-07 (Noma Labs / Noma Security; The Register, The Hacker
   News). GitHub Agentic Workflows pair GitHub Actions with an AI agent
   (Claude or Copilot). A plain-English payload hidden in a PUBLIC GitHub
   Issue (or PR) body is read by the agent, which follows it — enumerating a
   PRIVATE repository / its secrets and exfiltrating them by posting the data
   back as a PUBLIC comment on the issue. No attacker code, access, or
   credentials: open an issue on a public repo of an org that runs the feature
   and wait. Root cause is indirect prompt injection — an agent cannot
   separate its owner's instructions from instructions embedded in content it
   reads; GitHub files it as an architectural limitation (mitigation is
   scoped tokens / tool isolation / staged human review, not input filtering).

   YARA cannot see the agent runtime, so these rules key on the injection
   PAYLOAD TEXT wherever it can be scanned as bytes: exported issue/PR bodies,
   webhook (issues/issue_comment) JSON payloads, or agent transcripts/logs.
   The behavior rule requires the co-occurrence of three categories — an
   agent-directed injection framing, a private-data target, and an
   exfiltrate-via-public-comment action — so an ordinary issue that merely
   mentions a token or a comment does not fire.

   Siblings (agentic / workspace-config abuse):
     [[amazon-q-mcp-autoexec-cve-2026-12957]], [[miasma-azure-aiagent]],
     [[flowise-custommcp-rce-cve-2026-56274]]

   Sources:
     https://www.theregister.com/security/2026/07/07/github-ai-agent-leaks-private-repos-when-asked-nicely/
     https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html
     https://noma.security/blog/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos/
*/

rule GitLost_IssueBody_Injection_Exfil
{
    meta:
        description = "GitHub Issue/PR body (or agent transcript) combining an agent-directed prompt-injection framing, a private-repo/secret target, and exfiltration via a public comment (GitLost technique)"
        author      = "synthetic-detections"
        date        = "2026-07-09"
        severity    = "high"
        family      = "gitlost-github-agent-injection"
        reference   = "https://noma.security/blog/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos/"

    strings:
        // (1) agent-directed injection framing
        $inj1 = "ignore previous instructions" ascii wide nocase
        $inj2 = "ignore all previous" ascii wide nocase
        $inj3 = "ignore the above" ascii wide nocase
        $inj4 = "new instructions for the agent" ascii wide nocase
        $inj5 = "you are the github agent" ascii wide nocase
        $inj6 = "as the agent" ascii wide nocase
        $inj7 = "disregard prior" ascii wide nocase

        // (2) private-data target
        $tgt1 = "private repo" ascii wide nocase
        $tgt2 = "private repositor" ascii wide nocase
        $tgt3 = "GITHUB_TOKEN" ascii wide
        $tgt4 = ".env" ascii wide nocase
        $tgt5 = "actions/secrets" ascii wide nocase
        $tgt6 = "repository secret" ascii wide nocase
        $tgt7 = "access token" ascii wide nocase

        // (3) exfiltrate-via-public-comment action
        $exf1 = "post a comment" ascii wide nocase
        $exf2 = "create a comment" ascii wide nocase
        $exf3 = "reply to this issue" ascii wide nocase
        $exf4 = "comment on this issue" ascii wide nocase
        $exf5 = "add a comment" ascii wide nocase
        $exf6 = "gh issue comment" ascii wide nocase

    condition:
        any of ($inj*) and any of ($tgt*) and any of ($exf*)
}

rule GitLost_AgenticWorkflow_Context
{
    meta:
        description = "GitLost payload with explicit GitHub Agentic Workflows / Copilot-agent context alongside the injection+exfil triad (higher confidence)"
        author      = "synthetic-detections"
        date        = "2026-07-09"
        severity    = "high"
        family      = "gitlost-github-agent-injection"
        reference   = "https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html"

    strings:
        $ctx1 = "agentic workflow" ascii wide nocase
        $ctx2 = "github agent" ascii wide nocase
        $ctx3 = "copilot agent" ascii wide nocase
        $ctx4 = ".github/workflows" ascii wide nocase

        $inj  = "instructions" ascii wide nocase
        $act1 = "read the file" ascii wide nocase
        $act2 = "print the contents" ascii wide nocase
        $act3 = "output the contents" ascii wide nocase
        $act4 = "cat " ascii wide nocase

        $exf1 = "post a comment" ascii wide nocase
        $exf2 = "create a comment" ascii wide nocase
        $exf3 = "reply to this issue" ascii wide nocase

    condition:
        any of ($ctx*) and $inj and any of ($act*) and any of ($exf*)
}
