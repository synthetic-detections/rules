/*
   HollowGraph — Microsoft 365 Graph / calendar covert C2 implant
   (Group-IB, public reporting 2026-07-20; unattributed nation-state espionage)
   -----------------------------------------------------------------------
   An espionage implant, assessed by Group-IB as a component of the Cavern
   C2 framework, that uses a compromised Microsoft 365 mailbox's CALENDAR as
   its command-and-control dead-drop:

     - Authenticates to the Microsoft Graph API with HARDCODED credentials
       (tenant ID, client secret, keys) read from a config file named
       `logAzure.txt`.
     - Reads tasking and writes exfiltrated data as files ATTACHED to
       calendar events all scheduled for the far-future date 2050-05-13,
       keeping them out of any normal calendar view.
     - Supports GET / SEND verbs; traffic protected by a hybrid RSA +
       AES-256-GCM scheme.
     - No attacker domain/IP: C2 rides trusted Microsoft cloud traffic, so
       detection anchors on the on-host artifacts, not network IOCs.

   Group-IB counted 12 implanted victims (~3 actively beaconing), targeting
   organizations in Israel; observed activity 2026-06-03 .. 2026-07-09.

   Because Microsoft Graph SDK strings (graph.microsoft.com, /me/events,
   /me/calendar) appear in countless legitimate apps, the rules NEVER fire on
   Graph usage alone — they require the campaign-specific config filename, the
   2050-05-13 magic event date, or the GET/SEND + hybrid-crypto combo to
   co-occur with Graph/calendar usage.

   Rule 1 — Behavioral (critical): Graph calendar C2 + logAzure.txt + 2050 date.
   Rule 2 — IOC (high): config filename + magic date, co-occurrence guarded.
   Rule 3 — Specimen pin (critical): the full implant shape.

   Sources:
     https://www.group-ib.com/blog/hollowgraph-microsoft-365/
     https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html
     https://www.bleepingcomputer.com/news/security/new-hollowgraph-malware-uses-microsoft-graph-for-stealthy-c2-comms/

   Related: [[cavern-manticore]] — HollowGraph is a Cavern-framework component.
*/

rule HollowGraph_GraphCalendar_C2_Behavior
{
    meta:
        description = "HollowGraph M365 Graph/calendar covert C2 — logAzure.txt credential config + 2050-05-13 magic event date + Graph calendar API usage + GET/SEND tasking + RSA/AES-256-GCM hybrid"
        author      = "synthetic-detections"
        date        = "2026-07-22"
        severity    = "critical"
        family      = "hollowgraph-graph-c2"
        reference   = "https://www.group-ib.com/blog/hollowgraph-microsoft-365/"

    strings:
        // Campaign-specific credential/config file
        $cfg = "logAzure.txt" ascii wide nocase

        // Magic far-future calendar date used to hide C2 events
        $date_iso  = "2050-05-13" ascii wide
        $date_us   = "5/13/2050" ascii wide
        $date_2050 = "2050" ascii wide

        // Microsoft Graph calendar API surface
        $g_host  = "graph.microsoft.com" ascii wide nocase
        $g_events= "/me/events" ascii wide nocase
        $g_cal   = "/me/calendar" ascii wide nocase
        $g_attach= "attachments" ascii wide nocase
        $g_token = "login.microsoftonline.com" ascii wide nocase

        // Hybrid crypto (AES-256-GCM is the strong, campaign-consistent atom;
        // bare "RSA"/"GET" are too short/generic to be usable signals)
        $c_aes = "AES-256-GCM" ascii wide nocase
        $c_gcm = "AesGcm" ascii wide nocase

        // Hardcoded tenant/secret material read from the config
        $t_tenant = "tenant" ascii wide nocase
        $t_secret = "client_secret" ascii wide nocase

    condition:
        filesize < 10MB
        and (
            // Path 1: the config filename is campaign-unique
            $cfg
            or
            // Path 2: the 2050-05-13 magic date used with Graph calendar API
            (
                any of ($date_iso, $date_us)
                and any of ($g_host, $g_events, $g_cal)
            )
            or
            // Path 3: full behavioral shape — Graph calendar + attachment
            // dead-drop + AES-256-GCM payload crypto + hardcoded app
            // credential material, none of which alone is attributable but
            // together match the implant.
            (
                any of ($g_host, $g_events, $g_cal)
                and $g_attach
                and any of ($c_aes, $c_gcm)
                and (any of ($t_secret, $g_token) or ($t_tenant and $date_2050))
            )
        )
}

rule HollowGraph_IOC
{
    meta:
        description = "HollowGraph IOC — config filename logAzure.txt and the 2050-05-13 magic calendar date, guarded by co-occurrence with Graph/M365 usage so benign calendar tooling does not match"
        author      = "synthetic-detections"
        date        = "2026-07-22"
        severity    = "high"
        family      = "hollowgraph-graph-c2"
        reference   = "https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html"

    strings:
        $cfg      = "logAzure.txt" ascii wide nocase
        $date_iso = "2050-05-13" ascii wide
        $date_us  = "5/13/2050" ascii wide
        $g_host   = "graph.microsoft.com" ascii wide nocase
        $g_events = "/me/events" ascii wide nocase
        $g_cal    = "/me/calendar" ascii wide nocase
        $g_token  = "login.microsoftonline.com" ascii wide nocase

    condition:
        filesize < 10MB
        and (
            // Config filename alone is a strong signal
            $cfg
            or
            // Magic date must co-occur with Graph/M365 usage
            (
                any of ($date_iso, $date_us)
                and any of ($g_host, $g_events, $g_cal, $g_token)
            )
        )
}

rule HollowGraph_Implant_Specimen
{
    meta:
        description = "HollowGraph specimen pin — full implant shape: logAzure.txt config + Graph calendar dead-drop on 2050-05-13 + GET/SEND tasking + RSA/AES-256-GCM"
        author      = "synthetic-detections"
        date        = "2026-07-22"
        severity    = "critical"
        family      = "hollowgraph-graph-c2"
        reference   = "https://www.group-ib.com/blog/hollowgraph-microsoft-365/"

    strings:
        $cfg      = "logAzure.txt" ascii wide nocase
        $date_iso = "2050-05-13" ascii wide
        $g_host   = "graph.microsoft.com" ascii wide nocase
        $g_events = "/me/events" ascii wide nocase
        $c_aes    = "AES-256-GCM" ascii wide nocase
        $c_gcm    = "AesGcm" ascii wide nocase

    condition:
        filesize < 10MB
        and $cfg
        and $date_iso
        and any of ($g_host, $g_events)
        and any of ($c_aes, $c_gcm)
}
