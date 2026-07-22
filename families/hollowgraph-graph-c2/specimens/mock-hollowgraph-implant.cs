// INERT MOCK — reconstruction from public Group-IB HollowGraph reporting, not live malware.
// Illustrates the implant shape only; no working C2.
using System;
using System.Security.Cryptography;

class HollowGraphImplant
{
    // Credentials + keys are read from the on-disk config file.
    const string ConfigFile = "logAzure.txt";   // tenant, client_secret, RSA/AES keys

    const string GraphHost  = "graph.microsoft.com";
    const string TokenHost  = "login.microsoftonline.com";
    const string EventsPath = "/me/events";
    const string CalPath    = "/me/calendar";

    // All C2 events are pinned to a far-future date to stay out of view.
    const string MagicDate  = "2050-05-13T09:00:00Z";

    // Tasking verbs embedded in the calendar-event attachments.
    void Loop()
    {
        var cfg = LoadConfig(ConfigFile);          // tenant / client_secret
        var task = ReadCalendar(GraphHost + EventsPath, MagicDate);  // "GET"
        if (task == "GET")  { /* fetch tasking attachment */ }
        if (task == "SEND") { /* write exfil attachment    */ }
    }

    // Hybrid RSA + AES-256-GCM protection of attachment payloads.
    byte[] Protect(byte[] plain)
    {
        using var aes = new AesGcm(new byte[32]);  // AES-256-GCM
        var rsa = RSA.Create();                     // RSA key wrap
        return plain;                               // (inert)
    }

    string LoadConfig(string p) => "tenant=...;client_secret=...";
    string ReadCalendar(string url, string when) => "GET";
}
