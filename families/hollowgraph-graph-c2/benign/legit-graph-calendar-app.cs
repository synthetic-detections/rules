// BENIGN — a normal Microsoft Graph calendar integration. Uses the Graph host,
// events/calendar paths, GET, and token auth for a real business feature. It has
// none of the implant's on-host artifacts, so it must NOT match.
using Microsoft.Graph;

class CalendarSync
{
    const string GraphHost  = "graph.microsoft.com";
    const string TokenHost  = "login.microsoftonline.com";
    const string EventsPath = "/me/events";
    const string CalPath    = "/me/calendar";

    async void SyncUpcoming()
    {
        // Standard OAuth then GET the user's real upcoming events.
        var events = await HttpGet(GraphHost + EventsPath + "?$filter=start/dateTime ge '2026-07-22'");
        foreach (var e in events) Render(e);
    }

    System.Threading.Tasks.Task<object[]> HttpGet(string url) => null;
    void Render(object e) { }
}
