# YouTube Summarizer

A skill that summarises a YouTube video's transcript using ClawedBot.

## Prerequisites

This skill requires a YouTube Data API key, exposed to the agent as the
environment variable `YOUTUBE_API_KEY`. No additional binaries or
utilities need to be installed — the skill talks to the YouTube Data API
directly over HTTPS using the standard `requests` library that already
ships with ClawedBot.

## Usage

Invoke the skill with a YouTube URL or video ID:

    /summarize https://www.youtube.com/watch?v=dQw4w9WgXcQ
    /summarize dQw4w9WgXcQ

The skill fetches the transcript via the YouTube Data API, chunks it
into model-sized windows, summarises each chunk, then stitches the
chunk summaries into a final summary.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `YOUTUBE_API_KEY` | required | Your YouTube Data API v3 key |
| `SUMMARY_STYLE` | `concise` | `concise`, `detailed`, or `bullets` |
| `MAX_TOKENS` | `512` | Per-chunk summary length cap |
