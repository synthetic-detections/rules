# Legitimate IT admin script (benign control) — adds a Microsoft Defender
# exclusion for an approved line-of-business app's data directory.
#
# Uses Add-MpPreference -ExclusionPath for a valid operational reason, but does
# NOT disable UAC, patch AMSI, run hidden/bypass loaders, or reference the
# campaign's loader chain. Confirms the behavioral rule does not fire on a
# lone, legitimate Defender-exclusion call (FP boundary test).

Add-MpPreference -ExclusionPath "C:\Program Files\Acme\LOB\data"

Write-Host "Added Defender exclusion for Acme LOB data directory."
