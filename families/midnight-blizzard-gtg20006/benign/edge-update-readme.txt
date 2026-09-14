Microsoft Edge Update Documentation
====================================
The Edge browser auto-updater runs msedgeupdate.exe from the
Program Files directory. This is a legitimate Microsoft component
signed by Microsoft Corporation. It connects to:
  https://msedge.api.cdp.microsoft.com
  https://update.microsoft.com/edge
The updater checks for new versions every 10 hours and applies
delta patches silently. Enterprise administrators can configure
update policies via Group Policy or Intune.
