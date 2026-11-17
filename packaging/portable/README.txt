Woodshed - a syslog, SNMP and flow collector with a web UI
==========================================================

Run it without installing (portable)
------------------------------------
1. Unpack this archive (on Windows: right-click the zip, Extract All; don't run
   it from inside the zip).
2. Double-click woodshed (woodshed.exe on Windows), or run ./woodshed in a
   terminal. On Linux, port 514 needs rights: run "sudo ./woodshed", or once
   "sudo setcap cap_net_bind_service=+ep ./woodshed".
3. The web UI opens in your browser (http://localhost:8514/). The window shows
   the addresses to send logs to: point your devices there, UDP or TCP port 514.

Logs and settings go in the woodshed-data folder next to the program (or in
Woodshed in your home folder if that one can't be written; the window says
which). Zip or copy that folder to hand the logs to someone.

To stop Woodshed, press Ctrl-C or close its window. It saves everything first.

The first time, your system may ask before running it, because it isn't signed:
  Windows: "Windows protected your PC" -> More info -> Run anyway, then Allow
           in the firewall prompt so devices can reach it.
  macOS:   System Settings -> Privacy & Security -> Open Anyway.

Install it as a service instead
-------------------------------
To keep it running in the background and after a restart, use the installer
for your system (MSI, .pkg, .deb or .rpm) from the releases page, or run
"woodshed install" as an administrator.

More
----
User guide and FAQ: https://github.com/gmccollu/woodshed/blob/main/docs/user-guide.md
License: MIT (LICENSE). Third-party software: THIRD_PARTY_NOTICES.txt.
