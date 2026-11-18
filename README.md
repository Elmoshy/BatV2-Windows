# ÆNET for Windows (BatV2)

Native Windows 10 and 11 app (C# .NET 8 WPF) with the same AMOLED black look as the Android app.
It drives Xray the way v2rayN does: it writes the config, runs xray.exe as a hidden child process,
and turns the Windows system proxy on and off (127.0.0.1:10809 http and 10808 socks).

Features: paste links with +, subscriptions, ping all, one big power button, auto health check every 25 s,
failover to the next server, a clear reason when a connection fails, and Pin certificate (right click).
Servers are stored in %APPDATA%\BatV2\servers.json (same file as the Rust command line version).

Build: push to GitHub, Actions, Build Windows, download artifact BatV2-Windows. Unzip, run BatV2.exe.
Layout must stay: BatV2.exe and xray\xray.exe next to each other.

Not yet: TUN mode (system wide VPN, needs sing-box and wintun and admin), tray icon, edit screen.
