using System.IO;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace BatV2;

public static class SystemProxy
{
    [DllImport("wininet.dll")]
    static extern bool InternetSetOption(IntPtr h, int opt, IntPtr buf, int len);

    const string Key = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public static void Set(bool on, int port)
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(Key, true);
            if (k == null) return;
            if (on)
            {
                k.SetValue("ProxyServer", $"127.0.0.1:{port}");
                k.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            }
            else k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0); // settings changed
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0); // refresh
        }
        catch { }
    }

    /// after a crash the proxy can stay on pointing at nothing: turn it off at startup
    public static void ResetIfOurs()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(Key, false);
            if ((k?.GetValue("ProxyServer") as string) == $"127.0.0.1:{Engine.Http}") Set(false, Engine.Http);
        }
        catch { }
    }
}

public static class Engine
{
    public const int Socks = 10808;
    public const int Http = 10809;
    static Process proc;

    public static string LogPath => System.IO.Path.Combine(Store.Dir, "core.log");

    static string ExePath()
    {
        foreach (var c in new[]
        {
            System.IO.Path.Combine(AppContext.BaseDirectory, "xray", "xray.exe"),
            System.IO.Path.Combine(AppContext.BaseDirectory, "xray.exe")
        })
            if (File.Exists(c)) return c;
        throw new FileNotFoundException("xray.exe not found. Put it in the xray folder next to BatV2.exe");
    }

    public static bool Running => proc != null && !proc.HasExited;

    public static string Resolve(string host)
    {
        if (IPAddress.TryParse(host, out _)) return null;
        try
        {
            var a = Dns.GetHostAddresses(host);
            return (a.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork) ?? a.FirstOrDefault())?.ToString();
        }
        catch { return null; }
    }

    public static void Start(Server s)
    {
        Stop();
        var cfg = System.IO.Path.Combine(Store.Dir, "config.json");
        File.WriteAllText(cfg, ConfigBuilder.Full(s, Resolve(s.Address), Socks, Http, LogPath.Replace('\\', '/')));
        try { File.WriteAllText(LogPath, ""); } catch { }
        proc = Process.Start(new ProcessStartInfo
        {
            FileName = ExePath(),
            Arguments = $"run -c \"{cfg}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = System.IO.Path.GetDirectoryName(ExePath())
        });
    }

    public static void Stop()
    {
        try
        {
            if (proc != null && !proc.HasExited) { proc.Kill(true); proc.WaitForExit(2000); }
        }
        catch { }
        proc = null;
    }

    /// real test through the tunnel: two urls, one answer is enough
    public static async Task<bool> HealthAsync()
    {
        foreach (var url in new[] { "http://cp.cloudflare.com/generate_204", "http://www.gstatic.com/generate_204" })
        {
            try
            {
                using var h = new HttpClientHandler { Proxy = new WebProxy($"http://127.0.0.1:{Http}"), UseProxy = true };
                using var c = new HttpClient(h) { Timeout = TimeSpan.FromSeconds(8) };
                using var r = await c.GetAsync(url);
                if ((int)r.StatusCode == 204) return true;
            }
            catch { }
        }
        return false;
    }

    public static async Task<int> TcpPingAsync(string host, int port)
    {
        try
        {
            using var c = new TcpClient();
            var sw = Stopwatch.StartNew();
            var t = c.ConnectAsync(host, port);
            if (await Task.WhenAny(t, Task.Delay(4000)) != t) return -1;
            await t;
            return (int)sw.ElapsedMilliseconds;
        }
        catch { return -1; }
    }

    /// explain WHY it fails instead of just saying it failed
    public static async Task<string> DiagnoseAsync(Server s)
    {
        if (await TcpPingAsync(s.Address, s.Port) < 0) return "cannot reach the server (blocked or down)";
        if (s.Security == "tls" && s.Pin.Length == 0)
        {
            try
            {
                var c = await CertFetcher.FetchAsync(s.Address, s.Port, s.Sni.Length > 0 ? s.Sni : s.Address);
                if (c.NotAfter < DateTime.Now)
                    return $"server certificate expired on {c.NotAfter:yyyy-MM-dd}. Ask your provider or use Pin certificate";
            }
            catch { }
        }
        try
        {
            var bad = File.ReadAllLines(LogPath).TakeLast(40)
                .LastOrDefault(l => l.Contains("failed", StringComparison.OrdinalIgnoreCase));
            if (bad != null)
            {
                if (bad.Contains("closed pipe") || bad.Contains("EOF"))
                    return "server closed the connection (account expired or wrong settings)";
                return bad.Length > 160 ? bad[..160] : bad;
            }
        }
        catch { }
        return "no answer through the tunnel";
    }
}

public record CertInfo(string Hash, string Subject, string Issuer, DateTime NotAfter);

public static class CertFetcher
{
    public static async Task<CertInfo> FetchAsync(string host, int port, string sni)
    {
        using var c = new TcpClient();
        await c.ConnectAsync(host, port);
        using var ssl = new SslStream(c.GetStream(), false, (a, b, ch, e) => true);
        await ssl.AuthenticateAsClientAsync(sni);
        var cert = new X509Certificate2(ssl.RemoteCertificate);
        var hash = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
        return new CertInfo(hash, cert.Subject, cert.Issuer, cert.NotAfter);
    }
}

/// keeps the tunnel alive: health check, restart, failover to the next server
public sealed class Guard
{
    public event Action<string, string, string> Changed; // state, detail, error
    CancellationTokenSource cts;

    public void Start(List<Server> list, int idx)
    {
        Stop();
        cts = new CancellationTokenSource();
        var ct = cts.Token;
        _ = Task.Run(() => Loop(list, idx, ct));
    }

    public void Stop()
    {
        cts?.Cancel();
        Engine.Stop();
        SystemProxy.Set(false, Engine.Http);
        Changed?.Invoke("Disconnected", "", "");
    }

    async Task Loop(List<Server> list, int idx, CancellationToken ct)
    {
        int fails = 0;
        bool connected = false;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var s = list[idx];
                Changed?.Invoke("Connecting", s.Name, "");
                Engine.Start(s);
                SystemProxy.Set(true, Engine.Http);
                await Task.Delay(2000, ct);
                while (!ct.IsCancellationRequested)
                {
                    bool ok = Engine.Running && await Engine.HealthAsync();
                    if (ct.IsCancellationRequested) return;
                    if (ok)
                    {
                        fails = 0;
                        connected = true;
                        Changed?.Invoke("Connected", s.Name, "");
                        await Task.Delay(25000, ct);
                        continue;
                    }
                    fails++;
                    var why = await Engine.DiagnoseAsync(s);
                    if (fails >= 2 && list.Count > 1)
                    {
                        idx = (idx + 1) % list.Count;
                        Changed?.Invoke("Switching", $"to {list[idx].Name}", $"{s.Name}: {why}");
                        fails = 0;
                        break; // restart loop with the next server
                    }
                    Changed?.Invoke(connected ? "Retrying" : "Connecting", s.Name, why);
                    if (!Engine.Running) break;
                    await Task.Delay(6000, ct);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception e)
        {
            Engine.Stop();
            SystemProxy.Set(false, Engine.Http);
            Changed?.Invoke("Disconnected", "", e.Message);
        }
    }
}
