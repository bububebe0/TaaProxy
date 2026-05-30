using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Management;
using TaaProxy.Models;

namespace TaaProxy.Services
{
    internal static class SingBoxConfig
    {
        public static void Generate(ServerModel sv, AppSettings settings,
            string routesContent, int port, string logFile, string configPath, out string? tunInterfaceName)
        {
            tunInterfaceName = null;
            var p = sv.Params;
            var rules = new List<object>();

            foreach (var app in settings.AppExceptions)
            {
                var r = new Dictionary<string, object> { ["outbound"] = "direct" };
                if (app.ExType == "path") r["process_path"] = app.Value;
                else r["process_name"] = app.Value;
                rules.Add(r);
            }

            if (settings.DomainExceptions.Count > 0)
            {
                var suf = settings.DomainExceptions.ToList();
                rules.Add(new Dictionary<string, object> { ["outbound"] = "direct", ["domain_suffix"] = suf });
            }

            var isSplit = settings.SplitTunneling;
            var finalOut = isSplit ? "direct" : "proxy";
            if (isSplit && !string.IsNullOrWhiteSpace(routesContent))
            {
                var domains = new List<string>();
                var ips = new List<string>();
                foreach (var raw in routesContent.Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0))
                {
                    if (IsIpOrCidr(raw)) ips.Add(raw.Contains('/') ? raw : raw + "/32");
                    else domains.Add(raw);
                }
                var rule = new Dictionary<string, object> { ["outbound"] = "proxy" };
                if (domains.Count > 0) rule["domain_suffix"] = domains;
                if (ips.Count > 0) rule["ip_cidr"] = ips;
                if (rule.Count > 1) rules.Add(rule);
            }

            object[] inbounds;
            if (settings.UseTunMode)
            {
                tunInterfaceName = "taa-tun0";

                var excludeAddresses = new List<string>
                {
                    "192.168.0.0/16",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "127.0.0.0/8",
                    "169.254.0.0/16"
                };

                var serverExcludeIp = ResolveServerIpForExclusion(sv.Host);
                if (!string.IsNullOrEmpty(serverExcludeIp))
                    excludeAddresses.Insert(0, serverExcludeIp);

                inbounds = new object[]
                {
                    new
                    {
                        type = "tun",
                        interface_name = tunInterfaceName,
                        address = new[] { "172.19.0.1/30" },
                        mtu = 1400,
                        auto_route = true,
                        strict_route = false,
                        stack = "gvisor",
                        endpoint_independent_nat = true,
                        route_exclude_address = excludeAddresses.ToArray()
                    }
                };

                var selfExe = Path.GetFileName(
                    System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "TaaProxy.exe");
                rules.Insert(0, new Dictionary<string, object>
                {
                    ["process_name"] = selfExe,
                    ["outbound"]     = "direct"
                });

                rules.Insert(0, new Dictionary<string, object>
                {
                    ["process_name"] = "svchost.exe",
                    ["outbound"]     = "direct"
                });

                rules.Insert(0, new Dictionary<string, object>
                {
                    ["outbound"]      = "direct",
                    ["domain_suffix"] = new[] { "msftconnecttest.com", "msftncsi.com", "dns.msft.net" }
                });
            }
            else
            {
                inbounds = new object[]
                {
                    new
                    {
                        type = "mixed",
                        listen = "127.0.0.1",
                        listen_port = port
                    }
                };
            }

            var actionRules = new List<object>();
            actionRules.Add(new { action = "sniff" });
            if (settings.UseTunMode)
                actionRules.Add(new Dictionary<string, object> { ["protocol"] = "dns", ["action"] = "hijack-dns" });
            actionRules.Add(new { action = "resolve", strategy = "prefer_ipv4" });
            rules.InsertRange(0, actionRules);

            var config = new Dictionary<string, object>
            {
                ["log"]      = new { level = settings.DebugMode ? "debug" : "info" },
                ["inbounds"] = inbounds,
                ["route"]    = settings.UseTunMode
                    ? (object)new { rules, final = finalOut, auto_detect_interface = false,
                                    default_interface = GetDefaultPhysicalInterface() ?? "Ethernet" }
                    : new { rules, final = finalOut, auto_detect_interface = true,
                            default_interface = (string?)null }
            };

            config["outbounds"] = new object[] { BuildOutbound(sv, p), new { type = "direct", tag = "direct" } };

            var dns = settings.UseTunMode ? BuildDns(settings, forceFallback: true) : BuildDns(settings, forceFallback: false);
            if (dns != null) config["dns"] = dns;

            Directory.CreateDirectory(Paths.DataDir);
            File.WriteAllText(configPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
            FileAcl.SecureFile(configPath);
        }

        private static string ResolveSni(Dictionary<string, string> p, string fallback)
        {
            var sni = p.GetValueOrDefault("sni", "");
            if (string.IsNullOrEmpty(sni) || sni == "undefined" || sni == "null")
                return fallback;
            return sni;
        }

        private static object BuildOutbound(ServerModel sv, Dictionary<string, string> p)
        {
            return sv.Type switch
            {
                "hysteria2" => BuildHysteria2(sv, p),
                "ss" => (object)new
                {
                    type = "shadowsocks",
                    tag = "proxy",
                    server = sv.Host,
                    server_port = sv.Port,
                    method = sv.Method,
                    password = sv.Password
                },
                "trojan" => BuildTrojan(sv, p),
                _ => BuildVless(sv, p)
            };
        }

        private static object BuildHysteria2(ServerModel sv, Dictionary<string, string> p)
        {
            var outbound = new Dictionary<string, object>
            {
                ["type"]        = "hysteria2",
                ["tag"]         = "proxy",
                ["server"]      = sv.Host,
                ["server_port"] = sv.Port,
                ["password"]    = sv.Password,
                ["tls"] = new Dictionary<string, object>
                {
                    ["enabled"]     = true,
                    ["server_name"] = ResolveSni(p, sv.Host),
                    ["insecure"]    = p.GetValueOrDefault("insecure", "0") == "1"
                }
            };

            if (p.TryGetValue("obfs", out var obfsType) && !string.IsNullOrEmpty(obfsType))
            {
                outbound["obfs"] = new Dictionary<string, object>
                {
                    ["type"]     = obfsType,
                    ["password"] = p.GetValueOrDefault("obfs-password", "")
                };
            }

            int upMbps = 0, downMbps = 0;
            var hasUp   = p.TryGetValue("upmbps",   out var upStr)   && int.TryParse(upStr,   out upMbps);
            var hasDown = p.TryGetValue("downmbps", out var downStr) && int.TryParse(downStr, out downMbps);
            if (hasUp || hasDown)
            {
                var bw = new Dictionary<string, object>();
                if (hasUp)   bw["up"]   = $"{upMbps} mbps";
                if (hasDown) bw["down"] = $"{downMbps} mbps";
                outbound["bandwidth"] = bw;
            }

            return outbound;
        }

        private static object BuildVless(ServerModel sv, Dictionary<string, string> p)
        {
            string serverName = ResolveSni(p, sv.Host);
            bool isReality = p.GetValueOrDefault("security", "") == "reality";
            bool sniIsIp = IPAddress.TryParse(serverName, out _);

            var tls = new Dictionary<string, object>
            {
                ["enabled"] = true,
                ["server_name"] = serverName,
                ["utls"] = new { enabled = true, fingerprint = p.GetValueOrDefault("fp", "chrome") }
            };

            if (isReality && sniIsIp)
                tls["insecure"] = true;

            if (isReality)
                tls["reality"] = new
                {
                    enabled = true,
                    public_key = p.GetValueOrDefault("pbk", ""),
                    short_id = p.GetValueOrDefault("sid", "")
                };

            var outbound = new Dictionary<string, object>
            {
                ["type"] = "vless",
                ["tag"] = "proxy",
                ["server"] = sv.Host,
                ["server_port"] = sv.Port,
                ["uuid"] = sv.Uuid,
                ["packet_encoding"] = "xudp",
                ["tls"] = tls
            };

            var flow = p.GetValueOrDefault("flow", "");
            if (string.IsNullOrEmpty(flow) && isReality)
            {
                flow = "xtls-rprx-vision";
            }
            if (!string.IsNullOrEmpty(flow)) outbound["flow"] = flow;

            var transport = BuildTransport(p);
            if (transport != null) outbound["transport"] = transport;

            return outbound;
        }

        private static object? BuildTransport(Dictionary<string, string> p)
        {
            var netType = p.GetValueOrDefault("type", "tcp");
            return netType switch
            {
                "ws" => (object)new Dictionary<string, object>
                {
                    ["type"] = "ws",
                    ["path"] = p.GetValueOrDefault("path", "/"),
                    ["headers"] = new Dictionary<string, string>
                    {
                        ["Host"] = p.GetValueOrDefault("host", p.GetValueOrDefault("sni", ""))
                    }
                },
                "grpc" => (object)new Dictionary<string, object>
                {
                    ["type"] = "grpc",
                    ["service_name"] = p.GetValueOrDefault("serviceName", p.GetValueOrDefault("authority", ""))
                },
                "h2" => (object)new Dictionary<string, object>
                {
                    ["type"] = "http",
                    ["host"] = new[] { p.GetValueOrDefault("host", p.GetValueOrDefault("sni", "")) },
                    ["path"] = p.GetValueOrDefault("path", "/")
                },
                "httpupgrade" => (object)new Dictionary<string, object>
                {
                    ["type"] = "httpupgrade",
                    ["path"] = p.GetValueOrDefault("path", "/"),
                    ["host"] = p.GetValueOrDefault("host", p.GetValueOrDefault("sni", ""))
                },
                _ => null
            };
        }

        private static object BuildTrojan(ServerModel sv, Dictionary<string, string> p)
        {
            string serverName = ResolveSni(p, sv.Host);
            bool isReality = p.GetValueOrDefault("security", "") == "reality";
            bool sniIsIp = IPAddress.TryParse(serverName, out _);

            var tls = new Dictionary<string, object>
            {
                ["enabled"] = true,
                ["server_name"] = serverName,
                ["utls"] = new { enabled = true, fingerprint = p.GetValueOrDefault("fp", "chrome") }
            };

            if (isReality && sniIsIp)
                tls["insecure"] = true;

            if (isReality)
                tls["reality"] = new
                {
                    enabled = true,
                    public_key = p.GetValueOrDefault("pbk", ""),
                    short_id = p.GetValueOrDefault("sid", "")
                };

            var outbound = new Dictionary<string, object>
            {
                ["type"] = "trojan",
                ["tag"] = "proxy",
                ["server"] = sv.Host,
                ["server_port"] = sv.Port,
                ["password"] = sv.Password,
                ["tls"] = tls
            };

            var transport = BuildTransport(p);
            if (transport != null) outbound["transport"] = transport;

            return outbound;
        }

        private static object? BuildDns(AppSettings s, bool forceFallback = false)
        {
            if (s.DnsType == "system")
            {
                if (!forceFallback) return null;
                var fallbackSrv = new Dictionary<string, object>
                {
                    ["tag"]    = "tun_dns",
                    ["type"]   = "udp",
                    ["server"] = "1.1.1.1",
                    ["detour"] = "proxy"
                };
                return new { servers = new[] { fallbackSrv }, final = "tun_dns" };
            }

            var addr = s.DnsServer;
            var srvDict = new Dictionary<string, object>();
            srvDict["tag"] = "custom_dns";

            if (s.DnsType == "doh")
            {
                if (!addr.StartsWith("https://")) addr = "https://" + addr;
                if (Uri.TryCreate(addr, UriKind.Absolute, out var uri))
                {
                    srvDict["type"]   = "https";
                    srvDict["server"] = uri.Host;
                    srvDict["path"]   = string.IsNullOrEmpty(uri.AbsolutePath) || uri.AbsolutePath == "/"
                                            ? "/dns-query"
                                            : uri.AbsolutePath;
                }
                else
                {
                    srvDict["type"]   = "https";
                    srvDict["server"] = addr.Replace("https://", "").Split('/')[0];
                    srvDict["path"]   = "/dns-query";
                }
            }
            else if (s.DnsType == "dot")
            {
                var host = addr.Replace("tls://", "").Split(':')[0];
                srvDict["type"]   = "tls";
                srvDict["server"] = host;
            }
            else
            {
                srvDict["type"]   = "udp";
                srvDict["server"] = addr.Split(':')[0];
            }

            if (s.DnsThroughProxy)
                srvDict["detour"] = "proxy";

            return new { servers = new[] { srvDict }, final = "custom_dns" };
        }

        private static bool IsIpOrCidr(string s)
        {
            if (s.Contains('/')) s = s[..s.IndexOf('/')];
            return IPAddress.TryParse(s, out _);
        }

        internal static string? GetDefaultPhysicalInterface()
        {
            static bool IsVirtual(string description, string name)
            {
                var tokens = new[]
                {
                    "tun", "tap", "virtual", "pseudo", "wintun", "wfp",
                    "loopback", "teredo", "isatap", "6to4", "miniport",
                    "hyper-v", "vmware", "virtualbox", "docker", "npcap",
                    "taa-tun"
                };
                var d = description.ToLowerInvariant();
                var n = name.ToLowerInvariant();
                return tokens.Any(t => d.Contains(t) || n.Contains(t));
            }

            try
            {
                int bestWmiIndex = -1;
                int bestWmiMetric = int.MaxValue;
                try
                {
                    using var searcher = new ManagementObjectSearcher(
                        "SELECT InterfaceIndex, Metric1 FROM Win32_IP4RouteTable WHERE Destination='0.0.0.0'");
                    foreach (ManagementObject row in searcher.Get())
                    {
                        int m = Convert.ToInt32(row["Metric1"]);
                        if (m < bestWmiMetric)
                        {
                            bestWmiMetric = m;
                            bestWmiIndex = Convert.ToInt32(row["InterfaceIndex"]);
                        }
                    }
                }
                catch { }

                if (bestWmiIndex >= 0)
                {
                    foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                        if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                        if (IsVirtual(ni.Description, ni.Name)) continue;
                        try
                        {
                            var ipv4 = ni.GetIPProperties().GetIPv4Properties();
                            if (ipv4 != null && ipv4.Index == bestWmiIndex)
                                return ni.Name;
                        }
                        catch { }
                    }
                }

                string? bestName   = null;
                int     bestMetric = int.MaxValue;

                foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                    if (IsVirtual(ni.Description, ni.Name)) continue;

                    var props = ni.GetIPProperties();
                    var gateways = props.GatewayAddresses
                        .Where(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .ToList();
                    if (gateways.Count == 0) continue;

                    int metric = int.MaxValue;
                    try
                    {
                        var ipv4 = props.GetIPv4Properties();
                        if (ipv4 != null) metric = ipv4.Index;
                    }
                    catch { }

                    if (metric < bestMetric)
                    {
                        bestMetric = metric;
                        bestName   = ni.Name;
                    }
                }

                return bestName;
            }
            catch { }
            return null;
        }

        internal static string? ResolveServerIpForExclusion(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return null;
            try
            {
                if (IPAddress.TryParse(host, out var addr)
                    && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    return addr.ToString() + "/32";

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                var resolveTask = Dns.GetHostAddressesAsync(host, cts.Token);
                if (resolveTask.Wait(3000))
                {
                    var ipv4 = resolveTask.Result
                        .FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (ipv4 != null) return ipv4.ToString() + "/32";
                }
            }
            catch { }
            return null;
        }
    }
}