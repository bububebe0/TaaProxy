using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using TaaProxy.Models;

namespace TaaProxy.Services
{
    internal static class LinkParser
    {
        private static readonly string[] Schemes = { "vless://", "hysteria2://", "ss://", "trojan://" };

        public static ServerModel? Parse(string link)
        {
            if (!Schemes.Any(s => link.StartsWith(s, StringComparison.OrdinalIgnoreCase))) return null;
            try
            {
                var uri = new Uri(link);
                var q = ParseQuery(uri.Query);
                var frag = uri.Fragment.TrimStart('#');
                var rawName = string.IsNullOrEmpty(frag) ? uri.Host : Uri.UnescapeDataString(frag);
                var name = rawName.Length > 120 ? rawName[..120] : rawName;
                var sv = new ServerModel
                {
                    Type = uri.Scheme,
                    Name = name,
                    Host = uri.Host,
                    Port = uri.Port > 0 ? uri.Port : 443,
                    Params = q
                };
                switch (uri.Scheme)
                {
                    case "vless":
                        sv.Uuid = uri.UserInfo;
                        break;
                    case "hysteria2":
                        sv.Password = Uri.UnescapeDataString(uri.UserInfo ?? "");
                        if (q.TryGetValue("security", out var sec) && sec.Equals("reality", StringComparison.OrdinalIgnoreCase))
                        {
                            sv.Type = "vless";
                            sv.Uuid = sv.Password;
                            sv.Password = "";
                        }
                        break;
                    case "ss":
                        var ui = uri.UserInfo ?? "";
                        if (ui.Contains(':'))
                        {
                            var idx = ui.IndexOf(':');
                            sv.Method = Uri.UnescapeDataString(ui[..idx]);
                            sv.Password = Uri.UnescapeDataString(ui[(idx + 1)..]);
                        }
                        else
                        {
                            try
                            {
                                var dec = Encoding.UTF8.GetString(Convert.FromBase64String(
                                    ui.PadRight(ui.Length + (4 - ui.Length % 4) % 4, '=')));
                                if (dec.Contains(':'))
                                { sv.Method = dec[..dec.IndexOf(':')]; sv.Password = dec[(dec.IndexOf(':') + 1)..]; }
                            }
                            catch { sv.Method = ui; }
                        }
                        if (sv.Method.StartsWith("2022-", StringComparison.OrdinalIgnoreCase)) return null;
                        break;
                    case "trojan":
                        sv.Password = Uri.UnescapeDataString(uri.UserInfo ?? "");
                        if (string.IsNullOrEmpty(frag))
                            sv.Name = $"Trojan {uri.Host}:{sv.Port}";
                        break;
                }
                return sv;
            }
            catch { return null; }
        }

        public static List<ServerModel> ExtractAll(string text)
        {
            var pat = @"(vless://[^\s]+|hysteria2://[^\s]+|ss://[^\s]+|trojan://[^\s]+)";
            return Regex.Matches(text, pat).Select(m => Parse(m.Value)).OfType<ServerModel>().ToList();
        }

        public static string ToShareUri(ServerModel sv)
        {
            var q     = string.Join("&", sv.Params.Select(kv => Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value)));
            var query = q.Length > 0 ? "?" + q : "";
            var frag  = "#" + Uri.EscapeDataString(sv.Name);
            return sv.Type switch
            {
                "vless"     => $"vless://{sv.Uuid}@{sv.Host}:{sv.Port}{query}{frag}",
                "trojan"    => $"trojan://{Uri.EscapeDataString(sv.Password)}@{sv.Host}:{sv.Port}{query}{frag}",
                "ss"        => $"ss://{Convert.ToBase64String(Encoding.UTF8.GetBytes($"{sv.Method}:{sv.Password}"))}@{sv.Host}:{sv.Port}{frag}",
                "hysteria2" => $"hysteria2://{Uri.EscapeDataString(sv.Password)}@{sv.Host}:{sv.Port}{query}{frag}",
                _           => ""
            };
        }

        private static Dictionary<string, string> ParseQuery(string q)
        {
            var d = new Dictionary<string, string>();
            foreach (var part in q.TrimStart('?').Split('&'))
            {
                var i = part.IndexOf('=');
                if (i < 0) continue;
                d[Uri.UnescapeDataString(part[..i])] = Uri.UnescapeDataString(part[(i + 1)..]);
            }
            return d;
        }
    }
}