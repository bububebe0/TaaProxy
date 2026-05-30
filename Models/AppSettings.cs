using System.Collections.Generic;

namespace TaaProxy.Models
{
    internal class AppSettings
    {
        public bool SplitTunneling { get; set; } = false;
        public string Language { get; set; } = "ru";
        public string DefaultServer { get; set; } = "";
        public string DnsType { get; set; } = "system";
        public string DnsServer { get; set; } = "https://1.1.1.1/dns-query";
        public bool DnsThroughProxy { get; set; } = true;
        public List<AppException> AppExceptions { get; set; } = new();
        public List<string> DomainExceptions { get; set; } = new();
        public bool MinimizeOnClose { get; set; } = true;
        public bool DebugMode { get; set; } = false;
        public bool KillSwitch { get; set; } = false;
        public bool AutoReconnect { get; set; } = true;
        public string CurrentRoutesFile { get; set; } = "routes.txt";
        public double WindowLeft { get; set; } = -1;
        public double WindowTop { get; set; } = -1;
        public double WindowWidth { get; set; } = 1032;
        public double WindowHeight { get; set; } = 695;
        public bool UseTunMode { get; set; } = false;
        public string HotkeyToggle { get; set; } = "";
        public string HotkeyRouting { get; set; } = "";
        public string HotkeyTun { get; set; } = "";
        public string HotkeyExit { get; set; } = "";
        public List<RouteListBinding> RouteListBindings { get; set; } = new();
        public bool EnableNotifications { get; set; } = false;
        public bool AutoConnectOnStart { get; set; } = false;
        public bool MinimizeOnStartup { get; set; } = false;
        public bool LogCollapsed { get; set; } = false;
    }
}