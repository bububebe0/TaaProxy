using System;
using System.Diagnostics;

namespace TaaProxy.Services
{
    internal static class KillSwitch
    {
        private const string Rule = "TaaProxy_KillSwitch";
        public static void Set(bool enable)
        {
            try
            {
                if (enable)
                    foreach (var p in new[] { "TCP", "UDP" })
                        Run($"advfirewall firewall add rule name=\"{Rule}\" dir=out action=block protocol={p} remoteaddress=any");
                else
                    Run($"advfirewall firewall delete rule name=\"{Rule}\"");
            }
            catch (Exception ex) { ExceptionLogger.Log(ex); }
        }
        private static void Run(string args)
        {
            using var p = new Process();
            p.StartInfo = new ProcessStartInfo("netsh", args) { CreateNoWindow = true, UseShellExecute = false };
            p.Start(); p.WaitForExit();
        }
    }
}