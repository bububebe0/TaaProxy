using System;
using System.Diagnostics;
using System.IO;

namespace TaaProxy.Services
{
    internal static class FileAcl
    {
        public static void SecureFile(string path)
        {
            if (!File.Exists(path)) return;
            try
            {
                var domain = Environment.UserDomainName;
                var user   = Environment.UserName;
                var account = string.IsNullOrEmpty(domain) || domain == Environment.MachineName
                    ? user
                    : $"{domain}\\{user}";

                RunIcacls($"\"{path}\" /inheritance:r /grant:r \"{account}:F\"");
            }
            catch { }
        }

        private static void RunIcacls(string args)
        {
            using var p = new Process();
            p.StartInfo = new ProcessStartInfo("icacls", args)
            {
                CreateNoWindow  = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            };
            p.Start();
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(5000);
        }
    }
}