using System;
using System.Diagnostics;
using Microsoft.Win32;

namespace TaaProxy.Services
{
    internal static class Autostart
    {
        private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Run";
        public static bool IsEnabled()
        {
            try { using var k = Registry.CurrentUser.OpenSubKey(Key)!; return (k.GetValue("TaaClient") as string) == ExePath(); }
            catch { return false; }
        }
        public static void Set(bool on)
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(Key, true)!;
                if (on) k.SetValue("TaaClient", ExePath(), RegistryValueKind.String);
                else k.DeleteValue("TaaClient", false);
            }
            catch (Exception ex) { ExceptionLogger.Log(ex); }
        }
        private static string ExePath() => Process.GetCurrentProcess().MainModule?.FileName ?? "";
    }
}