using System;
using Microsoft.Win32;

namespace TaaProxy.Services
{
    internal static class SystemProxy
    {
        private const string Reg = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        public static void Set(bool enable, int port = 1080)
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(Reg, true)!;
                k.SetValue("ProxyEnable", enable ? 1 : 0, RegistryValueKind.DWord);
                if (enable) k.SetValue("ProxyServer", $"127.0.0.1:{port}", RegistryValueKind.String);
                NativeInterop.RefreshIE();
            }
            catch (Exception ex) { ExceptionLogger.Log(ex); }
        }

        public static void ClearStale()
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(Reg)!;
                if ((int)(k.GetValue("ProxyEnable") ?? 0) == 1)
                    if (((k.GetValue("ProxyServer") as string) ?? "").StartsWith("127.0.0.1:"))
                        Set(false);
            }
            catch (Exception ex) { ExceptionLogger.Log(ex); }
        }
    }
}