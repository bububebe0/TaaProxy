#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using TaaProxy.Views;

namespace TaaProxy
{
    internal static class Program
    {
        private static Mutex? _mutex;

        [STAThread]
        public static void Main()
        {
            if (ApplyPendingSelfUpdate()) return;

            _mutex = new Mutex(true, "TaaClient_Singleton_Mutex_CSharp", out bool isNew);
            if (!isNew) { BringToFront(); return; }

            SystemProxy.ClearStale();
            TempConfigCleaner.DeleteOrphaned();

            AppDomain.CurrentDomain.ProcessExit += (_, _) => { SystemProxy.Set(false); KillSwitch.Set(false); };

            var app = new TaaApp();
            app.Run(new MainWindow());
        }

        private static bool ApplyPendingSelfUpdate()
        {
            try
            {
                var exe = Process.GetCurrentProcess().MainModule?.FileName;
                if (exe == null) return false;
                var pending = exe + ".new";
                if (!File.Exists(pending)) return false;

                File.Replace(pending, exe, destinationBackupFileName: null);
                try
                {
                    foreach (var hWnd in GetVisibleWindows())
                        NativeInterop.ShowWindow(hWnd, 0);
                }
                catch { }

                Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true });
                return true;
            }
            catch
            {
                try
                {
                    var exe = Process.GetCurrentProcess().MainModule?.FileName;
                    if (exe != null) File.Delete(exe + ".new");
                }
                catch { }
                return false;
            }
        }

        private static List<IntPtr> GetVisibleWindows()
        {
            var result = new List<IntPtr>();
            var pid = (uint)Process.GetCurrentProcess().Id;
            NativeInterop.EnumWindows((hWnd, _) =>
            {
                NativeInterop.GetWindowThreadProcessId(hWnd, out uint ownerPid);
                if (ownerPid == pid && NativeInterop.IsWindowVisible(hWnd))
                    result.Add(hWnd);
                return true;
            }, IntPtr.Zero);
            return result;
        }

        public static void ReleaseMutex()
        {
            try { _mutex?.ReleaseMutex(); } catch { }
            _mutex?.Dispose();
            _mutex = null;
        }

        private static void BringToFront()
        {
            const int WM_SHOW_INSTANCE = 0x0401;
            var ourExe = Process.GetCurrentProcess().MainModule?.FileName ?? "";

            NativeInterop.EnumWindows((hWnd, _) =>
            {
                NativeInterop.GetWindowThreadProcessId(hWnd, out uint pid);
                try
                {
                    var proc = Process.GetProcessById((int)pid);
                    if (string.Equals(proc.MainModule?.FileName, ourExe, StringComparison.OrdinalIgnoreCase))
                    {
                        NativeInterop.PostMessage(hWnd, WM_SHOW_INSTANCE, IntPtr.Zero, IntPtr.Zero);
                        return false;
                    }
                }
                catch { }
                return true;
            }, IntPtr.Zero);
        }
    }
}
