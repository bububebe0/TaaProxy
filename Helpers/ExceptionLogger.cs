using System;
using System.IO;

namespace TaaProxy
{
    internal static class ExceptionLogger
    {
        private static string LogFile =>
            Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "data", "logs", "error.log");

        public static bool Log(Exception ex)
        {
            try
            {
                var msg = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [swallowed] {ex}\n";
                var dir = Path.GetDirectoryName(LogFile);
                if (dir != null) Directory.CreateDirectory(dir);

                const long maxBytes = 6000L * 1024;
                if (File.Exists(LogFile) && new FileInfo(LogFile).Length >= maxBytes)
                    File.WriteAllText(LogFile, string.Empty);

                File.AppendAllText(LogFile, msg);
            }
            catch { }
            return false;
        }
    }
}