using System;
using System.IO;

namespace TaaProxy
{
    internal static class Paths
    {
        public static string Base => AppDomain.CurrentDomain.BaseDirectory;
        public static string DataDir => Path.Combine(Base, "data");
        public static string ListDir => Path.Combine(Base, "list");
        public static string DbFile => Path.Combine(DataDir, "servers.json");
        public static string SettingsFile => Path.Combine(DataDir, "settings.json");
        public static string ConfigFile => Path.Combine(DataDir, "config.json");
        public static string LogFile => Path.Combine(Base, "proxy.log");
        public static string Resource(string n) => Path.Combine(Base, n);
        public static string LogPath(string n) => Path.Combine(Base, n);

        private const long MaxLogBytes = 6000L * 1024;

        public static void RotateLogFile(string path)
        {
            try
            {
                if (!File.Exists(path)) return;
                if (new FileInfo(path).Length < MaxLogBytes) return;
                File.WriteAllText(path, string.Empty);
            }
            catch { }
        }

        public static void AppendLog(string path, string text)
        {
            try
            {
                if (File.Exists(path) && new FileInfo(path).Length >= MaxLogBytes)
                    File.WriteAllText(path, string.Empty);
                File.AppendAllText(path, text);
            }
            catch { }
        }
    }
}