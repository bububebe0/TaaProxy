using System;
using System.IO;

namespace TaaProxy
{
    internal static class TempConfigCleaner
    {
        public static void DeleteOrphaned()
        {
            try
            {
                var dataDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data");
                if (!Directory.Exists(dataDir)) return;

                foreach (var file in Directory.GetFiles(dataDir, "cfg_*.json"))
                {
                    try { File.Delete(file); }
                    catch { }
                }
            }
            catch { }
        }
    }
}