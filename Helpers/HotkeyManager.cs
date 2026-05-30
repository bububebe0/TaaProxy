using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Input;

namespace TaaProxy
{
    internal static class HotkeyManager
    {
        public const uint MOD_ALT      = 0x0001;
        public const uint MOD_CTRL     = 0x0002;
        public const uint MOD_SHIFT    = 0x0004;
        public const uint MOD_NOREPEAT = 0x4000;

        public static string Build(bool ctrl, bool alt, bool shift, Key key)
        {
            if (IsModOnly(key)) return "";
            if (!ctrl && !alt && !shift)
            {
                return KeyToStr(key);
            }
            var p = new List<string>();
            if (ctrl)  p.Add("Ctrl");
            if (alt)   p.Add("Alt");
            if (shift) p.Add("Shift");
            p.Add(KeyToStr(key));
            return string.Join("+", p);
        }

        public static bool TryParse(string s, out uint mods, out uint vk)
        {
            mods = 0; vk = 0;
            if (string.IsNullOrEmpty(s)) return false;
            var parts = s.Split('+');
            if (parts.Length == 1)
            {
                var ks = parts[0];
                if (ks.Length == 1 && char.IsDigit(ks[0])) ks = "D" + ks;
                try
                {
                    var key = (Key)Enum.Parse(typeof(Key), ks, ignoreCase: true);
                    vk = (uint)KeyInterop.VirtualKeyFromKey(key);
                    mods = MOD_NOREPEAT;
                    return vk != 0;
                }
                catch { return false; }
            }
            else if (parts.Length >= 2)
            {
                foreach (var t in parts[..^1])
                {
                    if (t == "Ctrl")       mods |= MOD_CTRL;
                    else if (t == "Alt")   mods |= MOD_ALT;
                    else if (t == "Shift") mods |= MOD_SHIFT;
                }
                mods |= MOD_NOREPEAT;
                var ks = parts[^1];
                if (ks.Length == 1 && char.IsDigit(ks[0])) ks = "D" + ks;
                try
                {
                    var key = (Key)Enum.Parse(typeof(Key), ks, ignoreCase: true);
                    vk = (uint)KeyInterop.VirtualKeyFromKey(key);
                    return vk != 0;
                }
                catch { return false; }
            }
            return false;
        }

        private static bool IsModOnly(Key k) => k is
            Key.LeftCtrl or Key.RightCtrl or Key.LeftAlt or Key.RightAlt or
            Key.LeftShift or Key.RightShift or Key.LWin or Key.RWin or
            Key.System or Key.None or Key.Tab or Key.CapsLock;

        private static string KeyToStr(Key k) => k switch
        {
            Key.D0 => "0", Key.D1 => "1", Key.D2 => "2", Key.D3 => "3", Key.D4 => "4",
            Key.D5 => "5", Key.D6 => "6", Key.D7 => "7", Key.D8 => "8", Key.D9 => "9",
            _ => k.ToString()
        };
    }
}