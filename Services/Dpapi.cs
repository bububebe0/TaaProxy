using System.Security.Cryptography;

namespace TaaProxy.Services
{
    internal static class Dpapi
    {
        public static byte[] Encrypt(byte[] d) => ProtectedData.Protect(d, null, DataProtectionScope.CurrentUser);
        public static byte[] Decrypt(byte[] d) => ProtectedData.Unprotect(d, null, DataProtectionScope.CurrentUser);
    }
}