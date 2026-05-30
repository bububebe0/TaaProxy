using System.Collections.Generic;

namespace TaaProxy.Models
{
    internal class ServerModel
    {
        public string Type { get; set; } = "vless";
        public string Name { get; set; } = "";
        public string Host { get; set; } = "";
        public int Port { get; set; } = 443;
        public Dictionary<string, string> Params { get; set; } = new();
        public string Uuid { get; set; } = "";
        public string Password { get; set; } = "";
        public string Method { get; set; } = "";
        public string PrivateKey { get; set; } = "";
    }
}