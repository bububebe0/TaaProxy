namespace TaaProxy.Models
{
    internal class AppException
    {
        public string ExType { get; set; } = "path";
        public string Value { get; set; } = "";
        public string Name { get; set; } = "";
    }
}