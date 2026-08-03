using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal static class MicrosoftIsoDownload
    {
        private const string DownloadPage = "https://www.microsoft.com/en-us/software-download/windows11";
        private const string SessionEndpoint = "https://vlscppe.microsoft.com/fp/tags?org_id=y6jn8c31&session_id=";
        private const string SkuEndpoint = "https://www.microsoft.com/software-download-connector/api/getskuinformationbyproductedition";
        private const string LinkEndpoint = "https://www.microsoft.com/software-download-connector/api/GetProductDownloadLinksBySku";
        private const string Profile = "606624d44113";

        public static Uri Resolve(HttpClient Client, string Locale, Action<string> Report)
        {
            string Session = Guid.NewGuid().ToString();

            Report("[*] Asking Microsoft for a Windows 11 download link...");

            string Page = Get(Client, DownloadPage);
            string Edition = ParseProductEditionId(Page);
            Report($"[*] Edition {Edition} from a {Page.Length} byte page.");

            Get(Client, SessionEndpoint + Session);

            string SkuJson = Get(Client, $"{SkuEndpoint}?profile={Profile}&ProductEditionId={Edition}&SKU=undefined&friendlyFileName=undefined&Locale=en-US&sessionID={Session}", DownloadPage);
            string Sku = ParseSkuId(SkuJson, Locale);
            Report($"[*] Edition SKU {Sku} for {Locale}.");

            string LinkJson = Get(Client, $"{LinkEndpoint}?profile={Profile}&productEditionId=undefined&SKU={Sku}&friendlyFileName=undefined&Locale=en-US&sessionID={Session}", DownloadPage);
            return ParseDownloadUri(LinkJson);
        }

        private static string Get(HttpClient Client, string Address, string? Referer = null)
        {
            using HttpRequestMessage Request = new HttpRequestMessage(HttpMethod.Get, Address);

            if (Referer != null)
                Request.Headers.Referrer = new Uri(Referer);

            using HttpResponseMessage Response = Client.Send(Request, HttpCompletionOption.ResponseContentRead);

            Response.EnsureSuccessStatusCode();
            return Response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        }

        private static string ParseProductEditionId(string Page)
        {
            Match Match = Regex.Match(Page, "<option[^>]*value=\"(\\d{3,5})\"[^>]*>[^<]*Windows\\s*11", RegexOptions.IgnoreCase);

            if (!Match.Success)
                Match = Regex.Match(Page, "ProductEditionId[\"']?\\s*[:=]\\s*[\"']?(\\d{3,5})", RegexOptions.IgnoreCase);

            if (!Match.Success)
                throw new InvalidOperationException("Microsoft's download page did not list a Windows 11 edition. Pass a local ISO with --windows-iso instead.");

            return Match.Groups[1].Value;
        }

        private static string ParseSkuId(string Json, string Locale)
        {
            using JsonDocument Document = JsonDocument.Parse(Json);

            if (!Document.RootElement.TryGetProperty("Skus", out JsonElement Skus) || Skus.ValueKind != JsonValueKind.Array)
                throw new InvalidOperationException(DescribeServiceError(Document, "Microsoft's download service returned no editions."));

            string? Fallback = null;

            foreach (JsonElement Sku in Skus.EnumerateArray())
            {
                string Id = Sku.TryGetProperty("Id", out JsonElement IdValue) ? IdValue.ToString() : string.Empty;
                if (Id.Length == 0)
                    continue;

                Fallback ??= Id;

                string Language = Sku.TryGetProperty("LocalizedLanguage", out JsonElement LanguageValue) ? LanguageValue.ToString() : string.Empty;
                string Code = Sku.TryGetProperty("Language", out JsonElement CodeValue) ? CodeValue.ToString() : string.Empty;

                if (Language.Contains(Locale, StringComparison.OrdinalIgnoreCase) || Code.Equals(Locale, StringComparison.OrdinalIgnoreCase))
                    return Id;
            }

            if (Fallback == null)
                throw new InvalidOperationException("Microsoft's download service listed no usable editions.");

            return Fallback;
        }

        private static Uri ParseDownloadUri(string Json)
        {
            using JsonDocument Document = JsonDocument.Parse(Json);

            if (!Document.RootElement.TryGetProperty("ProductDownloadOptions", out JsonElement Options) || Options.ValueKind != JsonValueKind.Array)
                throw new InvalidOperationException(DescribeServiceError(Document, "Microsoft's download service returned no links."));

            string? First = null;

            foreach (JsonElement Option in Options.EnumerateArray())
            {
                if (!Option.TryGetProperty("Uri", out JsonElement UriValue))
                    continue;

                string Address = UriValue.ToString();
                if (Address.Length == 0)
                    continue;

                First ??= Address;

                if (Address.Contains("x64", StringComparison.OrdinalIgnoreCase))
                    return new Uri(Address);
            }

            if (First == null)
                throw new InvalidOperationException("Microsoft's download service returned no usable links.");

            return new Uri(First);
        }

        private static string DescribeServiceError(JsonDocument Document, string Fallback)
        {
            if (Document.RootElement.TryGetProperty("Errors", out JsonElement Errors) && Errors.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement Error in Errors.EnumerateArray())
                {
                    if (Error.TryGetProperty("Value", out JsonElement Value))
                        return $"Microsoft's download service refused the request: {Value}";
                }
            }

            return Fallback + " The service rate limits automated access; pass a local ISO with --windows-iso instead.";
        }
    }
}
