using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BrovanGUI.Models
{
    public sealed class SettingEntry
    {
        public string Key { get; set; } = string.Empty;
        public string Type { get; set; } = "string";
        public string Category { get; set; } = string.Empty;
        public string Scope { get; set; } = "program";
        public string Applies { get; set; } = "boot";
        public string Help { get; set; } = string.Empty;
        public string Cli { get; set; } = string.Empty;
        public bool Repeatable { get; set; }
        public string[] Platforms { get; set; } = Array.Empty<string>();
        public string[] Values { get; set; } = Array.Empty<string>();
        public double? Min { get; set; }
        public double? Max { get; set; }
        public JsonElement Default { get; set; }

        public bool IsGlobal => string.Equals(Scope, "global", StringComparison.OrdinalIgnoreCase);

        public bool AppliesToHost
        {
            get
            {
                if (Platforms == null || Platforms.Length == 0)
                    return true;

                string Host = OperatingSystem.IsWindows() ? "windows" : "linux";
                foreach (string Platform in Platforms)
                {
                    if (string.Equals(Platform, Host, StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                return false;
            }
        }

        // Text in the shape --set takes. A list keeps one item per line.
        public string DefaultText
        {
            get
            {
                switch (Default.ValueKind)
                {
                    case JsonValueKind.String:
                        return Default.GetString() ?? string.Empty;
                    case JsonValueKind.True:
                        return "true";
                    case JsonValueKind.False:
                        return "false";
                    case JsonValueKind.Number:
                        return Default.GetRawText();
                    case JsonValueKind.Array:
                        StringBuilder Builder = new StringBuilder();
                        foreach (JsonElement Item in Default.EnumerateArray())
                        {
                            if (Builder.Length != 0)
                                Builder.Append('\n');
                            Builder.Append(Item.ToString());
                        }
                        return Builder.ToString();
                    default:
                        return string.Empty;
                }
            }
        }
    }

    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true)]
    [JsonSerializable(typeof(SettingEntry[]))]
    internal sealed partial class SchemaJsonContext : JsonSerializerContext
    {
    }

    public static class SettingSchema
    {
        private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

        public static async Task<SettingEntry[]> LoadAsync(string BrovanExecutable)
        {
            ProcessStartInfo Info = new ProcessStartInfo(BrovanExecutable)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(BrovanExecutable),
                StandardOutputEncoding = Encoding.UTF8,
            };
            Info.ArgumentList.Add("--settings-schema");

            using Process Child = Process.Start(Info) ?? throw new InvalidOperationException("Brovan did not start.");

            // A build that does not know the option runs its whole startup instead and can stop at a prompt.
            Child.StandardInput.Close();
            Task<string> Output = Child.StandardOutput.ReadToEndAsync();
            Task<string> Errors = Child.StandardError.ReadToEndAsync();

            using CancellationTokenSource Deadline = new CancellationTokenSource(Patience);
            try
            {
                await Child.WaitForExitAsync(Deadline.Token);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    Child.Kill(true);
                }
                catch (Exception)
                {
                }

                throw new InvalidOperationException("Brovan did not answer --settings-schema within "
                    + Patience.TotalSeconds + " seconds. Update Brovan.");
            }

            string Text = (await Output).TrimStart('\uFEFF', ' ', '\t', '\r', '\n');
            await Errors;

            if (Child.ExitCode != 0 || !Text.StartsWith('['))
                throw new InvalidOperationException("This Brovan build does not answer --settings-schema. Update Brovan.");

            return JsonSerializer.Deserialize(Text, SchemaJsonContext.Default.SettingEntryArray) ?? Array.Empty<SettingEntry>();
        }
    }
}
