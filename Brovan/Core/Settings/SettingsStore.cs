using System.Net;
using System.Text;
using System.Text.Json;
using Brovan.Android;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Helpers;

namespace Brovan.Core.Settings
{
    public static class SettingValue
    {
        // A list setting holds addresses and paths, which can carry a comma but never a newline.
        private const char ListSeparator = '\n';

        public static bool TryParseBoolean(string Value, out bool Result)
        {
            switch (Value.Trim().ToLowerInvariant())
            {
                case "1":
                case "on":
                case "yes":
                case "true":
                    Result = true;
                    return true;

                case "0":
                case "off":
                case "no":
                case "false":
                    Result = false;
                    return true;

                default:
                    Result = false;
                    return false;
            }
        }

        public static string[] SplitList(string Value)
        {
            return string.IsNullOrEmpty(Value)
                ? Array.Empty<string>()
                : Value.Split(ListSeparator, StringSplitOptions.RemoveEmptyEntries);
        }

        public static string AppendToList(string Existing, string Value)
        {
            return string.IsNullOrEmpty(Existing) ? Value : Existing + ListSeparator + Value;
        }
    }

    // Holds only the keys that one layer names.
    public sealed class SettingsLayer
    {
        private readonly Dictionary<string, string> Values = new(StringComparer.Ordinal);

        public IEnumerable<KeyValuePair<string, string>> Entries => Values;

        public void Set(string Key, string Value)
        {
            Values[Key] = Value;
        }

        public void Add(string Key, string Value)
        {
            Values[Key] = Values.TryGetValue(Key, out string? Existing)
                ? SettingValue.AppendToList(Existing, Value)
                : Value;
        }
    }

    public static class SettingsStore
    {
        private static readonly JsonDocumentOptions CommentOptions = new()
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };

        public static SettingDescriptor? FindByKey(string Key)
        {
            foreach (SettingDescriptor Descriptor in BrovanSettings.Descriptors)
            {
                if (string.Equals(Descriptor.Key, Key, StringComparison.Ordinal))
                    return Descriptor;
            }

            return null;
        }

        public static string ConfigPath()
        {
            return Path.Combine(AppContext.BaseDirectory, "settings.json");
        }

        // Layers arrive in precedence order. A key a layer does not name is left to the layer below it.
        public static BrovanSettings Resolve(IReadOnlyList<SettingsLayer> Layers, List<string>? Problems = null)
        {
            BrovanSettings Settings = new BrovanSettings();

            for (int i = 0; i < Layers.Count; i++)
            {
                foreach (KeyValuePair<string, string> Entry in Layers[i].Entries)
                {
                    if (!Settings.TryApply(Entry.Key, Entry.Value, out string Error))
                        Problems?.Add($"{Entry.Key}: {Error}");
                }
            }

            return Settings;
        }

        // Settings that reach the emulator as process state rather than as an argument.
        public static void ApplyGlobals(BrovanSettings Settings)
        {
            MemoryBudget.Profile = Settings.LowMemory;
            UnicornCodeCache.Enabled = Settings.JitCache;
            UnicornCodeCache.PrintStats = Settings.JitCacheStats;
            VulkanStandIns.Relax = Settings.RelaxVulkan;

            // Win32 and X11 report one extent the swapchain has to match, so only Android can present smaller.
            BrovVulkWsi.RenderScale = AndroidHost.IsActive ? Settings.RenderScale : 1f;

            if (Settings.JitCacheDirectory.Length != 0)
                UnicornCodeCache.CacheDirectory = Settings.JitCacheDirectory;
        }

        public static bool TryBuildNetworkPolicy(BrovanSettings Settings, out NetworkAccessPolicy Policy)
        {
            Policy = new NetworkAccessPolicy(Settings.NetworkMode);

            foreach (string Address in Settings.NetworkAllow)
            {
                if (!IPAddress.TryParse(Address, out IPAddress? Parsed))
                    return false;

                Policy.AddAllowedAddress(Parsed);
            }

            return true;
        }

        public static void EnsureConfigFile(string Path)
        {
            if (File.Exists(Path))
                return;

            // Utf8JsonWriter puts the separating comma after a comment, which reads as though the comment
            // belongs to the line above.
            StringBuilder Builder = new StringBuilder();
            SettingDescriptor[] Descriptors = BrovanSettings.Descriptors;
            Builder.AppendLine("{");

            for (int i = 0; i < Descriptors.Length; i++)
            {
                SettingDescriptor Descriptor = Descriptors[i];
                Builder.Append("    /*").Append(Describe(Descriptor)).AppendLine("*/");
                Builder.Append("    \"").Append(Descriptor.Key).Append("\": ").Append(Descriptor.DefaultJson);
                Builder.AppendLine(i + 1 < Descriptors.Length ? "," : string.Empty);

                if (i + 1 < Descriptors.Length)
                    Builder.AppendLine();
            }

            Builder.AppendLine("}");

            try
            {
                File.WriteAllText(Path, Builder.ToString());
            }
            catch (Exception)
            {
            }
        }

        private static string Describe(SettingDescriptor Descriptor)
        {
            StringBuilder Builder = new StringBuilder(" ").Append(Descriptor.Help);

            if (Descriptor.AllowedValues.Length != 0 && !Descriptor.IsBoolean)
                Builder.Append(" One of ").Append(string.Join(", ", Descriptor.AllowedValues)).Append('.');

            if (!double.IsNaN(Descriptor.Min) && !double.IsNaN(Descriptor.Max))
                Builder.Append(" From ").Append(Descriptor.Min).Append(" to ").Append(Descriptor.Max).Append('.');

            if (Descriptor.Cli.Length != 0)
                Builder.Append(" Command line ").Append(Descriptor.Cli).Append('.');

            return Builder.Append(' ').Replace("*/", "* /").ToString();
        }

        public static SettingsLayer LoadFile(string Path)
        {
            return File.Exists(Path) ? LoadJson(File.ReadAllBytes(Path)) : new SettingsLayer();
        }

        public static SettingsLayer LoadJson(ReadOnlySpan<byte> Text)
        {
            SettingsLayer Layer = new SettingsLayer();
            if (Text.Length == 0)
                return Layer;

            try
            {
                using JsonDocument Document = JsonDocument.Parse(Text.ToArray(), CommentOptions);
                if (Document.RootElement.ValueKind != JsonValueKind.Object)
                    return Layer;

                foreach (JsonProperty Property in Document.RootElement.EnumerateObject())
                {
                    if (Property.Value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement Element in Property.Value.EnumerateArray())
                            Layer.Add(Property.Name, ElementText(Element));

                        continue;
                    }

                    Layer.Set(Property.Name, ElementText(Property.Value));
                }
            }
            catch (Exception)
            {
                // Text that cannot be read leaves the layer below it in charge.
            }

            return Layer;
        }

        public static SettingsLayer LoadEnvironment()
        {
            SettingsLayer Layer = new SettingsLayer();

            foreach (SettingDescriptor Descriptor in BrovanSettings.Descriptors)
            {
                string Value = Environment.GetEnvironmentVariable(EnvironmentName(Descriptor.Key)) ?? string.Empty;
                if (Value.Length != 0)
                    Layer.Set(Descriptor.Key, Value);
            }

            return Layer;
        }

        public static string EnvironmentName(string Key)
        {
            StringBuilder Builder = new StringBuilder("BROVAN_", Key.Length + 8);
            foreach (char Character in Key)
                Builder.Append(Character is '.' or '-' ? '_' : char.ToUpperInvariant(Character));

            return Builder.ToString();
        }

        private static string ElementText(JsonElement Element)
        {
            return Element.ValueKind switch
            {
                JsonValueKind.String => Element.GetString() ?? string.Empty,
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Number => Element.GetRawText(),
                _ => Element.GetRawText(),
            };
        }
    }

    public static class SettingsCommandLine
    {
        // Options that are not settings but still take a value, which the parser has to step over.
        private static readonly string[] ValueTaking =
        {
            "-c", "--command", "--cwd", "--guest-cmdline", "--windows-iso", "--windows-image", "--regdir",
        };

        // The first bare token is the program path, so nothing after it is read as an option.
        public static SettingsLayer Parse(string[] Args, List<string> Remaining, List<string>? Problems = null)
        {
            SettingsLayer Layer = new SettingsLayer();
            bool Stopped = false;

            for (int i = 0; i < Args.Length; i++)
            {
                string Argument = Args[i];

                if (Stopped)
                {
                    Remaining.Add(Argument);
                    continue;
                }

                string Token = Argument;
                string Inline = string.Empty;
                bool HasInline = false;

                int Separator = Argument.IndexOf('=');
                if (Separator > 0 && Argument.StartsWith("-", StringComparison.Ordinal))
                {
                    Token = Argument.Substring(0, Separator);
                    Inline = Argument.Substring(Separator + 1);
                    HasInline = true;
                }

                if (string.Equals(Token, "--set", StringComparison.OrdinalIgnoreCase))
                {
                    string Pair = HasInline ? Inline : i + 1 < Args.Length ? Args[++i] : string.Empty;
                    int Assign = Pair.IndexOf('=');
                    if (Assign <= 0)
                    {
                        Problems?.Add("--set needs a setting written as key=value");
                        continue;
                    }

                    string Name = Pair.Substring(0, Assign);
                    SettingDescriptor? Named = SettingsStore.FindByKey(Name);
                    if (Named == null)
                        Problems?.Add($"{Name}: unknown setting");
                    else
                        Store(Layer, Named, Pair.Substring(Assign + 1), false, Problems, Token);

                    continue;
                }

                if (TryMatch(Token, out SettingDescriptor Descriptor, out bool Negated))
                {
                    string Value;

                    if (Negated)
                    {
                        Value = "false";
                    }
                    else if (HasInline)
                    {
                        Value = Inline;
                    }
                    else if (Descriptor.IsBoolean)
                    {
                        Value = "true";
                    }
                    else if (i + 1 < Args.Length)
                    {
                        Value = Args[++i];
                    }
                    else
                    {
                        Problems?.Add($"{Token} needs a value");
                        continue;
                    }

                    Store(Layer, Descriptor, Value, HasInline && !Negated, Problems, Token);
                    continue;
                }

                if (!HasInline && Array.IndexOf(ValueTaking, Argument) >= 0)
                {
                    Remaining.Add(Argument);
                    if (i + 1 < Args.Length)
                        Remaining.Add(Args[++i]);

                    continue;
                }

                if (!Argument.StartsWith("-", StringComparison.Ordinal))
                    Stopped = true;

                Remaining.Add(Argument);
            }

            return Layer;
        }

        private static void Store(SettingsLayer Layer, SettingDescriptor Descriptor, string Value,
            bool Inline, List<string>? Problems, string Token)
        {
            // A boolean alias written with a non-boolean value carries a payload for another setting, as
            // --jit-cache=DIR does.
            if (Inline && Descriptor.IsBoolean && !SettingValue.TryParseBoolean(Value, out _))
            {
                if (Descriptor.CliValueSets.Length == 0)
                {
                    Problems?.Add($"{Token} does not take a value");
                    return;
                }

                Layer.Set(Descriptor.Key, "true");
                Layer.Set(Descriptor.CliValueSets, Value);
                return;
            }

            if (Descriptor.Repeatable)
                Layer.Add(Descriptor.Key, Value);
            else
                Layer.Set(Descriptor.Key, Value);
        }

        private static bool TryMatch(string Token, out SettingDescriptor Descriptor, out bool Negated)
        {
            foreach (SettingDescriptor Candidate in BrovanSettings.Descriptors)
            {
                if (Candidate.Cli.Length != 0 && string.Equals(Token, Candidate.Cli, StringComparison.OrdinalIgnoreCase))
                {
                    Descriptor = Candidate;
                    Negated = false;
                    return true;
                }

                if (Candidate.CliShort.Length != 0 && string.Equals(Token, Candidate.CliShort, StringComparison.Ordinal))
                {
                    Descriptor = Candidate;
                    Negated = false;
                    return true;
                }

                if (Candidate.CliNegated.Length != 0 && string.Equals(Token, Candidate.CliNegated, StringComparison.OrdinalIgnoreCase))
                {
                    Descriptor = Candidate;
                    Negated = true;
                    return true;
                }
            }

            Descriptor = null!;
            Negated = false;
            return false;
        }
    }
}
