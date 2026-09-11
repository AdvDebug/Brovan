using Brovan.Core.Emulation;

namespace Brovan.Core.Settings
{
    public enum SettingCategory
    {
        Backend,
        Network,
        Graphics,
        Input,
        Platform,
        Diagnostics,
    }

    public enum SettingScope
    {
        Program,
        Global,
    }

    public enum SettingApplies
    {
        Boot,
        Live,
    }

    [Flags]
    public enum SettingPlatforms
    {
        Windows = 1,
        Linux = 2,
        Android = 4,
        All = Windows | Linux | Android,
    }

    [AttributeUsage(AttributeTargets.Property)]
    public sealed class SettingAttribute : Attribute
    {
        public SettingAttribute(string Key, SettingCategory Category)
        {
            this.Key = Key;
            this.Category = Category;
        }

        public string Key { get; }

        public SettingCategory Category { get; }

        public SettingScope Scope { get; set; } = SettingScope.Program;

        public SettingApplies Applies { get; set; } = SettingApplies.Boot;

        public SettingPlatforms Platforms { get; set; } = SettingPlatforms.All;

        public string Help { get; set; } = string.Empty;

        // Long command line alias, with the leading dashes.
        public string Cli { get; set; } = string.Empty;

        public string CliShort { get; set; } = string.Empty;

        // Alias that sets a boolean to the opposite of Cli.
        public string CliNegated { get; set; } = string.Empty;

        // Key that takes the value when a boolean alias is written with one, as in --jit-cache=DIR.
        public string CliValueSets { get; set; } = string.Empty;

        public bool Repeatable { get; set; }

        public double Min { get; set; } = double.NaN;

        public double Max { get; set; } = double.NaN;
    }

    public sealed class SettingDescriptor
    {
        public string Key = string.Empty;
        public string Cli = string.Empty;
        public string CliShort = string.Empty;
        public string CliNegated = string.Empty;
        public string CliValueSets = string.Empty;
        public string Help = string.Empty;
        public string DefaultText = string.Empty;
        public string DefaultJson = "null";
        public string[] AllowedValues = Array.Empty<string>();
        public SettingCategory Category;
        public SettingScope Scope;
        public SettingApplies Applies;
        public SettingPlatforms Platforms;
        public bool IsBoolean;
        public bool Repeatable;
        public double Min = double.NaN;
        public double Max = double.NaN;
    }

    // The parser, the help, the file reader and the launcher schema are generated from these properties.
    public sealed partial class BrovanSettings
    {
        [Setting("backend.kind", SettingCategory.Backend, Cli = "--backend",
            Help = "Emulation backend.")]
        public EmulationBackendKind Backend { get; set; } = EmulationBackendKind.Unicorn;

        [Setting("backend.smp", SettingCategory.Backend, CliNegated = "--no-smp",
            Help = "Run guest threads at once on a hypervisor backend.")]
        public bool Smp { get; set; } = true;

        [Setting("backend.cores", SettingCategory.Backend, Cli = "--cores", Min = 0, Max = 4096,
            Help = "Guest threads a hypervisor backend runs at once. 0 picks host processors minus one.")]
        public int Cores { get; set; }

        [Setting("backend.hooks", SettingCategory.Backend, CliNegated = "--no-hooks",
            Help = "Instrumentation hooks. Turning them off trades visibility for speed.")]
        public bool Hooks { get; set; } = true;

        [Setting("backend.quick", SettingCategory.Backend, Cli = "--quick", CliShort = "-q",
            Help = "Quick mode, which uses less memory on large binaries. Always on for this build.")]
        public bool Quick { get; set; } = true;

        [Setting("jit.cache", SettingCategory.Backend, Cli = "--jit-cache", CliNegated = "--no-jit-cache",
            CliValueSets = "jit.cache-dir",
            Help = "Reuse a persisted Unicorn code cache instead of translating on every launch.")]
        public bool JitCache { get; set; } = true;

        [Setting("jit.cache-dir", SettingCategory.Backend, Scope = SettingScope.Global,
            Help = "Where the persisted code cache lives. Empty means .jitcache next to Brovan.")]
        public string JitCacheDirectory { get; set; } = string.Empty;

        [Setting("jit.stats", SettingCategory.Diagnostics, Cli = "--jit-cache-stats",
            Help = "Print code cache statistics when the emulated program exits.")]
        public bool JitCacheStats { get; set; }

        [Setting("graphics.relax-vulkan", SettingCategory.Graphics,
            Help = "Claim the core Vulkan features nothing stands in for.")]
        public bool RelaxVulkan { get; set; }

        [Setting("graphics.render-scale", SettingCategory.Graphics, Cli = "--render-scale", Min = 0.25, Max = 1.0,
            Platforms = SettingPlatforms.Android,
            Help = "Fraction of the window the guest renders at. Below 1 every render target the program sizes from the surface gets smaller and the display scales the result back up.")]
        public float RenderScale { get; set; } = 1f;

        [Setting("platform.low-memory", SettingCategory.Platform, Cli = "--low-memory",
            Help = "How hard to trade throughput for a smaller footprint. Each step shrinks the caches and pools further and tells the program the machine has less memory.")]
        public MemoryProfile LowMemory { get; set; }

        [Setting("net.mode", SettingCategory.Network, Cli = "--net",
            Help = "Host networking policy.")]
        public NetworkAccessMode NetworkMode { get; set; } = NetworkAccessMode.Loopback;

        [Setting("net.allow", SettingCategory.Network, Cli = "--net-allow", Repeatable = true,
            Help = "Addresses allowed on top of the selected policy.")]
        public string[] NetworkAllow { get; set; } = Array.Empty<string>();

        [Setting("log.silent", SettingCategory.Diagnostics, Cli = "--silent", CliShort = "-s",
            Help = "Show only output coming from the emulated program.")]
        public bool Silent { get; set; }
    }
}
