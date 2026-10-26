using System.IO.Compression;
using System.Text.Json;

namespace Brovan.WinFacts.Sources
{
    internal sealed record FileBuild(string FileName, ushort Build, ushort Revision, uint Timestamp, uint VirtualSize)
    {
        internal string Version => $"{Build}.{Revision}";
    }

    internal static class Winbindex
    {
        private const string IndexUrl = "https://winbindex.m417z.com/data/by_filename_compressed/{0}.json.gz";
        private const ushort MachineAmd64 = 0x8664;

        internal static IReadOnlyList<FileBuild> Read(HttpClient Client, string FileName)
        {
            using Stream Compressed = Client.GetStreamAsync(string.Format(IndexUrl, FileName)).GetAwaiter().GetResult();
            using GZipStream Json = new(Compressed, CompressionMode.Decompress);
            using JsonDocument Document = JsonDocument.Parse(Json);

            List<FileBuild> Builds = new();
            foreach (JsonProperty Entry in Document.RootElement.EnumerateObject())
            {
                if (!Entry.Value.TryGetProperty("fileInfo", out JsonElement Info) || !Info.TryGetProperty("timestamp", out JsonElement Timestamp)
                    || !Info.TryGetProperty("virtualSize", out JsonElement Size) || !Info.TryGetProperty("version", out JsonElement VersionText)
                    || !Info.TryGetProperty("machineType", out JsonElement Machine))
                    continue;

                if (!TryParseVersion(VersionText.GetString(), out ushort Build, out ushort Revision) || Machine.GetInt32() != MachineAmd64
                    || !Entry.Value.TryGetProperty("windowsVersions", out JsonElement Releases))
                    continue;

                if (Releases.EnumerateObject().Any(Release => Release.Name.StartsWith("11-", StringComparison.Ordinal) && Release.Value.EnumerateObject().Any()))
                    Builds.Add(new FileBuild(FileName, Build, Revision, Timestamp.GetUInt32(), Size.GetUInt32()));
            }

            Builds.Sort((A, B) => (A.Build, A.Revision).CompareTo((B.Build, B.Revision)));
            return Builds;
        }

        // "10.0.26100.9711 (WinBuild.160101.0800)"
        private static bool TryParseVersion(string Text, out ushort Build, out ushort Revision)
        {
            Build = 0;
            Revision = 0;
            string[] Parts = Text?.Split(' ')[0].Split('.');
            return Parts is { Length: 4 } && Parts[0] == "10" && ushort.TryParse(Parts[2], out Build) && ushort.TryParse(Parts[3], out Revision);
        }
    }

    // Microsoft's symbol server. With a local store in the same layout, a file missing from the store is downloaded into
    // it whole, so a later run reads it without the network. Without one, only the byte ranges a rule reads are fetched.
    internal sealed class SymbolServer
    {
        private const string Root = "https://msdl.microsoft.com/download/symbols";

        private readonly HttpClient Client;
        private readonly string Store;

        internal SymbolServer(HttpClient Client, string Store)
        {
            this.Client = Client;
            this.Store = Store;
        }

        internal IByteSource OpenBinary(FileBuild File) => Open(File.FileName, $"{File.Timestamp:X8}{File.VirtualSize:x}");

        internal IByteSource OpenPdb(string PdbName, Guid Guid, uint Age) => Open(PdbName, $"{Guid.ToString("N").ToUpperInvariant()}{Age:X}");

        private IByteSource Open(string Name, string Key)
        {
            string Url = $"{Root}/{Name}/{Key}/{Name}";
            if (Store == null)
                return RemoteFile.Open(Client, Url);

            string Local = Path.Combine(Store, Name, Key, Name);
            return File.Exists(Local) || RemoteFile.TryDownload(Client, Url, Local) ? new LocalFile(Local) : null;
        }
    }
}
