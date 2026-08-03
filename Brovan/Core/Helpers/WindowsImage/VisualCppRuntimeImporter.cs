using System;
using System.Buffers;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Text.Json;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal static class VisualCppRuntimeImporter
    {
        private const string ChannelManifest = "https://aka.ms/vs/17/release/channel";
        private const string ManifestItemId = "Microsoft.VisualStudio.Manifests.VisualStudio";
        private const string X64PackageSuffix = ".CRT.Redist.X64.base";
        private const string X86PackageSuffix = ".CRT.Redist.X86.base";
        private const string DebugDirectory = "debug_nonredist";

        public const string LicenseNotice =
            "Brovan is about to download the Microsoft Visual C++ runtime libraries from Microsoft's servers. They are\n" +
            "not part of Windows and are what most Windows programs are built against. Brovan does not include or\n" +
            "redistribute any Microsoft software.";

        private readonly struct RuntimePackage
        {
            public readonly string Address;
            public readonly long Size;
            public readonly Version Version;
            public readonly string TargetDirectory;

            public RuntimePackage(string Address, long Size, Version Version, string TargetDirectory)
            {
                this.Address = Address;
                this.Size = Size;
                this.Version = Version;
                this.TargetDirectory = TargetDirectory;
            }

            public bool Found => Address.Length != 0;
        }

        public static bool Import(string BaseDirectory, HttpClient Client, Action<string> Report, Action<long, long, long, long>? Progress = null)
        {
            try
            {
                Report("[*] Asking Microsoft for the current Visual C++ runtime packages...");

                long Done = 0;
                byte[] Manifest = Download(Client, ResolveManifest(Client), Count => Progress?.Invoke(0, 0, Done += Count, 0));

                string Libraries = Path.Combine(BaseDirectory, "WindowsLibs");

                RuntimePackage[] Packages =
                {
                    FindPackage(Manifest, X64PackageSuffix, Libraries, Report),
                    FindPackage(Manifest, X86PackageSuffix, Path.Combine(Libraries, "SysWOW64"), Report),
                };

                long Total = Done;
                int Wanted = 0;

                for (int i = 0; i < Packages.Length; i++)
                {
                    if (!Packages[i].Found)
                        continue;

                    Total += Packages[i].Size;
                    Wanted++;
                }

                bool Any = false;
                int Completed = 0;

                for (int i = 0; i < Packages.Length; i++)
                {
                    RuntimePackage Package = Packages[i];
                    if (!Package.Found)
                        continue;

                    Report($"[*] Downloading Visual C++ {Package.Version} runtimes ({Package.Size / (1024 * 1024)} MB)...");

                    byte[] Content = Download(Client, Package.Address, Count => Progress?.Invoke(Completed, Wanted, Done += Count, Total));
                    int Installed = Extract(Content, Package.TargetDirectory);

                    Completed++;
                    Progress?.Invoke(Completed, Wanted, Done, Total);

                    Report($"[+] Installed {Installed} Visual C++ {Package.Version} runtime libraries into {Package.TargetDirectory}.");
                    Any |= Installed != 0;
                }

                return Any;
            }
            catch (Exception Error)
            {
                Report($"[-] Visual C++ runtime import failed: {Error.Message}");
                return false;
            }
        }

        private static string ResolveManifest(HttpClient Client)
        {
            using JsonDocument Channel = JsonDocument.Parse(Download(Client, ChannelManifest));

            if (!Channel.RootElement.TryGetProperty("channelItems", out JsonElement Items) || Items.ValueKind != JsonValueKind.Array)
                throw new InvalidOperationException("The Visual Studio channel manifest listed no items.");

            foreach (JsonElement Item in Items.EnumerateArray())
            {
                if (!Item.TryGetProperty("id", out JsonElement Id) || !ManifestItemId.Equals(Id.GetString(), StringComparison.OrdinalIgnoreCase))
                    continue;

                if (TryGetPayload(Item, out string Address, out _))
                    return Address;
            }

            throw new InvalidOperationException($"The Visual Studio channel manifest has no {ManifestItemId} payload.");
        }

        private static RuntimePackage FindPackage(byte[] Manifest, string Suffix, string TargetDirectory, Action<string> Report)
        {
            string Address = string.Empty;
            long Size = 0;
            Version? Newest = null;

            using JsonDocument Document = JsonDocument.Parse(Manifest);

            if (!Document.RootElement.TryGetProperty("packages", out JsonElement Packages) || Packages.ValueKind != JsonValueKind.Array)
                throw new InvalidOperationException("The Visual Studio manifest listed no packages.");

            foreach (JsonElement Package in Packages.EnumerateArray())
            {
                if (!Package.TryGetProperty("id", out JsonElement Id))
                    continue;

                string? Name = Id.GetString();
                if (Name == null || !Name.EndsWith(Suffix, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!Package.TryGetProperty("version", out JsonElement Value) || !Version.TryParse(Value.GetString(), out Version? Current))
                    continue;

                if (Newest != null && Current <= Newest)
                    continue;

                if (!TryGetPayload(Package, out string Candidate, out long CandidateSize))
                    continue;

                Newest = Current;
                Address = Candidate;
                Size = CandidateSize;
            }

            if (Newest == null)
                Report($"[-] The Visual Studio manifest lists no {Suffix.TrimStart('.')} package.");

            return new RuntimePackage(Address, Size, Newest ?? new Version(), TargetDirectory);
        }

        private static bool TryGetPayload(JsonElement Owner, out string Address, out long Size)
        {
            Address = string.Empty;
            Size = 0;

            if (!Owner.TryGetProperty("payloads", out JsonElement Payloads) || Payloads.ValueKind != JsonValueKind.Array)
                return false;

            foreach (JsonElement Payload in Payloads.EnumerateArray())
            {
                if (!Payload.TryGetProperty("url", out JsonElement Url))
                    continue;

                string? Value = Url.GetString();
                if (string.IsNullOrEmpty(Value))
                    continue;

                Address = Value;
                Size = Payload.TryGetProperty("size", out JsonElement Length) && Length.TryGetInt64(out long Bytes) ? Bytes : 0;
                return true;
            }

            return false;
        }

        private static int Extract(byte[] Package, string TargetDirectory)
        {
            using MemoryStream Content = new MemoryStream(Package, writable: false);
            using ZipArchive Archive = new ZipArchive(Content, ZipArchiveMode.Read);

            int Count = 0;

            foreach (ZipArchiveEntry Entry in Archive.Entries)
            {
                if (!Entry.FullName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                    Entry.FullName.Contains(DebugDirectory, StringComparison.OrdinalIgnoreCase))
                    continue;

                string Name = Path.GetFileName(Entry.FullName);
                if (Name.Length == 0)
                    continue;

                if (Count == 0)
                    Directory.CreateDirectory(TargetDirectory);

                Entry.ExtractToFile(Path.Combine(TargetDirectory, Name), overwrite: true);
                Count++;
            }

            return Count;
        }

        private static byte[] Download(HttpClient Client, string Address, Action<long>? Advanced = null)
        {
            using HttpRequestMessage Request = new HttpRequestMessage(HttpMethod.Get, Address);
            using HttpResponseMessage Response = Client.Send(Request, HttpCompletionOption.ResponseHeadersRead);

            Response.EnsureSuccessStatusCode();

            long Length = Response.Content.Headers.ContentLength ?? 0;

            using Stream Body = Response.Content.ReadAsStream();
            using MemoryStream Content = Length > 0 && Length <= int.MaxValue ? new MemoryStream((int)Length) : new MemoryStream();

            byte[] Buffer = ArrayPool<byte>.Shared.Rent(1 << 16);

            try
            {
                int Count;

                while ((Count = Body.Read(Buffer, 0, Buffer.Length)) > 0)
                {
                    Content.Write(Buffer, 0, Count);
                    Advanced?.Invoke(Count);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }

            return Content.ToArray();
        }
    }
}
