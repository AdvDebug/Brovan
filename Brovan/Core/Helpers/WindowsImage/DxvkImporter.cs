using System;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal static class DxvkImporter
    {
        private const string LatestRelease = "https://api.github.com/repos/doitsujin/dxvk/releases/latest";
        private const string TaggedRelease = "https://api.github.com/repos/doitsujin/dxvk/releases/tags/";
        private const string VersionFile = "dxvk.version";

        public static bool Import(string BaseDirectory, string? Version, Action<string> Report, Action<long, long, long, long>? Progress = null)
        {
            try
            {
                using HttpClient Client = HttpImageDataSource.CreateClient();

                string Wanted = Version == null ? string.Empty : Version.Trim();
                string Address = Wanted.Length == 0 ? LatestRelease : TaggedRelease + Uri.EscapeDataString(Wanted);

                Report(Wanted.Length == 0
                    ? "[*] Asking GitHub for the newest DXVK release..."
                    : $"[*] Asking GitHub for DXVK {Wanted}...");

                using JsonDocument Release = JsonDocument.Parse(ReadJson(Client, Address));

                string Tag = Release.RootElement.TryGetProperty("tag_name", out JsonElement Name) ? Name.GetString() ?? Wanted : Wanted;

                if (!TryFindArchive(Release.RootElement, out string ArchiveAddress, out long Size))
                {
                    Report($"[-] The DXVK {Tag} release has no build archive.");
                    return false;
                }

                string System32 = Path.Combine(BaseDirectory, "VirtualFS", "C", "Windows", "System32");
                string SysWow64 = Path.Combine(BaseDirectory, "VirtualFS", "C", "Windows", "SysWOW64");

                Report($"[*] Downloading DXVK {Tag} ({Size / (1024 * 1024)} MB)...");

                long Done = 0;
                int Installed = Extract(Client, ArchiveAddress, System32, SysWow64,
                    Count => Progress?.Invoke(0, 1, Done += Count, Size));

                if (Installed == 0)
                {
                    Report($"[-] The DXVK {Tag} archive held no libraries.");
                    return false;
                }

                File.WriteAllText(Path.Combine(BaseDirectory, VersionFile), Tag);
                Progress?.Invoke(1, 1, Size, Size);

                Report($"[+] Installed {Installed} DXVK {Tag} libraries into the emulated Windows directories.");
                return true;
            }
            catch (Exception Error)
            {
                Report($"[-] DXVK import failed: {Error.Message}");
                return false;
            }
        }

        private static bool TryFindArchive(JsonElement Release, out string Address, out long Size)
        {
            Address = string.Empty;
            Size = 0;

            if (!Release.TryGetProperty("assets", out JsonElement Assets) || Assets.ValueKind != JsonValueKind.Array)
                return false;

            foreach (JsonElement Asset in Assets.EnumerateArray())
            {
                if (!Asset.TryGetProperty("name", out JsonElement Name))
                    continue;

                string? FileName = Name.GetString();
                if (FileName == null || !FileName.StartsWith("dxvk-", StringComparison.OrdinalIgnoreCase) ||
                    !FileName.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase))
                    continue;

                // The same release also ships source and native (Linux ELF) archives, which hold no Windows DLLs.
                if (FileName.Contains("native", StringComparison.OrdinalIgnoreCase) ||
                    FileName.Contains("source", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!Asset.TryGetProperty("browser_download_url", out JsonElement Url))
                    continue;

                string? Value = Url.GetString();
                if (string.IsNullOrEmpty(Value))
                    continue;

                Address = Value;
                Size = Asset.TryGetProperty("size", out JsonElement Length) && Length.TryGetInt64(out long Bytes) ? Bytes : 0;
                return true;
            }

            return false;
        }

        private static int Extract(HttpClient Client, string Address, string System32, string SysWow64, Action<long> Advanced)
        {
            using HttpRequestMessage Request = new HttpRequestMessage(HttpMethod.Get, Address);
            using HttpResponseMessage Response = Client.Send(Request, HttpCompletionOption.ResponseHeadersRead);

            Response.EnsureSuccessStatusCode();

            using Stream Body = Response.Content.ReadAsStream();
            using CountingStream Counted = new CountingStream(Body, Advanced);
            using GZipStream Decompressed = new GZipStream(Counted, CompressionMode.Decompress);
            using TarReader Archive = new TarReader(Decompressed);

            int Count = 0;
            TarEntry? Entry;

            while ((Entry = Archive.GetNextEntry(copyData: false)) != null)
            {
                if (Entry.EntryType != TarEntryType.RegularFile && Entry.EntryType != TarEntryType.V7RegularFile)
                    continue;

                string EntryPath = Entry.Name.Replace('\\', '/');
                if (!EntryPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    continue;

                string? Target = TargetDirectory(EntryPath, System32, SysWow64);
                if (Target == null)
                    continue;

                Directory.CreateDirectory(Target);
                Entry.ExtractToFile(Path.Combine(Target, Path.GetFileName(EntryPath)), overwrite: true);
                Count++;
            }

            return Count;
        }

        private static string? TargetDirectory(string EntryPath, string System32, string SysWow64)
        {
            string[] Parts = EntryPath.Split('/', StringSplitOptions.RemoveEmptyEntries);

            for (int i = 0; i < Parts.Length - 1; i++)
            {
                if (Parts[i].Equals("x64", StringComparison.OrdinalIgnoreCase))
                    return System32;

                if (Parts[i].Equals("x32", StringComparison.OrdinalIgnoreCase))
                    return SysWow64;
            }

            return null;
        }

        private static byte[] ReadJson(HttpClient Client, string Address)
        {
            using HttpRequestMessage Request = new HttpRequestMessage(HttpMethod.Get, Address);
            Request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

            using HttpResponseMessage Response = Client.Send(Request);
            Response.EnsureSuccessStatusCode();

            using Stream Body = Response.Content.ReadAsStream();
            using MemoryStream Content = new MemoryStream();

            Body.CopyTo(Content);
            return Content.ToArray();
        }

        private sealed class CountingStream : Stream
        {
            private readonly Stream Inner;
            private readonly Action<long> Advanced;

            public CountingStream(Stream Inner, Action<long> Advanced)
            {
                this.Inner = Inner;
                this.Advanced = Advanced;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override int Read(byte[] Buffer, int Offset, int Count)
            {
                int Read = Inner.Read(Buffer, Offset, Count);
                if (Read > 0)
                    Advanced(Read);

                return Read;
            }

            public override int Read(Span<byte> Buffer)
            {
                int Read = Inner.Read(Buffer);
                if (Read > 0)
                    Advanced(Read);

                return Read;
            }

            public override void Flush()
            {
            }

            public override long Seek(long Offset, SeekOrigin Origin) => throw new NotSupportedException();

            public override void SetLength(long Value) => throw new NotSupportedException();

            public override void Write(byte[] Buffer, int Offset, int Count) => throw new NotSupportedException();
        }
    }
}
