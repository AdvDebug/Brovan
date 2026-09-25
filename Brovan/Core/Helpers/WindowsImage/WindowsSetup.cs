using System;
using System.IO;
using System.Net;
using System.Net.Http;
using Microsoft.Win32.SafeHandles;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal sealed class WindowsSetupOptions
    {
        public string? Media;
        public int MediaDescriptor = -1;
        public bool LicenseAccepted;
        public int ImageIndex = 1;
    }

    internal static class WindowsSetup
    {
        public const string LicenseNotice =
            "Brovan is about to extract the system libraries and registry hives it needs to run Windows programs from\n" +
            "the installation media you supply, followed by the Visual C++ runtimes that most Windows programs are\n" +
            "built against. Brovan does not include or redistribute any Microsoft software. Using these files requires\n" +
            "a valid Windows license.";

        private const string BrowserUserAgent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

        public static bool InstallRuntimes(string BaseDirectory, bool LicenseAccepted, Action<string> Report, Func<bool>? Confirm, Action<long, long, long, long>? Progress = null)
        {
            if (!LicenseAccepted)
            {
                Report(VisualCppRuntimeImporter.LicenseNotice);

                if (Confirm == null || !Confirm())
                {
                    Report("[-] Aborted; nothing was downloaded.");
                    return false;
                }
            }

            using HttpClient Client = CreateClient();
            return VisualCppRuntimeImporter.Import(BaseDirectory, Client, Report, Progress);
        }

        public static HttpClient CreateClient()
        {
            HttpClientHandler Handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                AutomaticDecompression = DecompressionMethods.None,
            };

            HttpClient Created = new HttpClient(Handler);
            Created.Timeout = TimeSpan.FromMinutes(5);

            Created.DefaultRequestHeaders.UserAgent.ParseAdd(BrowserUserAgent);
            Created.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.9");
            Created.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            return Created;
        }

        public static bool Install(string BaseDirectory, WindowsSetupOptions Options, Action<string> Report, Func<bool>? Confirm, Action<long, long, long, long>? Progress = null)
        {
            if (!Options.LicenseAccepted)
            {
                Report(LicenseNotice);

                if (Confirm == null || !Confirm())
                {
                    Report("[-] Aborted; nothing was installed.");
                    return false;
                }
            }

            ImageDataSource? Media = null;

            try
            {
                string? Location = Options.Media;

                if (Options.MediaDescriptor >= 0)
                {
                    SafeFileHandle Handle = new SafeFileHandle((IntPtr)Options.MediaDescriptor, ownsHandle: false);
                    Media = new FileImageDataSource(Handle, RandomAccess.GetLength(Handle));
                }
                else if (string.IsNullOrWhiteSpace(Location))
                {
                    Report("[-] No installation media. Give a path to an ISO, WIM or ESD file.");
                    return false;
                }
                else
                {
                    if (!File.Exists(Location))
                    {
                        Report($"[-] '{Location}' does not exist.");
                        return false;
                    }

                    Media = new FileImageDataSource(Location);
                }

                Report($"[*] Media is {Media.Length / (1024 * 1024)} MB; only the parts that are extracted are read.");

                WindowsImageImporter.Import(Media, BaseDirectory, Options.ImageIndex, Report, Progress);

                if (!WindowsImageImporter.TryWriteApiSetMap(BaseDirectory, Report))
                    Report("[!] The image had no apisetschema.dll; keeping the existing API set map.");

                using HttpClient Client = CreateClient();
                VisualCppRuntimeImporter.Import(BaseDirectory, Client, Report, Progress);

                return true;
            }
            catch (Exception Error)
            {
                Report($"[-] Windows system file import failed: {Describe(Error)}");
                return false;
            }
            finally
            {
                Media?.Dispose();
            }
        }

        private static string Describe(Exception Error)
        {
            string Text = Error.Message;

            for (Exception? Inner = Error.InnerException; Inner != null; Inner = Inner.InnerException)
                Text += " -> " + Inner.Message;

            return Text;
        }
    }
}
