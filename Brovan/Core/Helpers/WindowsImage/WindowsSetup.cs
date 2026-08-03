using System;
using System.IO;
using System.Net.Http;
using Microsoft.Win32.SafeHandles;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal sealed class WindowsSetupOptions
    {
        public string? Media;
        public int MediaDescriptor = -1;
        public bool BuildPack;
        public bool LicenseAccepted;
        public string Locale = "English (United States)";
        public int ImageIndex = 1;
    }

    internal static class WindowsSetup
    {
        public const string LicenseNotice =
            "Brovan is about to download Windows installation media from Microsoft's servers and extract the system\n" +
            "libraries and registry hives it needs to run Windows programs. Brovan does not include or redistribute\n" +
            "any Microsoft software. Using these files requires a valid Windows license.";

        public static bool Install(string BaseDirectory, WindowsSetupOptions Options, Action<string> Report, Func<bool>? Confirm, Action<long, long, long, long>? Progress = null)
        {
            if (!Options.LicenseAccepted)
            {
                Report(LicenseNotice);

                if (Confirm == null || !Confirm())
                {
                    Report("[-] Aborted; nothing was downloaded.");
                    return false;
                }
            }

            HttpClient? Client = null;
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
                    Client = HttpImageDataSource.CreateClient();
                    Uri Resolved = MicrosoftIsoDownload.Resolve(Client, Options.Locale, Report);
                    Report($"[+] Microsoft returned a link for {Resolved.Host}.");
                    Media = new HttpImageDataSource(Resolved, Client);
                }
                else if (Location.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || Location.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    Client = HttpImageDataSource.CreateClient();
                    Media = new HttpImageDataSource(new Uri(Location), Client);
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

                WindowsImageImporter.Import(Media, BaseDirectory, Options.ImageIndex, Options.BuildPack, Report, Progress);

                if (Media is HttpImageDataSource Remote)
                    Report($"[*] Transferred {Remote.TransferredBytes / (1024 * 1024)} MB over the network.");

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
                Client?.Dispose();
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
