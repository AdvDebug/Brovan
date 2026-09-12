using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BrovanGUI.Models
{
    public sealed class Profile
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = string.Empty;
        public string Executable { get; set; } = string.Empty;
        public string Arguments { get; set; } = string.Empty;
        public string WorkingDirectory { get; set; } = string.Empty;
        public Dictionary<string, string> Settings { get; set; } = new();
        public DateTime? LastLaunched { get; set; }
    }

    public sealed class LibraryDocument
    {
        public string BrovanPath { get; set; } = string.Empty;
        public string Theme { get; set; } = "dark";
        public string SelectedProfile { get; set; } = string.Empty;
        public bool OutputOpen { get; set; }
        public bool LicenseAccepted { get; set; }
        public Dictionary<string, string> Defaults { get; set; } = new();
        public List<Profile> Profiles { get; set; } = new();

        // Set when the file could not be read and could not be copied aside. Overwriting it loses the only copy.
        [JsonIgnore]
        public bool SavingDisabled { get; set; }
    }

    [JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(LibraryDocument))]
    internal sealed partial class LibraryJsonContext : JsonSerializerContext
    {
    }

    public static class LibraryStore
    {
        public static string Directory { get; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Brovan", "GUI");

        public static string FilePath { get; } = Path.Combine(Directory, "library.json");

        public static LibraryDocument Load(out string? Problem)
        {
            Problem = null;
            if (!File.Exists(FilePath))
                return new LibraryDocument();

            try
            {
                ReadOnlySpan<byte> Text = File.ReadAllBytes(FilePath);
                if (Text.StartsWith(Encoding.UTF8.Preamble))
                    Text = Text.Slice(Encoding.UTF8.Preamble.Length);

                LibraryDocument? Document = JsonSerializer.Deserialize(Text, LibraryJsonContext.Default.LibraryDocument);
                if (Document != null)
                    return Document;

                Problem = "The library file is empty.";
            }
            catch (Exception Error)
            {
                Problem = "The library file could not be read: " + Error.Message;
            }

            string Backup = FilePath + ".broken";
            try
            {
                File.Copy(FilePath, Backup, true);
                Problem += " A copy was kept as " + Backup + ".";
                return new LibraryDocument();
            }
            catch (Exception Error)
            {
                Problem += " A copy could not be kept either: " + Error.Message
                    + " Saving stays off until the launcher restarts, so the file is left as it is.";
            }

            return new LibraryDocument { SavingDisabled = true };
        }

        public static string? Save(LibraryDocument Document)
        {
            if (Document.SavingDisabled)
                return null;

            string Pending = FilePath + ".new";
            try
            {
                System.IO.Directory.CreateDirectory(Directory);
                File.WriteAllBytes(Pending, JsonSerializer.SerializeToUtf8Bytes(Document, LibraryJsonContext.Default.LibraryDocument));
                File.Move(Pending, FilePath, true);
                return null;
            }
            catch (Exception Error)
            {
                try
                {
                    File.Delete(Pending);
                }
                catch (Exception)
                {
                }

                return "The library could not be saved: " + Error.Message;
            }
        }
    }
}
