using Avalonia.Controls;
using Avalonia.Platform.Storage;

namespace BrovanGUI.Views
{
    public sealed class Dialogs
    {
        private readonly TopLevel Top;

        public Dialogs(TopLevel Top)
        {
            this.Top = Top;
        }

        public Task<string?> PickProgramAsync(string Title)
        {
            return PickFileAsync(Title, "*.exe", "*.elf", "*.bin", "*");
        }

        public async Task<string?> PickFileAsync(string Title, params string[] Patterns)
        {
            FilePickerOpenOptions Options = new FilePickerOpenOptions
            {
                Title = Title,
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Programs") { Patterns = Patterns },
                    FilePickerFileTypes.All,
                },
            };

            IReadOnlyList<IStorageFile> Files = await Top.StorageProvider.OpenFilePickerAsync(Options);
            return Files.Count != 0 ? Files[0].TryGetLocalPath() : null;
        }

        public async Task<string?> PickFolderAsync(string Title)
        {
            IReadOnlyList<IStorageFolder> Folders = await Top.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = Title,
                AllowMultiple = false,
            });

            return Folders.Count != 0 ? Folders[0].TryGetLocalPath() : null;
        }
    }
}
