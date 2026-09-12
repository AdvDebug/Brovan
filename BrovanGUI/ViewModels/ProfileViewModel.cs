using Avalonia.Media.Imaging;
using Avalonia.Threading;
using BrovanGUI.Models;

namespace BrovanGUI.ViewModels
{
    public sealed class ProfileViewModel : ObservableObject
    {
        private readonly MainViewModel Owner;
        private Bitmap? IconValue;
        private bool Running;
        private List<CategoryViewModel> CategoryList = new List<CategoryViewModel>();

        public ProfileViewModel(Profile Model, MainViewModel Owner)
        {
            this.Model = Model;
            this.Owner = Owner;

            LaunchCommand = new RelayCommand(() => Owner.Launch(this));
            StopCommand = new RelayCommand(() => Owner.Stop(this));
            BrowseExecutableCommand = new AsyncCommand(BrowseExecutable, Owner.ReportError);
            BrowseWorkingDirectoryCommand = new AsyncCommand(BrowseWorkingDirectory, Owner.ReportError);
            OpenFolderCommand = new RelayCommand(() =>
            {
                string? Directory = Path.GetDirectoryName(Executable);
                if (Directory != null && System.IO.Directory.Exists(Directory))
                    BrovanHost.OpenExternal(Directory);
            });

            LoadIcon();
        }

        public Profile Model { get; }
        public RelayCommand LaunchCommand { get; }
        public RelayCommand StopCommand { get; }
        public AsyncCommand BrowseExecutableCommand { get; }
        public AsyncCommand BrowseWorkingDirectoryCommand { get; }
        public RelayCommand OpenFolderCommand { get; }

        public string Id => Model.Id;

        public string Name
        {
            get => Model.Name;
            set
            {
                if (Model.Name == value)
                    return;

                Model.Name = value;
                Raise();
                Raise(nameof(Initial));
                Owner.Save();
            }
        }

        public string Executable
        {
            get => Model.Executable;
            set
            {
                if (Model.Executable == value)
                    return;

                Model.Executable = value;
                Raise();
                Raise(nameof(ExecutableMissing));
                Owner.Save();
                LoadIcon();
            }
        }

        public string Arguments
        {
            get => Model.Arguments;
            set
            {
                if (Model.Arguments == value)
                    return;

                Model.Arguments = value;
                Raise();
                Owner.Save();
            }
        }

        public string WorkingDirectory
        {
            get => Model.WorkingDirectory;
            set
            {
                if (Model.WorkingDirectory == value)
                    return;

                Model.WorkingDirectory = value;
                Raise();
                Owner.Save();
            }
        }

        public string Initial
        {
            get
            {
                string Trimmed = Name.Trim();
                return Trimmed.Length == 0 ? "?" : Trimmed.Substring(0, 1).ToUpperInvariant();
            }
        }

        public bool ExecutableMissing => Executable.Length == 0 || !File.Exists(Executable);

        public Bitmap? Icon
        {
            get => IconValue;
            private set
            {
                if (Set(ref IconValue, value))
                    Raise(nameof(HasIcon));
            }
        }

        public bool HasIcon => IconValue != null;

        public bool IsRunning
        {
            get => Running;
            set => Set(ref Running, value);
        }

        public List<CategoryViewModel> Categories
        {
            get => CategoryList;
            private set => Set(ref CategoryList, value);
        }

        public string SchemaStatus => Owner.SchemaStatus;

        public void Rebuild(IReadOnlyList<SettingEntry> Schema, Dictionary<string, string> Defaults, bool HypervisorAvailable)
        {
            SettingsScope Scope = new SettingsScope(Model.Settings, Key =>
            {
                if (Defaults.TryGetValue(Key, out string? Value))
                    return Value;

                foreach (SettingEntry Entry in Schema)
                {
                    if (Entry.Key == Key)
                        return Entry.DefaultText;
                }

                return string.Empty;
            }, Owner.Save);

            Categories = SettingLabels.BuildCategories(Schema, Scope, false, HypervisorAvailable);
            Raise(nameof(SchemaStatus));
        }

        public void RefreshRows()
        {
            foreach (CategoryViewModel Category in CategoryList)
                foreach (SettingRow Row in Category.Rows)
                    Row.Refresh();
        }

        private void LoadIcon()
        {
            string Path = Executable;
            if (Path.Length == 0 || !File.Exists(Path))
            {
                Icon = null;
                return;
            }

            Task.Run(() =>
            {
                Bitmap? Loaded = PeIcon.Load(Path);
                Dispatcher.UIThread.Post(() =>
                {
                    if (Executable == Path)
                        Icon = Loaded;
                });
            });
        }

        private async Task BrowseExecutable()
        {
            string? Picked = await Owner.Dialogs.PickProgramAsync("Choose the program to run");
            if (Picked != null)
            {
                Executable = Picked;
                if (Name.Length == 0)
                    Name = Path.GetFileNameWithoutExtension(Picked);
            }
        }

        private async Task BrowseWorkingDirectory()
        {
            string? Picked = await Owner.Dialogs.PickFolderAsync("Choose the folder the program starts in");
            if (Picked != null)
                WorkingDirectory = Picked;
        }
    }

    public sealed class WelcomeViewModel
    {
        public WelcomeViewModel(MainViewModel Owner)
        {
            AddProgramCommand = Owner.AddProfileCommand;
            OpenSetupCommand = Owner.ShowSetupCommand;
        }

        public AsyncCommand AddProgramCommand { get; }
        public RelayCommand OpenSetupCommand { get; }
    }
}
