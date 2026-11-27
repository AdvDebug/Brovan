using BrovanGUI.Models;

namespace BrovanGUI.ViewModels
{
    public sealed class SettingsViewModel : ObservableObject
    {
        private readonly MainViewModel Owner;
        private Choice? Theme;
        private List<CategoryViewModel> CategoryList = new List<CategoryViewModel>();
        private string BackendWarningValue = string.Empty;

        public SettingsViewModel(MainViewModel Owner)
        {
            this.Owner = Owner;
            Themes = new[]
            {
                new Choice("dark", "Dark"),
                new Choice("light", "Light"),
                new Choice("system", "Follow the system"),
            };

            foreach (Choice Item in Themes)
            {
                if (Item.Value == Owner.Library.Theme)
                    Theme = Item;
            }

            Theme ??= Themes[0];

            ResetDefaultsCommand = new RelayCommand(Owner.ResetDefaults);
            OpenLibraryFolderCommand = new RelayCommand(() => BrovanHost.OpenExternal(LibraryStore.Directory));
        }

        public Choice[] Themes { get; }
        public RelayCommand ResetDefaultsCommand { get; }
        public RelayCommand OpenLibraryFolderCommand { get; }
        public string LibraryPath => LibraryStore.FilePath;
        public string LibraryShortPath
        {
            get
            {
                string AppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (OperatingSystem.IsWindows() && AppData.Length != 0 && LibraryStore.FilePath.StartsWith(AppData, StringComparison.OrdinalIgnoreCase))
                    return "%AppData%" + LibraryStore.FilePath.Substring(AppData.Length);

                return BrovanHost.ShortPath(LibraryStore.FilePath);
            }
        }
        public string SchemaStatus => Owner.SchemaStatus;

        public string ResetPrompt => Owner.Library.Defaults.Count switch
        {
            0 => "Nothing on this page is changed from Brovan's defaults.",
            1 => "Reset 1 changed setting to its default? Profile settings stay.",
            int Count => "Reset " + Count + " changed settings to their defaults? Profile settings stay.",
        };

        public string BackendWarning
        {
            get => BackendWarningValue;
            private set => Set(ref BackendWarningValue, value);
        }

        public Choice? SelectedTheme
        {
            get => Theme;
            set
            {
                if (Set(ref Theme, value) && value != null)
                {
                    Owner.Library.Theme = value.Value;
                    Owner.Save();
                    Owner.ApplyTheme();
                }
            }
        }

        public List<CategoryViewModel> Categories
        {
            get => CategoryList;
            private set => Set(ref CategoryList, value);
        }

        public void Rebuild(IReadOnlyList<SettingEntry> Schema)
        {
            SettingsScope Scope = new SettingsScope(Owner.Library.Defaults, Owner.DefaultValue, () =>
            {
                Owner.Save();
                Owner.DefaultsChanged();
            });

            Categories = SettingLabels.BuildCategories(Schema, Scope, true, Owner);
            Raise(nameof(SchemaStatus));
            BackendWarning = Owner.BackendWarning(null);
        }

        public void RefreshRows()
        {
            foreach (CategoryViewModel Category in CategoryList)
                foreach (SettingRow Row in Category.Rows)
                    Row.Refresh();

            BackendWarning = Owner.BackendWarning(null);
            Raise(nameof(ResetPrompt));
        }
    }
}
