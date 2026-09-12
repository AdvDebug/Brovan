using BrovanGUI.Models;

namespace BrovanGUI.ViewModels
{
    public sealed class SettingsViewModel : ObservableObject
    {
        private readonly MainViewModel Owner;
        private Choice? Theme;
        private List<CategoryViewModel> CategoryList = new List<CategoryViewModel>();

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

            ResetDefaultsCommand = new RelayCommand(() =>
            {
                Owner.Library.Defaults.Clear();
                Owner.Save();
                Owner.DefaultsChanged();
            });
            OpenLibraryFolderCommand = new RelayCommand(() => BrovanHost.OpenExternal(LibraryStore.Directory));
        }

        public Choice[] Themes { get; }
        public RelayCommand ResetDefaultsCommand { get; }
        public RelayCommand OpenLibraryFolderCommand { get; }
        public string LibraryPath => LibraryStore.FilePath;
        public string SchemaStatus => Owner.SchemaStatus;

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

        public void Rebuild(IReadOnlyList<SettingEntry> Schema, bool HypervisorAvailable)
        {
            SettingsScope Scope = new SettingsScope(Owner.Library.Defaults, Key =>
            {
                foreach (SettingEntry Entry in Schema)
                {
                    if (Entry.Key == Key)
                        return Entry.DefaultText;
                }

                return string.Empty;
            }, () =>
            {
                Owner.Save();
                Owner.DefaultsChanged();
            });

            Categories = SettingLabels.BuildCategories(Schema, Scope, true, HypervisorAvailable);
            Raise(nameof(SchemaStatus));
        }

        public void RefreshRows()
        {
            foreach (CategoryViewModel Category in CategoryList)
                foreach (SettingRow Row in Category.Rows)
                    Row.Refresh();
        }
    }
}
