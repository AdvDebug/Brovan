using System.Collections.ObjectModel;
using System.Diagnostics;
using Avalonia;
using Avalonia.Styling;
using Avalonia.Threading;
using BrovanGUI.Models;
using BrovanGUI.Views;

namespace BrovanGUI.ViewModels
{
    public enum PageKind
    {
        Profile,
        Setup,
        Settings,
    }

    public sealed class MainViewModel : ObservableObject
    {
        private readonly Dictionary<string, Process> Running = new Dictionary<string, Process>();
        private readonly DispatcherTimer SaveTimer;
        private Process? Tool;
        private ProfileViewModel? Selected;
        private PageKind Page;
        private SettingEntry[] Schema = Array.Empty<SettingEntry>();
        private string SchemaStatusValue = "Reading the settings Brovan supports...";

        public MainViewModel(Dialogs Dialogs, string? LaunchProfile)
        {
            this.Dialogs = Dialogs;
            bool FirstRun = !File.Exists(LibraryStore.FilePath);
            Library = LibraryStore.Load(out string? LibraryProblem);
            SaveTimer = new DispatcherTimer(TimeSpan.FromMilliseconds(400), DispatcherPriority.Background, (_, _) => SaveNow());
            ApplyTheme();

            Output = new OutputViewModel(Library.OutputOpen, () =>
            {
                Library.OutputOpen = Output.IsOpen;
                Save();
            });
            Output.InputSubmitted += Line =>
            {
                Process? Target = InputTarget();
                if (Target == null || !BrovanHost.SendLine(Target, Line))
                {
                    ReportProblem("Nothing is running that can read that line.");
                    return;
                }

                Output.WriteLine("< " + Line);
            };

            if (LibraryProblem != null)
                ReportProblem(LibraryProblem);

            Profiles = new ObservableCollection<ProfileViewModel>();
            foreach (Profile Model in Library.Profiles)
                Profiles.Add(new ProfileViewModel(Model, this));

            AddProfileCommand = new AsyncCommand(AddProfile, ReportError);
            RemoveSelectedCommand = new RelayCommand(RemoveSelected);
            ShowSetupCommand = new RelayCommand(() => CurrentPageKind = PageKind.Setup);
            ShowSettingsCommand = new RelayCommand(() => CurrentPageKind = PageKind.Settings);
            OpenManualCommand = new RelayCommand(() => BrovanHost.OpenExternal("https://github.com/AdvDebug/Brovan/wiki"));

            Setup = new SetupViewModel(this);
            Settings = new SettingsViewModel(this);
            Welcome = new WelcomeViewModel(this);

            BrovanExecutable = BrovanHost.Locate(Library.BrovanPath);
            Setup.Refresh();

            if (FirstRun)
                SeedDefaults();

            foreach (ProfileViewModel Profile in Profiles)
            {
                if (Profile.Id == Library.SelectedProfile)
                    Selected = Profile;
            }

            Selected ??= Profiles.Count != 0 ? Profiles[0] : null;
            Page = BrovanExecutable == null ? PageKind.Setup : PageKind.Profile;

            _ = Start(LaunchProfile);
        }

        private async Task Start(string? LaunchProfile)
        {
            await LoadSchema();
            if (LaunchProfile == null)
                return;

            foreach (ProfileViewModel Profile in Profiles)
            {
                if (string.Equals(Profile.Name, LaunchProfile, StringComparison.OrdinalIgnoreCase) || Profile.Id == LaunchProfile)
                {
                    SelectedProfile = Profile;
                    Launch(Profile);
                    return;
                }
            }

            ReportProblem("No profile is named " + LaunchProfile + ".");
        }

        public Dialogs Dialogs { get; }
        public LibraryDocument Library { get; }
        public ObservableCollection<ProfileViewModel> Profiles { get; }
        public OutputViewModel Output { get; }
        public SetupViewModel Setup { get; }
        public SettingsViewModel Settings { get; }
        public WelcomeViewModel Welcome { get; }
        public AsyncCommand AddProfileCommand { get; }
        public RelayCommand RemoveSelectedCommand { get; }
        public RelayCommand ShowSetupCommand { get; }
        public RelayCommand ShowSettingsCommand { get; }
        public RelayCommand OpenManualCommand { get; }
        public string? BrovanExecutable { get; private set; }

        public string SchemaStatus
        {
            get => SchemaStatusValue;
            private set => Set(ref SchemaStatusValue, value);
        }

        public ProfileViewModel? SelectedProfile
        {
            get => Selected;
            set
            {
                if (value == null && Profiles.Count != 0)
                    return;

                bool Changed = Set(ref Selected, value);
                if (value != null)
                {
                    Library.SelectedProfile = value.Id;
                    Save();
                }

                if (Changed)
                    Raise(nameof(HasSelection));

                CurrentPageKind = PageKind.Profile;
                Raise(nameof(CurrentPage));
            }
        }

        public bool HasSelection => Selected != null;

        // Null while another page is shown, so clicking the selected profile still counts as a selection.
        public ProfileViewModel? ListSelection
        {
            get => Page == PageKind.Profile ? Selected : null;
            set
            {
                if (value != null)
                    SelectedProfile = value;
            }
        }

        public PageKind CurrentPageKind
        {
            get => Page;
            set
            {
                Page = value;
                Raise();
                Raise(nameof(CurrentPage));
                Raise(nameof(IsSetupPage));
                Raise(nameof(IsSettingsPage));
                Raise(nameof(ListSelection));
            }
        }

        public bool IsSetupPage => Page == PageKind.Setup;
        public bool IsSettingsPage => Page == PageKind.Settings;

        public object CurrentPage => Page switch
        {
            PageKind.Setup => Setup,
            PageKind.Settings => Settings,
            _ => (object?)Selected ?? Welcome,
        };

        // Edits arrive per keystroke; the file is written once they pause.
        public void Save()
        {
            SaveTimer.Stop();
            SaveTimer.Start();
        }

        public void SaveNow()
        {
            SaveTimer.Stop();
            string? Problem = LibraryStore.Save(Library);
            if (Problem != null)
                ReportProblem(Problem);
        }

        public void ReportProblem(string Message)
        {
            Output.WriteLine("[-] " + Message);
            Output.IsOpen = true;
        }

        public void ReportError(Exception Error)
        {
            ReportProblem(Error.Message);
        }

        // Brovan's own defaults suit analysis, not launching.
        private void SeedDefaults()
        {
            Library.Defaults["log.silent"] = "true";
            if (Setup.HypervisorAvailable)
                Library.Defaults["backend.kind"] = BrovanHost.BackendValue;

            SaveNow();
        }

        public void ApplyTheme()
        {
            Application.Current!.RequestedThemeVariant = Library.Theme switch
            {
                "light" => ThemeVariant.Light,
                "system" => ThemeVariant.Default,
                _ => ThemeVariant.Dark,
            };
        }

        public async Task SetBrovanPath(string Path)
        {
            Library.BrovanPath = Path;
            Save();
            BrovanExecutable = BrovanHost.Locate(Path);
            Setup.Refresh();
            await LoadSchema();
        }

        private async Task LoadSchema()
        {
            if (BrovanExecutable == null)
            {
                Schema = Array.Empty<SettingEntry>();
                SchemaStatus = "Brovan was not found, so its settings cannot be shown. Go to Setup to locate it.";
                Rebuild();
                return;
            }

            try
            {
                Schema = await SettingSchema.LoadAsync(BrovanExecutable);
                SchemaStatus = string.Empty;
            }
            catch (Exception Error)
            {
                Schema = Array.Empty<SettingEntry>();
                SchemaStatus = Error.Message;
            }

            Rebuild();
        }

        public void Rebuild()
        {
            bool Hypervisor = Setup.HypervisorAvailable;
            Settings.Rebuild(Schema, Hypervisor);
            foreach (ProfileViewModel Profile in Profiles)
                Profile.Rebuild(Schema, Library.Defaults, Hypervisor);
        }

        public void DefaultsChanged()
        {
            Settings.RefreshRows();
            foreach (ProfileViewModel Profile in Profiles)
                Profile.RefreshRows();
        }

        private async Task AddProfile()
        {
            string? Picked = await Dialogs.PickProgramAsync("Choose a program to add");
            if (Picked != null)
                AddProfileFromPath(Picked);
        }

        public void AddProfileFromPath(string Path)
        {
            Profile Model = new Profile
            {
                Name = System.IO.Path.GetFileNameWithoutExtension(Path),
                Executable = Path,
            };
            Library.Profiles.Add(Model);

            ProfileViewModel Profile = new ProfileViewModel(Model, this);
            Profile.Rebuild(Schema, Library.Defaults, Setup.HypervisorAvailable);
            Profiles.Add(Profile);
            SelectedProfile = Profile;
        }

        private void RemoveSelected()
        {
            ProfileViewModel? Profile = Selected;
            if (Profile == null)
                return;

            Stop(Profile);
            int Index = Profiles.IndexOf(Profile);
            Profiles.Remove(Profile);
            Library.Profiles.Remove(Profile.Model);
            SaveNow();

            Selected = null;
            SelectedProfile = Profiles.Count == 0 ? null : Profiles[Math.Min(Index, Profiles.Count - 1)];
            Raise(nameof(HasSelection));
            Raise(nameof(ListSelection));
            Raise(nameof(CurrentPage));
        }

        public void Launch(ProfileViewModel Profile)
        {
            if (Running.ContainsKey(Profile.Id))
                return;

            if (BrovanExecutable == null)
            {
                ReportProblem("Brovan was not found. Open Setup and locate it first.");
                CurrentPageKind = PageKind.Setup;
                return;
            }

            if (Profile.ExecutableMissing)
            {
                ReportProblem("The program file does not exist: " + Profile.Executable);
                return;
            }

            List<string> Arguments = BrovanHost.LaunchArguments(Profile.Model, Library.Defaults, Schema);
            Output.WriteLine(string.Empty);
            Output.WriteLine("> " + BrovanHost.CommandLine(BrovanExecutable, Arguments));
            Output.Status = "Running " + Profile.Name;

            try
            {
                Process Child = BrovanHost.Start(BrovanExecutable, Arguments, Output.Write, Code =>
                {
                    Dispatcher.UIThread.Post(() =>
                    {
                        Running.Remove(Profile.Id);
                        Profile.IsRunning = false;
                        Output.WriteLine(Code == 0 ? "[*] " + Profile.Name + " finished." : "[-] " + Profile.Name + " exited with code " + Code + ".");
                        if (Code != 0)
                            Output.IsOpen = true;

                        if (Running.Count == 0)
                        {
                            Output.Status = "Idle";
                            OutputViewModel.ReleaseMemory();
                        }
                    });
                });

                Running[Profile.Id] = Child;
                Profile.IsRunning = true;
                Profile.Model.LastLaunched = DateTime.Now;
                Save();
            }
            catch (Exception Error)
            {
                ReportProblem("Could not start Brovan: " + Error.Message);
                Output.Status = "Idle";
            }
        }

        public void Stop(ProfileViewModel Profile)
        {
            if (Running.TryGetValue(Profile.Id, out Process? Child))
                Kill(Child);
        }

        // A child with no window of its own cannot be reached once the launcher goes.
        public void StopAll()
        {
            foreach (Process Child in Running.Values)
                Kill(Child);

            Running.Clear();

            if (Tool != null)
            {
                Kill(Tool);
                Tool = null;
            }
        }

        private static void Kill(Process Child)
        {
            try
            {
                Child.Kill(true);
            }
            catch (Exception)
            {
            }
        }

        private Process? InputTarget()
        {
            if (Tool != null)
                return Tool;

            if (Selected != null && Running.TryGetValue(Selected.Id, out Process? Child))
                return Child;

            return null;
        }

        public Task RunTool(string Title, IReadOnlyList<string> Arguments)
        {
            if (BrovanExecutable == null)
                return Task.CompletedTask;

            TaskCompletionSource Done = new TaskCompletionSource();
            Output.IsOpen = true;
            Output.WriteLine(string.Empty);
            Output.WriteLine("> " + BrovanHost.CommandLine(BrovanExecutable, Arguments));
            Output.Status = Title;

            try
            {
                Tool = BrovanHost.Start(BrovanExecutable, Arguments, Output.Write, Code =>
                {
                    Dispatcher.UIThread.Post(() =>
                    {
                        Tool = null;
                        Output.WriteLine(Code == 0 ? "[+] Done." : "[-] Failed with code " + Code + ".");
                        if (Running.Count == 0)
                            Output.Status = "Idle";

                        Done.TrySetResult();
                    });
                });
            }
            catch (Exception Error)
            {
                ReportProblem("Could not start Brovan: " + Error.Message);
                Output.Status = "Idle";
                Done.TrySetResult();
            }

            return Done.Task;
        }
    }
}
