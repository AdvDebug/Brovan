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
        private readonly Dictionary<ProfileViewModel, Process> Running = new Dictionary<ProfileViewModel, Process>();
        private readonly DispatcherTimer SaveTimer;
        private Process? Tool;
        private string? ToolTitle;
        private ProfileViewModel? Selected;
        private PageKind Page;
        private SettingEntry[] Schema = Array.Empty<SettingEntry>();
        private Dictionary<string, string> SchemaDefaults = new Dictionary<string, string>();
        private Task SchemaLoad = Task.CompletedTask;
        private int SchemaGeneration;
        private string SchemaStatusValue = "Reading the settings Brovan supports...";

        public MainViewModel(Dialogs Dialogs, string? LaunchProfile)
        {
            this.Dialogs = Dialogs;
            Library = LibraryStore.Load(out string? LibraryProblem);
            SaveTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(400) };
            SaveTimer.Tick += (_, _) => SaveNow();
            ApplyTheme();

            Output = new OutputViewModel(Library.OutputOpen, Library.OutputHeight, () =>
            {
                Library.OutputOpen = Output.IsOpen;
                Library.OutputHeight = Output.Height;
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
            ShowSetupCommand = new RelayCommand(ShowSetup);
            ShowSettingsCommand = new RelayCommand(() => CurrentPageKind = PageKind.Settings);
            OpenManualCommand = new RelayCommand(() => BrovanHost.OpenExternal("https://github.com/AdvDebug/Brovan/wiki"));

            Setup = new SetupViewModel(this);
            Settings = new SettingsViewModel(this);
            Welcome = new WelcomeViewModel(this);

            BrovanExecutable = BrovanHost.Locate(Library.BrovanPath);
            Setup.Refresh();

            foreach (ProfileViewModel Profile in Profiles)
            {
                if (Profile.Id == Library.SelectedProfile)
                    Selected = Profile;
            }

            Selected ??= Profiles.Count != 0 ? Profiles[0] : null;
            Page = BrovanExecutable == null ? PageKind.Setup : PageKind.Profile;

            SchemaLoad = LoadSchema();
            if (LaunchProfile != null)
                LaunchNamed(LaunchProfile);
        }

        private void LaunchNamed(string LaunchProfile)
        {
            foreach (ProfileViewModel Profile in Profiles)
            {
                if (string.Equals(Profile.Name, LaunchProfile, StringComparison.OrdinalIgnoreCase) || Profile.Id == LaunchProfile)
                {
                    SelectedProfile = Profile;
                    Profile.LaunchCommand.Execute(null);
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

        private void ShowSetup()
        {
            Setup.Refresh();
            CurrentPageKind = PageKind.Setup;
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

        public void ResetDefaults()
        {
            Library.Defaults.Clear();
            Save();
            DefaultsChanged();
        }

        public string BackendWarning(Profile? Model)
        {
            string? Chosen = BrovanHost.ChosenValue(Model, Library.Defaults, BrovanHost.BackendKey);
            if (Chosen == null)
            {
                return Setup.HypervisorAvailable
                    ? string.Empty
                    : "Programs run on Unicorn, the slower software backend, because " + Setup.HypervisorName + " cannot be used. " + Setup.HypervisorProblem;
            }

            string Backend = Chosen.Trim().ToLowerInvariant();
            if (SettingLabels.ChoiceAvailable(BrovanHost.BackendKey, Backend, Setup.HypervisorAvailable))
                return string.Empty;

            string Warning = SettingLabels.ChoiceLabel(BrovanHost.BackendKey, Backend) + " is selected, but this computer cannot run it, so the launch fails.";
            return Backend == BrovanHost.BackendValue ? Warning + " " + Setup.HypervisorProblem : Warning;
        }

        public string DefaultValue(string Key)
        {
            string? Value = BrovanHost.LauncherDefault(Key, Setup.HypervisorAvailable);
            if (Value != null)
                return Value;

            return SchemaDefaults.TryGetValue(Key, out string? Default) ? Default : string.Empty;
        }

        public string InheritedValue(string Key)
        {
            return Library.Defaults.TryGetValue(Key, out string? Value) ? Value : DefaultValue(Key);
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
            SchemaLoad = LoadSchema();
            await SchemaLoad;
        }

        private async Task LoadSchema()
        {
            int Generation = ++SchemaGeneration;
            SettingEntry[] Loaded = Array.Empty<SettingEntry>();
            string Status;

            if (BrovanExecutable == null)
            {
                Status = "Brovan was not found, so its settings cannot be shown. Go to Setup to locate it.";
            }
            else
            {
                try
                {
                    Loaded = await SettingSchema.LoadAsync(BrovanExecutable);
                    Status = string.Empty;
                }
                catch (Exception Error)
                {
                    Status = Error.Message;
                }
            }

            if (Generation != SchemaGeneration)
                return;

            Schema = Loaded;
            SchemaDefaults = new Dictionary<string, string>(Loaded.Length);
            foreach (SettingEntry Entry in Loaded)
                SchemaDefaults[Entry.Key] = Entry.DefaultText;

            SchemaStatus = Status;
            Rebuild();
        }

        public void Rebuild()
        {
            Settings.Rebuild(Schema);
            foreach (ProfileViewModel Profile in Profiles)
                Profile.Rebuild(Schema);
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

        public void AddDroppedFile(string Path)
        {
            if (BrovanHost.IsProgram(Path))
                AddProfileFromPath(Path);
            else
                ReportProblem(System.IO.Path.GetFileName(Path) + " was not added. It is not a Windows or Linux program, or it could not be read.");
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
            Profile.Rebuild(Schema);
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
            Profile.Discard();
            SaveNow();

            Selected = null;
            SelectedProfile = Profiles.Count == 0 ? null : Profiles[Math.Min(Index, Profiles.Count - 1)];
            Raise(nameof(HasSelection));
            Raise(nameof(ListSelection));
            Raise(nameof(CurrentPage));
        }

        public async Task Launch(ProfileViewModel Profile)
        {
            if (!CanLaunch(Profile))
                return;

            if (!SchemaLoad.IsCompleted || Schema.Length == 0)
            {
                await SchemaReady();
                if (Schema.Length == 0)
                {
                    SchemaLoad = LoadSchema();
                    await SchemaReady();
                }

                if (!CanLaunch(Profile))
                    return;
            }

            if (Setup.NeedsSystemFiles && !BrovanHost.IsLinuxProgram(Profile.Executable))
            {
                Setup.Refresh();
                if (Setup.NeedsSystemFiles && (!await InstallSystemFiles(Profile) || !CanLaunch(Profile)))
                    return;
            }

            if (Schema.Length == 0)
                ReportProblem(Profile.Name + " starts with Brovan's own defaults, because Brovan's settings could not be read. " + SchemaStatus);

            Start(Profile);
        }

        private bool CanLaunch(ProfileViewModel Profile)
        {
            if (Running.ContainsKey(Profile) || Profile.IsDiscarded)
                return false;

            if (BrovanExecutable == null)
            {
                ReportProblem("Brovan was not found. Open Setup and locate it first.");
                ShowSetup();
                return false;
            }

            if (Profile.ExecutableMissing)
            {
                ReportProblem("The program file does not exist: " + Profile.Executable);
                return false;
            }

            return true;
        }

        private async Task SchemaReady()
        {
            while (!SchemaLoad.IsCompleted)
                await SchemaLoad;
        }

        private async Task<bool> InstallSystemFiles(ProfileViewModel Profile)
        {
            CurrentPageKind = PageKind.Setup;
            if (!Setup.LicenseAccepted)
            {
                ReportProblem(Profile.Name + " needs the Windows system files. Confirm the Windows license here, then choose a Windows 11 ISO.");
                return false;
            }

            if (Setup.IsBusy)
            {
                ReportProblem(Profile.Name + " needs the Windows system files. Launch it again when the running setup task ends.");
                return false;
            }

            return await Setup.InstallSystemFilesAsync();
        }

        private void Start(ProfileViewModel Profile)
        {
            List<string> Arguments = BrovanHost.LaunchArguments(Profile.Model, Library.Defaults, Schema, Setup.HypervisorAvailable);
            Process? Child = StartBrovan(BrovanExecutable!, Arguments, BackendWarning(Profile.Model), Code =>
            {
                Running.Remove(Profile);
                Profile.IsRunning = false;
                Output.WriteLine(Code == 0 ? "[*] " + Profile.Name + " finished." : "[-] " + Profile.Name + " exited with code " + Code + ".");
                if (Code != 0)
                    Output.IsOpen = true;

                if (Running.Count == 0)
                    OutputViewModel.ReleaseMemory();
            });

            if (Child == null)
                return;

            Running[Profile] = Child;
            Profile.IsRunning = true;
            Profile.Model.LastLaunched = DateTime.Now;
            Save();
            UpdateStatus();
        }

        // Exited runs on the UI thread.
        private Process? StartBrovan(string Executable, IReadOnlyList<string> Arguments, string Warning, Action<int> Exited)
        {
            Output.WriteLine(string.Empty);
            Output.WriteLine("> " + BrovanHost.CommandLine(Executable, Arguments));
            if (Warning.Length != 0)
                Output.WriteLine("[!] " + Warning);

            try
            {
                return BrovanHost.Start(Executable, Arguments, Output.Write, Code => Dispatcher.UIThread.Post(() =>
                {
                    Exited(Code);
                    UpdateStatus();
                }));
            }
            catch (Exception Error)
            {
                ReportProblem("Could not start Brovan: " + Error.Message);
                return null;
            }
        }

        private void UpdateStatus()
        {
            if (Running.Count == 0)
                Output.Status = ToolTitle ?? "Idle";
            else
                Output.Status = (ToolTitle != null ? ToolTitle + ". " : string.Empty) + "Running " + string.Join(", ", RunningNames());
        }

        public bool HasRunning => Running.Count != 0 || Tool != null;

        private List<string> RunningNames()
        {
            List<string> Names = new List<string>(Running.Count + 1);
            foreach (ProfileViewModel Profile in Running.Keys)
                Names.Add(Profile.Name);

            return Names;
        }

        public string StopWarning()
        {
            List<string> Names = RunningNames();
            if (ToolTitle != null)
                Names.Insert(0, ToolTitle);

            return string.Join(", ", Names) + (Names.Count == 1 ? " is still running. Closing Brovan stops it." : " are still running. Closing Brovan stops them.");
        }

        public void Stop(ProfileViewModel Profile)
        {
            if (Running.TryGetValue(Profile, out Process? Child))
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
                ToolTitle = null;
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

            if (Selected != null && Running.TryGetValue(Selected, out Process? Child))
                return Child;

            return null;
        }

        public Task<int> RunTool(string Title, IReadOnlyList<string> Arguments)
        {
            if (BrovanExecutable == null)
                return Task.FromResult(-1);

            TaskCompletionSource<int> Done = new TaskCompletionSource<int>();
            Output.IsOpen = true;
            Tool = StartBrovan(BrovanExecutable, Arguments, string.Empty, Code =>
            {
                Tool = null;
                ToolTitle = null;
                Output.WriteLine(Code == 0 ? "[+] Done." : "[-] Failed with code " + Code + ".");
                Done.TrySetResult(Code);
            });

            if (Tool == null)
                return Task.FromResult(-1);

            ToolTitle = Title;
            UpdateStatus();
            return Done.Task;
        }
    }
}
