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
        private int? LastExit;
        private bool LinuxProgram;
        private List<CategoryViewModel> CategoryList = new List<CategoryViewModel>();
        private string BackendWarningValue = string.Empty;

        public ProfileViewModel(Profile Model, MainViewModel Owner)
        {
            this.Model = Model;
            this.Owner = Owner;

            LaunchCommand = new AsyncCommand(() => Owner.Launch(this), Owner.ReportError, () => !ExecutableMissing);
            StopCommand = new RelayCommand(() => Owner.Stop(this));
            ShowOutputCommand = new RelayCommand(() => Owner.Output.IsOpen = true);
            ToggleRunsCommand = new RelayCommand(() =>
            {
                ShowingAllRuns = !ShowingAllRuns;
                Raise(nameof(RunsToggleText));
                Raise(nameof(RecentRuns));
            });
            Owner.Output.PropertyChanged += (_, Event) =>
            {
                if (Event.PropertyName == nameof(OutputViewModel.IsOpen))
                    Raise(nameof(RecentRuns));
            };
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
        public AsyncCommand LaunchCommand { get; }
        public RelayCommand StopCommand { get; }
        public RelayCommand RemoveCommand => Owner.RemoveSelectedCommand;
        public RelayCommand ShowOutputCommand { get; }
        public RelayCommand ToggleRunsCommand { get; }
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
                RaiseStatus();
                LaunchCommand.Refresh();
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

        // Avalonia render data keeps its own reference to every bitmap it draws.
        public Bitmap? Icon
        {
            get => IconValue;
            private set
            {
                Bitmap? Old = IconValue;
                if (!Set(ref IconValue, value))
                    return;

                Raise(nameof(HasIcon));
                Old?.Dispose();
            }
        }

        public bool HasIcon => IconValue != null;

        public bool IsRunning
        {
            get => Running;
            set
            {
                if (!Set(ref Running, value))
                    return;

                RaiseStatus();
                if (value)
                {
                    RunClock ??= new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background, (_, _) => Raise(nameof(RecentRuns)));
                    RunClock.Start();
                }
                else
                {
                    RunClock?.Stop();
                }
            }
        }

        private DispatcherTimer? RunClock;

        public int? LastExitCode
        {
            get => LastExit;
            set
            {
                if (Set(ref LastExit, value))
                    RaiseStatus();
            }
        }

        public string StatusText
        {
            get
            {
                if (Running)
                    return "Running";

                if (ExecutableMissing)
                    return "File missing";

                return LastExit is int Code && Code != 0 ? "Exited with code " + Code : "Ready";
            }
        }

        public bool StatusGood => Running;
        public bool ShowChip => Running || LastRunFailed;
        public bool LastRunFailed => !Running && !ExecutableMissing && LastExit is int Code && Code != 0;

        private const int KeptRuns = 20;
        private const int ShownRuns = 3;
        private const int AllRuns = 10;
        private bool ShowingAllRuns;

        public bool HasMoreRuns => Model.Runs.Count > ShownRuns;
        public string RunsToggleText => ShowingAllRuns ? "Show less" : "Show " + (Math.Min(Model.Runs.Count, AllRuns) - ShownRuns) + " more";

        public string? SidebarTip
        {
            get
            {
                if (Running && Model.LastLaunched is DateTime Started)
                    return "Running since " + Started.ToString("HH:mm");

                if (CanLocate)
                    return "The program file is missing";

                return LastRunFailed && Model.Runs.Count != 0
                    ? "Exited with code " + Model.Runs[0].ExitCode + " at " + Model.Runs[0].Started.AddSeconds(Model.Runs[0].Seconds).ToString("HH:mm")
                    : null;
            }
        }

        public bool HasRuns => Model.Runs.Count != 0 || Running;

        public List<RunRow> RecentRuns
        {
            get
            {
                List<RunRow> Rows = new List<RunRow>();
                RelayCommand? Output = Owner.Output.IsOpen ? null : ShowOutputCommand;
                if (Running && Model.LastLaunched is DateTime Started)
                    Rows.Add(RunRow.Current(Started, Output));

                int Limit = ShowingAllRuns ? AllRuns : ShownRuns;
                for (int i = 0; i < Model.Runs.Count && Rows.Count < Limit; i++)
                    Rows.Add(new RunRow(Model.Runs[i], i == 0 && LastRunFailed ? Output : null));

                return Rows;
            }
        }

        public void RecordRun(int Code, bool Stopped)
        {
            DateTime Started = Model.LastLaunched ?? DateTime.Now;
            Model.Runs.Insert(0, new RunRecord { Started = Started, Seconds = (DateTime.Now - Started).TotalSeconds, ExitCode = Code, Stopped = Stopped });
            if (Model.Runs.Count > KeptRuns)
                Model.Runs.RemoveRange(KeptRuns, Model.Runs.Count - KeptRuns);

            Raise(nameof(HasRuns));
            Raise(nameof(HasMoreRuns));
            Raise(nameof(RunsToggleText));
            Raise(nameof(RecentRuns));
        }
        public bool StatusWarn => !Running && (ExecutableMissing || LastExit is int Code && Code != 0);
        public bool CanLocate => ExecutableMissing && !Running;
        public bool CanLaunch => !ExecutableMissing && !Running;

        private void RaiseStatus()
        {
            Raise(nameof(StatusText));
            Raise(nameof(StatusGood));
            Raise(nameof(StatusWarn));
            Raise(nameof(CanLocate));
            Raise(nameof(CanLaunch));
            Raise(nameof(ShowChip));
            Raise(nameof(LastRunFailed));
            Raise(nameof(HasRuns));
            Raise(nameof(RecentRuns));
            Raise(nameof(SidebarTip));
            Raise(nameof(HasNotice));
            Raise(nameof(HeaderDetail));
        }

        public List<CategoryViewModel> Categories
        {
            get => CategoryList;
            private set => Set(ref CategoryList, value);
        }

        public string SchemaStatus => Owner.SchemaStatus;

        public string BackendWarning
        {
            get => BackendWarningValue;
            private set
            {
                if (Set(ref BackendWarningValue, value))
                    Raise(nameof(HasNotice));
            }
        }

        public bool HasNotice => CanLocate || SchemaStatus.Length != 0 || BackendWarningValue.Length != 0;

        public string HeaderDetail
        {
            get
            {
                string Detail = (LinuxProgram ? "Linux program" : "Windows program") + " \u00b7 " + Owner.BackendLabel(Model);
                return HasRuns ? Detail : Detail + " \u00b7 Never launched";
            }
        }

        public bool IsDiscarded { get; private set; }

        public void Rebuild(IReadOnlyList<SettingEntry> Schema)
        {
            SettingsScope Scope = new SettingsScope(Model.Settings, Owner.InheritedValue, () =>
            {
                Owner.Save();
                BackendWarning = Owner.BackendWarning(Model);
                Raise(nameof(HeaderDetail));
                foreach (CategoryViewModel Category in CategoryList)
                    foreach (SettingRow Row in Category.Rows)
                        Row.RefreshNote();
            });

            Categories = SettingLabels.BuildCategories(Schema, Scope, false, Owner);
            Raise(nameof(SchemaStatus));
            Raise(nameof(HasNotice));
            BackendWarning = Owner.BackendWarning(Model);
        }

        public void RefreshRows()
        {
            foreach (CategoryViewModel Category in CategoryList)
                foreach (SettingRow Row in Category.Rows)
                    Row.Refresh();

            BackendWarning = Owner.BackendWarning(Model);
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
                bool Linux = BrovanHost.IsLinuxProgram(Path);
                Dispatcher.UIThread.Post(() =>
                {
                    if (Executable == Path && !IsDiscarded)
                    {
                        Icon = Loaded;
                        LinuxProgram = Linux;
                        Raise(nameof(HeaderDetail));
                    }
                    else
                    {
                        Loaded?.Dispose();
                    }
                });
            });
        }

        public void Discard()
        {
            IsDiscarded = true;
            Icon = null;
        }

        private async Task BrowseExecutable()
        {
            string? Picked = await Owner.Dialogs.PickProgramAsync("Choose the program to run");
            if (Picked != null)
            {
                Executable = Picked;
                if (Name.Length == 0)
                    Name = BrovanHost.ProgramName(Picked);
            }
        }

        private async Task BrowseWorkingDirectory()
        {
            string? Picked = await Owner.Dialogs.PickFolderAsync("Choose the folder the program starts in");
            if (Picked != null)
                WorkingDirectory = Picked;
        }
    }

    public sealed class RunRow
    {
        public RunRow(RunRecord Run, RelayCommand? ShowOutput)
        {
            Stopped = Run.Stopped;
            Failed = !Stopped && Run.ExitCode != 0;
            Finished = !Stopped && !Failed;
            Result = Stopped ? "Stopped" : Failed ? "Exited with code " + Run.ExitCode : string.Empty;
            When = Run.Started.Date == DateTime.Today ? "Today at " + Run.Started.ToString("HH:mm")
                : Run.Started.Date == DateTime.Today.AddDays(-1) ? "Yesterday at " + Run.Started.ToString("HH:mm")
                : Run.Started.ToString("MMM d, HH:mm");
            Duration = Format(TimeSpan.FromSeconds(Math.Max(0, Run.Seconds)));
            ShowOutputCommand = ShowOutput;
            DateTime Ended = Run.Started.AddSeconds(Math.Max(0, Run.Seconds));
            Tip = Run.Started.ToString("HH:mm") + " \u2013 " + Ended.ToString("HH:mm") + " \u00b7 " + (Stopped ? "stopped" : "exit code " + Run.ExitCode);
        }

        private RunRow(DateTime Started, RelayCommand ShowOutput)
        {
            Live = true;
            Result = "Running";
            When = "Now";
            Duration = Format(DateTime.Now - Started);
            ShowOutputCommand = ShowOutput;
        }

        public static RunRow Current(DateTime Started, RelayCommand ShowOutput)
        {
            return new RunRow(Started, ShowOutput);
        }

        private static string Format(TimeSpan Length)
        {
            if (Length < TimeSpan.Zero)
                Length = TimeSpan.Zero;

            return Length.TotalHours >= 1 ? (int)Length.TotalHours + "h " + Length.Minutes + "m"
                : Length.TotalMinutes >= 1 ? (int)Length.TotalMinutes + "m " + Length.Seconds + "s"
                : Length.Seconds + "s";
        }

        public bool Failed { get; }
        public bool Finished { get; }
        public bool Live { get; }
        public bool Stopped { get; }
        public string Result { get; }
        public string When { get; }
        public string Duration { get; }
        public string? Tip { get; }
        public RelayCommand? ShowOutputCommand { get; }
        public bool CanShowOutput => ShowOutputCommand != null;
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
