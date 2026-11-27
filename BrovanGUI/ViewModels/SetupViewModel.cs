using BrovanGUI.Models;

namespace BrovanGUI.ViewModels
{
    public sealed class SetupViewModel : ObservableObject
    {
        private readonly MainViewModel Owner;
        private SetupState State = new SetupState();
        private string? HypervisorProblemValue;
        private bool Busy;
        private string? CopyProblem;
        private bool Copying;
        private bool InstallingDxvkValue;

        public SetupViewModel(MainViewModel Owner)
        {
            this.Owner = Owner;
            HypervisorProblemValue = BrovanHost.HypervisorProblem();

            BrowseBrovanCommand = new AsyncCommand(BrowseBrovan, Owner.ReportError);
            RefreshCommand = new RelayCommand(Reprobe);
            InstallFromIsoCommand = new AsyncCommand(InstallSystemFilesAsync, Owner.ReportError, () => CanInstallWindows);
            InstallRuntimesCommand = new AsyncCommand(() => Run("Installing the Visual C++ runtimes", "--install-runtimes", "--accept-windows-license"), Owner.ReportError, () => CanInstallWindows);
            InstallDxvkCommand = new AsyncCommand(InstallDxvk, Owner.ReportError, () => CanRunTool);
            CopyRegistryCommand = new AsyncCommand(CopyRegistry, Owner.ReportError, () => CanRunTool && HostIsWindows);
            OpenFolderCommand = new RelayCommand(() =>
            {
                if (State.Directory != null)
                    BrovanHost.OpenExternal(State.Directory);
            });
            OpenLogCommand = new RelayCommand(() =>
            {
                if (State.Directory != null)
                    BrovanHost.OpenExternal(Path.Combine(State.Directory, "error_log.log"));
            });
        }

        public AsyncCommand BrowseBrovanCommand { get; }
        public RelayCommand RefreshCommand { get; }
        public AsyncCommand InstallFromIsoCommand { get; }
        public AsyncCommand InstallRuntimesCommand { get; }
        public AsyncCommand InstallDxvkCommand { get; }
        public AsyncCommand CopyRegistryCommand { get; }
        public RelayCommand OpenFolderCommand { get; }
        public RelayCommand OpenLogCommand { get; }

        public bool HostIsWindows => State.HostIsWindows;
        public bool HostIsLinux => !State.HostIsWindows;
        public bool BrovanFound => State.Executable != null;
        public string BrovanPath => State.Executable ?? "Not found. Put BrovanGUI next to " + BrovanHost.ExecutableName + " or locate it here.";
        public StatusKind BrovanStatus => BrovanFound ? StatusKind.Good : StatusKind.Bad;
        public string BrovanShortPath => State.Executable != null ? BrovanHost.ShortPath(State.Executable) : BrovanPath;

        public bool NeedsSystemFiles => HostIsLinux && !State.SystemFiles;
        public bool SystemFilesReady => State.SystemFiles;
        public bool RuntimesReady => State.Runtimes;
        public bool RegistryReady => State.Registry;
        public string? DxvkVersion => State.DxvkVersion;
        public bool DxvkInstalled => State.DxvkVersion != null;
        public bool IsInitialized => BrovanFound && (HostIsWindows ? State.Registry : State.SystemFiles);

        public StatusKind SystemFilesStatus => State.SystemFiles ? StatusKind.Good : StatusKind.Bad;
        public string SystemFilesDescription => State.SystemFiles
            ? "Installed."
            : "Not installed. Windows programs need the real Windows libraries, NLS tables and registry hives.";

        public StatusKind RuntimesStatus => State.Runtimes ? StatusKind.Good : StatusKind.Warn;
        public string RuntimesDescription => State.Runtimes
            ? "Installed."
            : "Not installed. Most Windows programs are built against them.";

        public StatusKind RegistryStatus => State.Registry ? StatusKind.Good : StatusKind.Warn;
        public string RegistryDescription => State.Registry
            ? "Copied from this PC"
            : "Programs read settings from a private copy of this PC's registry. Windows asks for administrator approval once.";

        public bool HypervisorAvailable => HypervisorProblemValue == null;
        public string HypervisorName => BrovanHost.HypervisorName;
        public StatusKind HypervisorStatus => HypervisorAvailable ? StatusKind.Good : StatusKind.Warn;
        public string HypervisorDescription => HypervisorAvailable
            ? HypervisorName + " is on \u00b7 Programs run at near native speed"
            : "Not available, so programs run on Unicorn, the slower software backend. " + HypervisorProblemValue;

        public string HypervisorProblem => HypervisorProblemValue ?? string.Empty;

        public StatusKind DxvkStatus => State.DxvkVersion != null ? StatusKind.Good : StatusKind.Warn;
        public string DxvkDescription => State.DxvkVersion != null
            ? State.DxvkVersion + " installed \u00b7 Direct3D 8 to 11 through Vulkan"
            : "Not installed. Most Windows games draw with Direct3D and need it.";

        public bool LogExists => State.Directory != null && File.Exists(Path.Combine(State.Directory, "error_log.log"));

        public bool LicenseAccepted
        {
            get => Owner.Library.LicenseAccepted;
            set
            {
                if (Owner.Library.LicenseAccepted == value)
                    return;

                Owner.Library.LicenseAccepted = value;
                Owner.Save();
                Raise();
                RefreshCommands();
            }
        }

        public bool IsBusy
        {
            get => Busy;
            set
            {
                if (Set(ref Busy, value))
                    RefreshCommands();
            }
        }

        public string? CopyRegistryProblem
        {
            get => CopyProblem;
            private set => Set(ref CopyProblem, value);
        }

        public bool CopyingRegistry
        {
            get => Copying;
            private set => Set(ref Copying, value);
        }

        public bool InstallingDxvk
        {
            get => InstallingDxvkValue;
            private set => Set(ref InstallingDxvkValue, value);
        }

        public bool CanRunTool => BrovanFound && !Busy;
        public bool CanInstallWindows => CanRunTool && LicenseAccepted;

        private void Reprobe()
        {
            bool Available = HypervisorAvailable;
            HypervisorProblemValue = BrovanHost.HypervisorProblem();
            Raise(nameof(HypervisorAvailable));
            Raise(nameof(HypervisorStatus));
            Raise(nameof(HypervisorDescription));
            Raise(nameof(HypervisorProblem));
            Refresh();

            // A choice row keeps the availability it was built with.
            if (HypervisorAvailable != Available)
                Owner.Rebuild();
        }

        public void Refresh()
        {
            State = BrovanHost.Inspect(Owner.BrovanExecutable);
            Raise(nameof(HostIsWindows));
            Raise(nameof(HostIsLinux));
            Raise(nameof(BrovanFound));
            Raise(nameof(BrovanPath));
            Raise(nameof(BrovanShortPath));
            Raise(nameof(BrovanStatus));
            Raise(nameof(SystemFilesStatus));
            Raise(nameof(SystemFilesDescription));
            Raise(nameof(RuntimesStatus));
            Raise(nameof(RuntimesDescription));
            Raise(nameof(RegistryStatus));
            Raise(nameof(RegistryDescription));
            Raise(nameof(DxvkStatus));
            Raise(nameof(DxvkDescription));
            Raise(nameof(LogExists));
            Raise(nameof(SystemFilesReady));
            Raise(nameof(RuntimesReady));
            Raise(nameof(RegistryReady));
            Raise(nameof(DxvkVersion));
            Raise(nameof(DxvkInstalled));
            Raise(nameof(IsInitialized));
            RefreshCommands();
        }

        private void RefreshCommands()
        {
            Raise(nameof(CanRunTool));
            Raise(nameof(CanInstallWindows));
            InstallFromIsoCommand.Refresh();
            InstallRuntimesCommand.Refresh();
            InstallDxvkCommand.Refresh();
            CopyRegistryCommand.Refresh();
        }

        private async Task BrowseBrovan()
        {
            string? Picked = await Owner.Dialogs.PickFileAsync("Locate the Brovan emulator", BrovanHost.ExecutableName);
            if (Picked != null)
                await Owner.SetBrovanPath(Picked);
        }

        public async Task<bool> InstallSystemFilesAsync()
        {
            if (!CanInstallWindows)
                return false;

            string? Picked;
            IsBusy = true;
            try
            {
                Picked = await Owner.Dialogs.PickFileAsync("Choose a Windows 11 ISO", "*.iso", "*.wim", "*.esd");
            }
            finally
            {
                IsBusy = false;
            }

            return Picked != null
                && await Run("Installing the Windows system files from " + Path.GetFileName(Picked), "--install-windows", "--accept-windows-license", "--windows-iso", Picked) == 0
                && State.SystemFiles;
        }

        private async Task CopyRegistry()
        {
            if (State.Executable == null || State.Directory == null)
                return;

            string Folder = Path.Combine(State.Directory, "WinReg");
            Owner.Output.WriteLine("[*] Copying the registry hives of this Windows installation into " + Folder + ".");
            CopyRegistryProblem = null;
            CopyingRegistry = true;
            IsBusy = true;
            int? Code;
            try
            {
                Code = await BrovanHost.RunElevatedAsync(State.Executable, new[] { "--dump-reg", "--regdir", Folder });
            }
            finally
            {
                IsBusy = false;
                CopyingRegistry = false;
                Refresh();
            }

            if (Code == null)
                CopyRegistryProblem = "Administrator approval was declined, so nothing was copied. Choose Yes when Windows asks.";
            else if (Code != 0 || !State.Registry)
                CopyRegistryProblem = "The registry could not be copied (code " + Code + ").";

            Owner.Output.WriteLine(CopyRegistryProblem == null ? "[+] Done." : "[-] " + CopyRegistryProblem);
        }

        private async Task InstallDxvk()
        {
            InstallingDxvk = true;
            try
            {
                await Run("Installing DXVK", "--install-dxvk");
            }
            finally
            {
                InstallingDxvk = false;
            }
        }

        private async Task<int> Run(string Title, params string[] Arguments)
        {
            IsBusy = true;
            try
            {
                return await Owner.RunTool(Title, Arguments);
            }
            finally
            {
                IsBusy = false;
                Refresh();
            }
        }
    }

    public sealed class OnboardingViewModel : ObservableObject
    {
        private const int RequiredSteps = 2;

        public OnboardingViewModel(MainViewModel Owner)
        {
            Setup = Owner.Setup;
            FinishCommand = new RelayCommand(() => Owner.CurrentPageKind = Owner.BrovanExecutable == null ? PageKind.Setup : PageKind.Profile);
            AddProgramCommand = new RelayCommand(() =>
            {
                FinishCommand.Execute(null);
                Owner.AddProfileCommand.Execute(null);
            }, () => Setup.BrovanFound);
            Setup.PropertyChanged += (_, _) =>
            {
                Raise(null);
                AddProgramCommand.Refresh();
            };
        }

        public SetupViewModel Setup { get; }
        public RelayCommand FinishCommand { get; }
        public RelayCommand AddProgramCommand { get; }

        private bool FilesReady => Setup.HostIsWindows ? Setup.RegistryReady : Setup.SystemFilesReady;

        public int RequiredDone => (Setup.BrovanFound ? 1 : 0) + (FilesReady ? 1 : 0);
        public int RequiredCount => RequiredSteps;
        public bool EmulatorCurrent => !Setup.BrovanFound;
        public bool FilesCurrent => Setup.BrovanFound && !FilesReady;
        public bool DxvkActionable => Setup.BrovanFound && Setup.DxvkVersion == null && !Setup.InstallingDxvk;
        public bool CopyActionable => FilesCurrent && !Setup.CopyingRegistry;
        public bool RuntimesActionable => Setup.BrovanFound && Setup.LicenseAccepted && !Setup.RuntimesReady;
        public bool RuntimesWaiting => !Setup.RuntimesReady && !RuntimesActionable;
        public string RuntimesWaitText => Setup.BrovanFound ? "Needs the license in step 2" : "After step 1";
        public string? BusyTip => Setup.IsBusy ? "Available when the current task finishes." : null;

        public string Title => Setup.IsInitialized ? "You're all set" : "Welcome to Brovan";

        public string Lead => Setup.IsInitialized
            ? "Add a program to start. You can revisit these steps any time under Setup."
            : "Brovan runs Windows and Linux programs on this computer. Finish the steps below, then add your first program.";

        public bool RegistryFailed => Setup.CopyRegistryProblem != null && !Setup.RegistryReady;

        private bool ExtrasDone => Setup.HypervisorAvailable && Setup.DxvkVersion != null && (Setup.HostIsWindows || Setup.RuntimesReady);

        public string ReadySummary => RequiredDone == RequiredSteps
            ? "Ready to go"
            : RequiredSteps - RequiredDone == 1 ? "1 step left" : (RequiredSteps - RequiredDone) + " steps left";

        public string ReadyHint
        {
            get
            {
                if (!Setup.BrovanFound)
                    return "Next: find " + BrovanHost.ExecutableName + ".";

                if (Setup.CopyingRegistry)
                    return "Working on the Windows registry\u2026";

                if (RegistryFailed)
                    return "Next: approve the registry copy.";

                if (!FilesReady)
                    return Setup.HostIsWindows ? "Next: copy the Windows registry." : "Next: install the Windows system files.";

                return ExtrasDone ? string.Empty : "The recommended extras are optional.";
            }
        }

        public string EmulatorText => Setup.BrovanFound
            ? FoundText(Setup.BrovanPath)
            : BrovanHost.ExecutableName + " isn't next to this app. Browse to it.";

        public string RegistryText => Setup.RegistryReady
            ? "Copied"
            : Setup.CopyingRegistry ? "Approve the Windows prompt to start. Copying takes a few seconds after you approve it."
            : Setup.CopyRegistryProblem ?? "Programs read settings from a private copy of this PC's registry. Windows asks for administrator approval once.";

        public string SystemFilesText => Setup.SystemFilesReady
            ? "Installed"
            : "Windows programs need the real Windows libraries. Brovan takes only the files it needs from a Windows 11 ISO you supply.";

        public string RuntimesText => Setup.RuntimesReady
            ? "Installed"
            : "Many Windows programs need these to start.";

        public string SpeedText => Setup.HypervisorAvailable
            ? Setup.HypervisorName + " is on"
            : Setup.HypervisorProblem + " Programs still run, only slower.";

        public string DxvkText => Setup.DxvkVersion != null
            ? "DXVK " + Setup.DxvkVersion + " installed"
            : "Runs most Direct3D games through Vulkan. Downloads from the DXVK releases on GitHub.";

        private static string FoundText(string Executable)
        {
            string Folder = Path.GetDirectoryName(Executable) ?? Executable;
            if (Path.TrimEndingDirectorySeparator(Folder) == Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory))
                return "Found next to this app.";

            return "Found in " + BrovanHost.ShortPath(Folder);
        }
    }
}
