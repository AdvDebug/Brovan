using BrovanGUI.Models;

namespace BrovanGUI.ViewModels
{
    public sealed class SetupViewModel : ObservableObject
    {
        private readonly MainViewModel Owner;
        private SetupState State = new SetupState();
        private string? HypervisorProblemValue;
        private bool Busy;

        public SetupViewModel(MainViewModel Owner)
        {
            this.Owner = Owner;
            HypervisorProblemValue = BrovanHost.HypervisorProblem();

            BrowseBrovanCommand = new AsyncCommand(BrowseBrovan, Owner.ReportError);
            RefreshCommand = new RelayCommand(Reprobe);
            InstallFromIsoCommand = new AsyncCommand(InstallSystemFilesAsync, Owner.ReportError, () => CanInstallWindows);
            InstallRuntimesCommand = new AsyncCommand(() => Run("Installing the Visual C++ runtimes", "--install-runtimes", "--accept-windows-license"), Owner.ReportError, () => CanInstallWindows);
            InstallDxvkCommand = new AsyncCommand(() => Run("Installing DXVK", "--install-dxvk"), Owner.ReportError, () => CanRunTool);
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
        public RelayCommand OpenFolderCommand { get; }
        public RelayCommand OpenLogCommand { get; }

        public bool HostIsWindows => State.HostIsWindows;
        public bool HostIsLinux => !State.HostIsWindows;
        public bool BrovanFound => State.Executable != null;
        public string BrovanPath => State.Executable ?? "Not found. Put BrovanGUI next to " + BrovanHost.ExecutableName + " or locate it here.";
        public StatusKind BrovanStatus => BrovanFound ? StatusKind.Good : StatusKind.Bad;

        public bool NeedsSystemFiles => HostIsLinux && !State.SystemFiles;

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
            ? "Ready."
            : "Copied from this Windows installation on the first launch, which asks for administrator rights once.";

        public bool HypervisorAvailable => HypervisorProblemValue == null;
        public string HypervisorName => BrovanHost.HypervisorName;
        public StatusKind HypervisorStatus => HypervisorAvailable ? StatusKind.Good : StatusKind.Warn;
        public string HypervisorDescription => HypervisorAvailable
            ? "Available, and programs run on it unless a profile or Settings picks another backend. Games run at near native speed on it."
            : "Not available, so programs run on Unicorn, the slower software backend. " + HypervisorProblemValue;

        public string HypervisorProblem => HypervisorProblemValue ?? string.Empty;

        public StatusKind DxvkStatus => State.DxvkVersion != null ? StatusKind.Good : StatusKind.Warn;
        public string DxvkDescription => State.DxvkVersion != null
            ? State.DxvkVersion + " installed. Direct3D 8 to 11 programs are translated to Vulkan through it."
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
            RefreshCommands();
        }

        private void RefreshCommands()
        {
            Raise(nameof(CanRunTool));
            Raise(nameof(CanInstallWindows));
            InstallFromIsoCommand.Refresh();
            InstallRuntimesCommand.Refresh();
            InstallDxvkCommand.Refresh();
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
}
