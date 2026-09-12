using BrovanGUI.Models;

namespace BrovanGUI.ViewModels
{
    public sealed class SetupViewModel : ObservableObject
    {
        private readonly MainViewModel Owner;
        private SetupState State = new SetupState();
        private bool Busy;

        public SetupViewModel(MainViewModel Owner)
        {
            this.Owner = Owner;

            BrowseBrovanCommand = new AsyncCommand(BrowseBrovan, Owner.ReportError);
            RefreshCommand = new RelayCommand(Refresh);
            InstallFromIsoCommand = new AsyncCommand(InstallFromIso, Owner.ReportError, () => CanInstallWindows);
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

        public bool HypervisorAvailable => State.HypervisorAvailable;
        public string HypervisorName => State.HypervisorName;
        public StatusKind HypervisorStatus => State.HypervisorAvailable ? StatusKind.Good : StatusKind.Warn;
        public string HypervisorDescription => State.HypervisorAvailable
            ? "Available. Games run at near native speed on it. Pick it as the backend in a profile or in Settings."
            : State.HypervisorHint;

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

        public void Refresh()
        {
            bool Hypervisor = State.HypervisorAvailable;
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
            Raise(nameof(HypervisorAvailable));
            Raise(nameof(HypervisorName));
            Raise(nameof(HypervisorStatus));
            Raise(nameof(HypervisorDescription));
            Raise(nameof(DxvkStatus));
            Raise(nameof(DxvkDescription));
            Raise(nameof(LogExists));
            RefreshCommands();

            // A choice row keeps the availability it was built with.
            if (State.HypervisorAvailable != Hypervisor)
                Owner.Rebuild();
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

        private async Task InstallFromIso()
        {
            string? Picked = await Owner.Dialogs.PickFileAsync("Choose a Windows ISO, WIM or ESD", "*.iso", "*.wim", "*.esd");
            if (Picked != null)
                await Run("Installing the Windows system files from " + Path.GetFileName(Picked), "--install-windows", "--accept-windows-license", "--windows-iso", Picked);
        }

        private async Task Run(string Title, params string[] Arguments)
        {
            IsBusy = true;
            try
            {
                await Owner.RunTool(Title, Arguments);
            }
            finally
            {
                IsBusy = false;
                Refresh();
            }
        }
    }
}
