using System.Diagnostics;
using System.Text;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    internal sealed record LocalServer(string ImagePath, string CommandLine, bool RunsAsInteractiveUser, bool PerPackage);

    internal enum LaunchOutcome
    {
        Running,
        Joined,
        Served,
        Failed,
        Cancelled,
    }

    internal sealed class RpcssLaunch
    {
        // NT: rpcss waits this long for a server it started to register, and then ends it.
        internal const int ServerStartTimeoutMilliseconds = 120000;
        private const int ServerSecondChanceMilliseconds = 30000;
        private const uint StatusDllInitFailedLogoff = 0xC000026B;

        internal const uint CoEServerExecFailure = 0x80080005;
        private const string ServerExecFailureText = "Server execution failed\r\n";

        // NT: rpcss answers a failed CreateProcess with HRESULT_FROM_WIN32 of its error and that error's message text.
        private static readonly (NTSTATUS Status, uint Result, string Text)[] Failures =
        {
            (NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND, 0x80070002, "The system cannot find the file specified.\r\n"),
            (NTSTATUS.STATUS_NOT_SUPPORTED, 0x80070032, "The request is not supported.\r\n"),
            (NTSTATUS.STATUS_INVALID_PARAMETER, 0x80070057, "The parameter is incorrect.\r\n"),
            (NTSTATUS.STATUS_OBJECT_PATH_SYNTAX_BAD, 0x800700A1, "The specified path is invalid.\r\n"),
            (NTSTATUS.STATUS_INVALID_IMAGE_FORMAT, 0x800700C1, "%1 is not a valid Win32 application.\r\n"),
            (NTSTATUS.STATUS_INSUFFICIENT_RESOURCES, 0x800705AA, "Insufficient system resources exist to complete the requested service.\r\n"),
        };

        private static readonly char[] CommandLineBreaks = { ' ', '\t' };

        private const string MachineClasses = "\\Registry\\Machine\\Software\\Classes";
        private const string InteractiveUser = "Interactive User";
        private const uint AppIdPerPackage = 0x1000;

        // NT: the application id and package claims kernel.appcore gives every per-app broker token.
        private const string BrokerApplicationId = "runtimebroker07f4358a809ac99a64a67c1";
        private const ulong BrokerPackageClaims = 0x40;

        private const int ShutdownWaitMilliseconds = 5000;

        private const int ServerPollMilliseconds = GuestProcessLauncher.StartupPollMilliseconds;

        // Only touched under KernelLock.
        private static readonly List<RpcssLaunch> Running = new List<RpcssLaunch>();

        private static readonly object WorkSync = new();
        private static readonly List<Task> Works = new List<Task>();
        private static readonly CancellationTokenSource Cancel = new CancellationTokenSource();

        internal RpcssPortHandler.LaunchKey Key { get; }

        private readonly LaunchRequest Request;
        private readonly string Location;
        private readonly TaskCompletionSource Registered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        private RpcssSessionTable.LaunchCell Cell;
        private bool OwnsCell;
        private StartedProcess Started;
        private uint Status;
        private int State;

        private RpcssLaunch(RpcssPortHandler.LaunchKey Key, in LaunchRequest Request, string Location)
        {
            this.Key = Key;
            this.Request = Request;
            this.Location = Location;
        }

        internal LaunchOutcome Outcome => (LaunchOutcome)Volatile.Read(ref State);

        internal static LocalServer TryReadServer(WinSysHelper Helper, Guid Class)
        {
            string ClassKey = MachineClasses + "\\CLSID\\" + Class.ToString("B");
            WinRegKey ServerKey = Helper.ResolveRegistryKey(ClassKey + "\\LocalServer32");
            if (!TryReadString(Helper, ServerKey, null, out string CommandLine) || string.IsNullOrWhiteSpace(CommandLine))
                return null;

            TryReadString(Helper, ServerKey, "ServerExecutable", out string Executable);
            bool Interactive = false;
            uint Flags = 0;
            if (TryReadString(Helper, Helper.ResolveRegistryKey(ClassKey), "AppID", out string AppIdText) && Guid.TryParse(AppIdText, out Guid AppId))
            {
                WinRegKey AppIdKey = Helper.ResolveRegistryKey(MachineClasses + "\\AppID\\" + AppId.ToString("B"));
                if (Helper.TryGetRegistryValue(AppIdKey, "LocalService", out _) || Helper.TryGetRegistryValue(AppIdKey, "DllSurrogate", out _))
                {
                    Utils.LogError($"[-] RPCSS: {Class} is served by a service or a surrogate, which is not launched.");
                    return null;
                }

                if (TryReadString(Helper, AppIdKey, "RunAs", out string RunAs))
                {
                    if (!string.Equals(RunAs, InteractiveUser, StringComparison.OrdinalIgnoreCase))
                    {
                        Utils.LogError($"[-] RPCSS: {Class} runs as \"{RunAs}\", which is not launched.");
                        return null;
                    }

                    Interactive = true;
                }

                Flags = Helper.ReadRegistryDword(AppIdKey, "AppIDFlags");
            }

            string ImagePath = string.IsNullOrWhiteSpace(Executable) ? null : Executable;
            return new LocalServer(ImagePath, CommandLine + " -Embedding", Interactive, (Flags & AppIdPerPackage) != 0);
        }

        // NT: CreateProcess without an application name tries each prefix of an unquoted command line that ends at a
        // space or a tab, and adds .exe to one without an extension.
        private static string FindImage(string CommandLine)
        {
            string Line = CommandLine.TrimStart();
            if (Line.StartsWith('"'))
                return GuestProcessLauncher.Argv0(Line);

            int End = 0;
            while (End < Line.Length)
            {
                int Break = Line.IndexOfAny(CommandLineBreaks, End + 1);
                End = Break < 0 ? Line.Length : Break;
                string Candidate = Line.Substring(0, End);
                if (!GeneralHelper.IO.GetWindowsFileName(Candidate).Contains('.'))
                    Candidate += ".exe";

                string HostImage = GeneralHelper.IO.ResolveHostPath(Candidate, BinaryHelpers.BinaryFormat.PE);
                if (!string.IsNullOrEmpty(HostImage) && File.Exists(HostImage))
                    return Candidate;
            }

            return GuestProcessLauncher.Argv0(Line);
        }

        // NT: rpcss reads the value with RegGetValueW, which expands REG_EXPAND_SZ with rpcss's own environment.
        private static bool TryReadString(WinSysHelper Helper, WinRegKey Key, string Name, out string Text)
        {
            Text = null;
            if (!Helper.TryGetRegistryValue(Key, Name, out ValueNode Value) || (Value.Type != WinSysHelper.RegSz && Value.Type != WinSysHelper.RegExpandSz))
                return false;

            Text = WinSysHelper.DecodeRegistryString(Value.Data);
            if (Value.Type == WinSysHelper.RegExpandSz)
                Text = ExpandSystemVariables(Text);
            return true;
        }

        private static string ExpandSystemVariables(string Text)
        {
            Dictionary<string, string> Machine = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            Guests.WindowsGuest.AddMachineEnvironment(Machine);
            StringBuilder Expanded = new StringBuilder(Text.Length + 16);
            int Position = 0;
            while (Position < Text.Length)
            {
                int Start = Text.IndexOf('%', Position);
                int End = Start < 0 ? -1 : Text.IndexOf('%', Start + 1);
                if (End < 0)
                    break;

                Expanded.Append(Text, Position, Start - Position);
                if (!Machine.TryGetValue(Text.Substring(Start + 1, End - Start - 1), out string Value))
                {
                    Expanded.Append(Text, Start, End - Start);
                    Position = End;
                    continue;
                }

                Expanded.Append(Value);
                Position = End + 1;
            }

            Expanded.Append(Text, Position, Text.Length - Position);
            return Expanded.ToString();
        }

        // NT gives a server without RunAs the client's token, one with RunAs Interactive User the user's, and a per-app
        // server the client's package claims on top.
        internal static WinToken ServerToken(BinaryEmulator Instance, LocalServer Server, WinToken Client, string PackageFullName)
        {
            WinToken Token = Server.RunsAsInteractiveUser ? WinToken.CreatePrimary(Client.User, 0) : Client;
            if (Server.PerPackage && PackageFullName.Length != 0)
            {
                AppxPackage Package = Instance.WindowsGuest?.PackageIdentity?.Package;
                if (Package == null || !string.Equals(Package.FullName, PackageFullName, StringComparison.OrdinalIgnoreCase))
                    return null;

                Token = AppxPackageModel.BuildPackageToken(Token, Package, BrokerApplicationId, false, false, BrokerPackageClaims, WinTokenSecurityAttribute.InheritOnce, 0);
            }

            return Token.AssignPrimary(0);
        }

        internal static RpcssLaunch Start(RpcssPortHandler.LaunchKey Key, in LaunchRequest Request)
        {
            RpcssLaunch Launch = new RpcssLaunch(Key, Request, RpcssSessionTable.PendingLocation());
            lock (WorkSync)
            {
                if (Cancel.IsCancellationRequested)
                    return null;

                Works.RemoveAll(Work => Work.IsCompleted);
                Works.Add(Task.Factory.StartNew(Launch.Run, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default));
            }

            Running.Add(Launch);
            return Launch;
        }

        internal static void Advance()
        {
            for (int Index = Running.Count - 1; Index >= 0; Index--)
            {
                RpcssLaunch Launch = Running[Index];
                if (Launch.Outcome != LaunchOutcome.Running)
                    Running.RemoveAt(Index);
                else if (RpcssPortHandler.IsServedInSession(Launch.Key))
                    Launch.Registered.TrySetResult();
            }
        }

        // A cancelled launch leaves its cell and its server to the session, because other processes may wait for it.
        internal static void Shutdown()
        {
            Task[] Pending;
            lock (WorkSync)
            {
                Cancel.Cancel();
                Pending = Works.ToArray();
                Works.Clear();
            }

            if (Pending.Length != 0 && !Task.WaitAll(Pending, ShutdownWaitMilliseconds))
                Utils.LogError("[-] RPCSS: a server launch did not end at shutdown.");
        }

        internal uint FailureStatus()
        {
            switch (Outcome)
            {
                case LaunchOutcome.Failed:
                    return Status;

                case LaunchOutcome.Joined:
                    return RpcssSessionTable.ReadLaunchState(Cell, out uint Failed) == RpcssSessionTable.CellFailed ? Failed : 0;

                default:
                    return 0;
            }
        }

        private void Publish(LaunchOutcome Reached, uint Failure)
        {
            Status = Failure;
            Volatile.Write(ref State, (int)Reached);
        }

        private void Run()
        {
            try
            {
                RunLaunch(Cancel.Token);
            }
            catch (Exception Error)
            {
                Utils.LogError($"[-] RPCSS: the launch of {Key.Class} failed: {Error.Message}");
                GuestProcessLauncher.Abandon(Started);
                if (OwnsCell)
                    Fail(CoEServerExecFailure);
                else
                    Publish(LaunchOutcome.Failed, CoEServerExecFailure);
            }
            finally
            {
                Started.HostProcess?.Dispose();
                SessionPump.Ring(GuestSession.OwnSlot);
            }
        }

        private void RunLaunch(CancellationToken Token)
        {
            long Deadline = Environment.TickCount64 + ServerStartTimeoutMilliseconds;
            if (!TryClaim(Deadline, out LaunchOutcome Reached))
            {
                Publish(LaunchOutcome.Failed, CoEServerExecFailure);
                return;
            }

            if (Reached != LaunchOutcome.Running)
            {
                Publish(Reached, 0);
                return;
            }

            OwnsCell = true;
            if (Token.IsCancellationRequested)
            {
                EndCell(0);
                Publish(LaunchOutcome.Cancelled, 0);
                return;
            }

            LaunchRequest Starting = Request.ImagePath != null ? Request : Request with { ImagePath = FindImage(Request.CommandLine) };
            if (!GuestProcessLauncher.TryStart(Starting, (_, Identity) => ProcessInheritance.BuildWithoutHandles(Identity), out Started, out NTSTATUS Refused))
            {
                if (Refused == NTSTATUS.STATUS_IMAGE_MACHINE_TYPE_MISMATCH)
                    Utils.LogError($"[-] RPCSS: the server of {Key.Class} is 32-bit, and other processes do not see its class objects.");
                Fail(LaunchFailure(Refused));
                return;
            }

            Process HostProcess = Started.HostProcess;
            SetServer((uint)(HostProcess?.Id ?? 0));
            if (!GuestProcessLauncher.WaitForStartup(HostProcess, Started.SpawnToken, Deadline, Token, out uint GuestProcessId, out uint HostProcessId,
                    out _, out _, out _))
            {
                if (Token.IsCancellationRequested)
                {
                    Publish(LaunchOutcome.Cancelled, 0);
                    return;
                }

                Utils.LogError($"[-] RPCSS: {Path.GetFileName(Started.HostImage)} never reached guest startup.");
                GuestProcessLauncher.Abandon(Started);
                Fail(CoEServerExecFailure);
                return;
            }

            SetServer(HostProcessId);

            // Registered is set only on this process's pump, so the session table decides at the deadline.
            ServerWait Waited = WaitForServer(HostProcess, HostProcessId, Deadline, Token);
            if (Waited == ServerWait.Ended)
                Waited = WaitAfterExit(HostProcess, Token);
            if (Waited == ServerWait.Expired && RpcssPortHandler.IsServedInSession(Key))
                Waited = ServerWait.Registered;

            switch (Waited)
            {
                case ServerWait.Registered:
                    EndCell(0);
                    Publish(LaunchOutcome.Served, 0);
                    break;

                case ServerWait.Cancelled:
                    Publish(LaunchOutcome.Cancelled, 0);
                    break;

                case ServerWait.Expired:
                    Utils.LogError($"[-] RPCSS: {Path.GetFileName(Started.HostImage)} did not register its class in time and is ended.");
                    if (!GuestSession.RequestTerminate(GuestProcessId, 0))
                        GuestProcessLauncher.Abandon(Started);
                    Fail(CoEServerExecFailure);
                    break;

                default:
                    Utils.LogError($"[-] RPCSS: {Path.GetFileName(Started.HostImage)} ended before it registered its class.");
                    Fail(CoEServerExecFailure);
                    break;
            }
        }

        private enum ServerWait
        {
            Registered,
            Ended,
            Expired,
            Cancelled,
        }

        private ServerWait WaitForServer(Process HostProcess, uint HostProcessId, long Deadline, CancellationToken Token)
        {
            if (HostProcess != null)
            {
                using CancellationTokenSource Waits = CancellationTokenSource.CreateLinkedTokenSource(Token);
                Task Exited = HostProcess.WaitForExitAsync(Waits.Token);
                Task Expired = Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, Deadline - Environment.TickCount64)), Waits.Token);
                Task.WaitAny(Registered.Task, Exited, Expired);
                ServerWait Result = Registered.Task.IsCompleted ? ServerWait.Registered
                    : Token.IsCancellationRequested ? ServerWait.Cancelled
                    : Exited.IsCompletedSuccessfully ? ServerWait.Ended
                    : ServerWait.Expired;
                Waits.Cancel();
                return Result;
            }

            while (true)
            {
                if (Registered.Task.Wait(ServerPollMilliseconds))
                    return ServerWait.Registered;
                if (Token.IsCancellationRequested)
                    return ServerWait.Cancelled;
                if (!GuestSession.IsHostAlive(HostProcessId))
                    return ServerWait.Ended;
                if (Environment.TickCount64 >= Deadline)
                    return ServerWait.Expired;
            }
        }

        // NT: a server that exits before it registers gets a second chance, because a process it started may register.
        // A DLL it could not load ends it at once (CServerTableEntry::WaitForLocalServer).
        private ServerWait WaitAfterExit(Process HostProcess, CancellationToken Token)
        {
            if (HostProcess != null && (uint)HostProcess.ExitCode is (uint)NTSTATUS.STATUS_DLL_NOT_FOUND or StatusDllInitFailedLogoff)
                return ServerWait.Ended;

            try
            {
                if (Registered.Task.Wait(ServerSecondChanceMilliseconds, Token))
                    return ServerWait.Registered;
            }
            catch (OperationCanceledException)
            {
                return ServerWait.Cancelled;
            }

            return RpcssPortHandler.IsServedInSession(Key) ? ServerWait.Registered : ServerWait.Ended;
        }

        private bool TryClaim(long Deadline, out LaunchOutcome Reached)
        {
            Reached = LaunchOutcome.Running;
            if (!RpcssSessionTable.TryOpen(Location))
            {
                Utils.LogError($"[-] RPCSS: the session table cannot be opened; {Key.Class} is not launched.");
                return false;
            }

            List<RpcssSessionTable.LaunchCellRecord> Cells = new List<RpcssSessionTable.LaunchCellRecord>(RpcssSessionTable.LaunchCellCapacity);
            // One hold of the session lock covers the read and the claim, so two launches of one key cannot both claim.
            using SessionLock Lock = GuestSession.Acquire();
            if (!Lock.Held || !RpcssSessionTable.TryReadLaunchCells(Cells))
            {
                Utils.LogError($"[-] RPCSS: the launch cells of the session could not be read; {Key.Class} is not launched.");
                return false;
            }

            int Free = -1;
            for (int Index = 0; Index < Cells.Count; Index++)
            {
                RpcssSessionTable.LaunchCellRecord Each = Cells[Index];
                if (Each.State == RpcssSessionTable.CellFree)
                {
                    if (Free < 0)
                        Free = Index;
                }
                else if (RpcssPortHandler.SameKey(Each.Key, Key) && IsLive(Each))
                {
                    Cell = Each.Cell;
                    Reached = LaunchOutcome.Joined;
                    return true;
                }
            }

            // A server that registered after the activation looked for one serves it, and no second one starts.
            if (RpcssPortHandler.IsServedInSession(Key))
            {
                Reached = LaunchOutcome.Served;
                return true;
            }

            for (int Index = 0; Free < 0 && Index < Cells.Count; Index++)
            {
                if (!IsLive(Cells[Index]))
                    Free = Index;
            }

            if (Free < 0 || !RpcssSessionTable.TryClaimLaunchCell(Cells[Free].Cell, Key, Deadline, out Cell))
            {
                Utils.LogError($"[-] RPCSS: every launch cell of the session is in use; {Key.Class} is not launched.");
                return false;
            }

            return true;
        }

        private static bool IsLive(in RpcssSessionTable.LaunchCellRecord Each)
        {
            if (Each.State == RpcssSessionTable.CellStarting && RpcssPortHandler.IsServedInSession(Each.Key))
                return false;

            ulong Holder = Each.Holder;
            if (Holder == 0 && Each.HostProcessId != 0)
            {
                Holder = RpcssSessionTable.FindHolder(Each.HostProcessId);
                if (Holder != 0)
                    RpcssSessionTable.SetLaunchServer(Each.Cell, 0, Holder);
            }

            if (Holder != 0)
                return GuestSession.IsHolderAliveCached(Holder);
            if (Each.HostProcessId != 0)
                return GuestSession.IsHostAlive(Each.HostProcessId);
            return Each.State == RpcssSessionTable.CellStarting && Environment.TickCount64 < Each.Deadline;
        }

        private void SetServer(uint HostProcessId)
        {
            using SessionLock Lock = GuestSession.Acquire();
            if (Lock.Held)
                RpcssSessionTable.SetLaunchServer(Cell, HostProcessId, 0);
        }

        private void EndCell(uint FailedStatus)
        {
            using SessionLock Lock = GuestSession.Acquire();
            if (Lock.Held)
                RpcssSessionTable.EndLaunchCell(Cell, FailedStatus);
            else
                Utils.LogError($"[-] RPCSS: the launch cell of {Key.Class} could not be ended.");
        }

        private void Fail(uint FailedStatus)
        {
            EndCell(FailedStatus);
            SessionPump.RingAll();
            Publish(LaunchOutcome.Failed, FailedStatus);
        }

        private static uint LaunchFailure(NTSTATUS Refused)
        {
            foreach ((NTSTATUS Status, uint Result, string _) Each in Failures)
            {
                if (Each.Status == Refused)
                    return Each.Result;
            }

            return CoEServerExecFailure;
        }

        internal static string DescribeFailure(uint Result)
        {
            if (Result == CoEServerExecFailure)
                return ServerExecFailureText;

            foreach ((NTSTATUS _, uint Failed, string Text) in Failures)
            {
                if (Failed == Result)
                    return Text;
            }

            return string.Empty;
        }
    }
}
