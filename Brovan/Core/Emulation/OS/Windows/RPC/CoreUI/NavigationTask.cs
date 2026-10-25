using System;
using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Emulation.OS.Windows.RPC.Shell;
using Brovan.Core.Emulation.OS.Windows.Win32k;

namespace Brovan.Core.Emulation.OS.Windows.RPC.CoreUI
{
    // The states follow the Modern table of target Active (TaskStateTransitions::GetModernActiveStateTable).
    internal sealed class NavigationTask
    {
        // These are the ServerTaskState values that a launch reaches.
        private const int StateNone = 0;
        private const int StateResuming = 1;
        private const int StateNavigatedTo = 2;
        private const int StateReadyToShow = 3;
        private const int StateShown = 4;
        private const int StateActive = 5;
        private const int StateVisible = 13;
        private const int StateActivating = 14;
        private const int StateCount = 17;

        // These are TaskStateTransitions__Condition values, as ServerTask::IsConditionMet reads them.
        private const byte Always = 0;
        private const byte Never = 1;
        private const byte OperationComplete = 2;
        private const byte VisibleAndPresented = 4;
        private const byte NavigationReady = 8;
        private const byte NotRunning = 11;
        private const byte NavigatedAndPresenting = 14;
        private const byte NoRow = 0xFF;

        private static readonly (byte Condition, byte Next)[] ActiveRows = BuildActiveRows();

        // The server calls these IRemoteTask methods on the app.
        private const ushort ConnectionCompleteMethod = 0;
        private const ushort ShowMethod = 2;
        private const ushort NavigateToMethod = 4;
        private const ushort ActivateMethod = 14;

        // The app calls these IRemoteClientTask methods on the server.
        private const ushort ReadyToNavigateMethod = 111;
        private const ushort ShowCompleteMethod = 112;
        private const ushort NavigateToCompleteMethod = 114;
        private const ushort ActivateCompleteMethod = 116;

        private readonly NavigationServer Navigation;
        private readonly HostMessagingServer Server;
        private readonly ActivatableApplicationRegistrar Registrar;
        private readonly PendingViewActivation View;
        internal readonly uint ViewId;

        private int State;
        private int Target;
        private CoreUIProxy Proxy;
        private NavigationServerWindow Window;
        private NavigationClientTask Client;
        private bool Released;

        private bool WantsNavigation;
        private bool OperationDone;
        private bool PresentationBegun;
        private bool PresentationEnded;
        private bool Visible;
        private bool Active;
        private bool Running;
        private bool CountsReady;

        internal readonly string AppId;
        internal readonly string ContractId;

        internal NavigationTask(NavigationServer Navigation, HostMessagingServer Server, ActivatableApplicationRegistrar Registrar, PendingViewActivation View,
            uint ViewId, string AppId, string ContractId)
        {
            this.Navigation = Navigation;
            this.Server = Server;
            this.Registrar = Registrar;
            this.View = View;
            this.ViewId = ViewId;
            this.AppId = AppId;
            this.ContractId = ContractId;
        }

        internal bool ViewActivationLive => View == null || Registrar.IsPending(View);

        // ServerTask::_Construct sets adjacent display flags 3, view state 1, user interaction mode 1 and allowed view
        // modes 1, and the shell sets the size and the position.
        private static byte[] BuildBounds(NavigationServerWindow Window)
        {
            byte[] Bounds = new byte[NavigationServerWindow.BoundsSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Bounds, Window.Width);
            BinaryPrimitives.WriteUInt32LittleEndian(Bounds.AsSpan(0x04), Window.Height);
            BinaryPrimitives.WriteUInt32LittleEndian(Bounds.AsSpan(0x08), 3);
            BinaryPrimitives.WriteUInt32LittleEndian(Bounds.AsSpan(0x0C), 1);
            BinaryPrimitives.WriteInt32LittleEndian(Bounds.AsSpan(0x10), Window.X);
            BinaryPrimitives.WriteInt32LittleEndian(Bounds.AsSpan(0x14), Window.Y);
            BinaryPrimitives.WriteUInt32LittleEndian(Bounds.AsSpan(0x18), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Bounds.AsSpan(0x28), 1);
            return Bounds;
        }

        private static (byte Condition, byte Next)[] BuildActiveRows()
        {
            (byte, byte)[] Rows = new (byte, byte)[StateCount];
            Array.Fill(Rows, (NoRow, (byte)0));
            Rows[StateNone] = (NotRunning, StateResuming);
            Rows[StateResuming] = (NavigationReady, StateNavigatedTo);
            Rows[StateNavigatedTo] = (NavigatedAndPresenting, StateReadyToShow);
            Rows[StateReadyToShow] = (VisibleAndPresented, StateShown);
            Rows[StateShown] = (OperationComplete, StateVisible);
            Rows[StateVisible] = (Always, StateActivating);
            Rows[StateActivating] = (OperationComplete, StateActive);
            Rows[StateActive] = (Never, StateActive);
            return Rows;
        }

        internal void Connect(HostMessagingCall Call, CoreUIProxy Task, NavigationServerWindow ServerWindow, ReadOnlySpan<byte> ShellData)
        {
            Proxy = Task;
            Proxy.Disconnected = ProxyDisconnected;
            Window = ServerWindow;
            byte[] Bounds = BuildBounds(ServerWindow);
            ServerWindow.SetTaskValues(Call, Bounds);
            CoreUIMessageMap ExtensionMap = new CoreUIMessageMap();
            NavigationClientTask ClientTask = new NavigationClientTask(this, ServerWindow, ExtensionMap, CoreMessagingRouting.ProcessId(Task.ObjectRouting), Bounds, ShellData);
            if (!Server.TryAdd(Call.Connection, ExtensionMap) || !Server.TryAdd(Call.Connection, ClientTask))
            {
                Server.Remove(ExtensionMap);
                CoreUIMessage.Refuse($"the client task of view {ViewId} past the limit of objects");
                Release(Call);
                return;
            }

            Client = ClientTask;
            ClientTask.HoldReferences();

            // The shell activates and presents the view at once.
            PresentationBegun = true;
            PresentationEnded = true;
            Target = StateActive;
            ProcessState(Call);

            Proxy.InvokeWithObject(Call, ConnectionCompleteMethod, ClientTask);
            Window.Evaluate(Call);
        }

        internal void ClientCall(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
        {
            switch (Method)
            {
                case ReadyToNavigateMethod:
                    if (!Parameters.TryReadBool(out bool Ready) || !Parameters.AtEnd)
                    {
                        CoreUIMessage.Refuse("ReadyToNavigate with parameters that do not match it");
                        return;
                    }

                    WantsNavigation = Ready;
                    break;
                case NavigateToCompleteMethod:
                    Complete(Call, StateNavigatedTo, "NavigateToComplete");
                    break;
                case ShowCompleteMethod:
                    Complete(Call, StateShown, "ShowComplete");
                    break;
                case ActivateCompleteMethod:
                    Complete(Call, StateActivating, "ActivateComplete");
                    break;
                default:
                    CoreUIMessage.Refuse($"IRemoteClientTask method {Method}");
                    return;
            }

            if (Released)
                return;

            ProcessState(Call);
            Window.Evaluate(Call);
        }

        private void Complete(HostMessagingCall Call, int Expected, string What)
        {
            if (State == Expected)
            {
                OperationDone = true;
                return;
            }

            // NT also aborts the app and disconnects its process, and Brovan ends the task only.
            CoreUIMessage.Refuse($"{What} for view {ViewId} in state {State}, which ends the task");
            Release(Call);
        }

        private void ProcessState(HostMessagingCall Call)
        {
            if (State == Target)
                return;

            while (true)
            {
                int Before = State;
                (byte Condition, byte Next) Row = ActiveRows[State];
                if (Target != StateActive || Row.Condition == NoRow)
                {
                    CoreUIMessage.Refuse($"to move view {ViewId} from state {State} toward state {Target}");
                    return;
                }

                if (IsConditionMet(Row.Condition))
                    EnterState(Call, Row.Next);

                if (State == Before)
                    return;
            }
        }

        private bool IsConditionMet(byte Condition)
        {
            switch (Condition)
            {
                case Always:
                    return true;
                case Never:
                    return false;
                case OperationComplete:
                    return OperationDone;
                case VisibleAndPresented:
                    return Visible && PresentationEnded;
                case NavigationReady:
                    return Running && Proxy != null && WantsNavigation;
                case NotRunning:
                    return !Running;
                case NavigatedAndPresenting:
                    return (OperationDone && PresentationBegun) || Proxy == null;
                default:
                    return false;
            }
        }

        private void EnterState(HostMessagingCall Call, int Next)
        {
            State = Next;
            switch (Next)
            {
                // The shell resumes the task at once.
                case StateResuming:
                    Running = true;
                    break;
                case StateNavigatedTo:
                    CountsReady = true;
                    Window.CountReady(1);
                    SendNavigation(Call, NavigateToMethod);
                    break;
                // The shell's session is visible, so the task becomes visible.
                case StateReadyToShow:
                    Visible = true;
                    Window.CountVisible(1);
                    break;
                case StateShown:
                    SendNavigation(Call, ShowMethod);
                    break;
                case StateActivating:
                    Proxy?.Invoke(Call, ActivateMethod, null);
                    OperationDone = false;
                    break;
                case StateActive:
                    Active = true;
                    Window.CountActive(1);
                    break;
            }
        }

        // The direction, the animation type and the animation flags. With no flag 2 the animation type is 1.
        private void SendNavigation(HostMessagingCall Call, ushort Method)
        {
            if (Proxy != null)
            {
                CoreMessagingWriter Parameters = new CoreMessagingWriter();
                Parameters.UInt32(0);
                Parameters.UInt32(1);
                Parameters.UInt32(0);
                Proxy.Invoke(Call, Method, Parameters);
            }

            OperationDone = false;
        }

        private void ProxyDisconnected(HostMessagingCall Call) => Release(Call);

        internal void Release(HostMessagingCall Call)
        {
            if (Released)
                return;

            Released = true;
            if (Proxy != null)
            {
                Proxy.Disconnected = null;
                Proxy = null;
            }

            if (Window != null)
            {
                if (CountsReady)
                    Window.CountReady(-1);
                if (Visible)
                    Window.CountVisible(-1);
                if (Active)
                    Window.CountActive(-1);
                if (Call != null)
                    Window.Evaluate(Call);
                Window = null;
            }

            if (Client != null)
            {
                NavigationClientTask ClientTask = Client;
                Client = null;
                Server.Remove(ClientTask);
                Registrar.EndViewActivation(View);
            }

            Navigation.TaskReleased(this);
        }
    }

    internal sealed class NavigationClientTask : CoreUIObject
    {
        private const ushort ClientTaskType = 0x00B1;

        private readonly NavigationTask Task;
        private readonly NavigationServerWindow Window;
        private readonly CoreUIMessageMap ExtensionMap;
        private readonly uint ProcessId;
        private readonly byte[] Bounds;
        private readonly byte[] ShellData;
        // NT joins the app id and the contract id with no separator.
        private readonly string DisplayName;

        internal NavigationClientTask(NavigationTask Task, NavigationServerWindow Window, CoreUIMessageMap ExtensionMap, uint ProcessId, byte[] Bounds, ReadOnlySpan<byte> ShellData)
        {
            this.Task = Task;
            this.Window = Window;
            this.ExtensionMap = ExtensionMap;
            this.ProcessId = ProcessId;
            this.Bounds = Bounds;
            this.ShellData = ShellData.ToArray();
            DisplayName = Task.AppId + Task.ContractId;
        }

        protected override uint TypeId => CoreUIMessage.TypeId(CoreUIMessage.RemoteInterfacesModule, ClientTaskType);

        protected override int PropertyCount => 100;

        internal void HoldReferences()
        {
            Connection.Server.Hold(Window);
            Connection.Server.Hold(ExtensionMap);
        }

        // Uri is empty, PauseOnLock, IsMinimized and WindowManagementEnabled are true, and the bounds and scales come
        // from the window and the system DPI.
        protected override bool WriteProperty(ref CoreUIPropertyWriter Writer, ushort Index)
        {
            const uint SupportedOrientations = 15;
            const uint CurrentOrientation = 1;
            const uint TaskTypeModern = 2;

            switch (Index)
            {
                case 0:
                    Writer.UInt32(Task.ViewId);
                    return true;
                case 1:
                    Writer.Value.String(string.Empty);
                    return true;
                case 2:
                    Writer.Value.String(Task.AppId);
                    return Task.AppId != null;
                case 3:
                    Writer.Value.String(Task.ContractId);
                    return Task.ContractId != null;
                case 4:
                case 5:
                    Writer.Value.String(DisplayName);
                    return true;
                case 9:
                    return Writer.UInt32(ProcessId);
                case 10:
                    return Writer.WriteObject(Window);
                case 11:
                    return Writer.Bytes(ShellData);
                case 12:
                    return Writer.UInt32(SupportedOrientations);
                case 13:
                    return Writer.UInt32(CurrentOrientation);
                case 18:
                case 55:
                case 94:
                    return Writer.Bool(true);
                case 20:
                    return Writer.UInt32(TaskTypeModern);
                case 24:
                    Writer.Bytes(Bounds);
                    return true;
                case 27:
                    return Writer.WriteObject(ExtensionMap);
                case 31:
                    Span<byte> Rect = stackalloc byte[Win32kHelper.GuestRectSize];
                    Win32kHelper.WriteGuestRect(Rect, new GdiClipRect { Left = Window.X, Top = Window.Y, Right = Window.X + (int)Window.Width, Bottom = Window.Y + (int)Window.Height });
                    Writer.Bytes(Rect);
                    return true;
                case 66:
                case 67:
                    Span<byte> Scale = stackalloc byte[sizeof(float)];
                    BinaryPrimitives.WriteSingleLittleEndian(Scale, HostDisplayMetrics.SystemDpi / (float)HostDisplayMetrics.DefaultDpi);
                    Writer.Bytes(Scale);
                    return true;
                default:
                    return false;
            }
        }

        protected override void Invoke(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
            => Task.ClientCall(Call, Method, ref Parameters);

        internal override void Released()
        {
            Connection.Server.Unhold(ExtensionMap);
            Connection.Server.Unhold(Window);
            Task.Release(null);
        }
    }
}
