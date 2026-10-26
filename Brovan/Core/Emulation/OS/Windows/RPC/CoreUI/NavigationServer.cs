using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;
using Brovan.Core.Emulation.OS.Windows.RPC.Shell;

namespace Brovan.Core.Emulation.OS.Windows.RPC.CoreUI
{
    // The part of sihost's CoreUI navigation server that an app view needs. It answers as a shell that runs one app in
    // the foreground.
    internal sealed class NavigationServer
    {
        private const string ClientViewCreatorName = "System\\NavigationServer_ClientViewCreator";
        private const string WindowManagerName = "System\\NavigationServer_WindowManager";
        private const string ClientSessionManagerName = "System\\NavigationServer_ClientSessionManager";
        private const string RotationManagerName = "System\\RotationManager";

        private const ushort RemoteWindowType = 0x00B8;
        private const ushort RemoteTaskType = 0x00B7;

        private HostMessagingServer Server;

        // The shell keeps one pending view activation, so a new view replaces a task that still waits.
        private NavigationTask WaitingTask;

        private readonly Dictionary<uint, NavigationServerWindow> Windows = new Dictionary<uint, NavigationServerWindow>();

        internal static NavigationServer Create(WinSysHelper Helper, CoreMessagingRegistrarPort Registrar, uint ProcessId, uint ThreadId)
        {
            HostMessagingServer Server = CoreUIMessage.CreateServer(Helper, Registrar, ProcessId, ThreadId);
            if (Server == null)
                return null;

            NavigationServer Navigation = new NavigationServer { Server = Server };
            Server.TryAddNamed(ClientViewCreatorName, new ClientViewCreator(Navigation));
            Server.TryAddNamed(WindowManagerName, new WindowManager(Navigation));
            Server.TryAddNamed(ClientSessionManagerName, new ClientSessionManager(Navigation));
            Server.TryAddNamed(RotationManagerName, new RotationManager());
            return Navigation;
        }

        private bool TryAddView(BinaryEmulator Instance, uint ViewId, string AppId, string ContractId, Guid Request)
        {
            if (WaitingTask != null)
                WaitingTask.Release(null);

            if (!Server.TryReserveObject())
                return false;

            ActivatableApplicationRegistrar Registrar = Instance.WinHelper.ShellRegistrar;
            WaitingTask = new NavigationTask(this, Server, Registrar, Registrar.FindPendingView(Request), ViewId, AppId, ContractId);
            return true;
        }

        internal void TaskReleased(NavigationTask Task)
        {
            if (WaitingTask == Task)
                WaitingTask = null;

            Server.ReleaseObject();
        }

        // InstanceId is the low 32 bits of the window handle.
        internal bool HasWindow(uint InstanceId) => Windows.ContainsKey(InstanceId);

        internal void WindowReleased(NavigationServerWindow Window)
        {
            if (Windows.TryGetValue(Window.InstanceId, out NavigationServerWindow Found) && Found == Window)
                Windows.Remove(Window.InstanceId);
        }

        private sealed class ClientViewCreator : CoreUIObject
        {
            private const ushort ClientViewCreatorType = 0x00A7;

            private const ushort CreateViewMethod = 2;

            // ValidationException::GetHResult(0xC00, 23), which NT answers when it runs out of endpoints.
            private const uint ViewManagerError = 0x87B20C00;
            private const uint EndpointsShort = 23;

            private readonly NavigationServer Navigation;

            internal ClientViewCreator(NavigationServer Navigation) => this.Navigation = Navigation;

            protected override uint TypeId => CoreUIMessage.TypeId(CoreUIMessage.RemoteInterfacesModule, ClientViewCreatorType);

            protected override void Invoke(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
            {
                if (Method != CreateViewMethod)
                {
                    CoreUIMessage.Refuse($"IRemoteClientViewCreator method {Method}");
                    return;
                }

                CreateView(Call, ref Parameters);
            }

            private void CreateView(HostMessagingCall Call, ref CoreMessagingReader Parameters)
            {
                if (!Parameters.TryReadUInt32(out uint ViewId) || !Parameters.TryReadString(out ReadOnlySpan<char> AppId)
                    || !Parameters.TryReadGuid(out Guid Request) || !Parameters.TryReadUInt64(out _)
                    || !Parameters.TryReadString(out ReadOnlySpan<char> ContractId) || !Parameters.TryReadString(out _)
                    || !Parameters.TryReadUInt64(out _) || !Parameters.TryReadUInt64(out _)
                    || !Parameters.TryReadUInt32(out _) || !Parameters.TryReadOutSlot() || !Parameters.AtEnd)
                {
                    CoreUIMessage.Refuse("CreateView with parameters that do not match it");
                    return;
                }

                uint Result = Navigation.TryAddView(Call.Instance, ViewId, AppId.ToString(), ContractId.IsEmpty ? null : ContractId.ToString(), Request) ? 0 : ViewManagerError | EndpointsShort;
                Span<byte> Out = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32LittleEndian(Out, Result);
                Call.SetPendingResult(Out);
            }
        }

        private sealed class WindowManager : CoreUIObject
        {
            private const ushort WindowManagerType = 0x00B6;
            private const ushort RegisterNavigationWindowMethod = 0;

            private readonly NavigationServer Navigation;

            internal WindowManager(NavigationServer Navigation) => this.Navigation = Navigation;

            protected override uint TypeId => CoreUIMessage.TypeId(CoreUIMessage.RemoteInterfacesModule, WindowManagerType);

            protected override void Invoke(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
            {
                if (Method != RegisterNavigationWindowMethod)
                {
                    CoreUIMessage.Refuse($"IRemoteWindowManager method {Method}");
                    return;
                }

                if (!CoreUIMessage.TryReadProxy(ref Parameters, Call, out CoreUIProxy Window) || !Parameters.TryReadUInt32(out uint InstanceId)
                    || !Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> TouchInput)
                    || !Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> TextInput) || !Parameters.AtEnd)
                {
                    CoreUIMessage.Refuse("RegisterNavigationWindow with parameters that do not match it");
                    return;
                }

                Navigation.RegisterWindow(Call, Window, InstanceId, TextInput, TouchInput);
            }
        }

        private void RegisterWindow(HostMessagingCall Call, CoreUIProxy Window, uint InstanceId, ReadOnlySpan<byte> TextInput, ReadOnlySpan<byte> TouchInput)
        {
            const ushort RegistrationCompleteMethod = 3;

            if (Window == null || Window.TypeId != CoreUIMessage.TypeId(CoreUIMessage.RemoteInterfacesModule, RemoteWindowType))
            {
                CoreUIMessage.Refuse("RegisterNavigationWindow without an IRemoteWindow");
                return;
            }

            CoreMessagingRegistrarPort.Client Sender = Call.Connection.Client;
            WinWindow Owner = Call.Instance.WinHelper.GetWindow((ulong)(long)(int)InstanceId);
            if (Owner == null || Owner.OwnerThreadId != Sender.ThreadId || Call.Instance.WinHelper.PID != Sender.ProcessId)
            {
                CoreUIMessage.Refuse($"to register window 0x{InstanceId:X}, which is not a window of the sending thread");
                return;
            }

            NavigationServerWindow ServerWindow = new NavigationServerWindow(this, InstanceId, Sender.ProcessId, Sender.ThreadId, TextInput, TouchInput, Owner, Window);
            if (!Server.TryAdd(Call.Connection, ServerWindow))
            {
                CoreUIMessage.Refuse("a server window past the limit of objects");
                return;
            }

            Windows[InstanceId] = ServerWindow;
            Window.InvokeWithObject(Call, RegistrationCompleteMethod, ServerWindow);
        }

        private sealed class ClientSessionManager : CoreUIObject
        {
            private const ushort ClientSessionManagerType = 0x00A5;
            private const ushort ConnectNavigationTaskMethod = 0;

            private readonly NavigationServer Navigation;

            internal ClientSessionManager(NavigationServer Navigation) => this.Navigation = Navigation;

            protected override uint TypeId => CoreUIMessage.TypeId(CoreUIMessage.RemoteInterfacesModule, ClientSessionManagerType);

            protected override void Invoke(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
            {
                if (Method != ConnectNavigationTaskMethod)
                {
                    CoreUIMessage.Refuse($"IRemoteClientSessionManager method {Method}");
                    return;
                }

                if (!CoreUIMessage.TryReadProxy(ref Parameters, Call, out CoreUIProxy Task) || !Parameters.TryReadUInt32(out uint TaskId)
                    || !Parameters.TryReadUInt32(out uint WindowId)
                    || !Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> ShellData) || !Parameters.AtEnd)
                {
                    CoreUIMessage.Refuse("ConnectNavigationTask with parameters that do not match it");
                    return;
                }

                Navigation.ConnectTask(Call, Task, TaskId, WindowId, ShellData);
            }
        }

        // The checks and their order follow SessionManager::ConnectNavigationTask.
        private void ConnectTask(HostMessagingCall Call, CoreUIProxy Task, uint TaskId, uint WindowId, ReadOnlySpan<byte> ShellData)
        {
            if (Task == null || TaskId == 0 || WindowId == 0)
            {
                CoreUIMessage.Refuse("ConnectNavigationTask without a task, a task id or a window id");
                return;
            }

            if (Task.TypeId != CoreUIMessage.TypeId(CoreUIMessage.RemoteInterfacesModule, RemoteTaskType))
            {
                CoreUIMessage.Refuse("ConnectNavigationTask without an IRemoteTask");
                return;
            }

            NavigationTask Waiting = WaitingTask;
            if (Waiting == null || Waiting.ViewId != TaskId)
            {
                CoreUIMessage.Refuse($"ConnectNavigationTask for task {TaskId}, which no view waits for");
                return;
            }

            if (!Waiting.ViewActivationLive)
            {
                Waiting.Release(Call);
                CoreUIMessage.Refuse($"ConnectNavigationTask for task {TaskId}, whose view activation ended");
                return;
            }

            if (!Windows.TryGetValue(WindowId, out NavigationServerWindow Window))
            {
                Waiting.Release(Call);
                CoreUIMessage.Refuse($"ConnectNavigationTask for window 0x{WindowId:X}, which is not registered");
                return;
            }

            // Only the connection that registered the window can reach it, and an app does both from one thread.
            if (Window.Connection != Call.Connection)
            {
                Waiting.Release(Call);
                CoreUIMessage.Refuse($"ConnectNavigationTask for window 0x{WindowId:X}, which another connection registered");
                return;
            }

            WaitingTask = null;
            Waiting.Connect(Call, Task, Window, ShellData);
        }

        private sealed class RotationManager : CoreUIObject
        {
            private const ushort RotationManagerType = 0x00F9;

            protected override uint TypeId => CoreUIMessage.TypeId(CoreUIMessage.RemoteInterfacesModule, RotationManagerType);

            protected override int PropertyCount => 11;

            // NT: RotationManager::_Construct sets DefaultSupportedOrientations, CurrentOrientation and DeviceOrientation
            // to PortraitUp (1) and LastLandscapeOrientation to LandscapeLeft (2), which no sensor changes on a desktop.
            protected override bool WriteProperty(ref CoreUIPropertyWriter Writer, ushort Index) => Index switch
            {
                0 or 2 or 4 => Writer.UInt32(1),
                3 => Writer.UInt32(2),
                6 or 8 or 10 => Writer.Bool(false),
                _ => Writer.UInt32(0),
            };

            protected override void Invoke(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
                => CoreUIMessage.Refuse($"IRemoteRotationManager method {Method}");
        }
    }

    internal sealed class NavigationServerWindow : CoreUIObject
    {
        private const ushort ServerWindowType = 0x00B5;

        private const ushort InstanceIdProperty = 0;
        private const ushort ReadyProperty = 1;
        private const ushort VisibleProperty = 2;
        private const ushort TouchInputProperty = 3;
        private const ushort TextInputProperty = 4;
        private const ushort ActiveProperty = 5;
        private const ushort WindowTypeProperty = 6;
        private const ushort DisplayProperty = 7;
        private const ushort BoundsProperty = 8;
        private const ushort ThreadIdProperty = 9;
        private const ushort PowerTerminalProperty = 10;
        private const ushort ProcessIdProperty = 11;
        private const ushort OwnerProperty = 12;
        private const ushort ActivationObjectIdProperty = 13;
        private const int PropertyTotal = 14;

        internal const int BoundsSize = 44;
        private const uint NoPowerTerminal = 0xFFFFFFFF;

        private const ushort ChangeTouchInputMethod = 4;
        private const ushort ChangeTextInputMethod = 6;

        private readonly NavigationServer Navigation;
        internal readonly uint InstanceId;
        private readonly uint ProcessId;
        private readonly uint ThreadId;
        private readonly byte[] TextInput;
        private readonly byte[] TouchInput;
        private readonly ulong ActivationObjectId;
        private readonly byte[] Bounds = new byte[BoundsSize];
        internal readonly int X;
        internal readonly int Y;
        internal readonly uint Width;
        internal readonly uint Height;

        private int ReadyTasks;
        private int VisibleTasks;
        private int ActiveTasks;
        private bool Ready;
        private bool Visible;
        private bool Active;

        // Property 1 of the app's IRemoteWindow is its ActivationObjectId.
        internal NavigationServerWindow(NavigationServer Navigation, uint InstanceId, uint ProcessId, uint ThreadId, ReadOnlySpan<byte> TextInput, ReadOnlySpan<byte> TouchInput, WinWindow Owner, CoreUIProxy AppWindow)
        {
            this.Navigation = Navigation;
            this.InstanceId = InstanceId;
            this.ProcessId = ProcessId;
            this.ThreadId = ThreadId;
            this.TextInput = TextInput.ToArray();
            this.TouchInput = TouchInput.ToArray();
            ReadOnlySpan<byte> Activation = AppWindow.Property(1);
            ActivationObjectId = Activation.Length == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(Activation) : 0;
            X = Owner.X;
            Y = Owner.Y;
            Width = Owner.Width;
            Height = Owner.Height;
        }

        // NT tells the proxies of all three, also when they do not change.
        internal void SetTaskValues(HostMessagingCall Call, ReadOnlySpan<byte> TaskBounds)
        {
            TaskBounds.CopyTo(Bounds);
            NotifyPropertyChanged(Call, DisplayProperty);
            NotifyPropertyChanged(Call, BoundsProperty);
            NotifyPropertyChanged(Call, PowerTerminalProperty);
        }

        protected override uint TypeId => CoreUIMessage.TypeId(CoreUIMessage.RemoteInterfacesModule, ServerWindowType);

        protected override int PropertyCount => PropertyTotal;

        internal void CountReady(int Delta) => ReadyTasks += Delta;

        internal void CountVisible(int Delta) => VisibleTasks += Delta;

        internal void CountActive(int Delta) => ActiveTasks += Delta;

        internal void Evaluate(HostMessagingCall Call)
        {
            if (Ready != ReadyTasks > 0)
            {
                Ready = ReadyTasks > 0;
                NotifyPropertyChanged(Call, ReadyProperty);
            }

            if (Visible != VisibleTasks > 0)
            {
                Visible = VisibleTasks > 0;
                NotifyPropertyChanged(Call, VisibleProperty);
            }

            if (Active != ActiveTasks > 0)
            {
                Active = ActiveTasks > 0;
                NotifyPropertyChanged(Call, ActiveProperty);
            }
        }

        protected override bool WriteProperty(ref CoreUIPropertyWriter Writer, ushort Index) => Index switch
        {
            InstanceIdProperty => Writer.UInt32(InstanceId),
            ReadyProperty => Writer.Bool(Ready),
            VisibleProperty => Writer.Bool(Visible),
            TouchInputProperty => Writer.Bytes(TouchInput),
            TextInputProperty => Writer.Bytes(TextInput),
            ActiveProperty => Writer.Bool(Active),
            WindowTypeProperty or OwnerProperty => Writer.UInt32(0),
            DisplayProperty => Writer.UInt64(0),
            BoundsProperty => Writer.Bytes(Bounds),
            ThreadIdProperty => Writer.UInt32(ThreadId),
            PowerTerminalProperty => Writer.UInt32(NoPowerTerminal),
            ProcessIdProperty => Writer.UInt32(ProcessId),
            ActivationObjectIdProperty => Writer.UInt64(ActivationObjectId),
            _ => false,
        };

        protected override void Invoke(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
        {
            if ((Method != ChangeTouchInputMethod && Method != ChangeTextInputMethod)
                || !Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> Routing) || !Parameters.AtEnd)
            {
                CoreUIMessage.Refuse($"IRemoteServerWindow method {Method}");
                return;
            }

            byte[] Current = Method == ChangeTouchInputMethod ? TouchInput : TextInput;
            if (Routing.SequenceEqual(Current))
                return;

            Routing.CopyTo(Current);
            NotifyPropertyChanged(Call, Method == ChangeTouchInputMethod ? TouchInputProperty : TextInputProperty);
        }

        internal override void Released() => Navigation.WindowReleased(this);
    }
}
