using System.Buffers;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Emulation.OS.Windows.Win32k;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Helpers;
using Brovan.Analysis;
using static Brovan.Core.Helpers.BinaryHelpers;
using static Brovan.Core.Emulation.OS.Windows.WinSysHelper;

namespace Brovan.Core.Emulation
{
    public partial class BinaryEmulator
    {
        public static readonly string ApiSetMapPath = Path.Combine(Environment.CurrentDirectory, "apisetmap.bin");

        private static readonly Lazy<byte[]> LazyApiSetMapBlob = new(() =>
        {
            try
            {
                return File.Exists(ApiSetMapPath) ? File.ReadAllBytes(ApiSetMapPath) : Array.Empty<byte>();
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }, isThreadSafe: true);

        internal WindowsGuest WindowsGuest => GetGuest<WindowsGuest>();
        internal WinSysHelper WinHelper => WindowsGuest?.WinHelper;
        internal ulong TEB => WindowsGuest?.GetCurrentTeb(this) ?? 0;
        internal ulong PEB => WindowsGuest?.PEB ?? 0;
        internal ulong ProcessParams => WindowsGuest?.ProcessParams ?? 0;
        internal ulong ApiSetMap => WindowsGuest?.ApiSetMap ?? 0;

        public ulong KUSER_SHARED_DATA = 0x7FFE0000;

        internal bool SuppressSyscallStatusWrite = false;

        public ulong ProcessCookie = 0;

        public ulong StackSize = 0;

        private static IcedX86Disassembler Disassembler = new IcedX86Disassembler(X86DisassembleMode.Bit64, X86DisassemblerFormat.FastFormat);
        private static CodeHookCallback InstructionHook;

        private WinModule _lastAddressModule = null;
        private ulong _lastAddressModuleStart = 0;
        private ulong _lastAddressModuleEnd = 0;
        private readonly byte[] _instructionDisasmBuffer = new byte[16];
        private readonly List<KeyValuePair<ulong, IHandleObject>> WindowsTimerHandleSnapshot = new();
        private readonly List<KeyValuePair<ulong, IHandleObject>> WindowsNextTimerHandleSnapshot = new();
        private readonly List<KeyValuePair<ulong, IHandleObject>> WindowsNextTimerPacketSnapshot = new();
        private readonly List<KeyValuePair<ulong, IHandleObject>> WindowsWakePacketSnapshot = new();
        private readonly List<KeyValuePair<ulong, IHandleObject>> WindowsMaterializePacketSnapshot = new();
        private readonly List<EmulatedThread> WindowsWakeThreadSnapshot = new();

        public string LastFunc = string.Empty;
        public ulong Instruction = 0;

        /// <summary>
        /// An indicator to start disassembling instructions. mostly used when debugging something.
        /// </summary>
        public bool StopTheReturn = false;

        internal NTSTATUS WinUnimplemented
        {
            get
            {
                if (Settings.FakeUnimplementedSyscalls)
                    return NTSTATUS.STATUS_SUCCESS;
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }
        }

        public void SetLastWinError(uint LastError)
        {
            WindowsGuest?.SetLastWinError(this, LastError);
        }

        /// <summary>
        /// Sets a raw syscall return value.
        /// </summary>
        /// <param name="returnValue">Return value to be set.</param>
        public void SetRawSyscallReturn(ulong returnValue)
        {
            if (_binary.Architecture == BinaryArchitecture.x64)
                WriteRegister(Registers.UC_X86_REG_RAX, returnValue);
            else
                WriteRegister32(Registers.UC_X86_REG_EAX, (uint)returnValue);

            SuppressSyscallStatusWrite = true;
        }

        /// <summary>
        /// Sets a boolean syscall return value.
        /// </summary>
        /// <param name="success">Return value to be set.</param>
        public void SetBooleanSyscallReturn(bool success)
        {
            SetRawSyscallReturn(success ? 1UL : 0UL);
        }

        public void SetLastWinErrorRegister(NTSTATUS Status)
        {
            WindowsGuest?.SetLastWinErrorRegister(this, Status);
        }

        internal bool CanSatisfyWaitHandle(ulong Handle)
        {
            return CanSatisfyWaitHandle(Handle, CurrentThread);
        }

        internal bool CanSatisfyWaitHandle(ulong Handle, EmulatedThread AcquiringThread)
        {
            if (WindowsGuest == null || WinHelper == null)
                return Guest != null && Guest.IsHandleSignaled(this, Handle);

            IHandleObject Obj = WinHelper.HandleManager.GetObjectByHandle(Handle);
            if (Obj == null)
                return false;

            if (Obj is WinEvent Event)
                return Event.Signaled;

            if (Obj is WinSemaphore Semaphore)
                return Semaphore.CurrentCount > 0;

            if (Obj is WinRegKey RegKey)
                return RegKey.NotifySignaled;

            if (Obj is WinMutex Mutex)
                return Mutex.Signaled || (AcquiringThread != null && Mutex.OwnerThreadId == AcquiringThread.ThreadId);

            if (Obj is EmulatedThread Thread)
                return Thread.State == EmulatedThreadState.Terminated;

            if (Obj is WinTimer Timer)
            {
                RefreshTimerState(Timer);
                return Timer.Signaled;
            }

            return Guest != null && Guest.IsHandleSignaled(this, Handle);
        }

        internal bool HasHandleWaiters(ulong Handle)
        {
            if (WinHelper == null)
                return false;

            foreach (EmulatedThread Thread in Threads.Values)
            {
                if (Thread == null || Thread.State != EmulatedThreadState.Waiting || !Thread.WaitActive)
                    continue;

                if (Thread.WaitHandles != null && Thread.WaitHandles.Contains(Handle))
                    return true;
            }

            return false;
        }

        internal bool TryAcquireWaitHandle(ulong Handle)
        {
            return TryAcquireWaitHandle(Handle, CurrentThread);
        }

        internal bool TryAcquireWaitHandle(ulong Handle, EmulatedThread AcquiringThread)
        {
            return TryAcquireWaitHandle(Handle, AcquiringThread, out _);
        }

        internal bool TryAcquireWaitHandle(ulong Handle, EmulatedThread AcquiringThread, out NTSTATUS WaitStatus)
        {
            WaitStatus = NTSTATUS.STATUS_SUCCESS;

            if (WindowsGuest == null || WinHelper == null)
                return Guest != null && Guest.IsHandleSignaled(this, Handle);

            IHandleObject Obj = WinHelper.HandleManager.GetObjectByHandle(Handle);
            if (Obj == null)
                return false;

            if (Obj is WinEvent Event)
            {
                if (!Event.Signaled)
                    return false;

                if (Event.EventType == 1)
                    Event.Signaled = false;

                return true;
            }

            if (Obj is WinSemaphore Semaphore)
            {
                if (Semaphore.CurrentCount <= 0)
                    return false;

                Semaphore.CurrentCount--;
                return true;
            }

            if (Obj is WinRegKey RegKey)
            {
                if (!RegKey.NotifySignaled)
                    return false;

                RegKey.NotifySignaled = false;
                return true;
            }

            if (Obj is WinMutex Mutex)
            {
                if (AcquiringThread == null)
                    return false;

                if (!Mutex.Signaled && Mutex.OwnerThreadId != AcquiringThread.ThreadId)
                    return false;

                bool WasAbandoned = Mutex.Abandoned;
                Mutex.Signaled = false;
                Mutex.Abandoned = false;
                Mutex.OwnerThreadId = AcquiringThread.ThreadId;
                Mutex.RecursionCount++;
                WaitStatus = WasAbandoned ? NTSTATUS.STATUS_ABANDONED_WAIT_0 : NTSTATUS.STATUS_SUCCESS;
                return true;
            }

            if (Obj is EmulatedThread Thread)
                return Thread.State == EmulatedThreadState.Terminated;

            if (Obj is WinTimer Timer)
            {
                RefreshTimerState(Timer);
                if (!Timer.Signaled)
                    return false;

                if (Timer.TimerType == TIMER_TYPE.SynchronizationTimer)
                    Timer.Signaled = false;

                return true;
            }

            return Guest != null && Guest.IsHandleSignaled(this, Handle);
        }

        private bool RefreshTimerState(WinTimer Timer)
        {
            if (Timer == null || !Timer.Active)
                return false;

            long Now = EmulatedTickCount64;
            if (Now < Timer.DueTick)
                return false;

            bool WasSignaled = Timer.Signaled;
            Timer.Signaled = true;

            if (Timer.PeriodMilliseconds > 0)
            {
                long Period = Timer.PeriodMilliseconds;
                long Next = Timer.DueTick;
                do
                {
                    Next += Period;
                }
                while (Next <= Now);

                Timer.DueTick = Next;
            }
            else
            {
                Timer.Active = false;
            }

            return !WasSignaled;
        }

        internal bool RefreshWindowsTimersAndWakeWaiters()
        {
            bool WokeThread = false;

            if (WinHelper == null)
                return false;

            WinHelper.HandleManager.SnapshotHandles(WindowsTimerHandleSnapshot);
            for (int i = 0; i < WindowsTimerHandleSnapshot.Count; i++)
            {
                KeyValuePair<ulong, IHandleObject> Pair = WindowsTimerHandleSnapshot[i];
                if (Pair.Value is not WinTimer Timer)
                    continue;

                if (RefreshTimerState(Timer))
                    WokeThread |= WakeWorkerFactoryWaitersForObject(Pair.Key);
            }

            return WokeThread;
        }

        internal bool TryGetNextWindowsTimerSleepMs(out int SleepMs, int MaxSleepMs = 10)
        {
            SleepMs = 0;

            if (WinHelper == null)
                return false;

            long Now = EmulatedTickCount64;
            long BestDelta = long.MaxValue;
            bool HasWorkerFactoryWaiter = false;

            foreach (EmulatedThread Thread in Threads.Values)
            {
                if (Thread == null || Thread.State != EmulatedThreadState.Waiting || !Thread.WaitActive)
                    continue;

                WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
                if (State != null && State.WorkerFactoryWaitActive)
                {
                    HasWorkerFactoryWaiter = true;
                    break;
                }
            }

            WinHelper.HandleManager.SnapshotHandles(WindowsNextTimerHandleSnapshot);
            if (HasWorkerFactoryWaiter)
                WinHelper.HandleManager.SnapshotHandles(WindowsNextTimerPacketSnapshot);
            else
                WindowsNextTimerPacketSnapshot.Clear();

            for (int i = 0; i < WindowsNextTimerHandleSnapshot.Count; i++)
            {
                KeyValuePair<ulong, IHandleObject> Pair = WindowsNextTimerHandleSnapshot[i];
                if (Pair.Value is not WinTimer Timer)
                    continue;

                bool HasHandleWaiter = false;
                foreach (EmulatedThread Thread in Threads.Values)
                {
                    if (Thread == null || Thread.State != EmulatedThreadState.Waiting || !Thread.WaitActive)
                        continue;

                    if (Thread.WaitHandles != null && Thread.WaitHandles.Contains(Pair.Key))
                    {
                        HasHandleWaiter = true;
                        break;
                    }
                }

                bool HasWorkerFactoryTimerWaiter = false;
                if (HasWorkerFactoryWaiter)
                {
                    for (int PacketIndex = 0; PacketIndex < WindowsNextTimerPacketSnapshot.Count; PacketIndex++)
                    {
                        KeyValuePair<ulong, IHandleObject> WaitPair = WindowsNextTimerPacketSnapshot[PacketIndex];
                        if (WaitPair.Value is not WinWaitCompletionPacket Packet)
                            continue;

                        if (Packet.Associated && !Packet.QueuedCompletion && Packet.TargetObjectHandle == Pair.Key)
                        {
                            HasWorkerFactoryTimerWaiter = true;
                            break;
                        }
                    }
                }

                bool BecameSignaled = RefreshTimerState(Timer);

                if ((BecameSignaled || Timer.Signaled) && HasWorkerFactoryTimerWaiter && WakeWorkerFactoryWaitersForObject(Pair.Key))
                    return true;

                if (!HasHandleWaiter && !HasWorkerFactoryTimerWaiter)
                    continue;

                if ((BecameSignaled || Timer.Signaled) && HasHandleWaiter)
                    return true;

                if (!Timer.Active || Timer.Signaled)
                    continue;

                long Delta = Timer.DueTick - Now;
                if (Delta > 0 && Delta < BestDelta)
                    BestDelta = Delta;
            }

            if (BestDelta == long.MaxValue)
                return false;

            long Clamped = BestDelta > MaxSleepMs ? MaxSleepMs : BestDelta;
            SleepMs = (int)Clamped;
            if (SleepMs < 1)
                SleepMs = 1;

            return true;
        }

        internal bool WakeWorkerFactoryWaitersForObject(ulong TargetObjectHandle)
        {
            bool WokeThread = false;

            if (WinHelper == null)
                return false;

            WinHelper.HandleManager.SnapshotHandles(WindowsWakePacketSnapshot);
            for (int i = 0; i < WindowsWakePacketSnapshot.Count; i++)
            {
                KeyValuePair<ulong, IHandleObject> Pair = WindowsWakePacketSnapshot[i];
                if (Pair.Value is not WinWaitCompletionPacket Packet)
                    continue;

                if (!Packet.Associated || Packet.TargetObjectHandle != TargetObjectHandle)
                    continue;

                MaterializeSignaledWaitPackets(Packet.IoCompletionHandle);
            }

            WindowsWakeThreadSnapshot.Clear();
            foreach (EmulatedThread Thread in Threads.Values)
                WindowsWakeThreadSnapshot.Add(Thread);

            for (int i = 0; i < WindowsWakeThreadSnapshot.Count; i++)
            {
                EmulatedThread Thread = WindowsWakeThreadSnapshot[i];
                if (Thread == null || Thread.State != EmulatedThreadState.Waiting || !Thread.WaitActive)
                    continue;

                WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
                if (State == null || !State.WorkerFactoryWaitActive)
                    continue;

                if (!TrySatisfyThreadWait(Thread))
                    continue;

                CompleteThreadWait(Thread);
                WokeThread = true;
            }

            WindowsWakeThreadSnapshot.Clear();

            return WokeThread;
        }

        internal void MaterializeSignaledWaitPackets(ulong IoCompletionHandle)
        {
            if (WinHelper == null)
                return;

            WinIoCompletion Completion = WinHelper.HandleManager.GetObjectByHandle<WinIoCompletion>(IoCompletionHandle);
            if (Completion == null)
                return;

            WinHelper.HandleManager.SnapshotHandles(WindowsMaterializePacketSnapshot);
            for (int i = 0; i < WindowsMaterializePacketSnapshot.Count; i++)
            {
                KeyValuePair<ulong, IHandleObject> Pair = WindowsMaterializePacketSnapshot[i];
                ulong PacketHandle = Pair.Key;
                if (Pair.Value is not WinWaitCompletionPacket Packet)
                    continue;

                if (!Packet.Associated || Packet.QueuedCompletion)
                    continue;

                if (Packet.IoCompletionHandle != IoCompletionHandle)
                    continue;

                if (!TryAcquireWaitHandle(Packet.TargetObjectHandle, null, out _))
                    continue;

                Completion.Entries.Enqueue(new WinIoCompletionEntry
                {
                    KeyContext = Packet.KeyContext,
                    ApcContext = Packet.ApcContext,
                    IoStatus = Packet.IoStatus,
                    IoStatusInformation = Packet.IoStatusInformation,
                    WaitCompletionPacketHandle = PacketHandle
                });

                Packet.QueuedCompletion = true;
            }
        }

        private bool ReserveWorkerFactoryEntries(ulong WorkerFactoryHandle, uint MaxPackets, List<WinIoCompletionEntry> Reserved)
        {
            if (Reserved == null)
                return false;

            Reserved.Clear();

            if (WinHelper == null)
                return false;

            WinWorkerFactory Factory = WinHelper.HandleManager.GetObjectByHandle<WinWorkerFactory>(WorkerFactoryHandle);
            if (Factory == null)
                return false;

            WinIoCompletion Completion = WinHelper.HandleManager.GetObjectByHandle<WinIoCompletion>(Factory.IoCompletionHandle);
            if (Completion == null)
                return false;

            MaterializeSignaledWaitPackets(Factory.IoCompletionHandle);

            uint Limit = MaxPackets == 0 ? 1u : MaxPackets;
            while (Reserved.Count < Limit && Completion.Entries.Count > 0)
            {
                WinIoCompletionEntry Entry = Completion.Entries.Dequeue();
                Reserved.Add(Entry);

                if (Entry.WaitCompletionPacketHandle != 0)
                {
                    WinWaitCompletionPacket Packet = WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(Entry.WaitCompletionPacketHandle);
                    if (Packet != null)
                    {
                        Packet.Associated = false;
                        Packet.QueuedCompletion = false;
                    }
                }
            }

            return Reserved.Count > 0;
        }

        internal bool TrySatisfyThreadWait(EmulatedThread Thread)
        {
            if (Thread == null || !Thread.WaitActive)
                return false;

            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;

            WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
            if (State != null && State.WorkerFactoryWaitActive)
            {
                if (State.WorkerFactoryHandle != 0)
                {
                    WinWorkerFactory Factory = WinHelper?.HandleManager.GetObjectByHandle<WinWorkerFactory>(State.WorkerFactoryHandle);
                    if (Factory == null || Factory.Shutdown)
                        return true;

                    if (State.WorkerFactoryReservedEntries == null)
                        State.WorkerFactoryReservedEntries = new List<WinIoCompletionEntry>();

                    if (ReserveWorkerFactoryEntries(State.WorkerFactoryHandle, State.WorkerFactoryMaxPackets, State.WorkerFactoryReservedEntries))
                    {
                        Thread.WaitSatisfiedIndex = 0;
                        return true;
                    }
                }

                if (IsEmulatedDeadlineExpired(Thread.WaitDeadline))
                {
                    Thread.WaitTimedOut = true;
                    return true;
                }

                return false;
            }

            if (State != null && State.AlertByThreadIdWaitActive)
            {
                if (State.AlertByThreadIdPending)
                {
                    State.AlertByThreadIdPending = false;
                    Thread.WaitSatisfiedIndex = 0;
                    return true;
                }

                if (IsEmulatedDeadlineExpired(Thread.WaitDeadline))
                {
                    Thread.WaitTimedOut = true;
                    return true;
                }

                return false;
            }

            if (State != null && State.GetMessageWaitActive)
            {
                if (Win32kHelper.TryGetMessage(this, State.GetMessageHwndFilter, State.GetMessageMinMessage, State.GetMessageMaxMessage, true, out Win32kMessage Message))
                {
                    Win32kHelper.WriteMessage(this, State.GetMessageMessagePtr, Message);
                    State.GetMessageWaitActive = false;
                    Thread.WaitSatisfiedIndex = Message.Message == Win32kHelper.WM_QUIT ? 0 : 1;
                    State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                    return true;
                }

                return false;
            }

            if (State != null && State.MsgWaitActive)
            {
                bool MessageReady = Win32kHelper.HasQueuedInputEvent(this, State.MsgWaitMask);
                bool HasHandles = Thread.WaitHandles != null && Thread.WaitHandles.Count > 0;

                if (Thread.WaitAll)
                {
                    if (HasHandles)
                    {
                        for (int i = 0; i < Thread.WaitHandles.Count; i++)
                        {
                            if (!CanSatisfyWaitHandle(Thread.WaitHandles[i], Thread))
                                goto CheckTimeout;
                        }
                    }

                    if (!MessageReady)
                        goto CheckTimeout;

                    NTSTATUS AllWaitStatus = NTSTATUS.STATUS_SUCCESS;
                    if (HasHandles)
                    {
                        for (int i = 0; i < Thread.WaitHandles.Count; i++)
                        {
                            ulong Handle = Thread.WaitHandles[i];
                            bool AlreadyAcquired = false;
                            for (int j = 0; j < i; j++)
                            {
                                if (Thread.WaitHandles[j] == Handle)
                                {
                                    AlreadyAcquired = true;
                                    break;
                                }
                            }

                            if (AlreadyAcquired)
                                continue;

                            if (!TryAcquireWaitHandle(Handle, Thread, out NTSTATUS AcquiredStatus))
                                goto CheckTimeout;

                            if (AcquiredStatus == NTSTATUS.STATUS_ABANDONED_WAIT_0 && AllWaitStatus == NTSTATUS.STATUS_SUCCESS)
                                AllWaitStatus = (NTSTATUS)((uint)NTSTATUS.STATUS_ABANDONED_WAIT_0 + (uint)i);
                        }
                    }

                    Thread.WaitSatisfiedIndex = 0;
                    State.WaitStatus = AllWaitStatus;
                    return true;
                }

                if (HasHandles)
                {
                    for (int i = 0; i < Thread.WaitHandles.Count; i++)
                    {
                        if (!TryAcquireWaitHandle(Thread.WaitHandles[i], Thread, out NTSTATUS AcquiredStatus))
                            continue;

                        Thread.WaitSatisfiedIndex = i;
                        State.WaitStatus = AcquiredStatus == NTSTATUS.STATUS_ABANDONED_WAIT_0
                            ? (NTSTATUS)((uint)NTSTATUS.STATUS_ABANDONED_WAIT_0 + (uint)i)
                            : (NTSTATUS)(uint)i;
                        return true;
                    }
                }

                if (MessageReady)
                {
                    Thread.WaitSatisfiedIndex = Thread.WaitHandles?.Count ?? 0;
                    State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                    return true;
                }

                goto CheckTimeout;
            }

            if (Thread.WaitHandles != null && Thread.WaitHandles.Count > 0)
            {
                if (Thread.WaitAll)
                {
                    for (int i = 0; i < Thread.WaitHandles.Count; i++)
                    {
                        if (!CanSatisfyWaitHandle(Thread.WaitHandles[i], Thread))
                            goto CheckTimeout;
                    }

                    NTSTATUS WaitStatus = NTSTATUS.STATUS_SUCCESS;
                    for (int i = 0; i < Thread.WaitHandles.Count; i++)
                    {
                        ulong Handle = Thread.WaitHandles[i];
                        bool AlreadyAcquired = false;
                        for (int j = 0; j < i; j++)
                        {
                            if (Thread.WaitHandles[j] == Handle)
                            {
                                AlreadyAcquired = true;
                                break;
                            }
                        }

                        if (AlreadyAcquired)
                            continue;

                        if (!TryAcquireWaitHandle(Handle, Thread, out NTSTATUS AcquiredStatus))
                            goto CheckTimeout;

                        if (AcquiredStatus == NTSTATUS.STATUS_ABANDONED_WAIT_0 && WaitStatus == NTSTATUS.STATUS_SUCCESS)
                            WaitStatus = (NTSTATUS)((uint)NTSTATUS.STATUS_ABANDONED_WAIT_0 + (uint)i);
                    }

                    Thread.WaitSatisfiedIndex = 0;
                    if (State != null)
                        State.WaitStatus = WaitStatus;
                    return true;
                }

                for (int i = 0; i < Thread.WaitHandles.Count; i++)
                {
                    if (!TryAcquireWaitHandle(Thread.WaitHandles[i], Thread, out NTSTATUS AcquiredStatus))
                        continue;

                    Thread.WaitSatisfiedIndex = i;
                    if (State != null)
                        State.WaitStatus = AcquiredStatus == NTSTATUS.STATUS_ABANDONED_WAIT_0
                            ? (NTSTATUS)((uint)NTSTATUS.STATUS_ABANDONED_WAIT_0 + (uint)i)
                            : (NTSTATUS)(uint)i;
                    return true;
                }
            }

        CheckTimeout:
            if (IsEmulatedDeadlineExpired(Thread.WaitDeadline))
            {
                Thread.WaitTimedOut = true;
                return true;
            }

            return false;
        }

        internal bool HasActiveGetMessageWait()
        {
            foreach (EmulatedThread Thread in Threads.Values)
            {
                if (Thread == null || Thread.State != EmulatedThreadState.Waiting || !Thread.WaitActive)
                    continue;

                WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
                if (State != null && State.GetMessageWaitActive)
                    return true;
            }

            return false;
        }

        public ulong TranslateVirtualAddress(ulong OriginalVA, string ModuleName)
        {
            WinModule ProcessModule = WinHelper?.WinModules.FirstOrDefault(m => m.Name.Equals(ModuleName, StringComparison.OrdinalIgnoreCase));
            if (ProcessModule != null)
            {
                ulong OriginalBase = ProcessModule.OriginalBase;
                ulong MappedBase = ProcessModule.MappedBase;
                ulong ImageSize = ProcessModule.SizeOfImage;

                if (OriginalVA >= OriginalBase && OriginalVA < OriginalBase + ImageSize)
                {
                    ulong Offset = OriginalVA - OriginalBase;
                    return MappedBase + Offset;
                }
            }

            return 0;
        }

        public ulong TranslateVirtualAddress(ulong OriginalVA, WinModule Module)
        {
            return Module.MappedBase + (OriginalVA - Module.OriginalBase);
        }

        internal void ApplyPERelocations(WinModule Module, BinaryFile Binary)
        {
            ulong PreferredBase = Binary.PE.ImageBase;
            ulong MappedBase = Module.MappedBase;

            long RelocationDelta = (long)(MappedBase - PreferredBase);
            if (RelocationDelta == 0)
                return;

            var RelocationDirectory = Binary.Architecture == BinaryArchitecture.x64 ? Binary.PE.OptionalHeader64.DataDirectory[5] : Binary.PE.OptionalHeader32.DataDirectory[5];
            if (RelocationDirectory.VirtualAddress == 0 || RelocationDirectory.Size == 0)
                return;

            ulong RelocationTableAddress = MappedBase + RelocationDirectory.VirtualAddress;
            ulong RelocationTableEnd = RelocationTableAddress + RelocationDirectory.Size;

            while (RelocationTableAddress < RelocationTableEnd)
            {
                uint PageRva = ReadMemoryUInt(RelocationTableAddress);
                uint BlockSize = ReadMemoryUInt(RelocationTableAddress + 4);
                RelocationTableAddress += 8;

                int EntryCount = ((int)BlockSize - 8) / 2;
                for (int Index = 0; Index < EntryCount; Index++)
                {
                    ushort Entry = BitConverter.ToUInt16(ReadMemory(RelocationTableAddress, 2));
                    RelocationTableAddress += 2;

                    ushort RelocationType = (ushort)(Entry >> 12);
                    ushort Offset = (ushort)(Entry & 0x0FFF);
                    ulong PatchAddress = MappedBase + PageRva + Offset;

                    switch (RelocationType)
                    {
                        case 0:
                            break;

                        case 3:
                            uint Original32 = ReadMemoryUInt(PatchAddress);
                            uint Patched32 = unchecked((uint)((long)Original32 + RelocationDelta));
                            _emulator.WriteMemory(PatchAddress, Patched32);
                            break;

                        case 10:
                            ulong Original64 = ReadMemoryULong(PatchAddress);
                            ulong Patched64 = unchecked((ulong)((long)Original64 + RelocationDelta));
                            _emulator.WriteMemory(PatchAddress, Patched64);
                            break;

                        default:
                            TriggerEventMessage($"[-] Unsupported relocation type {RelocationType} in {Module.Name}", LogFlags.Issues);
                            break;
                    }
                }
            }
        }

        public BinaryFile LoadBinary(string Path)
        {
            return new BinaryFile(Path, true);
        }

        private static bool CanMergeProtectedWinRegions(MemoryRegion Left, MemoryRegion Right)
        {
            return GetRangeEnd(Left.BaseAddress, Left.Size) == Right.BaseAddress &&
                   Left.AllocationBase == Right.AllocationBase &&
                   Left.AllocationProtect == Right.AllocationProtect &&
                   Left.Protect == Right.Protect &&
                   Left.IsReserved == Right.IsReserved &&
                   Left.IsCommitted == Right.IsCommitted &&
                   Left.IsReset == Right.IsReset &&
                   Left.Protections == Right.Protections &&
                   Left.InitialProtections == Right.InitialProtections &&
                   Left.SpecialProtections == Right.SpecialProtections &&
                   Left.Flags == Right.Flags;
        }

        private static List<MemoryRegion> MergeProtectedWinRegions(List<MemoryRegion> Regions)
        {
            Regions.Sort((Left, Right) => Left.BaseAddress.CompareTo(Right.BaseAddress));

            List<MemoryRegion> Merged = new List<MemoryRegion>(Regions.Count);
            foreach (MemoryRegion Region in Regions)
            {
                if (Merged.Count == 0)
                {
                    Merged.Add(Region);
                    continue;
                }

                MemoryRegion Last = Merged[Merged.Count - 1];
                if (CanMergeProtectedWinRegions(Last, Region))
                {
                    Last.Size += Region.Size;
                    Last.RequestedSize = Last.Size;
                    Merged[Merged.Count - 1] = Last;
                    continue;
                }

                Merged.Add(Region);
            }

            return Merged;
        }

        private static bool HasGuardProtection(SpecialProtections Protections)
        {
            return (Protections & SpecialProtections.Guard) != 0;
        }

        private static MemoryProtection GetGuardedHostProtection(MemoryProtection Protection, SpecialProtections Special)
        {
            return HasGuardProtection(Special) ? MemoryProtection.None : Protection;
        }

        private static ExceptionType MapGuardAccessType(BackendMemoryAccessType Type)
        {
            switch (Type)
            {
                case BackendMemoryAccessType.WriteUnmapped:
                case BackendMemoryAccessType.WriteProtected:
                    return ExceptionType.Write;

                case BackendMemoryAccessType.FetchUnmapped:
                case BackendMemoryAccessType.FetchProtected:
                    return ExceptionType.Execute;

                default:
                    return ExceptionType.Read;
            }
        }

        private static bool IsGuardFaultType(BackendMemoryAccessType Type)
        {
            switch (Type)
            {
                case BackendMemoryAccessType.ReadProtected:
                case BackendMemoryAccessType.WriteProtected:
                case BackendMemoryAccessType.FetchProtected:
                    return true;

                default:
                    return false;
            }
        }

        internal bool TryHandleGuardPageViolation(BackendMemoryAccessType Type, ulong Address)
        {
            WindowsGuest GuestEnvironment = WindowsGuest;
            if (GuestEnvironment == null || Guest == null || Guest.Os != GuestOsKind.Windows || !IsGuardFaultType(Type))
                return false;

            if (!TryFindMemoryRegion(Address, out MemoryRegion GuardedRegion) || !HasGuardProtection(GuardedRegion.SpecialProtections))
                return false;

            ulong PageBase = Address & ~(PageSize - 1);
            if (!_emulator.SetMemoryProtection(PageBase, PageSize, GuardedRegion.Protections))
                return false;

            ulong PageEnd = PageBase + PageSize;
            List<MemoryRegion> NewRegions = new List<MemoryRegion>(_memory.Count + 2);

            foreach (MemoryRegion Region in EnumerateMemoryRegionsByBase())
            {
                ulong RegionStart = Region.BaseAddress;
                ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);

                if (RegionEnd <= PageBase || RegionStart >= PageEnd)
                {
                    NewRegions.Add(Region);
                    continue;
                }

                ulong MiddleStart = Math.Max(RegionStart, PageBase);
                ulong MiddleEnd = Math.Min(RegionEnd, PageEnd);

                if (RegionStart < MiddleStart)
                {
                    MemoryRegion Left = Region;
                    Left.BaseAddress = RegionStart;
                    Left.Size = MiddleStart - RegionStart;
                    Left.RequestedSize = Left.Size;
                    NewRegions.Add(Left);
                }

                if (MiddleEnd > MiddleStart)
                {
                    MemoryRegion Middle = Region;
                    Middle.BaseAddress = MiddleStart;
                    Middle.Size = MiddleEnd - MiddleStart;
                    Middle.RequestedSize = Middle.Size;
                    Middle.SpecialProtections = SpecialProtections.None;
                    Middle.Protect &= ~0x100U;
                    NewRegions.Add(Middle);
                }

                if (MiddleEnd < RegionEnd)
                {
                    MemoryRegion Right = Region;
                    Right.BaseAddress = MiddleEnd;
                    Right.Size = RegionEnd - MiddleEnd;
                    Right.RequestedSize = Right.Size;
                    NewRegions.Add(Right);
                }
            }

            ReplaceMemoryRegions(MergeProtectedWinRegions(NewRegions));

            ExceptionInformation Info = new ExceptionInformation
            {
                Address = Address,
                Type = MapGuardAccessType(Type),
                Status = NTSTATUS.STATUS_GUARD_PAGE_VIOLATION
            };

            GuestEnvironment.QueueUserModeException(this, NTSTATUS.STATUS_GUARD_PAGE_VIOLATION, Info);
            return true;
        }

        private bool ProtectWinMemoryRange(ulong Address, ulong Size, MemoryProtection Protection, uint WinProtect = 0)
        {
            if (Size == 0)
                return true;

            ulong AlignedBase = Address & ~0xFFFUL;
            ulong AlignedEnd = AlignUp(GetRangeEnd(Address, Size), PageSize);
            ulong AlignedSize = AlignedEnd - AlignedBase;
            if (AlignedSize == 0)
                return true;

            if (!_emulator.SetMemoryProtection(AlignedBase, AlignedSize, Protection))
                return false;

            uint EffectiveWinProtect = WinProtect != 0 ? WinProtect : (WinHelper != null ? (uint)WinHelper.ConvertInternalToWinProtect(Protection) : 0);
            List<MemoryRegion> NewRegions = new List<MemoryRegion>();

            foreach (MemoryRegion Region in EnumerateMemoryRegionsByBase())
            {
                ulong RegionStart = Region.BaseAddress;
                ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);

                if (RegionEnd <= AlignedBase || RegionStart >= AlignedEnd)
                {
                    NewRegions.Add(Region);
                    continue;
                }

                if (RegionStart < AlignedBase)
                {
                    MemoryRegion Left = Region;
                    Left.BaseAddress = RegionStart;
                    Left.Size = AlignedBase - RegionStart;
                    Left.RequestedSize = Left.Size;
                    NewRegions.Add(Left);
                }

                ulong MiddleStart = Math.Max(RegionStart, AlignedBase);
                ulong MiddleEnd = Math.Min(RegionEnd, AlignedEnd);
                if (MiddleEnd > MiddleStart)
                {
                    MemoryRegion Middle = Region;
                    Middle.BaseAddress = MiddleStart;
                    Middle.Size = MiddleEnd - MiddleStart;
                    Middle.RequestedSize = Middle.Size;
                    Middle.Protections = Protection;
                    Middle.Protect = EffectiveWinProtect;
                    Middle.SpecialProtections = SpecialProtections.None;
                    NewRegions.Add(Middle);
                }

                if (RegionEnd > AlignedEnd)
                {
                    MemoryRegion Right = Region;
                    Right.BaseAddress = AlignedEnd;
                    Right.Size = RegionEnd - AlignedEnd;
                    Right.RequestedSize = Right.Size;
                    NewRegions.Add(Right);
                }
            }

            ReplaceMemoryRegions(MergeProtectedWinRegions(NewRegions));
            return true;
        }

        /// <summary>
        /// Applies multiple page-protection changes while rebuilding memory-region metadata once.
        /// </summary>
        private bool ApplyWinProtectionRanges(List<(ulong Address, ulong Size, MemoryProtection Protection, uint WinProtect)> Ranges)
        {
            if (Ranges.Count == 0)
                return true;

            List<(ulong BaseAddress, ulong EndAddress, MemoryProtection Protection, uint WinProtect)> AlignedRanges = new List<(ulong BaseAddress, ulong EndAddress, MemoryProtection Protection, uint WinProtect)>(Ranges.Count);
            foreach (var Range in Ranges)
            {
                if (Range.Size == 0)
                    continue;

                ulong AlignedBase = Range.Address & ~0xFFFUL;
                ulong AlignedEnd = AlignUp(GetRangeEnd(Range.Address, Range.Size), PageSize);
                if (AlignedEnd <= AlignedBase)
                    continue;

                if (!_emulator.SetMemoryProtection(AlignedBase, AlignedEnd - AlignedBase, Range.Protection))
                    continue;

                uint EffectiveWinProtect = Range.WinProtect != 0 ? Range.WinProtect : (WinHelper != null ? (uint)WinHelper.ConvertInternalToWinProtect(Range.Protection) : 0);
                AlignedRanges.Add((AlignedBase, AlignedEnd, Range.Protection, EffectiveWinProtect));
            }

            if (AlignedRanges.Count == 0)
                return true;

            List<MemoryRegion> Regions = EnumerateMemoryRegionsByBase().ToList();
            foreach (var Range in AlignedRanges)
            {
                List<MemoryRegion> NewRegions = new List<MemoryRegion>(Regions.Count + 2);

                foreach (MemoryRegion Region in Regions)
                {
                    ulong RegionStart = Region.BaseAddress;
                    ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);

                    if (RegionEnd <= Range.BaseAddress || RegionStart >= Range.EndAddress)
                    {
                        NewRegions.Add(Region);
                        continue;
                    }

                    if (RegionStart < Range.BaseAddress)
                    {
                        MemoryRegion Left = Region;
                        Left.BaseAddress = RegionStart;
                        Left.Size = Range.BaseAddress - RegionStart;
                        Left.RequestedSize = Left.Size;
                        NewRegions.Add(Left);
                    }

                    ulong MiddleStart = Math.Max(RegionStart, Range.BaseAddress);
                    ulong MiddleEnd = Math.Min(RegionEnd, Range.EndAddress);
                    if (MiddleEnd > MiddleStart)
                    {
                        MemoryRegion Middle = Region;
                        Middle.BaseAddress = MiddleStart;
                        Middle.Size = MiddleEnd - MiddleStart;
                        Middle.RequestedSize = Middle.Size;
                        Middle.Protections = Range.Protection;
                        Middle.Protect = Range.WinProtect;
                        Middle.SpecialProtections = SpecialProtections.None;
                        NewRegions.Add(Middle);
                    }

                    if (RegionEnd > Range.EndAddress)
                    {
                        MemoryRegion Right = Region;
                        Right.BaseAddress = Range.EndAddress;
                        Right.Size = RegionEnd - Range.EndAddress;
                        Right.RequestedSize = Right.Size;
                        NewRegions.Add(Right);
                    }
                }

                Regions = NewRegions;
            }

            ReplaceMemoryRegions(MergeProtectedWinRegions(Regions));
            return true;
        }

        private const int PeImageCopyChunkSize = 1024 * 1024;

        private static int GetPeHeaderCopySize(BinaryFile Library)
        {
            ulong HeaderSize = Library.PE.SizeOfHeaders;
            if (HeaderSize > (ulong)Library.BinarySize)
                HeaderSize = (ulong)Library.BinarySize;

            return HeaderSize > int.MaxValue ? int.MaxValue : (int)HeaderSize;
        }

        private static ulong GetPeSectionCopySize(BinaryFile Library, PortableBinarySection Section, ulong SectionSize)
        {
            ulong RawOffset = Section.RawOffset;
            if (Section.RawSize == 0 || RawOffset >= (ulong)Library.BinarySize)
                return 0;

            ulong MaxReadable = (ulong)Library.BinarySize - RawOffset;
            return Math.Min(Math.Min((ulong)Section.RawSize, MaxReadable), SectionSize);
        }

        private static FileStream? OpenBinaryReadStream(BinaryFile Library)
        {
            if (string.IsNullOrEmpty(Library.Location) || !File.Exists(Library.Location))
                return null;

            try
            {
                return new FileStream(Library.Location, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, PeImageCopyChunkSize, FileOptions.SequentialScan);
            }
            catch
            {
                return null;
            }
        }

        private bool WritePeFileRange(BinaryFile Library, FileStream? Stream, ulong Destination, long RawOffset, ulong Size)
        {
            if (Size == 0)
                return true;

            if (RawOffset < 0 || RawOffset >= Library.BinarySize)
                return true;

            ulong MaxReadable = (ulong)(Library.BinarySize - RawOffset);
            ulong BytesToWrite = Math.Min(Size, MaxReadable);
            if (BytesToWrite == 0)
                return true;

            if (Stream == null)
            {
                ReadOnlySpan<byte> ImageData = Library.GetBinaryData();
                int Offset = (int)RawOffset;
                int Count = (int)Math.Min(BytesToWrite, (ulong)(ImageData.Length - Offset));
                return Count == 0 || _emulator.WriteMemory(Destination, ImageData.Slice(Offset, Count));
            }

            byte[] Buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min((ulong)PeImageCopyChunkSize, BytesToWrite));
            try
            {
                Stream.Position = RawOffset;
                ulong Written = 0;

                while (Written < BytesToWrite)
                {
                    int Wanted = (int)Math.Min((ulong)Buffer.Length, BytesToWrite - Written);
                    int Read = Stream.Read(Buffer, 0, Wanted);
                    if (Read <= 0)
                        return false;

                    if (!_emulator.WriteMemory(Destination + Written, Buffer.AsSpan(0, Read)))
                        return false;

                    Written += (uint)Read;
                }

                return true;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }
        }

        /// <summary>
        /// Writes PE headers and section raw data into an already mapped image without forcing a full managed image copy.
        /// </summary>
        /// <param name="Library">PE image metadata and backing data.</param>
        /// <param name="BaseAddress">Mapped image base.</param>
        /// <param name="ImageSize">Mapped image size.</param>
        /// <param name="Module">Module metadata to populate with mapped sections.</param>
        /// <returns>True if the image bytes were written successfully; otherwise false.</returns>
        internal bool WritePeImageHeadersAndSections(BinaryFile Library, ulong BaseAddress, ulong ImageSize, WinModule Module)
        {
            using FileStream? Stream = OpenBinaryReadStream(Library);

            int HeaderSize = GetPeHeaderCopySize(Library);
            if (HeaderSize != 0 && !WritePeFileRange(Library, Stream, BaseAddress, 0, (ulong)HeaderSize))
                return false;

            foreach (PortableBinarySection Section in Library.PE.Sections)
            {
                if (Section.VirtualAddress == 0)
                    continue;

                ulong VirtualSpan = Section.VirtualSize != 0 ? Section.VirtualSize : Section.RawSize;
                if (VirtualSpan == 0 || (ulong)Section.VirtualAddress >= ImageSize)
                    continue;

                ulong SectionSize = AlignToPageSize(VirtualSpan);
                ulong MaxSectionSize = ImageSize - Section.VirtualAddress;
                if (SectionSize > MaxSectionSize)
                    SectionSize = MaxSectionSize;

                ulong SectionAddress = BaseAddress + (ulong)Section.VirtualAddress;
                ulong BytesToWrite = GetPeSectionCopySize(Library, Section, SectionSize);

                bool Ok = BytesToWrite == 0 || WritePeFileRange(Library, Stream, SectionAddress, Section.RawOffset, BytesToWrite);
                if (Ok)
                    Module.Sections.TryAdd(SectionAddress, Section);
            }

            return true;
        }

        /// <summary>
        /// Maps a PE image by mapping only its headers and PE sections.
        /// </summary>
        /// <param name="Library">PE image to map.</param>
        /// <param name="BaseAddress">Chosen image base.</param>
        /// <param name="Module">Module metadata to populate with section locations.</param>
        /// <returns>The mapped image base, or zero on failure.</returns>
        internal ulong MapPeImageBySections(BinaryFile Library, ulong BaseAddress, WinModule Module)
        {
            ulong ImageSize = AlignToPageSize(Library.PE.SizeOfImage != 0 ? Library.PE.SizeOfImage : (uint)Library.BinarySize);
            int HeaderSize = GetPeHeaderCopySize(Library);
            ulong HeaderMapSize = HeaderSize != 0 ? AlignToPageSize((ulong)HeaderSize) : 0;
            ulong MappedBase = HeaderMapSize != 0
                ? MapWinMemoryRegion(BaseAddress, HeaderMapSize, MemoryProtection.ReadWrite, SpecialProtections.None, AllocationType.Image, BaseAddress)
                : BaseAddress;
            if (MappedBase == 0)
                return 0;

            using FileStream? Stream = OpenBinaryReadStream(Library);

            if (HeaderSize != 0 && !WritePeFileRange(Library, Stream, MappedBase, 0, (ulong)HeaderSize))
                return 0;

            foreach (PortableBinarySection Section in Library.PE.Sections)
            {
                if (Section.VirtualAddress == 0)
                    continue;

                ulong VirtualSpan = Section.VirtualSize != 0 ? Section.VirtualSize : Section.RawSize;
                if (VirtualSpan == 0 || (ulong)Section.VirtualAddress >= ImageSize)
                    continue;

                ulong SectionSize = AlignToPageSize(VirtualSpan);
                ulong MaxSectionSize = ImageSize - Section.VirtualAddress;
                if (SectionSize > MaxSectionSize)
                    SectionSize = MaxSectionSize;

                ulong SectionAddress = BaseAddress + (ulong)Section.VirtualAddress;

                if (MapWinMemoryRegion(SectionAddress, SectionSize, GetMemoryProtection(Section.Characteristics), SpecialProtections.None, AllocationType.Image, BaseAddress) == 0)
                    continue;

                ulong BytesToWrite = GetPeSectionCopySize(Library, Section, SectionSize);
                bool Ok = BytesToWrite == 0 || WritePeFileRange(Library, Stream, SectionAddress, Section.RawOffset, BytesToWrite);
                if (Ok)
                    Module.Sections.TryAdd(SectionAddress, Section);
            }

            return MappedBase;
        }

        internal bool ApplyPeImageProtections(BinaryFile Library, WinModule Module, bool IsSectionMapped = false)
        {
            List<(ulong Address, ulong Size, MemoryProtection Protection, uint WinProtect)> Ranges = new List<(ulong Address, ulong Size, MemoryProtection Protection, uint WinProtect)>();

            if (!IsSectionMapped)
            {
                Ranges.Add((Module.MappedBase, Module.SizeOfImage, MemoryProtection.Read, 0));
            }
            else
            {
                ulong HeaderSize = Library.PE.SizeOfHeaders;
                if (HeaderSize > Module.SizeOfImage)
                    HeaderSize = Module.SizeOfImage;

                if (HeaderSize != 0)
                    Ranges.Add((Module.MappedBase, HeaderSize, MemoryProtection.Read, 0));
            }

            foreach (PortableBinarySection Section in Library.PE.Sections)
            {
                if (Section.VirtualAddress == 0)
                    continue;

                ulong VirtualSpan = Section.VirtualSize != 0 ? Section.VirtualSize : Section.RawSize;
                if (VirtualSpan == 0 || (ulong)Section.VirtualAddress >= Module.SizeOfImage)
                    continue;

                ulong SectionSize = AlignToPageSize(VirtualSpan);
                ulong MaxSectionSize = Module.SizeOfImage - Section.VirtualAddress;
                if (SectionSize > MaxSectionSize)
                    SectionSize = MaxSectionSize;

                Ranges.Add((Module.MappedBase + Section.VirtualAddress, SectionSize, GetMemoryProtection(Section.Characteristics), 0));
            }

            return ApplyWinProtectionRanges(Ranges);
        }

        public WinModule LoadWinLibrary(BinaryFile Library, bool TriggerMessage, bool AddToModuleList = true, ulong RequestedBase = 0, bool MapBySections = false)
        {
            if (Library.FileFormat != BinaryFormat.PE || Library.Architecture != _binary.Architecture)
                throw new InvalidOperationException("Emulator tried to load a non-valid PE library.");

            ulong ImageSize = AlignToPageSize(Library.PE.SizeOfImage != 0 ? Library.PE.SizeOfImage : (uint)Library.BinarySize);
            ulong PreferredBase = Library.PE.ImageBase;
            ulong BaseAddress = 0;

            if (RequestedBase != 0)
            {
                if (IsRegionMapped(RequestedBase, ImageSize))
                    return null;

                BaseAddress = RequestedBase;
            }
            else if (PreferredBase != 0 && !IsRegionMapped(PreferredBase, ImageSize))
                BaseAddress = PreferredBase;
            else
                BaseAddress = GetSuitableBaseAddress(ImageSize);

            if (BaseAddress == 0)
                return null;

            WinModule Module = new WinModule();
            if (MapBySections)
            {
                BaseAddress = MapPeImageBySections(Library, BaseAddress, Module);
                if (BaseAddress == 0)
                    return null;
            }
            else
            {
                BaseAddress = MapWinMemoryRegion(BaseAddress, ImageSize, MemoryProtection.ReadWrite, SpecialProtections.None, AllocationType.Image, BaseAddress);
                if (BaseAddress == 0)
                    return null;

                if (!WritePeImageHeadersAndSections(Library, BaseAddress, ImageSize, Module))
                    return null;
            }

            if (!string.IsNullOrEmpty(Library.Location) && File.Exists(Library.Location))
            {
                Module.Name = Path.GetFileName(Library.Location);
                Module.Path = Library.Location;
            }

            Module.OriginalBase = Library.PE.ImageBase;
            Module.MappedBase = BaseAddress;
            Module.SizeOfImage = ImageSize;
            Module.EntryPoint = Module.MappedBase + Library.EntryPoint;
            Module.Architecture = Library.Architecture;

            foreach (BinaryFunction Export in Library.ExportFunctions)
            {
                if (!Module.Exports.TryGetValue(Export.Address, out _))
                    Module.Exports.Add(Export.Address, Export.FunctionName);

                if (!string.IsNullOrEmpty(Export.FunctionName))
                    Module.ExportsByName[Export.FunctionName] = Export.Address;
            }

            ApplyPERelocations(Module, Library);
            if (!MapBySections && !ApplyPeImageProtections(Library, Module))
                return null;

            WinHelper.RegisterMappedImageView(Module, !AddToModuleList);

            if (AddToModuleList)
                WinHelper.AddModule(Module, TriggerMessage);

            Library.DisposeBinaryData();
            Library.Dispose();
            return Module;
        }

        public bool ReserveMemory(ulong BaseAddress, ulong Size, uint Protect)
        {
            Size = AlignUp(Size, PageSize);

            if (IsRegionInUse(BaseAddress, Size))
                return false;

            if (_freedmemory.Count > 0)
            {
                ulong Start = BaseAddress;
                ulong End = BaseAddress + Size;

                for (int Index = 0; Index < _freedmemory.Count; Index++)
                {
                    MemoryRegion Freed = _freedmemory[Index];
                    ulong FreedStart = Freed.BaseAddress;
                    ulong FreedEnd = Freed.BaseAddress + Freed.Size;

                    if (End <= FreedStart || Start >= FreedEnd)
                        continue;

                    if (Start <= FreedStart && End >= FreedEnd)
                    {
                        _freedmemory.RemoveAt(Index);
                        Index--;
                        continue;
                    }

                    if (Start <= FreedStart && End < FreedEnd)
                    {
                        Freed.BaseAddress = End;
                        Freed.Size = FreedEnd - End;
                        _freedmemory[Index] = Freed;
                        continue;
                    }

                    if (Start > FreedStart && End >= FreedEnd)
                    {
                        Freed.Size = Start - FreedStart;
                        _freedmemory[Index] = Freed;
                        continue;
                    }

                    if (Start > FreedStart && End < FreedEnd)
                    {
                        ulong LeftSize = Start - FreedStart;
                        ulong RightStart = End;
                        ulong RightSize = FreedEnd - End;

                        Freed.Size = LeftSize;
                        _freedmemory[Index] = Freed;
                        _freedmemory.Insert(Index + 1, new MemoryRegion
                        {
                            BaseAddress = RightStart,
                            Size = RightSize,
                            RequestedSize = RightSize
                        });
                        Index++;
                    }
                }
            }

            if (WinHelper == null)
                return false;

            MemoryProtection AllocationProt = WinHelper.ConvertWinProtectToInternal(Protect);
            AddMemoryRegion(new MemoryRegion
            {
                BaseAddress = BaseAddress,
                Size = Size,
                RequestedSize = Size,
                AllocationBase = BaseAddress,
                AllocationProtect = Protect,
                Protect = Protect,
                IsReserved = true,
                IsCommitted = false,
                InitialProtections = AllocationProt,
                Protections = MemoryProtection.None,
                SpecialProtections = SpecialProtections.None,
                Flags = AllocationType.Reserved
            });

            return true;
        }

        public bool CommitMemory(ulong BaseAddress, ulong Size, uint Protect)
        {
            Size = AlignUp(Size, PageSize);
            if (IsRegionCommitted(BaseAddress, Size))
                return true;

            if (!TryFindMemoryRegion(BaseAddress, out MemoryRegion Region) ||
                !Region.IsReserved ||
                BaseAddress + Size > Region.BaseAddress + Region.Size ||
                WinHelper == null)
                return false;

            MemoryProtection NewProt = WinHelper.ConvertWinProtectToInternal(Protect);
            SpecialProtections Special = (Protect & 0x100) != 0 ? SpecialProtections.Guard : SpecialProtections.None;
            if (!_emulator.MapMemory(BaseAddress, Size, GetGuardedHostProtection(NewProt, Special)))
                return false;

            MemoryProtection AllocationProt = WinHelper.ConvertWinProtectToInternal(Region.AllocationProtect);

            RemoveMemoryRegion(Region);

            ulong Before = BaseAddress - Region.BaseAddress;
            ulong After = (Region.BaseAddress + Region.Size) - (BaseAddress + Size);

            if (Before > 0)
            {
                AddMemoryRegion(new MemoryRegion
                {
                    BaseAddress = Region.BaseAddress,
                    Size = Before,
                    RequestedSize = Before,
                    AllocationBase = Region.AllocationBase,
                    AllocationProtect = Region.AllocationProtect,
                    Protect = Region.AllocationProtect,
                    IsReserved = true,
                    IsCommitted = false,
                    IsReset = Region.IsReset,
                    InitialProtections = AllocationProt,
                    Protections = MemoryProtection.None,
                    SpecialProtections = SpecialProtections.None,
                    Flags = AllocationType.Reserved
                });
            }

            AddMemoryRegion(new MemoryRegion
            {
                BaseAddress = BaseAddress,
                Size = Size,
                RequestedSize = Size,
                AllocationBase = Region.AllocationBase,
                AllocationProtect = Region.AllocationProtect,
                Protect = Protect,
                IsReserved = true,
                IsCommitted = true,
                IsReset = Region.IsReset,
                InitialProtections = AllocationProt,
                Protections = NewProt,
                SpecialProtections = Special,
                Flags = AllocationType.Commited
            });

            if (After > 0)
            {
                AddMemoryRegion(new MemoryRegion
                {
                    BaseAddress = BaseAddress + Size,
                    Size = After,
                    RequestedSize = After,
                    AllocationBase = Region.AllocationBase,
                    AllocationProtect = Region.AllocationProtect,
                    Protect = Region.AllocationProtect,
                    IsReserved = true,
                    IsCommitted = false,
                    IsReset = Region.IsReset,
                    InitialProtections = AllocationProt,
                    Protections = MemoryProtection.None,
                    SpecialProtections = SpecialProtections.None,
                    Flags = AllocationType.Reserved
                });
            }

            return true;
        }

        private static bool CanMergeWindowsMemoryRegions(MemoryRegion Left, MemoryRegion Right)
        {
            return GetRangeEnd(Left.BaseAddress, Left.Size) == Right.BaseAddress &&
                   Left.AllocationBase == Right.AllocationBase &&
                   Left.AllocationProtect == Right.AllocationProtect &&
                   Left.Protect == Right.Protect &&
                   Left.IsReserved == Right.IsReserved &&
                   Left.IsCommitted == Right.IsCommitted &&
                   Left.IsReset == Right.IsReset &&
                   Left.InitialProtections == Right.InitialProtections &&
                   Left.Protections == Right.Protections &&
                   Left.SpecialProtections == Right.SpecialProtections &&
                   Left.Flags == Right.Flags;
        }

        public bool DecommitMemory(ulong BaseAddress, ulong Size)
        {
            if (Size == 0)
                return false;

            ulong Start = BaseAddress & ~0xFFFUL;
            ulong End = AlignUp(BaseAddress + Size, PageSize);

            if (!TryFindMemoryRegion(Start, out MemoryRegion Anchor) || !Anchor.IsReserved || WinHelper == null)
                return false;

            ulong AllocationBase = Anchor.AllocationBase;
            var Regions = EnumerateMemoryRegionsByBase().ToList();
            List<MemoryRegion> NewRegions = new List<MemoryRegion>(Regions.Count + 4);

            foreach (var Region in Regions)
            {
                if (!Region.IsReserved || Region.AllocationBase != AllocationBase)
                {
                    NewRegions.Add(Region);
                    continue;
                }

                ulong RegionStart = Region.BaseAddress;
                ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);
                if (RegionEnd <= Start || RegionStart >= End)
                {
                    NewRegions.Add(Region);
                    continue;
                }

                ulong OverlapStart = Math.Max(RegionStart, Start);
                ulong OverlapEnd = Math.Min(RegionEnd, End);
                ulong LeftSize = OverlapStart - RegionStart;
                ulong MidSize = OverlapEnd - OverlapStart;
                ulong RightSize = RegionEnd - OverlapEnd;

                if (LeftSize > 0)
                {
                    MemoryRegion Left = Region;
                    Left.BaseAddress = RegionStart;
                    Left.Size = LeftSize;
                    Left.RequestedSize = LeftSize;
                    NewRegions.Add(Left);
                }

                if (MidSize > 0)
                {
                    if (Region.IsCommitted && IsRegionMapped(OverlapStart, 1) && !_emulator.UnmapMemory(OverlapStart, MidSize))
                        return false;

                    MemoryProtection AllocationProt = WinHelper.ConvertWinProtectToInternal(Region.AllocationProtect);
                    NewRegions.Add(new MemoryRegion
                    {
                        BaseAddress = OverlapStart,
                        Size = MidSize,
                        RequestedSize = MidSize,
                        AllocationBase = Region.AllocationBase,
                        AllocationProtect = Region.AllocationProtect,
                        Protect = Region.AllocationProtect,
                        IsReserved = true,
                        IsCommitted = false,
                        IsReset = Region.IsReset,
                        InitialProtections = AllocationProt,
                        Protections = MemoryProtection.None,
                        SpecialProtections = SpecialProtections.None,
                        Flags = AllocationType.Reserved
                    });
                }

                if (RightSize > 0)
                {
                    MemoryRegion Right = Region;
                    Right.BaseAddress = OverlapEnd;
                    Right.Size = RightSize;
                    Right.RequestedSize = RightSize;
                    NewRegions.Add(Right);
                }
            }

            List<MemoryRegion> Merged = new List<MemoryRegion>(NewRegions.Count);
            foreach (var Region in NewRegions.OrderBy(R => R.BaseAddress))
            {
                if (Merged.Count == 0)
                {
                    Merged.Add(Region);
                    continue;
                }

                var Last = Merged[Merged.Count - 1];
                if (CanMergeWindowsMemoryRegions(Last, Region))
                {
                    Last.Size += Region.Size;
                    Last.RequestedSize = Last.Size;
                    Merged[Merged.Count - 1] = Last;
                }
                else
                {
                    Merged.Add(Region);
                }
            }

            ReplaceMemoryRegions(Merged);
            return true;
        }

        public bool ReleaseMemory(ulong AllocationBase)
        {
            var Regions = _memory
                .Where(R => R.IsReserved && R.AllocationBase == AllocationBase)
                .OrderBy(R => R.BaseAddress)
                .ToList();

            if (Regions.Count == 0)
                return false;

            ulong Start = Regions[0].BaseAddress;
            if (Start != AllocationBase)
                return false;

            ulong End = Regions.Max(R => R.BaseAddress + R.Size);

            foreach (var Region in Regions)
            {
                if (Region.IsCommitted && IsRegionMapped(Region.BaseAddress, 1) && !_emulator.UnmapMemory(Region.BaseAddress, Region.Size))
                    return false;
            }

            foreach (var Region in Regions)
                RemoveMemoryRegion(Region);

            _freedmemory.Add(new MemoryRegion
            {
                BaseAddress = Start,
                Size = End - Start,
                RequestedSize = End - Start,
                AllocationBase = Start,
                AllocationProtect = 0,
                Protect = 0,
                IsReserved = false,
                IsCommitted = false,
                InitialProtections = MemoryProtection.None,
                Protections = MemoryProtection.None,
                SpecialProtections = SpecialProtections.None,
                Flags = AllocationType.None
            });

            return true;
        }

        public ulong MapWinMemoryRegion(ulong Address, ulong Size, MemoryProtection Protection, SpecialProtections Special, AllocationType Flags, ulong AllocationBase = 0, uint AllocationProtect = 0, uint Protect = 0)
        {
            ulong AlignedSize = AlignToPageSize(Size);
            if (Address != 0)
            {
                ulong AlignedAddress = Address & ~0xFFFUL;
                if (IsRegionMapped(AlignedAddress, AlignedSize))
                {
                    Utils.LogError($"[MapWinMemoryRegion] Already mapped memory at {AlignedAddress:X} with size {Size:X} was trying to be mapped again.");
                    return 0;
                }

                if (_emulator.MapMemory(AlignedAddress, AlignedSize, GetGuardedHostProtection(Protection, Special)))
                {
                    ConsumeFreedMemoryRange(AlignedAddress, AlignedSize);

                    uint WinProtect = Protect != 0 ? Protect : (WinHelper != null ? (uint)WinHelper.ConvertInternalToWinProtect(Protection) : 0);
                    uint WinAllocationProtect = AllocationProtect != 0 ? AllocationProtect : WinProtect;

                    MemoryRegion Region = new MemoryRegion
                    {
                        BaseAddress = AlignedAddress,
                        Size = Size,
                        RequestedSize = Size,
                        AllocationBase = AllocationBase != 0 ? AllocationBase : AlignedAddress,
                        AllocationProtect = WinAllocationProtect,
                        Protect = WinProtect,
                        IsReserved = true,
                        IsCommitted = true,
                        InitialProtections = Protection,
                        Protections = Protection,
                        SpecialProtections = Special,
                        Flags = Flags
                    };

                    if (Size < AlignedSize)
                        Region.PoisonedMemory = (AlignedAddress + Size, AlignedAddress + AlignedSize);

                    AddMemoryRegion(Region);
                    return AlignedAddress;
                }

                return 0;
            }

            return MapWinUniqueAddress(Size, Protection, Special, Flags);
        }

        public ulong MapWinUniqueAddress(ulong Size, MemoryProtection Protection, SpecialProtections Special, AllocationType Flags)
        {
            ulong CurrentAddress = BaseAddress;
            ulong AlignedSize = AlignToPageSize(Size);
            while (CurrentAddress + AlignedSize < MaxAddress)
            {
                if (!IsRegionMapped(CurrentAddress, AlignedSize))
                {
                    if (_emulator.MapMemory(CurrentAddress, AlignedSize, GetGuardedHostProtection(Protection, Special)))
                    {
                        ConsumeFreedMemoryRange(CurrentAddress, AlignedSize);

                        uint WinProtect = WinHelper != null ? (uint)WinHelper.ConvertInternalToWinProtect(Protection) : 0;

                        MemoryRegion Region = new MemoryRegion
                        {
                            BaseAddress = CurrentAddress,
                            Size = Size,
                            RequestedSize = Size,
                            AllocationBase = CurrentAddress,
                            AllocationProtect = WinProtect,
                            Protect = WinProtect,
                            IsReserved = true,
                            IsCommitted = true,
                            InitialProtections = Protection,
                            Protections = Protection,
                            SpecialProtections = Special,
                            Flags = Flags
                        };

                        if (Size < AlignedSize)
                            Region.PoisonedMemory = (CurrentAddress + Size, CurrentAddress + AlignedSize);

                        AddMemoryRegion(Region);
                        return CurrentAddress;
                    }
                }

                CurrentAddress += AlignedSize;
            }

            return 0;
        }

        private static string ResolveFunctionName(ulong Address, WinModule Module)
        {
            if (Module.Exports == null || Module.Exports.Count == 0)
                return null;

            ulong Rva = Address - Module.MappedBase + Module.OriginalBase;
            ulong BestMatch = 0;
            string BestName = null;

            foreach (var Exp in Module.Exports)
            {
                ulong ExpVa = Exp.Key;
                if (ExpVa <= Rva && ExpVa >= BestMatch)
                {
                    BestMatch = ExpVa;
                    BestName = Exp.Value;
                }
            }

            if (BestName == null)
                return null;

            ulong Offset = Rva - BestMatch;
            return Offset == 0 ? BestName : $"{BestName}+0x{Offset:X}";
        }

        private static bool InsideWinModule(ulong Address, WinModule Module)
        {
            return Address >= Module.MappedBase && Address < Module.MappedBase + Module.SizeOfImage;
        }

        private bool InsideAnyWinModule(ulong Address)
        {
            return InsideAnyWinModule(Address, WinHelper);
        }

        private static bool InsideAnyWinModule(ulong Address, WinSysHelper Helper)
        {
            if (Helper == null)
                return false;

            List<WinModule> Modules = Helper.WinModules;
            for (int i = 0; i < Modules.Count; i++)
            {
                WinModule Module = Modules[i];
                if (Address >= Module.MappedBase && Address < Module.MappedBase + Module.SizeOfImage)
                    return true;
            }

            return false;
        }

        private WinModule FindModuleByAddress(ulong Address)
        {
            return FindModuleByAddress(Address, WinHelper);
        }

        private WinModule FindModuleByAddress(ulong Address, WinSysHelper Helper)
        {
            if (_lastAddressModule != null && Address >= _lastAddressModuleStart && Address < _lastAddressModuleEnd)
                return _lastAddressModule;

            if (Helper == null)
                return null;

            List<WinModule> Modules = Helper.WinModules;
            for (int i = 0; i < Modules.Count; i++)
            {
                WinModule Module = Modules[i];
                if (Address >= Module.MappedBase && Address < Module.MappedBase + Module.SizeOfImage)
                {
                    _lastAddressModule = Module;
                    _lastAddressModuleStart = Module.MappedBase;
                    _lastAddressModuleEnd = Module.MappedBase + Module.SizeOfImage;
                    return Module;
                }
            }

            return null;
        }

        private static bool TryGetSectionByAddress(WinModule module, ulong address, out PortableBinarySection section)
        {
            foreach (PortableBinarySection s in module.Sections.Values)
            {
                ulong start = module.MappedBase + s.VirtualAddress;
                ulong end = start + Math.Max(s.VirtualSize, s.RawSize);
                if (address >= start && address < end)
                {
                    section = s;
                    return true;
                }
            }

            section = default;
            return false;
        }

        private void InstructionHandler(ulong Address, uint Size)
        {
            Instruction++;
            if (Size == 2)
            {
                Span<byte> Data = stackalloc byte[2];
                if (ReadMemory(Address, Data, 2) && Data[0] == 0x48 && Data[1] == 0xCF)
                {
                    ulong RSP = _emulator.ReadRegister(Registers.UC_X86_REG_RSP);
                    ulong NewRIP = ReadMemoryULong(RSP + 0x0);
                    ulong NewRFlags = ReadMemoryULong(RSP + 0x10);
                    ulong NewRSP = ReadMemoryULong(RSP + 0x18);
                    _emulator.WriteRegister(IPRegister, NewRIP);
                    _emulator.WriteRegister(Registers.UC_X86_REG_EFLAGS, NewRFlags);
                    _emulator.WriteRegister(Registers.UC_X86_REG_RSP, NewRSP);
                }
            }

            _timestampCounter += TscCyclesPerInstruction;

            EmulatedThread Thread = CurrentThread;
            WinSysHelper Helper = WinHelper;
            if (Thread == null || Helper == null || Helper.WinModules.Count == 0)
                return;

            ulong PreviousRip = Thread.LastRIP;
            WinModule MainModule = Helper.WinModules[0];
            if (this.Debug || InsideWinModule(PreviousRip, MainModule))
            {
                if (this.Debug || InsideWinModule(Address, MainModule))
                {
                    if (TryGetSectionByAddress(MainModule, PreviousRip, out PortableBinarySection PrevSection) &&
                        TryGetSectionByAddress(MainModule, Address, out PortableBinarySection CurrSection) &&
                        IsExecutableSection(PrevSection) &&
                        IsExecutableSection(CurrSection) &&
                        !string.Equals(PrevSection.SectionName, CurrSection.SectionName, StringComparison.OrdinalIgnoreCase))
                    {
                        TriggerEventMessage($"[/] [CFT] {MainModule.Name} executable section change: {PrevSection.SectionName} (0x{PreviousRip:X}) -> {CurrSection.SectionName} (0x{Address:X})", LogFlags.General);
                        Thread.LastRIP = Address;
                        return;
                    }
                }
                else if (!InsideAnyWinModule(Address, Helper))
                {
                    TriggerEventMessage($"[/] [CFT] {MainModule.Name} (0x{PreviousRip:X}) -> 0x{Address:X} (NO MODULE)", LogFlags.General);
                    Thread.LastRIP = Address;
                    return;
                }

                WinModule CurrentModule = FindModuleByAddress(Address, Helper);
                if (CurrentModule != null)
                {
                    ulong LookupVA = (Address - CurrentModule.MappedBase) + CurrentModule.OriginalBase;
                    if (CurrentModule.Exports.TryGetValue(LookupVA, out string Func) && LastFunc != Func)
                    {
                        LastFunc = Func;
                        WinModule PreviousModule = PreviousRip != 0 ? FindModuleByAddress(PreviousRip, Helper) : null;
                        TriggerEventMessage($"[!] [ENTRY] {CurrentModule.Name}!{Func} @ 0x{Address:X} from {PreviousModule?.Name} @ 0x{PreviousRip:X}", LogFlags.General);
                    }
                }
            }

            Thread.LastRIP = Address;
            if (!StopTheReturn)
                return;

            int InstructionSize = Size > (uint)_instructionDisasmBuffer.Length ? _instructionDisasmBuffer.Length : (int)Size;
            if (InstructionSize == 0)
                return;

            if (!ReadMemory(Address, _instructionDisasmBuffer.AsSpan(0, InstructionSize), (uint)InstructionSize))
                return;

            if (InstructionSize < _instructionDisasmBuffer.Length)
                Array.Clear(_instructionDisasmBuffer, InstructionSize, _instructionDisasmBuffer.Length - InstructionSize);

            string disasm = Disassembler.DisassembleToStringEmu(_instructionDisasmBuffer, Address, _binary, 1, false);
            if (Size == 2 && _instructionDisasmBuffer[0] == 0x48 && _instructionDisasmBuffer[1] == 0xCF)
            {
                ulong RSP = _emulator.ReadRegister(Registers.UC_X86_REG_RSP);
                ulong NewRIP = ReadMemoryULong(RSP + 0x0);
                ulong NewRFlags = ReadMemoryULong(RSP + 0x10);
                ulong NewRSP = ReadMemoryULong(RSP + 0x18);
                _emulator.WriteRegister(IPRegister, NewRIP);
                _emulator.WriteRegister(Registers.UC_X86_REG_EFLAGS, NewRFlags);
                _emulator.WriteRegister(Registers.UC_X86_REG_RSP, NewRSP);
            }

            WinModule Module = FindModuleByAddress(Address, Helper);
            string FunctionInfo = Module != null ? ResolveFunctionName(Address, Module) : null;

            if (Module != null && FunctionInfo != null)
                Console.WriteLine($"(MODULE: {Module.Name} | FUNC: {FunctionInfo}) 0x{Address:X}: {disasm}");
            else if (Module != null)
                Console.WriteLine($"(MODULE: {Module.Name}) 0x{Address:X}: {disasm}");
            else
                Console.WriteLine($"0x{Address:X}: {disasm}");
        }

        internal void EnsureInstructionHook()
        {
            if (InstructionHook == null)
                InstructionHook = InstructionHandler;
            _emulator.AddCodeHook(1, 0, InstructionHook);
        }

        internal static byte[] GetApiSetMapBlob()
        {
            return LazyApiSetMapBlob.Value;
        }
    }
}
