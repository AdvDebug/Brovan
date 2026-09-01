using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Emulation.OS.Windows.Win32k;
using Brovan.Core.Helpers;
using static Brovan.Core.Emulation.OS.Windows.WinSysHelper;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.Guests
{
    public enum WindowsBlobLaunchMode
    {
        Ntdll = 1,
        Direct = 2
    }

    internal class WindowsGuest : IGuestEnvironment
    {
        public GuestOsKind Os => GuestOsKind.Windows;

        public ulong StackSize { get; private set; }
        public ulong PEB { get; internal set; }

        // The 64-bit PEB a WOW64 process also owns. SysWOW64 modules reach it through the TEB and read it with x64 offsets.
        public ulong NativePEB { get; internal set; }
        public ulong ProcessParams { get; internal set; }
        public ulong ApiSetMap { get; internal set; }
        public ulong WowSyscallGate { get; internal set; }
        public ulong GuestGdt { get; internal set; }

        private const uint GdtCodeIndex = 4;
        private const uint GdtDataIndex = 5;
        private const uint GdtFsIndex = 10;
        private const ulong GdtCodeSelector = GdtCodeIndex << 3;
        private const ulong GdtDataSelector = GdtDataIndex << 3;
        private const ulong GdtFsSelector = GdtFsIndex << 3;
        private const uint GdtSize = 0x1000;
        private const ulong NtUserCodeSelector = 0x33;
        private const ulong NtUserCodeSelector32 = 0x23;
        private const ulong NtUserDataSelector = 0x2B;
        private const ulong NtUserTebSelector32 = 0x53;
        private const byte GdtCodeAccess = 0x9B;
        private const byte GdtDataAccess = 0x93;
        private const byte GdtGranularityDefault = 0xC;
        private const byte GdtGranularityLongMode = 0xA;

        private const uint Wow64InfoOffset = 0x490;
        private const uint Wow64TlsWow64InfoOffset = 0xE10 + 10 * 4;
        private const uint TebWowTebOffset32 = 0xFDC;
        private const uint TebWowTebOffset64 = 0x180C;
        private const uint NativeTebWow64InfoSlotOffset = 0x1480 + 10 * 8;
        private const uint PageSize = 0x1000;
        public ulong LdrInitializeThunk { get; internal set; }
        public ulong RtlUserThreadStart { get; internal set; }
        public WinSysHelper WinHelper { get; internal set; }

        private readonly BlobData _blob;
        private readonly WindowsBlobLaunchMode _blobLaunchMode;
        private SyscallDispatchTable<WinSyscallEntry> WinSyscallTable = SyscallDispatchTable<WinSyscallEntry>.Empty;
        private WinModule _ntdllModule;

        private bool UsesDirectBlobStartup => IsBlob && _blobLaunchMode == WindowsBlobLaunchMode.Direct;

        /// <summary>
        /// Indicates whether the Windows guest should treat the input as a raw blob instead of a PE image.
        /// </summary>
        internal bool IsBlob { get; }

        internal ulong BlobMappedBase => _blob?.MappedBase ?? 0;

        private const ulong TebSameTebFlagsOffset64 = 0x17EE;
        private const ushort TEB_SAME_TEB_FLAG_SKIP_THREAD_ATTACH = 0x0008;
        private const ushort TEB_SAME_TEB_FLAG_INITIAL_THREAD = 0x0400;
        private const ushort TEB_SAME_TEB_FLAG_LOADER_WORKER = 0x2000;
        private const ushort TEB_SAME_TEB_FLAG_SKIP_LOADER_INIT = 0x4000;
        internal const uint THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x1;
        internal const uint THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x2;
        internal const uint THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x4;
        internal const uint THREAD_CREATE_FLAGS_LOADER_WORKER = 0x10;
        internal const uint THREAD_CREATE_FLAGS_SKIP_LOADER_INIT = 0x20;

        /// <summary>
        /// Creates a Windows guest for a PE image or, when blob data is supplied, a raw Windows blob.
        /// </summary>
        /// <param name="Blob">Optional raw blob mapping information.</param>
        /// <param name="BlobLaunchMode">Startup path to use for raw blobs.</param>
        public WindowsGuest(BlobData Blob = null!, WindowsBlobLaunchMode BlobLaunchMode = WindowsBlobLaunchMode.Ntdll)
        {
            _blob = Blob;
            _blobLaunchMode = BlobLaunchMode;
            IsBlob = Blob != null;
        }

        public ulong GetCurrentTeb(BinaryEmulator Instance)
        {
            WindowsThreadState State = WinEmulatedThread.TryGetState(Instance.CurrentThread);
            if (State == null)
                return 0;

            return State.Teb;
        }

        /// <summary>
        /// Returns the TEB the running thread is seen through with x64 offsets.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <returns>The native TEB, or the only TEB for a 64-bit guest.</returns>
        public ulong GetCurrentNativeTeb(BinaryEmulator Instance)
        {
            WindowsThreadState State = WinEmulatedThread.TryGetState(Instance.CurrentThread);
            if (State == null)
                return 0;

            return State.NativeTeb != 0 ? State.NativeTeb : State.Teb;
        }

        public void Initialize(BinaryEmulator Instance, BinaryFile Binary)
        {
            if (!Instance.IsArchX86Guest)
                throw new Exception("Windows guest supports only x86/x64.");

            if (Binary.FileFormat != BinaryFormat.PE)
            {
                if (!IsBlob)
                    return;

                InitializeBlob(Instance, Binary);
                return;
            }

            StackSize = Binary.Architecture == BinaryArchitecture.x64 ? Binary.PE.OptionalHeader64.SizeOfStackReserve : Binary.PE.OptionalHeader32.SizeOfStackReserve;
            ulong ImageBase = Binary.PE.ImageBase;
            ReadOnlySpan<byte> BinaryData = Binary.GetBinaryData();
            ulong ImageSize = Instance.AlignToPageSize(Binary.PE.SizeOfImage != 0 ? Binary.PE.SizeOfImage : (uint)Binary.BinarySize);
            ulong HeaderSizeUlong = Binary.PE.SizeOfHeaders;
            if (HeaderSizeUlong > (ulong)BinaryData.Length)
                HeaderSizeUlong = (ulong)BinaryData.Length;

            int HeaderSize = HeaderSizeUlong > int.MaxValue ? int.MaxValue : (int)HeaderSizeUlong;
            ulong BaseAddress = Instance.MapWinMemoryRegion(ImageBase, (ulong)HeaderSize, MemoryProtection.ReadWrite, SpecialProtections.None, AllocationType.Image, ImageBase);

            if (HeaderSize != 0)
            {
                int HeaderBytes = Math.Min(HeaderSize, BinaryData.Length);
                if (HeaderBytes != 0)
                    Instance._emulator.WriteMemory(BaseAddress, BinaryData.Slice(0, HeaderBytes));
            }

            WinModule Module = new WinModule();

            foreach (PortableBinarySection Section in Binary.PE.Sections)
            {
                if (Section.VirtualAddress == 0)
                    continue;

                ulong VirtualSpan = Section.VirtualSize != 0 ? Section.VirtualSize : Section.RawSize;
                if (VirtualSpan == 0)
                    continue;

                ulong SectionSize = Instance.AlignToPageSize(VirtualSpan);
                ulong SectionAddr = ImageBase + (ulong)Section.VirtualAddress;

                if (Instance.MapWinMemoryRegion(SectionAddr, SectionSize, Instance.GetMemoryProtection(Section.Characteristics), SpecialProtections.None, AllocationType.Image, ImageBase) == 0)
                    continue;

                bool Ok = true;
                if (Section.RawSize > 0 && Section.RawSize <= int.MaxValue)
                {
                    long RawOffsetLong = Section.RawOffset;
                    if (RawOffsetLong >= 0 && RawOffsetLong < BinaryData.Length)
                    {
                        int RawOffset = (int)RawOffsetLong;
                        int RawSize = (int)Section.RawSize;
                        int MaxReadable = BinaryData.Length - RawOffset;
                        int BytesToWrite = Math.Min(RawSize, MaxReadable);
                        if (BytesToWrite != 0)
                            Ok = Instance._emulator.WriteMemory(SectionAddr, BinaryData.Slice(RawOffset, BytesToWrite));
                    }
                }

                if (Ok)
                    Module.Sections.TryAdd(SectionAddr, Section);
            }

            if (!string.IsNullOrEmpty(Binary.Location) && File.Exists(Binary.Location))
            {
                Module.Name = GeneralHelper.IO.GetWindowsFileName(Instance.GuestImagePath);
                Module.Path = Instance.GuestImagePath;
            }

            Module.OriginalBase = Binary.PE.ImageBase;
            Module.MappedBase = BaseAddress;
            Module.SizeOfImage = ImageSize;
            Module.EntryPoint = Module.MappedBase + Binary.EntryPoint;
            Module.Architecture = Binary.Architecture;

            PrepareWinEnvironment(Instance, Module);
        }

        /// <summary>
        /// Maps a raw Windows blob and prepares it as the main module for the Windows guest.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="Binary">The raw blob binary wrapper.</param>
        private void InitializeBlob(BinaryEmulator Instance, BinaryFile Binary)
        {
            ReadOnlySpan<byte> Data = Binary.GetBinaryData();
            ulong BlobSize = Instance.AlignToPageSize((ulong)Math.Max(Data.Length, 1));
            ulong RequestedBase = _blob?.LoadAddress ?? 0;
            ulong MappedBase;

            if (RequestedBase == 0 || Instance.IsRegionMapped(RequestedBase, BlobSize))
                MappedBase = Instance.MapWinUniqueAddress(BlobSize, MemoryProtection.All, SpecialProtections.None, AllocationType.Image);
            else
                MappedBase = Instance.MapWinMemoryRegion(RequestedBase, BlobSize, MemoryProtection.All, SpecialProtections.None, AllocationType.Image, RequestedBase);

            if (MappedBase == 0)
                throw new InvalidOperationException("Failed to map the Windows blob image.");

            if (Data.Length != 0)
                Instance._emulator.WriteMemory(MappedBase, Data);

            if (_blob != null)
                _blob.MappedBase = MappedBase;

            StackSize = (_blob?.StackSize).GetValueOrDefault();
            if (StackSize == 0)
                StackSize = Binary.Architecture == BinaryArchitecture.x64 ? 0x200000UL : 0x100000UL;

            ulong GuestEntry = MappedBase;
            if (_blob != null && _blob.EntryAddress != 0)
            {
                ulong EntryAddress = _blob.EntryAddress;
                if (_blob.LoadAddress != 0 && EntryAddress >= _blob.LoadAddress && EntryAddress < _blob.LoadAddress + BlobSize)
                    GuestEntry = MappedBase + (EntryAddress - _blob.LoadAddress);
                else
                    GuestEntry = EntryAddress;
            }

            if (MappedBase != 0 && GuestEntry >= MappedBase && GuestEntry - MappedBase <= uint.MaxValue)
                Binary.EntryPoint = (uint)(GuestEntry - MappedBase);

            WinModule Module = new WinModule
            {
                Architecture = Binary.Architecture,
                MappedBase = MappedBase,
                OriginalBase = RequestedBase != 0 ? RequestedBase : MappedBase,
                SizeOfImage = BlobSize,
                EntryPoint = GuestEntry,
                Name = !string.IsNullOrWhiteSpace(Instance.GuestImagePath) ? GeneralHelper.IO.GetWindowsFileName(Instance.GuestImagePath) : "blob.bin",
                Path = Instance.GuestImagePath
            };

            PrepareWinEnvironment(Instance, Module);
        }

        public void Start(BinaryEmulator Instance)
        {
            if (WinHelper == null || WinHelper.WinModules.Count == 0)
                return;

            ulong TID = CreateInitialThread(Instance);
            if (!Instance.Threads.TryGetValue((uint)TID, out EmulatedThread Thread) || Thread == null)
                return;

            Instance.LoadContext(Thread);
            Instance.RunMlfqScheduler();
        }

        public void OnThreadContextLoaded(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return;

            ulong Teb = WinEmulatedThread.GetState(Thread).Teb;
            if (Teb == 0)
                return;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_GS_BASE, Teb);

                if (GuestGdt != 0)
                {
                    Instance._emulator.WriteRegister(Registers.UC_X86_REG_CS, GdtCodeSelector);
                    Instance._emulator.WriteRegister(Registers.UC_X86_REG_SS, GdtDataSelector);
                }
            }
            else if (GuestGdt != 0)
            {
                Instance._emulator.WriteMemory(GuestGdt + GdtFsIndex * 8, MakeSegmentDescriptor(Teb, 0xFFF, GdtDataAccess, 0x4), 8);
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_CS, GdtCodeSelector);
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_SS, GdtDataSelector);
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_DS, GdtDataSelector);
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_ES, GdtDataSelector);
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_FS, GdtFsSelector);
            }
            else
            {
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_FS_BASE, Teb);
            }
        }

        public bool HasPendingGuestWork(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return false;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.DispatchException)
                return true;

            return WinHelper != null && WinHelper.CanDispatchUserApc(Thread);
        }

        public bool IsHandleSignaled(BinaryEmulator Instance, ulong Handle)
        {
            if (WinHelper == null)
                return false;

            IHandleObject Obj = WinHelper.HandleManager.GetObjectByHandle(Handle);
            if (Obj == null)
                return false;

            if (Obj is WinEvent Event)
                return Event.Signaled;

            if (Obj is WinMutex Mutex)
                return Mutex.Signaled;

            if (Obj is EmulatedThread Thread)
                return Thread.State == EmulatedThreadState.Terminated;

            if (Obj is WinTimer Timer)
                return Timer.Signaled;

            if (Obj is WinWorkerFactory Factory)
                return IsWorkerFactoryReady(Instance, Factory);

            if (Obj is WinIoCompletion Completion)
            {
                Instance.MaterializeSignaledWaitPackets(Handle);
                return Completion.PendingCount > 0;
            }

            return false;
        }


        public void OnThreadWaitSatisfied(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WorkerFactoryWaitActive)
            {
                CompleteWorkerFactoryWait(Instance, Thread, State);
                return;
            }

            if (State.IoCompletionWaitActive)
            {
                CompleteIoCompletionWait(Instance, Thread, State);
                return;
            }

            if (State.RetrySyscallActive)
            {
                CompleteSyscallRetry(Instance, Thread, State);
                return;
            }

            NTSTATUS WaitStatus = State.WaitStatus;
            if (WaitStatus == NTSTATUS.STATUS_PENDING)
                WaitStatus = NTSTATUS.STATUS_SUCCESS;

            if (Thread.WaitTimedOut)
            {
                WaitStatus = NTSTATUS.STATUS_TIMEOUT;
                if (!State.AlertByThreadIdWaitActive && Thread.WaitHandles == null)
                    WaitStatus = NTSTATUS.STATUS_SUCCESS;
            }
            else if (State.AlertByThreadIdWaitActive)
                WaitStatus = NTSTATUS.STATUS_ALERTED;
            else if (Thread.WaitSatisfiedIndex >= 0 && WaitStatus == NTSTATUS.STATUS_SUCCESS)
                WaitStatus = (NTSTATUS)(uint)Thread.WaitSatisfiedIndex;

            if (Thread.Context == null)
                Thread.Context = new CpuContext();

            ulong ResumeRip = State.WaitReturnRIP != 0 ? State.WaitReturnRIP : (State.WaitResumeRIP != 0 ? State.WaitResumeRIP + 2 : Thread.Context.RIP);
            Thread.Context.RIP = ResumeRip;
            Thread.Context.RAX = (ulong)(uint)WaitStatus;

            State.WaitCompleted = false;
            State.WaitStatus = WaitStatus;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.WaitObjects = null;
            State.ApcAlertable = false;
            State.AlertByThreadIdWaitActive = false;
            State.AlertByThreadIdAddress = 0;
            State.MsgWaitActive = false;
            State.MsgWaitMask = 0;
            State.WaitMessageActive = false;
            State.GetMessageWaitActive = false;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;

            if (Instance.CurrentThread == Thread)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Thread.Context.RIP);
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Thread.Context.RAX);
            }
        }

        /// <summary>
        /// Restores the syscall number that a completed wait would otherwise overwrite with its status.
        /// </summary>
        private void CompleteSyscallRetry(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State)
        {
            if (Thread.Context == null)
                Thread.Context = new CpuContext();

            Thread.Context.RIP = State.WaitResumeRIP;
            Thread.Context.RAX = State.RetrySyscallNumber;

            State.RetrySyscallActive = false;
            State.RetrySyscallNumber = 0;
            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.WaitObjects = null;
            State.ApcAlertable = false;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;

            if (Instance.CurrentThread == Thread)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Thread.Context.RIP);
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Thread.Context.RAX);
            }
        }

        private void CompleteIoCompletionWait(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State)
        {
            NTSTATUS WaitStatus = NTSTATUS.STATUS_TIMEOUT;
            WinIoCompletionEntry Entry = State.IoCompletionReservedEntry;

            if (Entry != null && WinHelper != null)
            {
                WinHelper.WritePointer(State.IoCompletionKeyContextPtr, Entry.KeyContext);
                WinHelper.WritePointer(State.IoCompletionApcContextPtr, Entry.ApcContext);
                WinHelper.WriteIoStatusBlock(Instance, State.IoCompletionIoStatusBlockPtr, Entry.IoStatus, Entry.IoStatusInformation);
                WaitStatus = NTSTATUS.STATUS_SUCCESS;
            }

            if (Thread.Context == null)
                Thread.Context = new CpuContext();

            ulong ResumeRip = State.WaitReturnRIP != 0 ? State.WaitReturnRIP : (State.WaitResumeRIP != 0 ? State.WaitResumeRIP + 2 : Thread.Context.RIP);
            Thread.Context.RIP = ResumeRip;
            Thread.Context.RAX = (ulong)(uint)WaitStatus;

            State.IoCompletionWaitActive = false;
            State.IoCompletionHandle = 0;
            State.IoCompletionKeyContextPtr = 0;
            State.IoCompletionApcContextPtr = 0;
            State.IoCompletionIoStatusBlockPtr = 0;
            State.IoCompletionReservedEntry = null;
            State.WaitCompleted = false;
            State.WaitStatus = WaitStatus;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.WaitObjects = null;
            State.ApcAlertable = false;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;

            if (Instance.CurrentThread == Thread)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Thread.Context.RIP);
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Thread.Context.RAX);
            }
        }

        private static uint GetWorkerFactoryPacketSize(BinaryArchitecture Architecture)
        {
            return Architecture == BinaryArchitecture.x64 ? 0x20u : 0x10u;
        }

        private bool IsWorkerFactoryReady(BinaryEmulator Instance, WinWorkerFactory Factory)
        {
            if (Factory == null)
                return false;

            if (Factory.Shutdown)
                return true;

            Instance.MaterializeSignaledWaitPackets(Factory.IoCompletionHandle);
            WinIoCompletion Completion = WinHelper?.HandleManager.GetObjectByHandle<WinIoCompletion>(Factory.IoCompletionHandle);
            if (Completion == null)
                return false;

            return Completion.PendingCount > 0;
        }

        private void CompleteWorkerFactoryWait(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State)
        {
            NTSTATUS WaitStatus = NTSTATUS.STATUS_SUCCESS;
            WinWorkerFactory Factory = WinHelper?.HandleManager.GetObjectByHandle<WinWorkerFactory>(State.WorkerFactoryHandle);

            if (Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
            {
                WaitStatus = NTSTATUS.STATUS_TIMEOUT;
                if (State.WorkerFactoryPacketsReturned != 0)
                {
                    if (Instance._binary.Architecture == BinaryArchitecture.x64)
                        Instance._emulator.WriteMemory(State.WorkerFactoryPacketsReturned, 0u, 4);
                    else
                        Instance._emulator.WriteMemory(State.WorkerFactoryPacketsReturned, 0u);
                }
            }
            else if (Factory != null)
            {
                uint Removed = 0;
                if (State.WorkerFactoryReservedEntries != null && State.WorkerFactoryReservedEntries.Count > 0)
                {
                    uint PacketSize = GetWorkerFactoryPacketSize(Instance._binary.Architecture);
                    foreach (WinIoCompletionEntry Entry in State.WorkerFactoryReservedEntries)
                    {
                        ulong Address = State.WorkerFactoryMiniPackets + ((ulong)Removed * PacketSize);

                        if (Instance._binary.Architecture == BinaryArchitecture.x64)
                        {
                            Instance._emulator.WriteMemory(Address + 0x0, Entry.KeyContext, 8);
                            Instance._emulator.WriteMemory(Address + 0x8, Entry.ApcContext, 8);
                            Instance._emulator.WriteMemory(Address + 0x10, unchecked((ulong)(long)(int)Entry.IoStatus), 8);
                            Instance._emulator.WriteMemory(Address + 0x18, Entry.IoStatusInformation, 8);
                        }
                        else
                        {
                            Instance._emulator.WriteMemory(Address + 0x0, (uint)Entry.KeyContext);
                            Instance._emulator.WriteMemory(Address + 0x4, (uint)Entry.ApcContext);
                            Instance._emulator.WriteMemory(Address + 0x8, (uint)Entry.IoStatus);
                            Instance._emulator.WriteMemory(Address + 0xC, (uint)Entry.IoStatusInformation);
                        }

                        Removed++;
                    }
                }

                if (State.WorkerFactoryPacketsReturned != 0)
                {
                    if (Instance._binary.Architecture == BinaryArchitecture.x64)
                        Instance._emulator.WriteMemory(State.WorkerFactoryPacketsReturned, Removed, 4);
                    else
                        Instance._emulator.WriteMemory(State.WorkerFactoryPacketsReturned, Removed);
                }
            }

            if (Thread.Context == null)
                Thread.Context = new CpuContext();

            ulong ResumeRip = State.WaitReturnRIP != 0 ? State.WaitReturnRIP : (State.WaitResumeRIP != 0 ? State.WaitResumeRIP + 2 : Thread.Context.RIP);
            Thread.Context.RIP = ResumeRip;
            Thread.Context.RAX = (ulong)(uint)WaitStatus;

            State.WorkerFactoryWaitActive = false;
            State.WorkerFactoryHandle = 0;
            State.WorkerFactoryMiniPackets = 0;
            State.WorkerFactoryPacketsReturned = 0;
            State.WorkerFactoryMaxPackets = 0;
            State.WorkerFactoryReservedEntries?.Clear();
            State.WaitCompleted = false;
            State.WaitStatus = WaitStatus;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.WaitObjects = null;
            State.ApcAlertable = false;

            if (Instance.CurrentThread == Thread)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Thread.Context.RIP);
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Thread.Context.RAX);
            }
        }

        public bool ExecuteThreadSlice(BinaryEmulator Instance, EmulatedThread Thread, uint QuantumInstructions, out bool State)
        {
            State = false;
            if (Thread == null)
                return false;

            if (WinHelper != null && WinHelper.CanDispatchUserApc(Thread))
                WinHelper.DispatchNextUserApc(Thread);

            WindowsThreadState ThreadState = WinEmulatedThread.GetState(Thread);
            if (ThreadState.DispatchException)
            {
                if (ThreadState.ExceptionInformation == null)
                    ThreadState.ExceptionInformation = new ExceptionInformation();

                WinHelper?.InvokeException(ThreadState.ExceptionInformation.Status, ThreadState.ExceptionInformation);

                ThreadState.DispatchException = false;

                State = Instance._emulator.Emulate(Instance.ReadRegister(Instance.IPRegister), 0, 0, QuantumInstructions);
                return true;
            }

            State = Instance._emulator.Emulate(Thread.Context.RIP, 0, 0, QuantumInstructions);
            if (!State && Instance._emulator.GetLastError() == BackendError.Exception)
            {
                ulong EFlags = Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS);
                if ((EFlags & (ulong)CPUFlags.TF) != 0 && !ThreadState.DispatchException)
                {
                    QueueUserModeException(Instance, NTSTATUS.STATUS_SINGLE_STEP);
                    State = true;
                }
            }

            if (Instance.CurrentThread != null && WinEmulatedThread.GetState(Instance.CurrentThread).DispatchException)
                State = true;
            return true;
        }

        private static ulong[] ReadWindowsSyscallArguments(BinaryEmulator Instance, int Count)
        {
            if (Count <= 0)
                return Array.Empty<ulong>();

            ulong[] Args = new ulong[Count];
            try
            {
                if (Instance._binary.Architecture == BinaryArchitecture.x64)
                {
                    ulong RSP = Instance.ReadRegister(Registers.UC_X86_REG_RSP);
                    for (int i = 0; i < Count; i++)
                    {
                        if (i == 0) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_RCX);
                        else if (i == 1) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_RDX);
                        else if (i == 2) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_R8);
                        else if (i == 3) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_R9);
                        else Args[i] = Instance.ReadMemoryULong(RSP + 0x20 + (ulong)((i - 4) * 8));
                    }
                }
                else
                {
                    uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
                    uint ArgBase = ESP + (Instance.WinHelper != null && Instance.WinHelper.X86GateArgs ? 8u : 4u);
                    for (int i = 0; i < Count; i++)
                        Args[i] = Instance.ReadMemoryUInt(ArgBase + (uint)(4 * i));
                }
            }
            catch
            {
            }

            return Args;
        }

        public bool TryHandleSyscall(BinaryEmulator Instance)
        {
            WinHelper?.LdrTracker?.SyncFromSyscall();

            try
            {
                uint Syscall = Instance._binary.Architecture == BinaryArchitecture.x64
                    ? Instance.ReadRegister32(Registers.UC_X86_REG_RAX)
                    : Instance.ReadRegister32(Registers.UC_X86_REG_EAX);
                SyscallAbi Abi = Instance._binary.Architecture == BinaryArchitecture.x64 ? SyscallAbi.X64 : SyscallAbi.X86;
                ulong Rip = Instance.WinHelper != null ? Instance.WinHelper.GetSyscallRip(null, false) : Instance.ReadRegister(Instance.IPRegister);
                bool CaptureSyscallHistory = Instance.Syscalls?.TraceEnabled == true;
                ulong[] HistoryArgs = CaptureSyscallHistory ? ReadWindowsSyscallArguments(Instance, 6) : Array.Empty<ulong>();

                WinSyscallEntry Entry = WinSyscallTable.Lookup(Syscall);
                string HandlerName = Entry.Name;
                bool IsImplemented = Entry.Handler != null;

                SyscallRule Rule = null;
                if (Instance.Syscalls.HasRules)
                    Instance.Syscalls.TryMatchRule(Syscall, HandlerName, out Rule);

                if (Rule != null)
                {
                    int MaxArgs = Rule.ArgsCount;
                    ulong[] Args = Array.Empty<ulong>();
                    if (MaxArgs > 0)
                    {
                        if (CaptureSyscallHistory && MaxArgs <= HistoryArgs.Length)
                        {
                            Args = new ulong[MaxArgs];
                            Array.Copy(HistoryArgs, Args, MaxArgs);
                        }
                        else
                        {
                            Args = ReadWindowsSyscallArguments(Instance, MaxArgs);
                        }
                    }

                    SyscallContext Ctx = Instance.Syscalls.HandleSyscall(Syscall, HandlerName, Args, Rule);
                    if (Ctx.Handled)
                    {
                        if (!Instance.SuppressSyscallStatusWrite)
                        {
                            SetLastWinErrorRegister(Instance, (NTSTATUS)Ctx.ReturnValue);
                            Instance.SuppressSyscallStatusWrite = false;
                        }

                        if (CaptureSyscallHistory)
                            Instance.Syscalls.RecordSyscall(GuestOsKind.Windows, Abi, Syscall, HandlerName, Ctx.Args, Ctx.ReturnValue, Rip, IsImplemented, true);
                        if ((Instance.Settings.Flags & LogFlags.General) != 0)
                            Instance.TriggerEventMessage($"[SYSCALL MANAGER] Syscall 0x{Syscall:X} handled, returned 0x{Ctx.ReturnValue:X}.", LogFlags.General);
                        return true;
                    }
                }

                if (IsImplemented)
                {
                    Instance.WinHelper.BeginSyscall();
                    NTSTATUS Status;
                    try
                    {
                        Status = Entry.Handler.Handle(Instance);
                    }
                    finally
                    {
                        Instance.WinHelper.EndSyscall();
                    }

                    if (Instance.Settings.SyscallNotificationCallback != null)
                    {
                        Instance.Settings.SyscallNotificationCallback.Invoke(Instance.ReadRegister(Instance.IPRegister), Syscall, HandlerName, (ulong)(uint)Status);
                    }
                    else
                    {
                        if ((Instance.Settings.Flags & LogFlags.General) != 0)
                            Instance.TriggerEventMessage($"[+] Syscall {HandlerName} (0x{Syscall:X}) executed, returned {Status}.", LogFlags.General);
                    }

                    if (CaptureSyscallHistory)
                        Instance.Syscalls.RecordSyscall(GuestOsKind.Windows, Abi, Syscall, HandlerName, HistoryArgs, (ulong)(uint)Status, Rip, true);

                    bool SuppressStatusWrite = Instance.SuppressSyscallStatusWrite || (Instance.IsX86Guest && Instance.ReadRegister(Instance.IPRegister) == Rip);
                    Instance.SuppressSyscallStatusWrite = false;

                    if (!SuppressStatusWrite)
                        SetLastWinErrorRegister(Instance, Status);
                }
                else
                {
                    if (Instance.Settings.SyscallNotificationCallback != null)
                    {
                        Instance.Settings.SyscallNotificationCallback.Invoke(Instance.ReadRegister(Instance.IPRegister), Syscall, null, (ulong)(uint)Instance.WinUnimplemented);
                    }
                    else
                    {
                        if ((Instance.Settings.Flags & LogFlags.General) != 0)
                            Instance.TriggerEventMessage($"[!] Syscall 0x{Syscall:X} not implemented. returned {Instance.WinUnimplemented}.", LogFlags.General);
                    }

                    if (CaptureSyscallHistory)
                        Instance.Syscalls.RecordSyscall(GuestOsKind.Windows, Abi, Syscall, HandlerName, HistoryArgs, (ulong)(uint)Instance.WinUnimplemented, Rip, false);

                    bool SuppressStatusWrite = Instance.SuppressSyscallStatusWrite || (Instance.IsX86Guest && Instance.ReadRegister(Instance.IPRegister) == Rip);
                    Instance.SuppressSyscallStatusWrite = false;

                    if (!SuppressStatusWrite)
                        SetLastWinErrorRegister(Instance, Instance.WinUnimplemented);
                }

                return true;
            }
            catch (Exception ex)
            {
                Utils.LogError($"[-] [TryHandleWinSyscall] ERROR: {ex.Message}\nStackTrace:\n\n{ex.StackTrace}");
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[-] Error while handling a Windows Syscall: {ex.Message}", LogFlags.Issues);

                // Leaving the return register untouched reads as STATUS_SUCCESS to the caller
                Instance.SuppressSyscallStatusWrite = false;
                SetLastWinErrorRegister(Instance, NTSTATUS.STATUS_UNSUCCESSFUL);
                return true;
            }
        }

        public void HandlePrivilegedInstruction(BinaryEmulator Instance)
        {
            QueueUserModeException(Instance, NTSTATUS.STATUS_PRIVILEGED_INSTRUCTION);
        }

        public void HandleInvalidInstruction(BinaryEmulator Instance)
        {
            QueueUserModeException(Instance, NTSTATUS.STATUS_ILLEGAL_INSTRUCTION);
        }

        private static ExceptionType MapMemoryTypeToExceptionType(BackendMemoryAccessType Type)
        {
            switch (Type)
            {
                case BackendMemoryAccessType.ReadUnmapped:
                case BackendMemoryAccessType.ReadProtected:
                    return ExceptionType.Read;

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

        public bool HandleInvalidMemory(BinaryEmulator Instance, BackendMemoryAccessType Type, ulong Address, uint Size, ulong Value)
        {
            if (Instance._binary == null || (!IsBlob && Instance._binary.FileFormat != BinaryFormat.PE))
                return false;

            ExceptionType ExType = MapMemoryTypeToExceptionType(Type);
            ExceptionInformation ExInfo = new ExceptionInformation
            {
                Address = Address,
                Type = ExType,
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION
            };

            QueueUserModeException(Instance, NTSTATUS.STATUS_ACCESS_VIOLATION, ExInfo);
            return false;
        }

        public bool TryHandleInterrupt(BinaryEmulator Instance, uint InterruptNumber)
        {
            switch (InterruptNumber)
            {
                case 0:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_INTEGER_DIVIDE_BY_ZERO);
                    return true;
                case 1:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_SINGLE_STEP);
                    return true;
                case 3:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_BREAKPOINT);
                    return true;
                case 0x29:
                    if ((Instance.Settings.Flags & LogFlags.General) != 0)
                    {
                        // __fastfail carries its reason in the first integer argument register.
                        ulong FailCode = Instance.ReadRegister(Instance.IsX86Guest
                            ? (int)Registers.UC_X86_REG_ECX
                            : (int)Registers.UC_X86_REG_RCX);
                        Instance.TriggerEventMessage($"[!] The Emulated Program asked to Fast-Fail at 0x{Instance.ReadRegister(Instance.IPRegister):X} with code {FailCode}.", LogFlags.General);
                    }
                    Instance.StopEmulation();
                    return true;
                case 0x2E:
                    if (Instance.IsX86Guest)
                        return TryHandleSyscall(Instance);
                    QueueUserModeException(Instance, NTSTATUS.STATUS_ILLEGAL_INSTRUCTION);
                    return true;
                default:
                    return false;
            }
        }


        public ulong CreateInitialThread(BinaryEmulator Instance)
        {
            if (WinHelper == null || WinHelper.WinModules.Count == 0)
                return 0;

            ulong EntryPoint = WinHelper.WinModules[0].EntryPoint;
            EmulatedThread Thread = UsesDirectBlobStartup
                ? CreateDirectEmulatedThread(Instance, EntryPoint, "InitialBlobStart", 0, null, 8, 0, true)
                : CreateEmulatedThread(Instance, EntryPoint, "InitialThreadStart", 0, null, 8, 0, true);

            return Thread?.ThreadId ?? 0;
        }

        public void QueueUserModeException(BinaryEmulator Instance, NTSTATUS Status, ExceptionInformation Info = null!)
        {
            if (Instance._binary == null || (!IsBlob && Instance._binary.FileFormat != BinaryFormat.PE))
                return;

            if (Status == NTSTATUS.STATUS_SINGLE_STEP)
            {
                ulong EFlags = Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS);
                Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, EFlags & ~(ulong)CPUFlags.TF);

                ulong Dr6 = Instance.ReadRegister(Registers.UC_X86_REG_DR6);
                Instance.WriteRegister(Registers.UC_X86_REG_DR6, Dr6 | (1UL << 14));
            }

            uint ThreadId = (uint)Instance.CurrentThreadId;
            if (!Instance.Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null)
                return;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);

            ExceptionInformation ExceptionInfo = Info ?? new ExceptionInformation();
            ExceptionInfo.Status = Status;

            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[-] Dispatching exception 0x{(uint)Status:X8} to thread {ThreadId} at 0x{Instance.ReadRegister(Instance.IPRegister):X} (fault address 0x{ExceptionInfo.Address:X}).", LogFlags.Issues);

            Thread.State = EmulatedThreadState.Exception;
            State.DispatchException = true;
            State.ExceptionInformation = ExceptionInfo;
            Instance.Threads[ThreadId] = Thread;
            Instance._emulator.StopEmulation();
        }

        public void SetLastWinError(BinaryEmulator Instance, uint LastError)
        {
            ulong Teb = GetCurrentTeb(Instance);
            if (Teb == 0)
                return;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                Instance._emulator.WriteMemory(Teb + 0x68, LastError);
            else
                Instance._emulator.WriteMemory(Teb + 0x34, LastError);
        }

        public void SetLastWinErrorRegister(BinaryEmulator Instance, NTSTATUS Status)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, (ulong)Status);
            else
                Instance.WriteRegister32(Registers.UC_X86_REG_EAX, (uint)Status);
        }

        private const ulong StackGuardPages = 3;
        private const ulong InitialStackCommitPages = 4;

        private static ulong AllocateGuardedThreadStack(BinaryEmulator Instance, ulong StackSize, out ulong StackLimit)
        {
            const uint PAGE_READWRITE = 0x04;
            const uint PAGE_GUARD = 0x100;
            const ulong AllocationGranularity = 0x10000;

            StackLimit = 0;

            ulong GuardSize = StackGuardPages * PageSize;
            ulong CommitSize = InitialStackCommitPages * PageSize;
            ulong Reserve = Instance.AlignToPageSize(StackSize);

            // Deliberately not allocate. its finder starts at 4 GB for x64 guests,
            // which puts the stack nowhere near the rest of the address space Brovan hands out.
            if (Instance.WinHelper != null && Reserve > GuardSize + CommitSize &&
                Instance.TryFindFreeBaseAddress(Reserve, AllocationGranularity, Instance.BaseAddress, Instance.MaxAddress, out ulong Base) &&
                Instance.ReserveMemory(Base, Reserve, PAGE_READWRITE))
            {
                ulong CommitBase = Base + Reserve - CommitSize;
                if (Instance.CommitMemory(CommitBase, CommitSize, PAGE_READWRITE) &&
                    Instance.CommitMemory(CommitBase - GuardSize, GuardSize, PAGE_READWRITE | PAGE_GUARD))
                {
                    StackLimit = CommitBase;
                    return Base;
                }

                Instance.ReleaseMemory(Base);
            }

            return Instance.AllocateThreadStack(StackSize);
        }

        private static ulong EffectiveStackLimit(EmulatedThread Thread)
        {
            return Thread.StackLimit != 0 ? Thread.StackLimit : Thread.StackAddress;
        }

        public ulong AllocateAndInitializeTEB(BinaryEmulator Instance, EmulatedThread Thread, uint CreateFlags = 0, bool InitialThread = false)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return AllocateAndInitializeWow64TEB(Instance, Thread);

            ulong Teb = Instance.MapUniqueAddress(0x2000, MemoryProtection.ReadWrite);
            Instance._emulator.WriteMemoryByte(Teb, 0, 0x2000);
            Instance._emulator.WriteMemory(Teb, ulong.MaxValue, 8);
            Instance._emulator.WriteMemory(Teb + 0x8, Thread.StackAddress + Thread.StackSize);
            Instance._emulator.WriteMemory(Teb + 0x10, EffectiveStackLimit(Thread));
            Instance._emulator.WriteMemory(Teb + 0x1478, Thread.StackAddress, 8);
            Instance._emulator.WriteMemory(Teb + 0x18, 0UL, 8);
            Instance._emulator.WriteMemory(Teb + 0x20, 0UL, 8);
            Instance._emulator.WriteMemory(Teb + 0x28, 0UL, 8);
            Instance._emulator.WriteMemory(Teb + 0x30, Teb, 8);
            Instance._emulator.WriteMemory(Teb + 0x40, WinHelper.PID, 8);
            Instance._emulator.WriteMemory(Teb + 0x48, Thread.ThreadId);
            Instance._emulator.WriteMemory(Teb + 0x60, PEB, 8);
            Instance._emulator.WriteMemory(Teb + 0x68, (uint)0u);
            Instance._emulator.WriteMemory(Teb + 0x108, (uint)0x0409u);
            Instance._emulator.WriteMemory(Teb + 0x1760, (uint)0u);
            Instance._emulator.WriteMemory(Teb + 0x179C, (uint)0u);
            Instance._emulator.WriteMemory(Teb + 0x17A0, (ulong)0ul);
            ushort SameTebFlags = 0;
            if (InitialThread)
                SameTebFlags |= TEB_SAME_TEB_FLAG_INITIAL_THREAD;
            if ((CreateFlags & THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_SKIP_THREAD_ATTACH;
            if ((CreateFlags & THREAD_CREATE_FLAGS_LOADER_WORKER) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_LOADER_WORKER;
            if ((CreateFlags & THREAD_CREATE_FLAGS_SKIP_LOADER_INIT) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_SKIP_LOADER_INIT;
            Instance._emulator.WriteMemory(Teb + TebSameTebFlagsOffset64, SameTebFlags, 2);
            Instance._emulator.WriteMemory(Teb + 0x180C, (uint)0u);

            Win32kDpi.ApplyThreadContext(Instance, Teb);
            return Teb;
        }

        /// <summary>
        /// Allocates the pair of TEBs a WOW64 thread owns and fills both views of it.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="Thread">The thread the TEBs belong to.</param>
        /// <returns>Address of the 32-bit TEB.</returns>
        private ulong AllocateAndInitializeWow64TEB(BinaryEmulator Instance, EmulatedThread Thread)
        {
            // The native TEB sits one WowTebOffset below the 32-bit one, the way a WOW64 process lays them out.
            const ulong TebSize = 0x2000;

            ulong NativeTeb = Instance.MapUniqueAddress(TebSize * 2, MemoryProtection.ReadWrite);
            if (NativeTeb == 0)
                return 0;

            ulong Teb = NativeTeb + TebSize;
            Instance._emulator.WriteMemoryByte(NativeTeb, 0, (int)(TebSize * 2));

            ulong StackBase = Thread.StackAddress + Thread.StackSize;
            ulong StackLimit = EffectiveStackLimit(Thread);

            Instance._emulator.WriteMemory(Teb + 0x0, 0xFFFFFFFFu);
            Instance._emulator.WriteMemory(Teb + 0x4, (uint)StackBase);
            Instance._emulator.WriteMemory(Teb + 0x8, (uint)StackLimit);
            Instance._emulator.WriteMemory(Teb + 0xE0C, (uint)Thread.StackAddress);
            Instance._emulator.WriteMemory(Teb + 0x18, (uint)Teb);
            Instance._emulator.WriteMemory(Teb + 0x20, WinHelper.PID);
            Instance._emulator.WriteMemory(Teb + 0x24, Thread.ThreadId);
            Instance._emulator.WriteMemory(Teb + 0x30, (uint)PEB);
            Instance._emulator.WriteMemory(Teb + 0x34, 0u);
            Instance._emulator.WriteMemory(Teb + TebWowTebOffset32, unchecked((uint)-(long)TebSize), 4);
            if (WowSyscallGate != 0)
                Instance._emulator.WriteMemory(Teb + 0xC0, (uint)WowSyscallGate);

            Instance._emulator.WriteMemory(Teb + Wow64InfoOffset, PageSize, 4);
            Instance._emulator.WriteMemory(Teb + Wow64InfoOffset + 0x04, 1u);
            Instance._emulator.WriteMemory(Teb + Wow64InfoOffset + 0x08, 0u);
            Instance._emulator.WriteMemory(Teb + Wow64InfoOffset + 0x0C, 0u);

            Instance._emulator.WriteMemory(Teb + Wow64InfoOffset + 0x20, (ushort)0x8664, 2);
            Instance._emulator.WriteMemory(Teb + Wow64InfoOffset + 0x22, (ushort)0x014C, 2);

            Instance._emulator.WriteMemory(NativeTeb + 0x08, StackBase, 8);
            Instance._emulator.WriteMemory(NativeTeb + 0x10, StackLimit, 8);
            Instance._emulator.WriteMemory(NativeTeb + 0x30, NativeTeb, 8);
            Instance._emulator.WriteMemory(NativeTeb + 0x40, (ulong)WinHelper.PID, 8);
            Instance._emulator.WriteMemory(NativeTeb + 0x48, (ulong)Thread.ThreadId, 8);
            Instance._emulator.WriteMemory(NativeTeb + 0x60, NativePEB, 8);
            Instance._emulator.WriteMemory(NativeTeb + 0x1478, Thread.StackAddress, 8);
            Instance._emulator.WriteMemory(NativeTeb + TebWowTebOffset64, (uint)TebSize, 4);

            // The WOW64 TLS slots live in the native TEB. The 32-bit ones belong to the program.
            Instance._emulator.WriteMemory(NativeTeb + NativeTebWow64InfoSlotOffset, Teb + Wow64InfoOffset, 8);

            WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
            if (State != null)
                State.NativeTeb = NativeTeb;

            Win32kDpi.ApplyThreadContext(Instance, NativeTeb);
            return Teb;
        }

        public void ResolveLdrInitializeThunk(BinaryEmulator Instance)
        {
            if (LdrInitializeThunk != 0)
                return;

            if (_ntdllModule == null)
                throw new Exception("ntdll.dll is not loaded.");

            LdrInitializeThunk = Instance.TranslateVirtualAddress(_ntdllModule.ExportsByName["LdrInitializeThunk"], "ntdll.dll");
        }

        public void ResolveRtlUserThreadStart(BinaryEmulator Instance)
        {
            if (RtlUserThreadStart != 0)
                return;

            if (_ntdllModule == null)
                throw new Exception("ntdll.dll is not loaded.");

            RtlUserThreadStart = Instance.TranslateVirtualAddress(_ntdllModule.ExportsByName["RtlUserThreadStart"], "ntdll.dll");
        }

        /// <summary>
        /// Creates a Windows thread that starts directly at the requested address without entering ntdll's user-thread startup path.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="StartAddress">Guest address to execute first.</param>
        /// <param name="Name">Optional thread name.</param>
        /// <param name="Parameter">Optional thread parameter.</param>
        /// <param name="StackSizeOverride">Optional stack size override.</param>
        /// <param name="BasePriority">Base scheduler priority.</param>
        /// <param name="CreateFlags">Thread creation flags used for TEB state.</param>
        /// <param name="InitialThread">Whether this is the initial process thread.</param>
        /// <returns>The created emulated thread.</returns>
        internal EmulatedThread CreateDirectEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name, ulong Parameter, ulong? StackSizeOverride, int BasePriority, uint CreateFlags, bool InitialThread)
        {
            ulong ThreadStackSize = StackSizeOverride ?? StackSize;
            EmulatedThread Thread = new EmulatedThread
            {
                Context = new CpuContext(),
                ThreadId = WinHelper.GenerateRandomPID(),
                Name = Name,
                State = EmulatedThreadState.Ready,
                BasePriority = BasePriority,
                DynamicBoost = 0,
                QueueLevel = 0,
                LastReadyTick = 0,
                LastRunTick = 0,
                StartAddress = StartAddress,
                Parameter = Parameter,
                StackSize = ThreadStackSize,
                StackAddress = AllocateGuardedThreadStack(Instance, ThreadStackSize, out ulong ThreadStackLimit),
                StackLimit = ThreadStackLimit,
                GuestState = new WindowsThreadState()
            };

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            Thread.Name ??= $"Thread_{Thread.ThreadId}";

            State.Teb = AllocateAndInitializeTEB(Instance, Thread, CreateFlags, InitialThread);

            ulong InitialStack = (Thread.StackAddress + Thread.StackSize) & ~0xFUL;
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                InitialStack -= 8;
                Instance._emulator.WriteMemory(InitialStack, 0UL, 8);
                InitialStack -= 0x20;
                Thread.Context.RCX = Parameter;
            }
            else
            {
                InitialStack -= 4;
                Instance._emulator.WriteMemory(InitialStack, (uint)Parameter);
                InitialStack -= 4;
                Instance._emulator.WriteMemory(InitialStack, 0u);
            }

            Thread.Context.RIP = StartAddress;
            Thread.Context.RSP = InitialStack;
            Thread.Context.RFLAGS = 0x202;
            ApplyInitialSegments(Instance, Thread.Context);
            Thread.Context.DR0 = Instance.ReadRegister(Registers.UC_X86_REG_DR0);
            Thread.Context.DR1 = Instance.ReadRegister(Registers.UC_X86_REG_DR1);
            Thread.Context.DR2 = Instance.ReadRegister(Registers.UC_X86_REG_DR2);
            Thread.Context.DR3 = Instance.ReadRegister(Registers.UC_X86_REG_DR3);
            Thread.Context.DR6 = Instance.ReadRegister(Registers.UC_X86_REG_DR6);
            Thread.Context.DR7 = Instance.ReadRegister(Registers.UC_X86_REG_DR7);

            Instance.Threads[Thread.ThreadId] = Thread;
            Instance.ThreadOrder.Add((int)Thread.ThreadId);
            if (Instance.CurrentThreadId == -1)
                Instance.CurrentThreadId = (int)Thread.ThreadId;

            return Thread;
        }

        public EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name = null!, ulong Parameter = 0, ulong? StackSizeOverride = null, int BasePriority = 8)
        {
            return CreateEmulatedThread(Instance, StartAddress, Name, Parameter, StackSizeOverride, BasePriority, 0, false);
        }

        internal EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name, ulong Parameter, ulong? StackSizeOverride, int BasePriority, uint CreateFlags, bool InitialThread)
        {
            ResolveLdrInitializeThunk(Instance);
            ResolveRtlUserThreadStart(Instance);

            ulong ThreadStackSize = StackSizeOverride ?? StackSize;
            EmulatedThread Thread = new EmulatedThread
            {
                Context = new CpuContext(),
                ThreadId = WinHelper.GenerateRandomPID(),
                Name = Name,
                State = EmulatedThreadState.Ready,
                BasePriority = BasePriority,
                DynamicBoost = 0,
                QueueLevel = 0,
                LastReadyTick = 0,
                LastRunTick = 0,
                StartAddress = StartAddress,
                Parameter = Parameter,
                StackSize = ThreadStackSize,
                StackAddress = AllocateGuardedThreadStack(Instance, ThreadStackSize, out ulong ThreadStackLimit),
                StackLimit = ThreadStackLimit,
                GuestState = new WindowsThreadState()
            };

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            Thread.Name ??= $"Thread_{Thread.ThreadId}";

            State.Teb = AllocateAndInitializeTEB(Instance, Thread, CreateFlags, InitialThread);

            Thread.Context.RIP = LdrInitializeThunk;
            Thread.Context.RFLAGS = 0x202;
            ApplyInitialSegments(Instance, Thread.Context);
            Thread.Context.DR0 = Instance.ReadRegister(Registers.UC_X86_REG_DR0);
            Thread.Context.DR1 = Instance.ReadRegister(Registers.UC_X86_REG_DR1);
            Thread.Context.DR2 = Instance.ReadRegister(Registers.UC_X86_REG_DR2);
            Thread.Context.DR3 = Instance.ReadRegister(Registers.UC_X86_REG_DR3);
            Thread.Context.DR6 = Instance.ReadRegister(Registers.UC_X86_REG_DR6);
            Thread.Context.DR7 = Instance.ReadRegister(Registers.UC_X86_REG_DR7);

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong InitialRSP = (Thread.StackAddress + Thread.StackSize) & ~0xFUL;
                InitialRSP -= 8;
                Instance._emulator.WriteMemory(InitialRSP, 0UL, 8);
                InitialRSP -= 0x20;

                ulong ContextAddress = Instance.BuildInitialContext(RtlUserThreadStart, InitialRSP, StartAddress, Parameter);
                Thread.Context.RSP = InitialRSP;
                Thread.Context.RCX = ContextAddress;
                Thread.Context.RDX = _ntdllModule?.MappedBase ?? 0;
            }
            else
            {
                ulong StackTop = (Thread.StackAddress + Thread.StackSize) & ~0xFUL;
                ulong ContextEsp = StackTop - 0x10;
                Instance._emulator.WriteMemory(ContextEsp, 0u);

                ulong ContextAddress = Instance.BuildInitialContext32(RtlUserThreadStart, ContextEsp, StartAddress, Parameter);

                ulong ThunkEsp = StackTop - 0x40;
                ThunkEsp -= 4;
                Instance._emulator.WriteMemory(ThunkEsp, (uint)(_ntdllModule?.MappedBase ?? 0));
                ThunkEsp -= 4;
                Instance._emulator.WriteMemory(ThunkEsp, (uint)ContextAddress);
                ThunkEsp -= 4;
                Instance._emulator.WriteMemory(ThunkEsp, 0u);
                Thread.Context.RSP = ThunkEsp;
            }

            Instance.Threads[Thread.ThreadId] = Thread;
            Instance.ThreadOrder.Add((int)Thread.ThreadId);
            if (Instance.CurrentThreadId == -1)
                Instance.CurrentThreadId = (int)Thread.ThreadId;

            return Thread;
        }


        public byte[] BuildEnvironment(BinaryEmulator Instance, out ulong size)
        {
            size = 0;

            string Username = WinSysHelper.CurrentUserName;
            string UserProfile = WinSysHelper.CurrentUserProfile;
            Random RandomGen = new Random();
            string PcName = $"DESKTOP-{RandomGen.Next(4, 10)}";
            Dictionary<string, string> Env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "PROCESSOR_ARCHITECTURE", Instance._binary.Architecture == BinaryArchitecture.x64 ? "AMD64" : "x86" },
                { "OS", "Windows_NT" },
                { "NUMBER_OF_PROCESSORS", Environment.ProcessorCount.ToString() },
                { "TEMP", @$"{UserProfile}\AppData\Local\Temp" },
                { "TMP",  @$"{UserProfile}\AppData\Local\Temp" },
                { "APPDATA", @$"{UserProfile}\AppData\Roaming" },
                { "LOCALAPPDATA", @$"{UserProfile}\AppData\Local" },
                { "HOMEPATH", @$"\Users\{Username}" },
                { "HOMEDRIVE", "C:" },
                { "SYSTEMDRIVE", "C:" },
                { "OneDrive", @$"{UserProfile}\OneDrive" },
                { "SESSIONNAME", "Console" },
                { "ALLUSERSPROFILE", @"C:\ProgramData" },
                { "PUBLIC", @"C:\Users\Public" },
                { "ProgramData", @"C:\ProgramData" },
                { "SYSTEMROOT", @"C:\WINDOWS" },
                { "CommonProgramFiles", @"C:\Program Files\Common Files" },
                { "CommonProgramFiles(x86)", @"C:\Program Files (x86)\Common Files" },
                { "CommonProgramW6432", @"C:\Program Files\Common Files" },
                { "ProgramFiles", @"C:\Program Files" },
                { "ProgramFiles(x86)", @"C:\Program Files (x86)" },
                { "ProgramW6432", @"C:\Program Files" },
                { "WINDIR", @"C:\WINDOWS" },
                { "USERNAME", Username },
                { "USERPROFILE", UserProfile },
                { "USERDOMAIN", PcName },
                { "USERDOMAIN_ROAMINGPROFILE", PcName },
                { "LOGONSERVER", @$"\\{PcName}" },
                { "PROCESSOR_IDENTIFIER", "Intel64 Family 6 Model 186 Stepping 2, GenuineIntel" },
                { "PROCESSOR_LEVEL", "6" },
                { "COMSPEC", @"C:\Windows\System32\cmd.exe" },
                { "PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC" },
                { "PATH", @"C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\" }
            };

            if (Instance._binary.Architecture != BinaryArchitecture.x64)
            {
                // WOW64 shows the 32-bit view in ProcessorArchitecture/ProgramFiles and the native one alongside it
                Env["PROCESSOR_ARCHITEW6432"] = "AMD64";
                Env["CommonProgramFiles"] = @"C:\Program Files (x86)\Common Files";
                Env["ProgramFiles"] = @"C:\Program Files (x86)";
            }

            // pass DXVK environment variables if available to the guest for debugging
            foreach (DictionaryEntry HostVariable in Environment.GetEnvironmentVariables())
            {
                string Name = HostVariable.Key as string;
                if (string.IsNullOrEmpty(Name))
                    continue;

                if (!Name.StartsWith("DXVK_", StringComparison.OrdinalIgnoreCase) && !Name.StartsWith("VKD3D_", StringComparison.OrdinalIgnoreCase) && !Name.StartsWith("VK_", StringComparison.OrdinalIgnoreCase) && !Name.StartsWith("SDL_", StringComparison.OrdinalIgnoreCase) && !Name.StartsWith("MONO_", StringComparison.OrdinalIgnoreCase) && !Name.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase) && !Name.StartsWith("COMPlus_", StringComparison.OrdinalIgnoreCase))
                    continue;

                Env[Name] = HostVariable.Value as string ?? string.Empty;
            }

            StringBuilder Builder = new StringBuilder(1024);
            foreach (var kv in Env)
            {
                Builder.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
            }
            Builder.Append('\0');

            byte[] EnvBytes = Encoding.Unicode.GetBytes(Builder.ToString());
            size = (ulong)EnvBytes.Length;
            return EnvBytes;
        }

        /// <summary>
        /// Ensures direct Windows blob startup has usable console standard handles before synthetic process parameters are written.
        /// </summary>
        private void EnsureDirectBlobStandardHandles()
        {
            if (WinHelper.ConsoleHandle == null)
            {
                WinFile Console = new WinFile
                {
                    Device = true,
                    Path = "\\Device\\ConDrv\\Connect",
                    ConsoleKind = ConsoleObjectKind.Connect,
                    Handler = ConsoleServer.Handle
                };
                WinHelper.ConsoleHandle = WinHelper.HandleManager.AddHandle(Console, AccessMask.GenericRead | AccessMask.GenericWrite);
            }

            if (WinHelper.STD_IN == null)
            {
                WinFile StdIn = WinSysHelper.CreateStandardHandleFile(ConsoleObjectKind.Input);
                WinHelper.STD_IN = WinHelper.HandleManager.AddHandle(StdIn, AccessMask.FileReadData);
            }

            if (WinHelper.STD_OUT == null)
            {
                WinFile StdOut = WinSysHelper.CreateStandardHandleFile(ConsoleObjectKind.Output);
                WinHelper.STD_OUT = WinHelper.HandleManager.AddHandle(StdOut, AccessMask.FileWriteData);
            }
        }

        private static void JoinGuestSession(BinaryEmulator Instance, WinModule MainModule)
        {
            string ImageName = MainModule?.Name;
            if (string.IsNullOrEmpty(ImageName))
                ImageName = GeneralHelper.IO.GetWindowsFileName(Instance.GuestImagePath ?? string.Empty);

            GuestSession.Join(
                Instance.WinHelper.PID,
                (uint)Instance._binary.Architecture,
                ImageName,
                ExitCode =>
                {
                    Instance.TriggerEventMessage($"[!] Another process in the session asked this one to stop with exit code 0x{ExitCode:X}.", LogFlags.Important);
                    GuestSession.PublishExit(ExitCode);
                    Instance.WinHelper.HideDesktopWindow();
                    Instance.StopEmulation();
                });
        }

        private static string ResolveStartupDirectory(BinaryEmulator Instance, string ImagePath)
        {
            string Directory = GeneralHelper.IO.ToGuestWindowsPath(Instance.WorkingDirectory);
            if (string.IsNullOrWhiteSpace(Directory))
                Directory = GeneralHelper.IO.GetWindowsDirectoryName(ImagePath);

            if (string.IsNullOrWhiteSpace(Directory))
                Directory = "C:\\";

            return Directory.EndsWith("\\", StringComparison.Ordinal) ? Directory : Directory + "\\";
        }

        public void PrepareWinEnvironment(BinaryEmulator Instance, WinModule MainModule)
        {
            Instance.EnsureInstructionHook();

            bool IsPeImage = Instance._binary.FileFormat == BinaryFormat.PE;
            if (IsPeImage)
                Instance.ApplyPERelocations(MainModule, Instance._binary);

            WinHelper = new WinSysHelper(Instance);
            WinHelper.X86GateArgs = !UsesDirectBlobStartup;
            if (UsesDirectBlobStartup)
                EnsureDirectBlobStandardHandles();

            WinSyscallTable = HelperFunctions.BuildWinSyscallTable(Instance._binary.Architecture);
            Win32kDpi.SeedFromImage(Instance, MainModule);
            JoinGuestSession(Instance, MainModule);

            ulong PageSize = 0x2000;
            PEB = Instance.MapUniqueAddress(PageSize, MemoryProtection.ReadWrite);
            byte[] ApiSetMapBlob = BinaryEmulator.GetApiSetMapBlob();
            if (ApiSetMapBlob.Length != 0)
            {
                ApiSetMap = Instance.MapUniqueAddress((ulong)ApiSetMapBlob.Length, MemoryProtection.Read);
                Instance._emulator.WriteMemory(ApiSetMap, ApiSetMapBlob);
            }

            InstallGdt(Instance);

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Instance._emulator.WriteMemory(PEB + 0x0, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x1, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x2, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x8, 0xFFFFFFFFFFFFFFFFUL, 8);
                Instance._emulator.WriteMemory(PEB + 0x10, MainModule.MappedBase, 8);
                Instance._emulator.WriteMemory(PEB + 0x18, 0UL, 8);
                Instance._emulator.WriteMemory(PEB + 0x30, 0UL, 8);
                Instance._emulator.WriteMemory(PEB + 0x68, ApiSetMap, 8);
                Instance._emulator.WriteMemory(PEB + 0xB8, 8, 4);
                Instance._emulator.WriteMemory(PEB + 0xBC, 0, 4);
                Instance._emulator.WriteMemory(PEB + 0x118, WindowsVersionInfo.MajorVersion, 4);
                Instance._emulator.WriteMemory(PEB + 0x11C, WindowsVersionInfo.MinorVersion, 4);
                Instance._emulator.WriteMemory(PEB + 0x120, WindowsVersionInfo.BuildNumberShort, 2);
                Instance._emulator.WriteMemory(PEB + 0x122, (ushort)0, 2);
                Instance._emulator.WriteMemory(PEB + 0x124, WindowsVersionInfo.PlatformIdWin32Nt, 4);

                if (IsPeImage)
                {
                    Instance._emulator.WriteMemory(PEB + 0xC8, Instance._binary.PE.OptionalHeader64.SizeOfHeapReserve);
                    Instance._emulator.WriteMemory(PEB + 0xD0, Instance._binary.PE.OptionalHeader64.SizeOfHeapCommit);
                }
                else if (UsesDirectBlobStartup)
                {
                    Instance._emulator.WriteMemory(PEB + 0xC8, 0x100000UL);
                    Instance._emulator.WriteMemory(PEB + 0xD0, 0x10000UL);
                }

                if (IsPeImage || UsesDirectBlobStartup)
                {
                    string ImagePath = IsPeImage
                        ? Instance.GuestImagePath
                        : (!string.IsNullOrWhiteSpace(Instance.GuestImagePath) ? Instance.GuestImagePath : (!string.IsNullOrWhiteSpace(MainModule.Path) ? MainModule.Path : (!string.IsNullOrWhiteSpace(MainModule.Name) ? MainModule.Name : "blob.bin")));
                    string CurrentDir = ResolveStartupDirectory(Instance, ImagePath);
                    string DesktopInfo = "Winsta0\\Default";
                    string WindowTitle = ImagePath;
                    string CommandLine = GeneralHelper.QuoteCommandLineArg(ImagePath);
                    if (!string.IsNullOrWhiteSpace(Instance.RawProgramArguments))
                        CommandLine += $" {Instance.RawProgramArguments}";

                    static byte[] Wz(string s) => Encoding.Unicode.GetBytes(s + "\0");

                    byte[] EnvBlock = BuildEnvironment(Instance, out ulong envSize);
                    ulong HeaderSize = 0x448;
                    ulong TotalSize = HeaderSize + (ulong)Wz(CurrentDir).Length + (ulong)Wz(ImagePath).Length + (ulong)Wz(CommandLine).Length + (ulong)Wz(WindowTitle).Length + (ulong)Wz(DesktopInfo).Length + envSize;
                    TotalSize = BinaryEmulator.AlignUp(TotalSize, 0x10);

                    ProcessParams = Instance.MapUniqueAddress(TotalSize, MemoryProtection.ReadWrite);
                    Instance._emulator.WriteMemory(ProcessParams, new byte[HeaderSize]);
                    Instance._emulator.WriteMemory(PEB + 0x20, ProcessParams, 8);
                    Instance._emulator.WriteMemory(ProcessParams + 0x410, new byte[0x38]);
                    ulong Cursor = ProcessParams + HeaderSize;

                    void WriteInlineUnicodeString(ulong StructOffset, string Value, ushort ForcedMax = 0)
                    {
                        byte[] Data = Wz(Value);
                        Instance._emulator.WriteMemory(Cursor, Data);
                        ushort Len = (ushort)(Data.Length - 2);
                        ushort Max = ForcedMax != 0 ? ForcedMax : (ushort)Data.Length;
                        Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x0, Len, 2);
                        Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x2, Max, 2);
                        Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x8, Cursor, 8);
                        Cursor += (ulong)Data.Length;
                        Cursor = BinaryEmulator.AlignUp(Cursor, 2);
                    }

                    Instance._emulator.WriteMemory(ProcessParams + 0x8, 0x6001u, 4);
                    WriteInlineUnicodeString(0x38, CurrentDir, ForcedMax: 1024);
                    if (UsesDirectBlobStartup || (IsPeImage && Instance._binary.PE.Subsystem.HasFlag(Subsystem.WindowsCui)))
                    {
                        ulong Handle = WinHelper.ConsoleHandle.Handle;
                        Instance._emulator.WriteMemory(ProcessParams + 0x10, Handle, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x18, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                        Instance._emulator.WriteMemory(ProcessParams + 0x20, WinHelper.STD_IN.Handle, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x28, WinHelper.STD_OUT.Handle, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x30, WinHelper.STD_OUT.Handle, 8);
                    }
                    WriteInlineUnicodeString(0x60, ImagePath);
                    WriteInlineUnicodeString(0x70, CommandLine);
                    ulong EnvPtr = Cursor;
                    Instance._emulator.WriteMemory(EnvPtr, EnvBlock);
                    Instance._emulator.WriteMemory(ProcessParams + 0x80, EnvPtr, 8);
                    Instance._emulator.WriteMemory(ProcessParams + 0x3F0, envSize, 8);
                    Instance._emulator.WriteMemory(ProcessParams + 0x3F8, 0UL, 8);
                    Cursor += envSize;
                    Cursor = BinaryEmulator.AlignUp(Cursor, 2);
                    WriteInlineUnicodeString(0xB0, WindowTitle);
                    WriteInlineUnicodeString(0xC0, DesktopInfo);
                    Instance._emulator.WriteMemory(ProcessParams + 0x408, 0u, 4);
                    Instance._emulator.WriteMemory(ProcessParams + 0x40C, 4u, 4);
                    uint Used = (uint)(Cursor - ProcessParams);
                    uint Length = Used < (uint)HeaderSize ? (uint)HeaderSize : Used;
                    Instance._emulator.WriteMemory(ProcessParams + 0x0, (uint)TotalSize, 4);
                    Instance._emulator.WriteMemory(ProcessParams + 0x4, Length, 4);
                }
            }
            else
            {
                Instance._emulator.WriteMemory(PEB + 0x0, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x1, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x2, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x8, (uint)MainModule.MappedBase);
                Instance._emulator.WriteMemory(PEB + 0x0C, 0u);
                Instance._emulator.WriteMemory(PEB + 0x10, 0u);
                Instance._emulator.WriteMemory(PEB + 0x38, (uint)ApiSetMap);
                Instance._emulator.WriteMemory(PEB + 0xA4, WindowsVersionInfo.MajorVersion, 4);
                Instance._emulator.WriteMemory(PEB + 0xA8, WindowsVersionInfo.MinorVersion, 4);
                Instance._emulator.WriteMemory(PEB + 0xAC, WindowsVersionInfo.BuildNumberShort, 2);
                Instance._emulator.WriteMemory(PEB + 0xAE, (ushort)0, 2);
                Instance._emulator.WriteMemory(PEB + 0xB0, WindowsVersionInfo.PlatformIdWin32Nt, 4);

                Instance._emulator.WriteMemory(PEB + 0x64, (uint)Environment.ProcessorCount);
                Instance._emulator.WriteMemory(PEB + 0x68, 0u);

                if (IsPeImage)
                {
                    ProcessParams = BuildProcessParameters32(Instance, MainModule);
                    Instance._emulator.WriteMemory(PEB + 0x10, (uint)ProcessParams);

                    uint HeapReserve = Instance._binary.PE.OptionalHeader32.SizeOfHeapReserve;
                    uint HeapCommit = Instance._binary.PE.OptionalHeader32.SizeOfHeapCommit;
                    Instance._emulator.WriteMemory(PEB + 0x78, HeapReserve != 0 ? HeapReserve : 0x100000u);
                    Instance._emulator.WriteMemory(PEB + 0x7C, HeapCommit != 0 ? HeapCommit : 0x2000u);
                    Instance._emulator.WriteMemory(PEB + 0x80, 0x10000u);
                    Instance._emulator.WriteMemory(PEB + 0x84, 0x1000u);
                    Instance._emulator.WriteMemory(PEB + 0x88, 0u);
                    Instance._emulator.WriteMemory(PEB + 0x8C, 16u);
                }

                InitializeNativePeb(Instance, MainModule);
            }

            WinHelper.AddModule(MainModule, true);
            LoadNtdll(Instance);
            if (IsPeImage && Instance._binary.Architecture != BinaryArchitecture.x64)
            {
                InstallWow64SyscallGate(Instance);
                InstallWow64SystemDllInitBlock(Instance);
                OS.Windows.NtMapViewOfSection.EnsureWindowsSharedSection(Instance);
            }
            if (UsesDirectBlobStartup)
                InstallSyntheticLdrData(Instance);
            WinHelper.LdrTracker = new PebLdrTracker(Instance, WinHelper);
            WinHelper.LdrTracker.Install();

            GuestSession.PublishStartup(PEB, ProcessParams);
        }

        private void InitializeNativePeb(BinaryEmulator Instance, WinModule MainModule)
        {
            NativePEB = Instance.MapUniqueAddress(0x2000, MemoryProtection.ReadWrite);
            if (NativePEB == 0)
                return;

            Instance._emulator.WriteMemoryByte(NativePEB, 0, 0x2000);
            Instance._emulator.WriteMemory(NativePEB + 0x10, MainModule.MappedBase, 8);
            Instance._emulator.WriteMemory(NativePEB + 0x68, ApiSetMap, 8);
            Instance._emulator.WriteMemory(NativePEB + 0xB8, (uint)Environment.ProcessorCount, 4);
            Instance._emulator.WriteMemory(NativePEB + 0x118, WindowsVersionInfo.MajorVersion, 4);
            Instance._emulator.WriteMemory(NativePEB + 0x11C, WindowsVersionInfo.MinorVersion, 4);
            Instance._emulator.WriteMemory(NativePEB + 0x120, WindowsVersionInfo.BuildNumberShort, 2);
            Instance._emulator.WriteMemory(NativePEB + 0x122, (ushort)0, 2);
            Instance._emulator.WriteMemory(NativePEB + 0x124, WindowsVersionInfo.PlatformIdWin32Nt, 4);
        }

        private ulong BuildProcessParameters32(BinaryEmulator Instance, WinModule MainModule)
        {
            string ImagePath = Instance.GuestImagePath;
            if (string.IsNullOrWhiteSpace(ImagePath))
                ImagePath = !string.IsNullOrWhiteSpace(MainModule.Path) ? MainModule.Path : (!string.IsNullOrWhiteSpace(MainModule.Name) ? MainModule.Name : "app.exe");
            string CurrentDir = ResolveStartupDirectory(Instance, ImagePath);
            string DesktopInfo = "Winsta0\\Default";
            string WindowTitle = ImagePath;
            string CommandLine = GeneralHelper.QuoteCommandLineArg(ImagePath);
            if (!string.IsNullOrWhiteSpace(Instance.RawProgramArguments))
                CommandLine += $" {Instance.RawProgramArguments}";

            static byte[] Wz(string s) => Encoding.Unicode.GetBytes(s + "\0");

            byte[] EnvBlock = BuildEnvironment(Instance, out ulong EnvSize);
            ulong HeaderSize = 0x300;
            ulong TotalSize = HeaderSize + (ulong)Wz(CurrentDir).Length + (ulong)Wz(ImagePath).Length + (ulong)Wz(CommandLine).Length + (ulong)Wz(WindowTitle).Length + (ulong)Wz(DesktopInfo).Length + EnvSize;
            TotalSize = BinaryEmulator.AlignUp(TotalSize, 0x10);

            ulong Params = Instance.MapUniqueAddress(TotalSize, MemoryProtection.ReadWrite);
            Instance._emulator.WriteMemory(Params, new byte[HeaderSize]);
            ulong Cursor = Params + HeaderSize;

            void WriteInlineUnicodeString(ulong StructOffset, string Value, ushort ForcedMax = 0)
            {
                byte[] Data = Wz(Value);
                Instance._emulator.WriteMemory(Cursor, Data);
                ushort Len = (ushort)(Data.Length - 2);
                ushort Max = ForcedMax != 0 ? ForcedMax : (ushort)Data.Length;
                Instance._emulator.WriteMemory(Params + StructOffset + 0x0, Len, 2);
                Instance._emulator.WriteMemory(Params + StructOffset + 0x2, Max, 2);
                Instance._emulator.WriteMemory(Params + StructOffset + 0x4, (uint)Cursor);
                Cursor += (ulong)Data.Length;
                Cursor = BinaryEmulator.AlignUp(Cursor, 2);
            }

            Instance._emulator.WriteMemory(Params + 0x08, 0x6001u, 4);
            WriteInlineUnicodeString(0x24, CurrentDir, ForcedMax: 1024);
            if (Instance._binary.PE.Subsystem.HasFlag(Subsystem.WindowsCui))
            {
                Instance._emulator.WriteMemory(Params + 0x10, (uint)WinHelper.ConsoleHandle.Handle);
                Instance._emulator.WriteMemory(Params + 0x18, (uint)WinHelper.STD_IN.Handle);
                Instance._emulator.WriteMemory(Params + 0x1C, (uint)WinHelper.STD_OUT.Handle);
                Instance._emulator.WriteMemory(Params + 0x20, (uint)WinHelper.STD_OUT.Handle);
            }
            WriteInlineUnicodeString(0x38, ImagePath);
            WriteInlineUnicodeString(0x40, CommandLine);
            ulong EnvPtr = Cursor;
            Instance._emulator.WriteMemory(EnvPtr, EnvBlock);
            Instance._emulator.WriteMemory(Params + 0x48, (uint)EnvPtr);
            Instance._emulator.WriteMemory(Params + 0x290, (uint)EnvSize);
            Cursor += EnvSize;
            Cursor = BinaryEmulator.AlignUp(Cursor, 2);
            WriteInlineUnicodeString(0x70, WindowTitle);
            WriteInlineUnicodeString(0x78, DesktopInfo);

            uint Used = (uint)(Cursor - Params);
            uint Length = Used < (uint)HeaderSize ? (uint)HeaderSize : Used;
            Instance._emulator.WriteMemory(Params + 0x00, (uint)TotalSize, 4);
            Instance._emulator.WriteMemory(Params + 0x04, Length, 4);
            return Params;
        }

        /// <summary>
        /// Installs a minimal PEB loader list for direct raw-blob starts where ntdll's loader entry path is intentionally skipped.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        private void InstallSyntheticLdrData(BinaryEmulator Instance)
        {
            if (WinHelper == null || WinHelper.WinModules.Count == 0)
                return;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                InstallSyntheticLdrData64(Instance);
            else
                InstallSyntheticLdrData32(Instance);
        }

        private void InstallSyntheticLdrData64(BinaryEmulator Instance)
        {
            const uint LdrSize = 0x58;
            const uint EntrySize = 0x120;
            ulong LdrData = Instance.MapUniqueAddress(LdrSize, MemoryProtection.ReadWrite);
            if (LdrData == 0)
                return;

            Instance._emulator.WriteMemoryByte(LdrData, 0, LdrSize);
            Instance._emulator.WriteMemory(LdrData + 0x0, (uint)LdrSize);
            Instance._emulator.WriteMemory(LdrData + 0x4, (byte)1, 1);

            List<ulong> Entries = new List<ulong>();
            foreach (WinModule Module in WinHelper.WinModules)
            {
                if (Module == null || Module.MappedBase == 0 || Module.SizeOfImage == 0)
                    continue;

                ulong Entry = Instance.MapUniqueAddress(EntrySize, MemoryProtection.ReadWrite);
                if (Entry == 0)
                    continue;

                Instance._emulator.WriteMemoryByte(Entry, 0, EntrySize);
                Instance._emulator.WriteMemory(Entry + 0x30, Module.MappedBase, 8);
                Instance._emulator.WriteMemory(Entry + 0x38, Module.EntryPoint, 8);
                Instance._emulator.WriteMemory(Entry + 0x40, (uint)Math.Min(Module.SizeOfImage, uint.MaxValue), 4);
                WriteUnicodeString64(Instance, Entry + 0x48, !string.IsNullOrWhiteSpace(Module.Path) ? Module.Path : GetModuleName(Module));
                WriteUnicodeString64(Instance, Entry + 0x58, GetModuleName(Module));
                Instance._emulator.WriteMemory(Entry + 0x68, 0x000022CCu, 4);
                Entries.Add(Entry);
            }

            LinkLdrList64(Instance, LdrData + 0x10, Entries, 0x00);
            LinkLdrList64(Instance, LdrData + 0x20, Entries, 0x10);
            LinkLdrList64(Instance, LdrData + 0x30, Entries, 0x20);
            Instance._emulator.WriteMemory(PEB + 0x18, LdrData, 8);
        }

        private void InstallSyntheticLdrData32(BinaryEmulator Instance)
        {
            const uint LdrSize = 0x30;
            const uint EntrySize = 0x80;
            ulong LdrData = Instance.MapUniqueAddress(LdrSize, MemoryProtection.ReadWrite);
            if (LdrData == 0)
                return;

            Instance._emulator.WriteMemoryByte(LdrData, 0, LdrSize);
            Instance._emulator.WriteMemory(LdrData + 0x0, (uint)LdrSize);
            Instance._emulator.WriteMemory(LdrData + 0x4, (byte)1, 1);

            List<ulong> Entries = new List<ulong>();
            foreach (WinModule Module in WinHelper.WinModules)
            {
                if (Module == null || Module.MappedBase == 0 || Module.SizeOfImage == 0)
                    continue;

                ulong Entry = Instance.MapUniqueAddress(EntrySize, MemoryProtection.ReadWrite);
                if (Entry == 0)
                    continue;

                Instance._emulator.WriteMemoryByte(Entry, 0, EntrySize);
                Instance._emulator.WriteMemory(Entry + 0x18, (uint)Module.MappedBase);
                Instance._emulator.WriteMemory(Entry + 0x1C, (uint)Module.EntryPoint);
                Instance._emulator.WriteMemory(Entry + 0x20, (uint)Math.Min(Module.SizeOfImage, uint.MaxValue));
                WriteUnicodeString32(Instance, Entry + 0x24, !string.IsNullOrWhiteSpace(Module.Path) ? Module.Path : GetModuleName(Module));
                WriteUnicodeString32(Instance, Entry + 0x2C, GetModuleName(Module));
                Instance._emulator.WriteMemory(Entry + 0x34, 0x000022CCu);
                Entries.Add(Entry);
            }

            LinkLdrList32(Instance, LdrData + 0x0C, Entries, 0x00);
            LinkLdrList32(Instance, LdrData + 0x14, Entries, 0x08);
            LinkLdrList32(Instance, LdrData + 0x1C, Entries, 0x10);
            Instance._emulator.WriteMemory(PEB + 0x0C, (uint)LdrData);
        }

        private void InstallWow64SyscallGate(BinaryEmulator Instance)
        {
            if (WowSyscallGate != 0)
                return;

            ulong Gate = Instance.MapUniqueAddress(0x10, MemoryProtection.ReadExecute);
            if (Gate == 0)
                return;

            Instance._emulator.WriteMemory(Gate, new byte[] { 0xCD, 0x2E, 0xC3 });
            WowSyscallGate = Gate;

            if (_ntdllModule?.ExportsByName != null && _ntdllModule.ExportsByName.TryGetValue("Wow64Transition", out ulong TransitionVa))
            {
                ulong Transition = Instance.TranslateVirtualAddress(TransitionVa, "ntdll.dll");
                if (Transition != 0)
                    Instance._emulator.WriteMemory(Transition, (uint)Gate);
            }
        }

        private static ulong MakeSegmentDescriptor(ulong Base, uint Limit, byte Access, byte Granularity)
        {
            ulong Descriptor = Limit & 0xFFFFUL;
            Descriptor |= (Base & 0xFFFFUL) << 16;
            Descriptor |= ((Base >> 16) & 0xFFUL) << 32;
            Descriptor |= (ulong)Access << 40;
            Descriptor |= ((ulong)(Limit >> 16) & 0xFUL) << 48;
            Descriptor |= (ulong)(Granularity & 0xF) << 52;
            Descriptor |= ((Base >> 24) & 0xFFUL) << 56;
            return Descriptor;
        }

        /// <summary>
        /// Fills the segment selectors a freshly created thread starts with.
        /// </summary>
        /// <remarks>
        /// Reading them off the CPU would capture whatever the syscall trap left behind, which is not a
        /// user-mode selector on every backend.
        /// </remarks>
        private void ApplyInitialSegments(BinaryEmulator Instance, CpuContext Context)
        {
            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;

            if (GuestGdt != 0)
            {
                Context.CS = GdtCodeSelector;
                Context.SS = GdtDataSelector;
                Context.DS = GdtDataSelector;
                Context.ES = GdtDataSelector;
                Context.GS = GdtDataSelector;
                Context.FS = Is64 ? GdtDataSelector : GdtFsSelector;
                return;
            }

            Context.CS = Is64 ? NtUserCodeSelector : NtUserCodeSelector32;
            Context.SS = NtUserDataSelector;
            Context.DS = NtUserDataSelector;
            Context.ES = NtUserDataSelector;
            Context.GS = NtUserDataSelector;
            Context.FS = Is64 ? NtUserDataSelector : NtUserTebSelector32;
        }

        private void InstallGdt(BinaryEmulator Instance)
        {
            if (GuestGdt != 0)
                return;

            bool LongMode = Instance._binary.Architecture == BinaryArchitecture.x64;
            if (LongMode && Instance.Settings.BackendKind != EmulationBackendKind.Unicorn)
                return;

            ulong Gdt = Instance.MapUniqueAddress(GdtSize, MemoryProtection.ReadWrite);
            if (Gdt == 0)
                return;

            byte CodeGranularity = LongMode ? GdtGranularityLongMode : GdtGranularityDefault;

            Instance._emulator.WriteMemoryByte(Gdt, 0, GdtSize);
            Instance._emulator.WriteMemory(Gdt + GdtCodeIndex * 8, MakeSegmentDescriptor(0, 0xFFFFF, GdtCodeAccess, CodeGranularity), 8);
            Instance._emulator.WriteMemory(Gdt + GdtDataIndex * 8, MakeSegmentDescriptor(0, 0xFFFFF, GdtDataAccess, GdtGranularityDefault), 8);

            if (!Instance._emulator.WriteGdtr(Gdt, GdtSize - 1))
                return;

            GuestGdt = Gdt;
        }

        private void InstallWow64SystemDllInitBlock(BinaryEmulator Instance)
        {
            if (_ntdllModule?.ExportsByName == null)
                return;

            if (!_ntdllModule.ExportsByName.TryGetValue("LdrSystemDllInitBlock", out ulong BlockVa))
                return;

            ulong Block = Instance.TranslateVirtualAddress(BlockVa, _ntdllModule);
            if (Block == 0)
                return;

            ulong Export(string Name)
            {
                return _ntdllModule.ExportsByName.TryGetValue(Name, out ulong Va)
                    ? Instance.TranslateVirtualAddress(Va, _ntdllModule)
                    : 0UL;
            }

            const int BlockSize = 0x128;
            Instance._emulator.WriteMemory(Block, new byte[BlockSize]);
            Instance._emulator.WriteMemory(Block + 0x00, (uint)BlockSize, 4);
            Instance._emulator.WriteMemory(Block + 0x08, _ntdllModule.MappedBase - _ntdllModule.OriginalBase, 8);
            Instance._emulator.WriteMemory(Block + 0x10, 0UL, 8);

            ulong Shared = Block + 0x18;
            Instance._emulator.WriteMemory(Shared + 0 * 8, Export("LdrInitializeThunk"), 8);
            Instance._emulator.WriteMemory(Shared + 1 * 8, Export("KiUserExceptionDispatcher"), 8);
            Instance._emulator.WriteMemory(Shared + 2 * 8, Export("KiUserApcDispatcher"), 8);
            Instance._emulator.WriteMemory(Shared + 3 * 8, Export("KiUserCallbackDispatcher"), 8);
            Instance._emulator.WriteMemory(Shared + 4 * 8, Export("RtlUserThreadStart"), 8);
            Instance._emulator.WriteMemory(Shared + 5 * 8, Export("RtlpQueryProcessDebugInformationRemote"), 8);
            Instance._emulator.WriteMemory(Shared + 6 * 8, _ntdllModule.MappedBase, 8);
            Instance._emulator.WriteMemory(Shared + 7 * 8, Block, 8);
            Instance._emulator.WriteMemory(Shared + 8 * 8, Export("RtlpFreezeTimeBias"), 8);

            Instance._emulator.WriteMemory(Block + 0x98, 0x11111111u, 4);
            Instance._emulator.WriteMemory(Block + 0x9C, 0x22222022u, 4);
            Instance._emulator.WriteMemory(Block + 0xA0, 0x20002000UL, 8);
            Instance._emulator.WriteMemory(Block + 0xA8, 0x00000002UL, 8);
        }

        private static string GetModuleName(WinModule Module)
        {
            if (!string.IsNullOrWhiteSpace(Module.Name))
                return Module.Name;

            if (!string.IsNullOrWhiteSpace(Module.Path))
                return Path.GetFileName(Module.Path);

            return "module.bin";
        }

        private void LinkLdrList64(BinaryEmulator Instance, ulong Head, List<ulong> Entries, ulong LinkOffset)
        {
            if (Entries.Count == 0)
            {
                Instance._emulator.WriteMemory(Head + 0x0, Head, 8);
                Instance._emulator.WriteMemory(Head + 0x8, Head, 8);
                return;
            }

            for (int i = 0; i < Entries.Count; i++)
            {
                ulong Current = Entries[i] + LinkOffset;
                ulong Next = i + 1 < Entries.Count ? Entries[i + 1] + LinkOffset : Head;
                ulong Previous = i == 0 ? Head : Entries[i - 1] + LinkOffset;
                Instance._emulator.WriteMemory(Current + 0x0, Next, 8);
                Instance._emulator.WriteMemory(Current + 0x8, Previous, 8);
            }

            Instance._emulator.WriteMemory(Head + 0x0, Entries[0] + LinkOffset, 8);
            Instance._emulator.WriteMemory(Head + 0x8, Entries[^1] + LinkOffset, 8);
        }

        private void LinkLdrList32(BinaryEmulator Instance, ulong Head, List<ulong> Entries, ulong LinkOffset)
        {
            if (Entries.Count == 0)
            {
                Instance._emulator.WriteMemory(Head + 0x0, (uint)Head);
                Instance._emulator.WriteMemory(Head + 0x4, (uint)Head);
                return;
            }

            for (int i = 0; i < Entries.Count; i++)
            {
                ulong Current = Entries[i] + LinkOffset;
                ulong Next = i + 1 < Entries.Count ? Entries[i + 1] + LinkOffset : Head;
                ulong Previous = i == 0 ? Head : Entries[i - 1] + LinkOffset;
                Instance._emulator.WriteMemory(Current + 0x0, (uint)Next);
                Instance._emulator.WriteMemory(Current + 0x4, (uint)Previous);
            }

            Instance._emulator.WriteMemory(Head + 0x0, (uint)(Entries[0] + LinkOffset));
            Instance._emulator.WriteMemory(Head + 0x4, (uint)(Entries[^1] + LinkOffset));
        }

        private void WriteUnicodeString64(BinaryEmulator Instance, ulong Address, string Value)
        {
            byte[] Data = Encoding.Unicode.GetBytes((Value ?? string.Empty) + "\0");
            ulong Buffer = Instance.MapUniqueAddress(Instance.AlignToPageSize((ulong)Math.Max(Data.Length, 2)), MemoryProtection.ReadWrite);
            if (Buffer == 0)
                return;

            Instance._emulator.WriteMemory(Buffer, Data);
            Instance._emulator.WriteMemory(Address + 0x0, (ushort)Math.Max(0, Data.Length - 2), 2);
            Instance._emulator.WriteMemory(Address + 0x2, (ushort)Data.Length, 2);
            Instance._emulator.WriteMemory(Address + 0x8, Buffer, 8);
        }

        private void WriteUnicodeString32(BinaryEmulator Instance, ulong Address, string Value)
        {
            byte[] Data = Encoding.Unicode.GetBytes((Value ?? string.Empty) + "\0");
            ulong Buffer = Instance.MapUniqueAddress(Instance.AlignToPageSize((ulong)Math.Max(Data.Length, 2)), MemoryProtection.ReadWrite);
            if (Buffer == 0)
                return;

            Instance._emulator.WriteMemory(Buffer, Data);
            Instance._emulator.WriteMemory(Address + 0x0, (ushort)Math.Max(0, Data.Length - 2), 2);
            Instance._emulator.WriteMemory(Address + 0x2, (ushort)Data.Length, 2);
            Instance._emulator.WriteMemory(Address + 0x4, (uint)Buffer);
        }

        private void LoadNtdll(BinaryEmulator Instance)
        {
            try
            {
                if (Instance._binary.Location == null && !UsesDirectBlobStartup)
                    return;

                string NtdllPath = Instance._binary.Architecture == BinaryArchitecture.x64
                    ? GeneralHelper.GetWindowsLibPath("ntdll.dll")
                    : GeneralHelper.GetWindowsLibPath("ntdll.dll", true, BinaryArchitecture.x86);

                if (!File.Exists(NtdllPath))
                {
                    string CurrentPathNtdll = Path.Combine(AppContext.BaseDirectory, "ntdll.dll");
                    if (File.Exists(CurrentPathNtdll))
                        NtdllPath = CurrentPathNtdll;
                }

                if (!File.Exists(NtdllPath))
                {
                    Instance.TriggerEventMessage("[-] ntdll.dll was not found for emulation.", LogFlags.Issues);
                    Utils.LogError("Couldn't find ntdll.dll for the windows guest environment.");
                    return;
                }

                using (BinaryFile Library = new BinaryFile(NtdllPath, true))
                {
                    _ntdllModule = Instance.LoadWinLibrary(Library, true, MapBySections: false);
                }
            }
            catch (Exception ex)
            {
                Utils.LogError($"Error while handling ntdll.dll loading for emulation: {ex.Message}");
            }
        }
    }
}
