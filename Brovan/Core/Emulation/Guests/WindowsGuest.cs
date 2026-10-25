using System;
using System.Buffers.Binary;
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
using Brovan.Core.Helpers.WindowsImage;
using static Brovan.Core.Emulation.OS.Windows.WinSysHelper;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.Guests
{
    public enum WindowsBlobLaunchMode
    {
        Ntdll = 1,
        Direct = 2
    }

    internal sealed class WindowsGuest : IGuestEnvironment
    {
        public GuestOsKind Os => GuestOsKind.Windows;

        public bool SupportsConcurrentSyscalls => true;

        public ulong StackSize { get; private set; }
        private ulong StackCommit;
        private bool RandomizeThreadStacks = true;

        private ulong StackOffsetSlots(int Range) => RandomizeThreadStacks ? (ulong)Random.Shared.Next(Range) : 0;

        public ulong PEB { get; internal set; }

        // The 64-bit PEB a WOW64 process also owns. SysWOW64 modules reach it through the TEB and read it with x64 offsets.
        public ulong NativePEB { get; internal set; }
        public ulong ProcessParams { get; internal set; }
        public ulong ApiSetMap { get; internal set; }
        public ulong ProcessActivationContext { get; internal set; }
        public AppxProcessIdentity PackageIdentity { get; private set; }
        public ulong WowSyscallGate { get; internal set; }
        public ulong GuestGdt { get; internal set; }

        private const uint GdtCodeIndex = 4;
        private const uint GdtDataIndex = 5;
        private const uint GdtFsIndex = 10;
        private const ulong GdtCodeSelector = GdtCodeIndex << 3;
        private const ulong GdtDataSelector = GdtDataIndex << 3;
        private const ulong GdtFsSelector = GdtFsIndex << 3;
        private const uint GdtSize = 0x1000;
        internal const ulong NtUserCodeSelector = 0x33;
        internal const ulong NtUserCodeSelector32 = 0x23;
        internal const ulong NtUserDataSelector = 0x2B;
        internal const ulong NtUserTebSelector32 = 0x53;
        private const byte GdtCodeAccess = 0x9B;
        private const byte GdtDataAccess = 0x93;
        private const byte GdtGranularityDefault = 0xC;
        private const byte GdtGranularityLongMode = 0xA;

        // NT: PEB BitField.
        private const byte PebIsPackagedProcess = 0x10;
        private const byte PebIsAppContainer = 0x20;

        // NT uses 30 days, and ntdll waits on critical sections with no timeout when this is over an hour.
        private const ulong CriticalSectionTimeout = unchecked((ulong)(-2592000L * 10000000));
        private const ulong ProcessParametersPackageDependencyData64 = 0x400;
        private const uint FirstLowBoxNumber = 1;

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
        private const ulong TebSameTebFlagsOffset32 = 0xFCA;
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
            StackCommit = Binary.Architecture == BinaryArchitecture.x64 ? Binary.PE.OptionalHeader64.SizeOfStackCommit : Binary.PE.OptionalHeader32.SizeOfStackCommit;

            // NT sets StackRandomizationDisabled unless the image is ASLR-relocated or IL-only (PspApplyMitigationOptions).
            RandomizeThreadStacks = Binary.PE.ILOnly || BinaryEmulator.IsDynamicallyRelocatable(Binary);
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
            if (WinHelper == null)
                return;

            if (WinHelper.WinModules.Count != 0 && Instance.Threads.TryGetValue((uint)CreateInitialThread(Instance), out EmulatedThread Thread)
                && Thread != null)
            {
                Instance.LoadContext(Thread);
                Instance.RunMlfqScheduler();
            }

            WinHelper.KernelFiles?.Dispose();
        }

        // SMP workers may still run here, so the release takes KernelLock.
        public void Shutdown(BinaryEmulator Instance)
        {
            if (WinHelper == null)
                return;

            lock (Instance.KernelLock)
            {
                WinHelper.UnloadAppHives();
                WinHelper.KernelFiles?.Dispose();
                WinHelper.DxgkProcess.ReleaseAll(Instance);
                WinHelper.RegManager.Dispose();
            }
        }

        public void OnThreadTerminated(BinaryEmulator Instance, EmulatedThread Thread)
        {
            Instance.WinHelper?.ReleaseThreadResources(Thread);
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

            // NT: a console input object is signalled while its buffer holds any record.
            if (Obj is WinFile File && File.ConsoleKind == ConsoleObjectKind.Input)
                return WinHelper.ConsoleState.HasInput(Instance);

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

            if (State.IoRequest != null)
            {
                CompleteIoRequestWait(Instance, Thread, State);
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

            ReturnFromWait(Instance, Thread, State, WaitStatus);

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
        }

        /// <summary>
        /// Restores the syscall number that a completed wait would otherwise overwrite with its status.
        /// </summary>
        private void CompleteSyscallRetry(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State)
        {
            if (Thread.Context == null)
                Thread.Context = new CpuContext();

            bool Cancelled = State.SyncIoCancelled;
            Thread.Context.RIP = Cancelled ? State.WaitResumeRIP + 2 : State.WaitResumeRIP;
            Thread.Context.RAX = Cancelled ? (ulong)(uint)NTSTATUS.STATUS_CANCELLED : State.RetrySyscallNumber;

            // Only a cancelled call returns. Otherwise the syscall runs again and needs its arguments.
            bool ExitRegisters = Cancelled && Instance.IsX64Guest;
            if (ExitRegisters)
                SetSyscallExitContext(Thread.Context);

            if (Cancelled)
            {
                State.PipeWaitHandle = 0;
                State.PipeWaitDeadline = -1;
            }

            if (Cancelled || State.SyncIo == null)
            {
                State.ResetSyncIo();
            }
            else
            {
                State.SyncIoBetweenRetries = true;
                State.SyncIoRip = State.WaitResumeRIP;
                State.SyncIoSyscall = State.RetrySyscallNumber;
            }

            State.RetrySyscallActive = false;
            State.RetrySyscallNumber = 0;
            State.HostWorkWaitActive = false;
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
                WriteWaitReturn(Instance, Thread.Context, ExitRegisters);
        }

        // The request already wrote the IO_STATUS_BLOCK.
        private static void CompleteIoRequestWait(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State)
        {
            NTSTATUS Status = State.IoRequest.Status;

            ReturnFromWait(Instance, Thread, State, Status);

            State.IoRequest = null;
            State.WaitCompleted = false;
            State.WaitStatus = Status;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.WaitObjects = null;
            State.ApcAlertable = false;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
        }

        private void CompleteIoCompletionWait(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State)
        {
            NTSTATUS WaitStatus = NTSTATUS.STATUS_TIMEOUT;
            List<WinIoCompletionEntry> Entries = State.IoCompletionReservedEntries;

            if (State.IoCompletionInformationPtr != 0)
            {
                if (!OS.Windows.NtRemoveIoCompletionEx.WriteEntries(Instance, State.IoCompletionInformationPtr, State.IoCompletionEntriesRemovedPtr, Entries))
                    WaitStatus = NTSTATUS.STATUS_ACCESS_VIOLATION;
                else if (Entries.Count > 0)
                    WaitStatus = NTSTATUS.STATUS_SUCCESS;
            }
            else if (Entries.Count > 0 && WinHelper != null)
            {
                WinIoCompletionEntry Entry = Entries[0];
                WinHelper.WritePointer(State.IoCompletionKeyContextPtr, Entry.KeyContext);
                WinHelper.WritePointer(State.IoCompletionApcContextPtr, Entry.ApcContext);
                WinHelper.WriteIoStatusBlock(Instance, State.IoCompletionIoStatusBlockPtr, Entry.IoStatus, Entry.IoStatusInformation);
                WaitStatus = NTSTATUS.STATUS_SUCCESS;
            }

            ReturnFromWait(Instance, Thread, State, WaitStatus);

            State.ResetIoCompletionWait();
            State.WaitCompleted = false;
            State.WaitStatus = WaitStatus;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.WaitObjects = null;
            State.ApcAlertable = false;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
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
            bool HasEntries = State.WorkerFactoryReservedEntries != null && State.WorkerFactoryReservedEntries.Count > 0;

            if (!HasEntries && Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
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
                    foreach (WinIoCompletionEntry Entry in State.WorkerFactoryReservedEntries)
                    {
                        if (!OS.Windows.NtWaitForWorkViaWorkerFactory.WritePacket(Instance, State.WorkerFactoryMiniPackets, Removed, Entry))
                            WaitStatus = NTSTATUS.STATUS_ACCESS_VIOLATION;
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

            ReturnFromWait(Instance, Thread, State, WaitStatus);

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
        }

        public bool ExecuteThreadSlice(BinaryEmulator Instance, EmulatedThread Thread, uint QuantumInstructions, out bool State)
        {
            State = false;
            if (Thread == null)
                return false;

            WindowsThreadState ThreadState = WinEmulatedThread.GetState(Thread);
            if (ThreadState.LoaderThunkPending)
                EnterLoaderThunk(Instance, Thread, ThreadState);

            if (WinHelper != null && WinHelper.CanDispatchUserApc(Thread))
                WinHelper.DispatchNextUserApc(Thread);

            if (ThreadState.DispatchException)
            {
                if (ThreadState.ExceptionInformation == null)
                    ThreadState.ExceptionInformation = new ExceptionInformation();

                WinHelper?.InvokeException(ThreadState.ExceptionInformation.Status, ThreadState.ExceptionInformation);

                ThreadState.DispatchException = false;
                if (Thread.State == EmulatedThreadState.Terminated)
                    return true;

                ThreadState.ReleaseHeldContext();
                State = Instance._emulator.Emulate(Instance.ReadRegister(Instance.IPRegister), 0, 0, QuantumInstructions);
                return true;
            }

            ThreadState.ReleaseHeldContext();
            State = Instance._emulator.Emulate(Thread.Context.RIP, 0, 0, QuantumInstructions);
            if (!State && Instance._emulator.GetLastError() == BackendError.Exception)
            {
                ulong EFlags = Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS);
                if ((EFlags & (ulong)CPUFlags.TF) != 0 && !ThreadState.DispatchException)
                {
                    QueueUserModeException(Instance, NTSTATUS.STATUS_SINGLE_STEP, CurrentEFlags: EFlags);
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
                        if (i == 0) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_R10);
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

        private const uint Win32kServiceBase = 0x1000;

        internal bool TryGetSyscallNumber(string Name, out uint Number)
        {
            foreach (WinSyscallEntry Entry in WinSyscallTable.Entries)
            {
                if (Entry.Name == Name)
                {
                    Number = Entry.Number;
                    return true;
                }
            }

            Number = 0;
            return false;
        }

        // Any other syscall means the thread left the I/O.
        private bool TryEndCancelledRetry(BinaryEmulator Instance, uint Syscall, ulong Rip)
        {
            WindowsThreadState State = WinEmulatedThread.TryGetState(Instance.CurrentThread);
            if (State == null)
                return false;

            bool SameCall = State.SyncIoBetweenRetries && State.SyncIoRip == Rip && State.SyncIoSyscall == Syscall;
            bool Cancelled = SameCall && State.SyncIoCancelled;
            State.SyncIoRerun = SameCall && !Cancelled;
            if (!State.SyncIoBetweenRetries)
                return false;

            State.ResetSyncIo();
            if (!Cancelled)
                return false;

            Instance.WinHelper.ClearPipeWait();
            SetLastWinErrorRegister(Instance, NTSTATUS.STATUS_CANCELLED);
            SetSyscallExitRegisters(Instance, Rip);
            return true;
        }

        // NT returns from every x64 system call with rcx, rdx and r8 to r11 set as KiSystemServiceExit sets them.
        // A waiting thread keeps its arguments for the retry, and a handler that moved RIP set its own context.
        private void SetSyscallExitRegisters(BinaryEmulator Instance, ulong SyscallRip)
        {
            if (!Instance.IsX64Guest || Instance.CurrentThread?.State == EmulatedThreadState.Waiting
                || Instance.ReadRegister(Instance.IPRegister) != SyscallRip)
                return;

            Instance._emulator.SetSyscallReturnRegisters(SyscallRip + 2);
        }

        private static void SetSyscallExitContext(CpuContext Context)
        {
            Context.RCX = Context.RIP;
            Context.R11 = Context.RFLAGS;
            Context.RDX = 0;
            Context.R8 = Context.RSP;
            Context.R9 = 0;
            Context.R10 = 0;
        }

        private static void ReturnFromWait(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State, NTSTATUS Status)
        {
            CpuContext Context = Thread.Context ??= new CpuContext();
            Context.RAX = (ulong)(uint)Status;

            bool ExitRegisters = false;
            if (State.WaitReturnRIP != 0 || State.WaitResumeRIP != 0)
            {
                Context.RIP = State.WaitReturnRIP != 0 ? State.WaitReturnRIP : State.WaitResumeRIP + 2;
                ExitRegisters = Instance.IsX64Guest;
                if (ExitRegisters)
                    SetSyscallExitContext(Context);
            }

            if (Instance.CurrentThread == Thread)
                WriteWaitReturn(Instance, Context, ExitRegisters);
        }

        private static readonly int[] WaitReturnRegisters =
        {
            (int)Registers.UC_X86_REG_RIP, (int)Registers.UC_X86_REG_RAX, (int)Registers.UC_X86_REG_RCX, (int)Registers.UC_X86_REG_R11,
            (int)Registers.UC_X86_REG_RDX, (int)Registers.UC_X86_REG_R8, (int)Registers.UC_X86_REG_R9, (int)Registers.UC_X86_REG_R10,
        };

        private static readonly int[] WaitReturnRegisters32 = { (int)Registers.UC_X86_REG_EIP, (int)Registers.UC_X86_REG_EAX };

        internal static void WriteWaitReturn(BinaryEmulator Instance, CpuContext Context, bool ExitRegisters)
        {
            ulong[] Values = Instance.RegisterScratch;
            Values[0] = Context.RIP;
            Values[1] = Context.RAX;
            if (Instance.IsX86Guest)
            {
                Instance._emulator.WriteRegisterBatch(WaitReturnRegisters32, Values, WaitReturnRegisters32.Length);
                return;
            }

            Values[2] = Context.RCX;
            Values[3] = Context.R11;
            Values[4] = Context.RDX;
            Values[5] = Context.R8;
            Values[6] = Context.R9;
            Values[7] = Context.R10;
            Instance._emulator.WriteRegisterBatch(WaitReturnRegisters, Values, ExitRegisters ? WaitReturnRegisters.Length : 2);
        }

        public bool TryHandleSyscall(BinaryEmulator Instance)
        {
            WinHelper?.LdrTracker?.SyncFromSyscall();

            try
            {
                uint Syscall = Instance._binary.Architecture == BinaryArchitecture.x64
                    ? (uint)Instance.ReadRegister(Registers.UC_X86_REG_RAX)
                    : Instance.ReadRegister32(Registers.UC_X86_REG_EAX);
                SyscallAbi Abi = Instance._binary.Architecture == BinaryArchitecture.x64 ? SyscallAbi.X64 : SyscallAbi.X86;
                ulong Rip = Instance.WinHelper != null ? Instance.WinHelper.GetSyscallRip() : Instance.ReadRegister(Instance.IPRegister);
                bool CaptureSyscallHistory = Instance.Syscalls?.TraceEnabled == true;
                ulong[] HistoryArgs = CaptureSyscallHistory ? ReadWindowsSyscallArguments(Instance, 6) : Array.Empty<ulong>();

                WinSyscallEntry Entry = WinSyscallTable.Lookup(Syscall);
                string HandlerName = Entry.Name;
                bool IsImplemented = Entry.Handler != null;

                if (TryEndCancelledRetry(Instance, Syscall, Rip))
                {
                    Instance.Settings.SyscallNotificationCallback?.Invoke(Instance.ReadRegister(Instance.IPRegister), Syscall, HandlerName, (ulong)(uint)NTSTATUS.STATUS_CANCELLED);
                    if (CaptureSyscallHistory)
                        Instance.Syscalls.RecordSyscall(GuestOsKind.Windows, Abi, Syscall, HandlerName, HistoryArgs, (ulong)(uint)NTSTATUS.STATUS_CANCELLED, Rip, IsImplemented);

                    return true;
                }

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

                NTSTATUS Status;
                if (IsImplemented)
                {
                    if (Syscall >= Win32kServiceBase)
                        Instance.WinHelper.FlushGdiBatch();

                    Instance.WinHelper.BeginSyscall();
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
                }
                else
                {
                    Status = Instance.WinUnimplemented;
                    if (Instance.Settings.SyscallNotificationCallback != null)
                    {
                        Instance.Settings.SyscallNotificationCallback.Invoke(Instance.ReadRegister(Instance.IPRegister), Syscall, null, (ulong)(uint)Status);
                    }
                    else
                    {
                        if ((Instance.Settings.Flags & LogFlags.General) != 0)
                            Instance.TriggerEventMessage($"[!] Syscall 0x{Syscall:X} not implemented. returned {Status}.", LogFlags.General);
                    }

                    if (CaptureSyscallHistory)
                        Instance.Syscalls.RecordSyscall(GuestOsKind.Windows, Abi, Syscall, HandlerName, HistoryArgs, (ulong)(uint)Status, Rip, false);
                }

                bool SuppressStatusWrite = Instance.SuppressSyscallStatusWrite || (Instance.IsX86Guest && Instance.ReadRegister(Instance.IPRegister) == Rip);
                Instance.SuppressSyscallStatusWrite = false;

                if (!SuppressStatusWrite)
                    SetLastWinErrorRegister(Instance, Status);

                SetSyscallExitRegisters(Instance, Rip);
                RaiseSysretSingleStep(Instance, Rip, Entry.Handler);
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

        // NT returns from a system call with sysretq, which traps on TF before the next instruction runs.
        private void RaiseSysretSingleStep(BinaryEmulator Instance, ulong SyscallRip, IWinSyscall Handler)
        {
            if (Instance.IsX86Guest)
                return;

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null || Thread.State is not (EmulatedThreadState.Running or EmulatedThreadState.Ready) || Thread.WaitActive
                || Thread.SwitchingContext || WinEmulatedThread.GetState(Thread).DispatchException)
                return;

            ulong EFlags = Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS);
            if ((EFlags & (ulong)CPUFlags.TF) == 0)
                return;

            if (Instance.ReadRegister(Instance.IPRegister) != SyscallRip && Handler is not NtSetContextThread)
                return;

            Span<byte> Code = stackalloc byte[2];
            if (!Instance.ReadMemory(SyscallRip, Code) || !((Code[0] == 0x0F && Code[1] == 0x05) || (Code[0] == 0xCD && Code[1] == 0x2E)))
                return;

            QueueUserModeException(Instance, NTSTATUS.STATUS_SINGLE_STEP, CurrentEFlags: EFlags);
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

        // A fetch at 0 is an access violation in NT, except on the direct blob thread, whose start routine
        // returns to 0.
        public bool EndsThreadOnNullFetch(uint ThreadId) => UsesDirectBlobStartup && ThreadId == WinHelper.InitialThreadId;

        // NT opens int 3, into, fast fail, assertion, debug service and the system call gate to ring 3 (KiInterruptInitTable).
        public bool RaisableFromUserMode(uint Vector) => Vector is 3 or 4 or 0x29 or 0x2C or 0x2D or 0x2E;

        public bool TryHandleInterrupt(BinaryEmulator Instance, uint InterruptNumber)
        {
            switch (InterruptNumber)
            {
                case 0:
                    QueueUserModeException(Instance, ClassifyDivideError(Instance));
                    return true;
                case 1:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_SINGLE_STEP);
                    return true;
                case 3:
                    Instance.WriteRegister(Instance.IPRegister, Instance.ReadRegister(Instance.IPRegister) - 1);
                    QueueUserModeException(Instance, NTSTATUS.STATUS_BREAKPOINT);
                    return true;
                case 4:
                    // NT moves the exception address back one byte, not the context RIP (KiOverflowTrap).
                    QueueUserModeException(Instance, NTSTATUS.STATUS_INTEGER_OVERFLOW,
                        new ExceptionInformation { ExceptionAddress = Instance.ReadRegister(Instance.IPRegister) - 1 });
                    return true;
                case 5:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_ARRAY_BOUNDS_EXCEEDED);
                    return true;
                case 12:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_ACCESS_VIOLATION, new ExceptionInformation
                    {
                        CustomParameters = new ulong[] { (Instance._emulator.InterruptErrorCode | 3) & 0xFFFF, 0 }
                    });
                    return true;
                case 13:
                    HandleGeneralProtectionFault(Instance);
                    return true;
                case 16:
                    return QueueX87Exception(Instance);
                case 19:
                    return QueueSimdException(Instance);
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
                case 0x2C:
                    Instance.WriteRegister(Instance.IPRegister, Instance.ReadRegister(Instance.IPRegister) - IntInstructionLength);
                    QueueUserModeException(Instance, NTSTATUS.STATUS_ASSERTION_FAILURE);
                    return true;
                case 0x2D:
                    RaiseDebugService(Instance);
                    return true;
                case 0x2E:
                    if (Instance.IsX86Guest)
                        return TryHandleSyscall(Instance);
                    HandleInt2ESyscall(Instance);
                    return true;
                default:
                    return false;
            }
        }

        // With no debugger attached, NT handles these x64 services itself and resumes after the int 3 that follows (KdpStub).
        private void RaiseDebugService(BinaryEmulator Instance)
        {
            ulong Rip = Instance.ReadRegister(Instance.IPRegister);
            ulong Service = Instance.IsX86Guest
                ? Instance.ReadRegister32(Registers.UC_X86_REG_EAX)
                : Instance.ReadRegister(Registers.UC_X86_REG_RAX);

            if (!Instance.IsX86Guest && Service is 1 or 3 or 4 or 5)
            {
                Instance.WriteRegister(Instance.IPRegister, Rip + 1);
                return;
            }

            QueueUserModeException(Instance, NTSTATUS.STATUS_BREAKPOINT, new ExceptionInformation
            {
                CustomParameters = new ulong[] { Service },
                ExceptionAddress = Rip + 1
            });
        }

        // NT sends int 2E down the same path as syscall, so the handler sees RIP on the instruction.
        private void HandleInt2ESyscall(BinaryEmulator Instance)
        {
            ulong Return = Instance.ReadRegister(Registers.UC_X86_REG_RIP);
            ulong Gate = Return - IntInstructionLength;
            Instance.WriteRegister(Registers.UC_X86_REG_RIP, Gate);

            TryHandleSyscall(Instance);

            ulong Rip = Instance.ReadRegister(Registers.UC_X86_REG_RIP);
            if (Rip != Gate)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Rip + IntInstructionLength);
                return;
            }

            Instance.WriteRegister(Registers.UC_X86_REG_RIP, Return);
            Instance.WriteRegister(Registers.UC_X86_REG_RCX, Return);
            Instance.WriteRegister(Registers.UC_X86_REG_R11, Instance.ReadRegister(Registers.UC_X86_REG_RFLAGS));
        }

        private bool QueueX87Exception(BinaryEmulator Instance)
        {
            Instance.ReadFpControl(out ulong Control, out ulong Status, out _);
            uint Pending = (uint)Status & ~((uint)Control & 0x3F);
            return QueueFloatingPointException(Instance, Pending, ExceptionInformation.SingleZeroParameter);
        }

        // WOW64 gives 32-bit code these same statuses, not the multiple-traps ones the kernel raises.
        private bool QueueSimdException(BinaryEmulator Instance)
        {
            uint Mxcsr = (uint)Instance.ReadRegister(Registers.UC_X86_REG_MXCSR);
            return QueueFloatingPointException(Instance, Mxcsr & ~(Mxcsr >> 7) & 0x3F, new ulong[] { 0, Mxcsr });
        }

        private bool QueueFloatingPointException(BinaryEmulator Instance, uint Pending, ulong[] Parameters)
        {
            NTSTATUS Status;
            if ((Pending & 0x1) != 0)
                Status = (Pending & 0x40) != 0 ? NTSTATUS.STATUS_FLOAT_STACK_CHECK : NTSTATUS.STATUS_FLOAT_INVALID_OPERATION;
            else if ((Pending & 0x4) != 0)
                Status = NTSTATUS.STATUS_FLOAT_DIVIDE_BY_ZERO;
            else if ((Pending & 0x2) != 0)
                Status = NTSTATUS.STATUS_FLOAT_INVALID_OPERATION;
            else if ((Pending & 0x8) != 0)
                Status = NTSTATUS.STATUS_FLOAT_OVERFLOW;
            else if ((Pending & 0x10) != 0)
                Status = NTSTATUS.STATUS_FLOAT_UNDERFLOW;
            else if ((Pending & 0x20) != 0)
                Status = NTSTATUS.STATUS_FLOAT_INEXACT_RESULT;
            else
                return false;

            QueueUserModeException(Instance, Status, new ExceptionInformation { CustomParameters = Parameters });
            return true;
        }

        private readonly record struct PrivilegedOpcode(bool TwoByte, byte First, int Count = 1, int Reg = -1, bool? RegisterForm = null, int Rm = -1);

        // The KiOpOneByteTable and KiOpTwoByteTable rows that NT sends to KiOp_Priv.
        private static readonly PrivilegedOpcode[] PrivilegedOpcodes =
        {
            new(TwoByte: false, First: 0xFA),
            new(TwoByte: false, First: 0xFB),
            new(TwoByte: false, First: 0xE4, Count: 4),
            new(TwoByte: false, First: 0xEC, Count: 4),
            new(TwoByte: false, First: 0x6C, Count: 4),
            new(TwoByte: false, First: 0xF4),
            new(TwoByte: true, First: 0x00, Reg: 2),
            new(TwoByte: true, First: 0x00, Reg: 3),
            new(TwoByte: true, First: 0x01, Reg: 2, RegisterForm: false),
            new(TwoByte: true, First: 0x01, Reg: 3, RegisterForm: false),
            new(TwoByte: true, First: 0x01, Reg: 6),
            new(TwoByte: true, First: 0x01, Reg: 7, RegisterForm: false),
            new(TwoByte: true, First: 0x01, Reg: 7, RegisterForm: true, Rm: 0),
            new(TwoByte: true, First: 0x06),
            new(TwoByte: true, First: 0x07),
            new(TwoByte: true, First: 0x08),
            new(TwoByte: true, First: 0x09),
            new(TwoByte: true, First: 0x20, Count: 4),
            new(TwoByte: true, First: 0x30, Count: 4),
            new(TwoByte: true, First: 0x35),
        };

        // One bit per prefix, in the order 26, 2E, 36, 3E, 64, 65, 66, 67, F0, F2, F3 and REX.
        private const uint SegmentPrefixes = 0x3F;
        private const uint OperandSizePrefix = 1u << 6;
        private const uint RepeatPrefixes = (1u << 9) | (1u << 10);
        private const uint RexPrefix = 1u << 11;

        // NT accepts a REX byte anywhere among the prefixes (KiOpPrefixTable).
        private static bool TryDecodePrefixes(BinaryEmulator Instance, ReadOnlySpan<byte> Code, out int Index, out uint Prefixes, out byte Rex)
        {
            Index = 0;
            Prefixes = 0;
            Rex = 0;
            while (Index < Code.Length)
            {
                byte Byte = Code[Index];
                uint Prefix = Byte switch
                {
                    0x26 => 1u << 0, 0x2E => 1u << 1, 0x36 => 1u << 2, 0x3E => 1u << 3, 0x64 => 1u << 4, 0x65 => 1u << 5,
                    0x66 => 1u << 6, 0x67 => 1u << 7, 0xF0 => 1u << 8, 0xF2 => 1u << 9, 0xF3 => 1u << 10,
                    _ => !Instance.IsX86Guest && (Byte & 0xF0) == 0x40 ? RexPrefix : 0,
                };
                if (Prefix == 0)
                    break;

                uint Conflicts = (Prefix & SegmentPrefixes) != 0 ? SegmentPrefixes : (Prefix & RepeatPrefixes) != 0 ? RepeatPrefixes : Prefix;
                if ((Prefixes & Conflicts) != 0)
                    return false;
                Prefixes |= Prefix;
                if (Prefix == RexPrefix)
                    Rex = Byte;
                Index++;
            }

            return Index < Code.Length;
        }

        private static readonly Registers[] SegmentOverrideRegisters =
        {
            Registers.UC_X86_REG_ES, Registers.UC_X86_REG_CS, Registers.UC_X86_REG_SS, Registers.UC_X86_REG_DS,
        };

        // NT reports a divide error with a nonzero divisor as an integer overflow (KiOp_Div).
        private static NTSTATUS ClassifyDivideError(BinaryEmulator Instance)
        {
            ulong Rip = Instance.ReadRegister(Instance.IPRegister);
            Span<byte> Code = stackalloc byte[BinaryEmulator.MaxInstructionLength];
            int Length = Instance.ReadInstructionBytes(Rip, Code);
            if (!TryDecodePrefixes(Instance, Code.Slice(0, Length), out int Index, out uint Prefixes, out byte Rex)
                || Index + 1 >= Length || Code[Index] is not (0xF6 or 0xF7))
                return NTSTATUS.STATUS_INTEGER_DIVIDE_BY_ZERO;

            int Size = Code[Index] == 0xF6 ? 1 : (Prefixes & OperandSizePrefix) != 0 ? 2 : (Rex & 8) != 0 ? 8 : 4;
            byte ModRm = Code[Index + 1];
            ulong Divisor;
            if (ModRm >> 6 == 3)
            {
                // NT reads a byte register from the low byte of its context slot, so AH reads as SPL.
                Divisor = Instance.ReadGeneralRegister((ModRm & 7) | ((Rex & 1) << 3));
            }
            else
            {
                if (!TryGetOperandAddress(Instance, Code.Slice(0, Length), Index + 2, ModRm, Prefixes, Rex, Rip, out ulong Address, out _)
                    || !NtWow64GetNativeSystemInformation.IsUserRange(Address, (ulong)Size))
                    return NTSTATUS.STATUS_INTEGER_DIVIDE_BY_ZERO;

                Span<byte> Operand = stackalloc byte[sizeof(ulong)];
                if (!Instance.ReadMemory(Address, Operand.Slice(0, Size)))
                    return NTSTATUS.STATUS_INTEGER_DIVIDE_BY_ZERO;
                Divisor = BinaryPrimitives.ReadUInt64LittleEndian(Operand);
            }

            Divisor &= BinaryEmulator.LowBytesMask(Size);
            return Divisor != 0 ? NTSTATUS.STATUS_INTEGER_OVERFLOW : NTSTATUS.STATUS_INTEGER_DIVIDE_BY_ZERO;
        }

        // NT does not truncate the address to the address size (KiOpRetrieveRegMemAddress).
        private static bool TryGetOperandAddress(BinaryEmulator Instance, ReadOnlySpan<byte> Code, int Index, byte ModRm,
            uint Prefixes, byte Rex, ulong Rip, out ulong Address, out int End)
        {
            Address = 0;
            End = Index;
            int Mod = ModRm >> 6;
            int Rm = ModRm & 7;
            ulong Base = 0;
            ulong Scaled = 0;
            bool RipRelative = false;

            if (Rm == 4)
            {
                if (Index >= Code.Length)
                    return false;
                byte Sib = Code[Index++];
                if ((Sib & 7) != 5 || Mod != 0)
                    Base = Instance.ReadGeneralRegister((Sib & 7) | ((Rex & 1) << 3));
                int ScaledIndex = ((Sib >> 3) & 7) | ((Rex & 2) << 2);
                if (ScaledIndex != 4)
                    Scaled = Instance.ReadGeneralRegister(ScaledIndex) << (Sib >> 6);
            }
            else if (Mod == 0 && Rm == 5)
            {
                RipRelative = !Instance.IsX86Guest;
            }
            else
            {
                Base = Instance.ReadGeneralRegister(Rm | ((Rex & 1) << 3));
            }

            long Displacement = 0;
            if ((Mod == 0 && Rm == 5) || Mod == 2)
            {
                if (Index + sizeof(int) > Code.Length)
                    return false;
                Displacement = BinaryPrimitives.ReadInt32LittleEndian(Code.Slice(Index));
                Index += sizeof(int);
            }
            else if (Mod == 1)
            {
                if (Index >= Code.Length)
                    return false;
                Displacement = (sbyte)Code[Index++];
            }

            End = Index;
            if (RipRelative)
                Base = Rip + (ulong)Index;
            Address = Base + Scaled + (ulong)Displacement;

            if ((Prefixes & SegmentPrefixes) == 0)
                return true;

            int Segment = System.Numerics.BitOperations.TrailingZeroCount(Prefixes & SegmentPrefixes);
            if (Segment == 4)
                Address += Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE);
            else if (Segment == 5)
                Address += Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE);
            else if (Instance.IsX86Guest && (ulong)(ushort)Instance.ReadRegister(SegmentOverrideRegisters[Segment]) is not (NtUserCodeSelector32 or NtUserDataSelector or NtUserCodeSelector))
                return false;
            return true;
        }

        // The tables NT reports for sidt and sgdt under UMIP (KiOpIdtr, KiOpGdtr).
        private const ushort UmipIdtLimit = 0x0FFF;
        private const ulong UmipIdtBase = 0xFFFFF80000001000;
        private const ushort UmipGdtLimit = 0x007F;
        private const ulong UmipGdtBase = 0xFFFFF8534B590000;
        private const ulong UmipTaskRegister = 0x40;

        private const ulong UmipMachineStatusWord = 0x80050033;

        private void HandleGeneralProtectionFault(BinaryEmulator Instance)
        {
            ulong Rip = Instance.ReadRegister(Instance.IPRegister);
            Span<byte> Code = stackalloc byte[BinaryEmulator.MaxInstructionLength];
            Code = Code.Slice(0, Instance.ReadInstructionBytes(Rip, Code));
            if (TryDecodePrefixes(Instance, Code, out int Index, out uint Prefixes, out byte Rex))
            {
                if (Instance._emulator.UmipEnabled && TryEmulateDescriptorStore(Instance, Rip, Code, Index, Prefixes, Rex))
                    return;

                if (IsPrivilegedInstruction(Code, Index))
                {
                    HandlePrivilegedInstruction(Instance);
                    return;
                }
            }

            QueueUserModeException(Instance, NTSTATUS.STATUS_ACCESS_VIOLATION,
                new ExceptionInformation { Type = ExceptionType.Read, Address = ulong.MaxValue });
        }

        private bool TryEmulateDescriptorStore(BinaryEmulator Instance, ulong Rip, ReadOnlySpan<byte> Code, int Index, uint Prefixes, byte Rex)
        {
            if (Index + 2 >= Code.Length || Code[Index] != 0x0F)
                return false;

            byte Opcode = Code[Index + 1];
            byte ModRm = Code[Index + 2];
            int Reg = (ModRm >> 3) & 7;
            bool Register = ModRm >> 6 == 3;
            bool Table = Opcode == 0x01 && (Reg is 0 or 1) && !Register;
            bool Selector = (Opcode == 0x00 && (Reg is 0 or 1)) || (Opcode == 0x01 && Reg == 4);
            if (!Table && !Selector)
                return false;

            ulong Address = 0;
            int End = Index + 3;
            if (!Register && !TryGetOperandAddress(Instance, Code, Index + 3, ModRm, Prefixes, Rex, Rip, out Address, out End))
            {
                RaiseStoreFault(Instance, ulong.MaxValue);
                return true;
            }

            if (Table)
            {
                Span<byte> Descriptor = stackalloc byte[10];
                BinaryPrimitives.WriteUInt16LittleEndian(Descriptor, Reg == 1 ? UmipIdtLimit : UmipGdtLimit);
                BinaryPrimitives.WriteUInt64LittleEndian(Descriptor.Slice(2), Reg == 1 ? UmipIdtBase : UmipGdtBase);
                int Size = Instance.IsX86Guest ? 6 : 10;
                if (!TryStoreToUser(Instance, Address, Descriptor.Slice(0, Size), Size))
                {
                    RaiseStoreFault(Instance, Address);
                    return true;
                }
            }
            else
            {
                ulong Value = Opcode == 0x01 ? UmipMachineStatusWord : Reg == 1 ? UmipTaskRegister : 0;
                int OperandSize = (Prefixes & OperandSizePrefix) != 0 ? 2 : Instance.IsX86Guest ? 4 : 8;
                if (Register)
                {
                    Instance.WriteGeneralRegister((ModRm & 7) | ((Rex & 1) << 3), Value, OperandSize);
                }
                else
                {
                    Span<byte> Word = stackalloc byte[sizeof(ushort)];
                    BinaryPrimitives.WriteUInt16LittleEndian(Word, (ushort)Value);
                    if (!TryStoreToUser(Instance, Address, Word, OperandSize))
                    {
                        RaiseStoreFault(Instance, Address);
                        return true;
                    }
                }
            }

            Instance.WriteRegister(Instance.IPRegister, Rip + (ulong)End);
            return true;
        }

        // NT checks the full operand size against the user range, then may store fewer bytes.
        private static bool TryStoreToUser(BinaryEmulator Instance, ulong Address, ReadOnlySpan<byte> Data, int CheckedSize)
            => NtWow64GetNativeSystemInformation.IsUserRange(Address, (ulong)CheckedSize) && Instance.IsAccessible(Address, (ulong)Data.Length, true) && Instance.WriteMemory(Address, Data);

        internal void RaiseStoreFault(BinaryEmulator Instance, ulong Address)
        {
            QueueUserModeException(Instance, NTSTATUS.STATUS_ACCESS_VIOLATION,
                new ExceptionInformation { Type = ExceptionType.Write, Address = Address });
        }

        private static bool IsPrivilegedInstruction(ReadOnlySpan<byte> Code, int Index)
        {
            bool TwoByte = false;
            byte Opcode = Code[Index++];
            if (Opcode == 0x0F)
            {
                if (Index >= Code.Length)
                    return false;
                TwoByte = true;
                Opcode = Code[Index++];
            }

            foreach (PrivilegedOpcode Row in PrivilegedOpcodes)
            {
                if (Row.TwoByte != TwoByte || Opcode < Row.First || Opcode >= Row.First + Row.Count)
                    continue;

                if (Row.Reg < 0 && Row.RegisterForm == null && Row.Rm < 0)
                    return true;
                if (Index >= Code.Length)
                    return false;

                byte ModRm = Code[Index];
                if (Row.Reg >= 0 && ((ModRm >> 3) & 7) != Row.Reg)
                    continue;
                if (Row.Rm >= 0 && (ModRm & 7) != Row.Rm)
                    continue;
                if (Row.RegisterForm is bool RegisterForm && (ModRm >> 6 == 3) != RegisterForm)
                    continue;
                return true;
            }

            return false;
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

        public void QueueUserModeException(BinaryEmulator Instance, NTSTATUS Status, ExceptionInformation Info = null!, ulong? CurrentEFlags = null)
        {
            if (Instance._binary == null || (!IsBlob && Instance._binary.FileFormat != BinaryFormat.PE))
                return;

            if (Status == NTSTATUS.STATUS_SINGLE_STEP)
            {
                ulong EFlags = CurrentEFlags ?? Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS);

                if ((EFlags & (ulong)CPUFlags.TF) != 0)
                {
                    Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, EFlags & ~(ulong)CPUFlags.TF);
                    ulong Dr6 = Instance.ReadRegister(Registers.UC_X86_REG_DR6);
                    if ((Dr6 & (DebugStatus.BreakpointHits | DebugStatus.SingleStep)) == 0)
                        Instance.WriteRegister(Registers.UC_X86_REG_DR6, Dr6 | DebugStatus.SingleStep);
                }
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

        // NT fills the PEB heap segment sizes from the system defaults, not from the image header (MmCreatePeb).
        private const ulong HeapSegmentReserve = 0x100000;
        private const ulong HeapSegmentCommit = 0x2000;

        private const ulong DefaultStackCommit = 0x4000;

        // NT commits the requested size, or the image's, with the guard pages below it (RtlCreateUserStack).
        private ulong AllocateGuardedThreadStack(BinaryEmulator Instance, ulong StackSize, ulong StackCommitOverride, out ulong StackLimit)
        {
            const uint PAGE_READWRITE = 0x04;
            const uint PAGE_GUARD = 0x100;

            StackLimit = 0;

            ulong GuardSize = Instance.StackGuardSize;
            ulong Commit = StackCommitOverride != 0 ? StackCommitOverride : StackCommit;
            ulong CommitSize = Instance.AlignToPageSize(Commit != 0 ? Commit : DefaultStackCommit);
            ulong Reserve = Instance.AlignToPageSize(StackSize);

            // Deliberately not allocate. its finder starts at 4 GB for x64 guests,
            // which puts the stack nowhere near the rest of the address space Brovan hands out.
            if (Instance.WinHelper != null && Reserve >= GuardSize + CommitSize &&
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
            ushort SameTebFlags = BuildSameTebFlags(CreateFlags, InitialThread);
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return AllocateAndInitializeWow64TEB(Instance, Thread, SameTebFlags);

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
            Instance._emulator.WriteMemory(Teb + TebSameTebFlagsOffset64, SameTebFlags, 2);
            Instance._emulator.WriteMemory(Teb + 0x180C, (uint)0u);

            Win32kDpi.ApplyThreadContext(Instance, Teb);
            return Teb;
        }

        private static ushort BuildSameTebFlags(uint CreateFlags, bool InitialThread)
        {
            ushort SameTebFlags = 0;
            if (InitialThread)
                SameTebFlags |= TEB_SAME_TEB_FLAG_INITIAL_THREAD;
            if ((CreateFlags & THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_SKIP_THREAD_ATTACH;
            if ((CreateFlags & THREAD_CREATE_FLAGS_LOADER_WORKER) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_LOADER_WORKER;
            if ((CreateFlags & THREAD_CREATE_FLAGS_SKIP_LOADER_INIT) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_SKIP_LOADER_INIT;

            return SameTebFlags;
        }

        /// <summary>
        /// Allocates the pair of TEBs a WOW64 thread owns and fills both views of it.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="Thread">The thread the TEBs belong to.</param>
        /// <returns>Address of the 32-bit TEB.</returns>
        private ulong AllocateAndInitializeWow64TEB(BinaryEmulator Instance, EmulatedThread Thread, ushort SameTebFlags)
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
            Instance._emulator.WriteMemory(Teb + TebSameTebFlagsOffset32, SameTebFlags, 2);
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
            Instance._emulator.WriteMemory(NativeTeb + TebSameTebFlagsOffset64, SameTebFlags, 2);
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
                ThreadId = NewThreadId(Instance, InitialThread),
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
                StackAddress = AllocateGuardedThreadStack(Instance, ThreadStackSize, 0, out ulong ThreadStackLimit),
                StackLimit = ThreadStackLimit,
                GuestState = NewThreadState(Instance)
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

            Instance.Threads[Thread.ThreadId] = Thread;
            Instance.ThreadOrder.Add((int)Thread.ThreadId);
            if (Instance.CurrentThreadId == -1)
                Instance.CurrentThreadId = (int)Thread.ThreadId;

            return Thread;
        }

        // WOW64 reads a new thread's EFLAGS from its CPU area, not the trap frame.
        private static WindowsThreadState NewThreadState(BinaryEmulator Instance)
            => new WindowsThreadState { CreateTime = Instance.GetEmulatedSystemTimeFileTimeUtc(), EFlagsFromContext = Instance.IsX64Guest };

        private uint NewThreadId(BinaryEmulator Instance, bool InitialThread)
        {
            uint Reserved = WinHelper.InitialThreadId;
            if (InitialThread && Reserved != 0 && !Instance.Threads.ContainsKey(Reserved))
                return Reserved;

            return WinHelper.GenerateRandomPID();
        }

        public EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name = null!, ulong Parameter = 0, ulong? StackSizeOverride = null, int BasePriority = 8)
        {
            return CreateEmulatedThread(Instance, StartAddress, Name, Parameter, StackSizeOverride, BasePriority, 0, false);
        }

        internal EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name, ulong Parameter, ulong? StackSizeOverride, int BasePriority, uint CreateFlags, bool InitialThread, ulong StackCommitOverride = 0)
        {
            ResolveLdrInitializeThunk(Instance);
            ResolveRtlUserThreadStart(Instance);

            ulong ThreadStackSize = StackSizeOverride ?? StackSize;
            EmulatedThread Thread = new EmulatedThread
            {
                Context = new CpuContext(),
                ThreadId = NewThreadId(Instance, InitialThread),
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
                StackAddress = AllocateGuardedThreadStack(Instance, ThreadStackSize, StackCommitOverride, out ulong ThreadStackLimit),
                StackLimit = ThreadStackLimit,
                GuestState = NewThreadState(Instance)
            };

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            Thread.Name ??= $"Thread_{Thread.ThreadId}";

            State.Teb = AllocateAndInitializeTEB(Instance, Thread, CreateFlags, InitialThread);
            State.LoaderThunkPending = true;

            Thread.Context.RIP = RtlUserThreadStart;
            Thread.Context.RFLAGS = 0x202;
            ApplyInitialSegments(Instance, Thread.Context);

            // NT starts a thread up to 0x7F0 bytes below its stack base, 0x7FC on a WOW64 stack (PspSetupUserStack).
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong InitialRSP = ((Thread.StackAddress + Thread.StackSize) & ~0xFUL) - 16UL * StackOffsetSlots(0x80);
                InitialRSP -= 8;
                Instance._emulator.WriteMemory(InitialRSP, 0UL, 8);
                InitialRSP -= 0x20;

                Thread.Context.RSP = InitialRSP;
                Thread.Context.RCX = StartAddress;
                Thread.Context.RDX = Parameter;
            }
            else
            {
                ulong ContextEsp = ((Thread.StackAddress + Thread.StackSize) & ~0xFUL) - 0x10 - 4UL * StackOffsetSlots(0x200);
                Instance._emulator.WriteMemory(ContextEsp, 0u);

                Thread.Context.RSP = ContextEsp;
                Thread.Context.RAX = StartAddress;
                Thread.Context.RBX = Parameter;
            }

            Instance.Threads[Thread.ThreadId] = Thread;
            Instance.ThreadOrder.Add((int)Thread.ThreadId);
            if (Instance.CurrentThreadId == -1)
                Instance.CurrentThreadId = (int)Thread.ThreadId;

            return Thread;
        }

        // The length RtlGetExtendedContextLength2 gives for CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS.
        private const ulong LoaderThunkContextLength = WindowsThreadContext64.ContextExOffset + WindowsThreadContext64.ContextExSize + 15;

        private void EnterLoaderThunk(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State)
        {
            State.LoaderThunkPending = false;
            bool X64 = Instance.IsX64Guest;
            CpuContext ThreadContext = Thread.Context;
            ulong UserSp = ThreadContext.RSP;

            ulong Length, Context, Sp, FrameBase;
            uint Flags;
            if (X64)
            {
                Length = LoaderThunkContextLength;
                Context = (UserSp - Length) & ~0xFUL;
                Sp = Context - 0x28;
                FrameBase = Context;
                Flags = WindowsThreadContext64.CONTEXT_AMD64 | WindowsThreadContext64.CONTEXT_CONTROL | WindowsThreadContext64.CONTEXT_INTEGER
                    | WindowsThreadContext64.CONTEXT_FLOATING_POINT | WindowsThreadContext64.CONTEXT_DEBUG_REGISTERS;
            }
            else
            {
                Length = WindowsThreadContext64.MinimumContextSize32;
                Context = (UserSp - Length) & ~3UL;
                Sp = Context - 0x10;
                FrameBase = Sp;
                Flags = WindowsThreadContext64.CONTEXT_I386 | WindowsThreadContext64.CONTEXT_CONTROL | WindowsThreadContext64.CONTEXT_INTEGER
                    | WindowsThreadContext64.CONTEXT_SEGMENTS | WindowsThreadContext64.CONTEXT_DEBUG_REGISTERS;
            }

            ulong FaultAddress = FrameBase;
            if (Context > UserSp || WinHelper?.TryMapUserFrame(FrameBase, Context + Length - FrameBase, out FaultAddress) != true)
            {
                RaiseStoreFault(Instance, FaultAddress);
                return;
            }

            WindowsThreadContext64.WriteContext(Instance, Thread, Context, Flags, ContextSource.SavedContext);
            ulong NtdllBase = _ntdllModule?.MappedBase ?? 0;
            if (X64)
            {
                ThreadContext.RCX = Context;
                ThreadContext.RDX = NtdllBase;
            }
            else
            {
                Instance._emulator.WriteMemory(Sp + 4, (ulong)(uint)Context | (ulong)(uint)NtdllBase << 32, 8);
            }

            ThreadContext.RSP = Sp;
            ThreadContext.RIP = LdrInitializeThunk;
            Instance.WriteGprBatch(ThreadContext);
        }


        private const string GuestVariablePrefix = "BROVAN_GUEST_";

        public byte[] BuildEnvironment(BinaryEmulator Instance, out ulong size)
        {
            byte[] Inherited = Instance.WinHelper?.InheritedEnvironment;
            if (Inherited != null)
            {
                size = (ulong)Inherited.Length;
                return Inherited;
            }

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
                { "SYSTEMROOT", WindowsVersionInfo.SystemRoot },
                { "CommonProgramFiles", @"C:\Program Files\Common Files" },
                { "CommonProgramFiles(x86)", @"C:\Program Files (x86)\Common Files" },
                { "CommonProgramW6432", @"C:\Program Files\Common Files" },
                { "ProgramFiles", @"C:\Program Files" },
                { "ProgramFiles(x86)", @"C:\Program Files (x86)" },
                { "ProgramW6432", @"C:\Program Files" },
                { "WINDIR", WindowsVersionInfo.SystemRoot },
                { "USERNAME", Username },
                { "USERPROFILE", UserProfile },
                { "USERDOMAIN", PcName },
                { "USERDOMAIN_ROAMINGPROFILE", PcName },
                { "LOGONSERVER", @$"\\{PcName}" },
                { "PROCESSOR_IDENTIFIER", "Intel64 Family 6 Model 186 Stepping 2, GenuineIntel" },
                { "PROCESSOR_LEVEL", "6" },
                { "COMSPEC", @$"{WindowsVersionInfo.SystemRoot}\system32\cmd.exe" },
                { "PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC" },
                { "PATH", @$"{WindowsVersionInfo.SystemRoot}\system32;{WindowsVersionInfo.SystemRoot};{WindowsVersionInfo.SystemRoot}\System32\Wbem;{WindowsVersionInfo.SystemRoot}\System32\WindowsPowerShell\v1.0\;{WindowsVersionInfo.SystemRoot}\System32\OpenSSH\" }
            };

            if (Instance.WinHelper != null && Instance.WinHelper.Steam != null && Instance.WinHelper.Steam.Enabled)
            {
                Env["SteamAppId"] = Instance.WinHelper.Steam.AppId.ToString();
                Env["SteamGameId"] = Instance.WinHelper.Steam.AppId.ToString();
            }

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

                if (Name.Length > GuestVariablePrefix.Length && Name.StartsWith(GuestVariablePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    Env[Name.Substring(GuestVariablePrefix.Length)] = HostVariable.Value as string ?? string.Empty;
                    continue;
                }

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
            WinHelper.ConsoleHandle ??= WinHelper.HandleManager.AddHandle(WinSysHelper.CreateConsoleObject(ConsoleObjectKind.Connect), AccessMask.GenericRead | AccessMask.GenericWrite);
            WinHelper.AddConsoleStandardHandles();
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
                    Utils.SetGuestExitCode(ExitCode);
                    Instance.RequestTermination();
                });
        }

        private AppxProcessIdentity CreatePackageIdentity(BinaryEmulator Instance)
        {
            AppxProcessIdentity Identity = AppxPackageModel.TryCreate(Instance, WinHelper, Instance.GuestImagePath);
            if (Identity == null)
                return null;

            if (Instance._binary.Architecture != BinaryArchitecture.x64)
            {
                Utils.LogError($"[-] AppX: package identity for x86 images is not implemented, {Identity.Package.FullName} runs without it.");
                return null;
            }

            WinToken Token = WinHelper.OwnProcess?.PrimaryToken;
            if (Token == null)
                return null;

            Token.SecurityAttributes = Identity.SecurityAttributes;
            if (Identity.IsAppContainer)
            {
                Token.AppContainerSid = Identity.AppContainerSid;
                Token.AppContainerNumber = FirstLowBoxNumber;
                Token.CapabilitySids = Identity.CapabilitySids;
                WinHelper.CreateAppContainerNamedObjects(NtQueryInformationToken.FormatSid(Identity.AppContainerSid));
            }

            AppxPackageModel.PublishRegistration(Instance, WinHelper, Identity);
            UseSystemGraphicsLibraries();
            return Identity;
        }

        private static void UseSystemGraphicsLibraries()
        {
            HashSet<string> DxvkNames = DxvkImporter.ReadInstalledNames(AppContext.BaseDirectory);
            if (DxvkNames == null)
            {
                if (DxvkImporter.IsInstalled(AppContext.BaseDirectory))
                    Utils.LogError("[-] AppX: DXVK is installed without dxvk.files, so its DLLs in VirtualFS System32 still load in this packaged process. Run --install-dxvk to write the list.");
                return;
            }

            GeneralHelper.IO.SystemCopyNames = DxvkNames;
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
            WinHelper.KernelFiles = KernelFileTable.TryCreate(Instance);
            WinHelper.KernelFileReads = KernelFileReads.TryCreate(Instance, this, WinHelper.KernelFiles);
            WinHelper.KernelFileInformation = KernelFileInformation.TryCreate(Instance, this, WinHelper.KernelFiles);
            if (WinHelper.KernelFiles != null)
                Instance.RefreshGuestKernel();
            Win32kDpi.SeedFromImage(Instance, MainModule);
            JoinGuestSession(Instance, MainModule);

            if (IsPeImage)
                PackageIdentity = CreatePackageIdentity(Instance);

            ulong PageSize = 0x2000;
            PEB = Instance.MapUniqueAddress(PageSize, MemoryProtection.ReadWrite);
            ProcessActivationContext = WinSxS.BuildProcessActivationContext(Instance, MainModule);
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
                if (PackageIdentity != null)
                    Instance._emulator.WriteMemory(PEB + 0x3, (byte)(PebIsPackagedProcess | (PackageIdentity.IsAppContainer ? PebIsAppContainer : 0)), 1);
                Instance._emulator.WriteMemory(PEB + 0x8, 0xFFFFFFFFFFFFFFFFUL, 8);
                Instance._emulator.WriteMemory(PEB + 0x10, MainModule.MappedBase, 8);
                Instance._emulator.WriteMemory(PEB + 0x18, 0UL, 8);
                Instance._emulator.WriteMemory(PEB + 0x30, 0UL, 8);
                Instance._emulator.WriteMemory(PEB + 0x68, ApiSetMap, 8);
                Instance._emulator.WriteMemory(PEB + 0xB8, WinHelper.ProcessorCount, 4);
                Instance._emulator.WriteMemory(PEB + 0xBC, 0, 4);
                Instance._emulator.WriteMemory(PEB + 0xC0, CriticalSectionTimeout, 8);
                Instance._emulator.WriteMemory(PEB + 0xD8, 0x10000UL, 8);
                Instance._emulator.WriteMemory(PEB + 0xE0, 0x1000UL, 8);
                Instance._emulator.WriteMemory(PEB + 0x118, WindowsVersionInfo.MajorVersion, 4);
                Instance._emulator.WriteMemory(PEB + 0x11C, WindowsVersionInfo.MinorVersion, 4);
                Instance._emulator.WriteMemory(PEB + 0x120, WindowsVersionInfo.BuildNumberShort, 2);
                Instance._emulator.WriteMemory(PEB + 0x122, (ushort)0, 2);
                Instance._emulator.WriteMemory(PEB + 0x124, WindowsVersionInfo.PlatformIdWin32Nt, 4);
                Instance._emulator.WriteMemory(PEB + 0x2C0, WinToken.InteractiveSessionId, 4);
                Instance._emulator.WriteMemory(PEB + WinSxS.PebActivationContextData64, ProcessActivationContext, 8);

                if (IsPeImage || UsesDirectBlobStartup)
                {
                    Instance._emulator.WriteMemory(PEB + 0xC8, HeapSegmentReserve);
                    Instance._emulator.WriteMemory(PEB + 0xD0, HeapSegmentCommit);

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
                    string DllPath = PackageIdentity?.LoaderSearchPath ?? string.Empty;
                    ulong HeaderSize = 0x450;
                    ulong TotalSize = HeaderSize + (ulong)Wz(CurrentDir).Length + (ulong)Wz(DllPath).Length + (ulong)Wz(ImagePath).Length + (ulong)Wz(CommandLine).Length + (ulong)Wz(WindowTitle).Length + (ulong)Wz(DesktopInfo).Length + envSize;
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
                    bool ConsoleApp = UsesDirectBlobStartup || (IsPeImage && Instance._binary.PE.Subsystem.HasFlag(Subsystem.WindowsCui));
                    if (ConsoleApp)
                    {
                        ulong Handle = WinHelper.ConsoleHandle.Handle;
                        Instance._emulator.WriteMemory(ProcessParams + 0x10, Handle, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x18, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                    }

                    if (ConsoleApp || WinHelper.InheritedStandardHandles)
                    {
                        Instance._emulator.WriteMemory(ProcessParams + 0x20, WinHelper.STD_IN?.Handle ?? 0, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x28, WinHelper.STD_OUT?.Handle ?? 0, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x30, WinHelper.STD_ERR?.Handle ?? 0, 8);
                    }
                    if (DllPath.Length != 0)
                        WriteInlineUnicodeString(0x50, DllPath);
                    WriteInlineUnicodeString(0x60, ImagePath);
                    WriteInlineUnicodeString(0x70, CommandLine);
                    ulong EnvPtr = Cursor;
                    Instance._emulator.WriteMemory(EnvPtr, EnvBlock);
                    Instance._emulator.WriteMemory(ProcessParams + 0x80, EnvPtr, 8);
                    Instance._emulator.WriteMemory(ProcessParams + 0x3F0, envSize, 8);
                    Instance._emulator.WriteMemory(ProcessParams + 0x3F8, 0UL, 8);
                    if (PackageIdentity != null)
                    {
                        ulong DependencyData = WinHelper.MapUnnamedSectionView(PackageIdentity.DependencyMiniRepository, MemoryProtection.Read);
                        if (DependencyData == 0)
                            Utils.LogError("[-] AppX: the dependency mini repository could not be mapped.");
                        Instance._emulator.WriteMemory(ProcessParams + ProcessParametersPackageDependencyData64, DependencyData, 8);
                    }
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
                Instance._emulator.WriteMemory(PEB + 0x1D4, WinToken.InteractiveSessionId, 4);
                Instance._emulator.WriteMemory(PEB + WinSxS.PebActivationContextData32, (uint)ProcessActivationContext);

                Instance._emulator.WriteMemory(PEB + 0x64, WinHelper.ProcessorCount);
                Instance._emulator.WriteMemory(PEB + 0x68, 0u);
                Instance._emulator.WriteMemory(PEB + 0x70, CriticalSectionTimeout, 8);

                if (IsPeImage)
                {
                    ProcessParams = BuildProcessParameters32(Instance, MainModule);
                    Instance._emulator.WriteMemory(PEB + 0x10, (uint)ProcessParams);

                    Instance._emulator.WriteMemory(PEB + 0x78, (uint)HeapSegmentReserve);
                    Instance._emulator.WriteMemory(PEB + 0x7C, (uint)HeapSegmentCommit);
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

            GuestSession.PublishStartup(PEB, ProcessParams, WinHelper.InitialThreadId);
        }

        private void InitializeNativePeb(BinaryEmulator Instance, WinModule MainModule)
        {
            NativePEB = Instance.MapUniqueAddress(0x2000, MemoryProtection.ReadWrite);
            if (NativePEB == 0)
                return;

            Instance._emulator.WriteMemoryByte(NativePEB, 0, 0x2000);
            Instance._emulator.WriteMemory(NativePEB + 0x10, MainModule.MappedBase, 8);
            Instance._emulator.WriteMemory(NativePEB + 0x68, ApiSetMap, 8);
            Instance._emulator.WriteMemory(NativePEB + 0xB8, WinSysHelper.HostProcessorCount(64), 4);
            Instance._emulator.WriteMemory(NativePEB + 0xC0, CriticalSectionTimeout, 8);
            Instance._emulator.WriteMemory(NativePEB + 0x118, WindowsVersionInfo.MajorVersion, 4);
            Instance._emulator.WriteMemory(NativePEB + 0x11C, WindowsVersionInfo.MinorVersion, 4);
            Instance._emulator.WriteMemory(NativePEB + 0x120, WindowsVersionInfo.BuildNumberShort, 2);
            Instance._emulator.WriteMemory(NativePEB + 0x122, (ushort)0, 2);
            Instance._emulator.WriteMemory(NativePEB + 0x124, WindowsVersionInfo.PlatformIdWin32Nt, 4);
            Instance._emulator.WriteMemory(NativePEB + 0x2C0, WinToken.InteractiveSessionId, 4);
            Instance._emulator.WriteMemory(NativePEB + WinSxS.PebActivationContextData64, ProcessActivationContext, 8);
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
            bool ConsoleApp = Instance._binary.PE.Subsystem.HasFlag(Subsystem.WindowsCui);
            if (ConsoleApp)
                Instance._emulator.WriteMemory(Params + 0x10, (uint)WinHelper.ConsoleHandle.Handle);

            if (ConsoleApp || WinHelper.InheritedStandardHandles)
            {
                Instance._emulator.WriteMemory(Params + 0x18, (uint)(WinHelper.STD_IN?.Handle ?? 0));
                Instance._emulator.WriteMemory(Params + 0x1C, (uint)(WinHelper.STD_OUT?.Handle ?? 0));
                Instance._emulator.WriteMemory(Params + 0x20, (uint)(WinHelper.STD_ERR?.Handle ?? 0));
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

                using (BinaryFile Library = Instance.LoadBinary(NtdllPath))
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
