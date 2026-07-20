using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    public class WindowsSharedBuffer
    {
        private byte[] Buffer;

        public int Length => Buffer.Length;

        public WindowsSharedBuffer()
        {
            Buffer = Array.Empty<byte>();
        }

        public Span<byte> GetSpan(ulong Size)
        {
            if (Size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(Size));

            EnsureCapacity((int)Size);
            return Buffer.AsSpan(0, (int)Size);
        }

        public ReadOnlySpan<byte> GetReadOnlySpan(ulong Size)
        {
            if (Size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(Size));

            EnsureCapacity((int)Size);
            return Buffer.AsSpan(0, (int)Size);
        }

        public byte[] GetBuffer(ulong Size)
        {
            if (Size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(Size));

            EnsureCapacity((int)Size);
            return Buffer;
        }

        public void Clear(ulong Size)
        {
            if (Size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(Size));

            int Count = (int)Math.Min(Size, (ulong)Buffer.Length);
            Buffer.AsSpan(0, Count).Clear();
        }

        private void EnsureCapacity(int Size)
        {
            if (Size <= Buffer.Length)
                return;

            int NewSize = Buffer.Length == 0 ? 0x1000 : Buffer.Length;
            while (NewSize < Size)
            {
                if (NewSize > int.MaxValue / 2)
                {
                    NewSize = Size;
                    break;
                }

                NewSize *= 2;
            }

            Array.Resize(ref Buffer, NewSize);
        }
    }

    internal struct HandleEntry
    {
        public IHandleObject Object;
        public AccessMask Permissions;
        public ObjectHandleFlags Flags;
    }

    /// <summary>
    /// Generic handles manager (for Processes, Files, Mutex, etc)
    /// </summary>
    internal class HandleManager
    {
        public static readonly ulong KNOWN_DLLS_DIRECTORY = 0x1111;
        public static readonly ulong KNOWN_DLLS32_DIRECTORY = 0x1112;
        public static readonly ulong BASE_NAMED_OBJECTS_DIRECTORY = 0x1113;
        public static readonly ulong RPC_CONTROL_DIRECTORY = 0x1114;
        public static readonly ulong CurrentProcess = ulong.MaxValue;
        public static readonly ulong CurrentThread = 0xFFFFFFFFFFFFFFFE;
        public const ulong CurrentProcess32 = uint.MaxValue;
        public const ulong CurrentThread32 = 0xFFFFFFFEUL;

        public static bool IsCurrentThreadPseudoHandle(ulong Handle) => Handle == CurrentThread || Handle == CurrentThread32;

        public static bool IsCurrentProcessPseudoHandle(ulong Handle) => Handle == CurrentProcess || Handle == CurrentProcess32;
        private ulong NextHandle = 0x40;
        private readonly Dictionary<ulong, HandleEntry> HandleTable = new();
        private readonly Dictionary<string, List<ulong>> ObjectIdToHandles = new();

        public WinHandle AddHandle(IHandleObject obj, AccessMask Permissions)
        {
            ulong handle = AllocateHandleValue();

            WinHandle winHandle = new WinHandle
            {
                Handle = handle,
                HandleType = obj.ObjectType,
                Permissions = Permissions
            };

            HandleTable[handle] = new HandleEntry { Object = obj, Permissions = Permissions, Flags = ObjectHandleFlags.None };

            if (!ObjectIdToHandles.TryGetValue(obj.ObjectId, out List<ulong> Handles))
            {
                Handles = new List<ulong>();
                ObjectIdToHandles[obj.ObjectId] = Handles;
            }

            Handles.Add(handle);

            return winHandle;
        }

        private ulong AllocateHandleValue()
        {
            while (HandleTable.ContainsKey(NextHandle) || IsReservedHandleValue(NextHandle))
                NextHandle += 4;

            ulong Handle = NextHandle;
            NextHandle += 4;
            return Handle;
        }

        private static bool IsReservedHandleValue(ulong Handle)
        {
            return Handle == KNOWN_DLLS_DIRECTORY ||
                Handle == KNOWN_DLLS32_DIRECTORY ||
                Handle == BASE_NAMED_OBJECTS_DIRECTORY ||
                Handle == RPC_CONTROL_DIRECTORY ||
                Handle == CurrentProcess ||
                Handle == CurrentThread ||
                Handle == 0;
        }

        public ObjectHandleFlags GetHandleFlags(ulong Handle)
        {
            if (HandleTable.TryGetValue(Handle, out HandleEntry Entry))
                return Entry.Flags;
            return ObjectHandleFlags.None;
        }

        public bool SetHandleFlags(ulong Handle, ObjectHandleFlags Flags)
        {
            if (!HandleTable.TryGetValue(Handle, out HandleEntry Entry))
                return false;
            Entry.Flags = Flags;
            HandleTable[Handle] = Entry;
            return true;
        }

        public T? GetObjectByHandle<T>(ulong Handle) where T : class, IHandleObject
        {
            if (HandleTable.TryGetValue(Handle, out HandleEntry Entry) && Entry.Object is T typedObj)
                return typedObj;
            return null;
        }

        public IHandleObject? GetObjectByHandle(ulong Handle)
        {
            if (HandleTable.TryGetValue(Handle, out HandleEntry Entry))
                return Entry.Object;
            return null;
        }

        public List<ulong> GetHandlesByObjectId(string ObjectId)
        {
            if (ObjectIdToHandles.TryGetValue(ObjectId, out List<ulong> Handles))
                return new List<ulong>(Handles);
            return new List<ulong>();
        }

        public AccessMask GetPermissionsByHandle(ulong Handle)
        {
            if (HandleTable.TryGetValue(Handle, out HandleEntry Entry))
                return Entry.Permissions;
            return AccessMask.None;
        }

        public bool TryGetHandle(ulong Handle, out HandleEntry Entry)
        {
            return HandleTable.TryGetValue(Handle, out Entry);
        }

        public bool TryRemoveHandle(ulong Handle, out HandleEntry Entry)
        {
            if (!HandleTable.TryGetValue(Handle, out Entry))
                return false;
            HandleTable.Remove(Handle);
            IHandleObject obj = Entry.Object;
            if (ObjectIdToHandles.TryGetValue(obj.ObjectId, out List<ulong> Handles))
            {
                Handles.Remove(Handle);
                if (Handles.Count == 0)
                    ObjectIdToHandles.Remove(obj.ObjectId);
            }
            return true;
        }

        public bool RemoveHandle(ulong Handle)
        {
            if (!HandleTable.TryGetValue(Handle, out HandleEntry Entry))
                return false;
            IHandleObject obj = Entry.Object;
            HandleTable.Remove(Handle);

            if (ObjectIdToHandles.TryGetValue(obj.ObjectId, out List<ulong> Handles))
            {
                Handles.Remove(Handle);

                if (Handles.Count == 0)
                    ObjectIdToHandles.Remove(obj.ObjectId);
            }

            return true;
        }

        public List<KeyValuePair<ulong, IHandleObject>> SnapshotHandles()
        {
            var Result = new List<KeyValuePair<ulong, IHandleObject>>(HandleTable.Count);
            foreach (var kv in HandleTable) Result.Add(new KeyValuePair<ulong, IHandleObject>(kv.Key, kv.Value.Object));
            return Result;
        }

        public void SnapshotHandles(List<KeyValuePair<ulong, IHandleObject>> Destination)
        {
            if (Destination == null)
                return;

            Destination.Clear();
            foreach (var kv in HandleTable) Destination.Add(new KeyValuePair<ulong, IHandleObject>(kv.Key, kv.Value.Object));
        }

        public bool HandleExists(ulong Handle)
        {
            return HandleTable.ContainsKey(Handle);
        }

        public bool HandleExists(ulong Handle, HandleType type)
        {
            if (!HandleTable.TryGetValue(Handle, out HandleEntry Entry))
                return false;
            return Entry.Object != null && Entry.Object.ObjectType == type;
        }

        public bool CheckAccess(ulong Handle, AccessMask RequiredAccess)
        {
            if (!HandleTable.TryGetValue(Handle, out HandleEntry Entry))
                return false;
            AccessMask GrantedAccess = Entry.Permissions;

            if (RequiredAccess == AccessMask.GiveTemp)
                return true;

            if ((GrantedAccess & AccessMask.MaximumAllowed) != 0 || (GrantedAccess & AccessMask.GenericAll) != 0)
                return true;

            return (GrantedAccess & RequiredAccess) == RequiredAccess;
        }
    }

    public sealed class KuserSharedDataManager
    {
        private const ulong PageSize = 0x1000;

        private const int OffsetTickCountLowDeprecated = 0x000;
        private const int OffsetTickCountMultiplier = 0x004;
        private const int OffsetInterruptTime = 0x008;
        private const int OffsetSystemTime = 0x014;
        private const int OffsetNtSystemRoot = 0x030;
        private const int OffsetNtBuildNumber = 0x260;
        private const int OffsetNtProductType = 0x264;
        private const int OffsetProductTypeIsValid = 0x268;
        private const int OffsetNtMajorVersion = 0x26C;
        private const int OffsetNtMinorVersion = 0x270;
        private const int OffsetProcessorFeatures = 0x274;
        private const int OffsetXStateConfiguration = 0x3D8;
        private const int OffsetQpcFrequency = 0x300;
        private const int OffsetQpcData = 0x3C6;
        private const int OffsetSystemCallX86 = 0x300;
        private const int OffsetSystemCallX64 = 0x308;

        internal const long QpcFrequency = 10_000_000;
        private const int OffsetTickCountQuad = 0x320;
        private const int OffsetCookie = 0x330;

        private const ulong HundredNsPerDefaultTick = 156_250UL;

        private readonly BinaryEmulator Emulator;
        private MemoryHookCallback ReadHook;
        private bool Installed;

        private long LastUpdateTimestamp;

        private ulong BaseInterruptTime;

        public KuserSharedDataManager(BinaryEmulator Emulator)
        {
            this.Emulator = Emulator;
            Initialize();
        }

        public void Initialize()
        {
            if (Installed)
                return;

            byte[] Page = BuildInitialPage();
            BaseInterruptTime = ReadKsystemTimeFromBuffer(Page, OffsetInterruptTime);
            LastUpdateTimestamp = 0;

            if (!Emulator._emulator.MapMmio(Emulator.KUSER_SHARED_DATA, PageSize, FillTimeFields, IgnoreWrite))
            {
                if (!Emulator.IsRegionMapped(Emulator.KUSER_SHARED_DATA, PageSize) &&
                    Emulator.MapMemoryRegion(Emulator.KUSER_SHARED_DATA, PageSize, MemoryProtection.Read) == 0)
                {
                    Utils.LogError($"[KUSER_MANAGER] Failed to map KUSER_SHARED_DATA: {Emulator.GetLastError()}");
                }

                ReadHook = OnRead;
                if (Emulator._emulator.AddMemoryHook(Emulator.KUSER_SHARED_DATA,
                        Emulator.KUSER_SHARED_DATA + (PageSize - 1), BackendHookType.MemoryRead, ReadHook) == IntPtr.Zero)
                {
                    Utils.LogError($"[KUSER_MANAGER] No way to keep KUSER_SHARED_DATA current: {Emulator.GetLastError()}");
                }
            }

            if (!Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA, Page))
            {
                Utils.LogError($"[KUSER_MANAGER] Failed write the initial page data to KUSER_SHARED_DATA: {Emulator.GetLastError()}");
            }

            Installed = true;

            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)GetSystemCallOffset(), 0u, 4);
            UpdateDynamicFields(true);
        }

        private bool OnRead(BackendMemoryAccessType Type, ulong Address, uint Size, ulong Value)
        {
            UpdateDynamicFields(false);
            return true;
        }

        private void FillTimeFields(ulong Offset, Span<byte> Destination)
        {
            if (Offset != 0 || Destination.Length < OffsetTickCountQuad + 12)
                return;

            ComputeDynamicFields(out ulong SystemTime, out ulong InterruptTime, out ulong TickCountQuad);

            WriteKsystemTimeToSpan(Destination, OffsetSystemTime, SystemTime);
            WriteKsystemTimeToSpan(Destination, OffsetInterruptTime, InterruptTime);
            WriteKsystemTimeToSpan(Destination, OffsetTickCountQuad, TickCountQuad);
            BitConverter.TryWriteBytes(Destination.Slice(OffsetTickCountLowDeprecated, 4), (uint)TickCountQuad);

            if (Destination.Length >= OffsetQpcFrequency + 8)
                BinaryPrimitives.WriteInt64LittleEndian(Destination.Slice(OffsetQpcFrequency, 8), QpcFrequency);
        }

        private void IgnoreWrite(ulong Offset, ReadOnlySpan<byte> Data)
        {
        }

        private void ComputeDynamicFields(out ulong SystemTime, out ulong InterruptTime, out ulong TickCountQuad)
        {
            long Now = Emulator.EmulatedTickCount64;
            ulong Elapsed100Ns = unchecked((ulong)Math.Max(0, Now)) * 10_000UL;

            SystemTime = unchecked((ulong)Emulator.GetEmulatedSystemTimeFileTimeUtc());
            InterruptTime = BaseInterruptTime + Elapsed100Ns;
            TickCountQuad = InterruptTime / HundredNsPerDefaultTick;
        }

        private void UpdateDynamicFields(bool Force)
        {
            long Now = Emulator.EmulatedTickCount64;
            if (!Force && Now == LastUpdateTimestamp)
                return;

            LastUpdateTimestamp = Now;

            ComputeDynamicFields(out ulong SystemTime, out ulong InterruptTime, out ulong TickCountQuad);

            WriteKsystemTimeToMemory(OffsetSystemTime, SystemTime);
            WriteKsystemTimeToMemory(OffsetInterruptTime, InterruptTime);
            WriteKsystemTimeToMemory(OffsetTickCountQuad, TickCountQuad);

            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + OffsetTickCountLowDeprecated, (uint)TickCountQuad, 4);
            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)GetSystemCallOffset(), 0u, 4);
            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)OffsetQpcFrequency, (ulong)QpcFrequency, 8);
        }

        private static void WriteKsystemTimeToSpan(Span<byte> Page, int Offset, ulong Value)
        {
            uint Low = (uint)(Value & 0xFFFFFFFF);
            uint High = (uint)(Value >> 32);

            BitConverter.TryWriteBytes(Page.Slice(Offset, 4), Low);
            BitConverter.TryWriteBytes(Page.Slice(Offset + 4, 4), High);
            BitConverter.TryWriteBytes(Page.Slice(Offset + 8, 4), High);
        }

        private int GetSystemCallOffset()
        {
            return Emulator._binary.Architecture == BinaryArchitecture.x86 ? OffsetSystemCallX86 : OffsetSystemCallX64;
        }

        private byte[] BuildInitialPage()
        {
            byte[] Page = new byte[PageSize];
            if (GeneralHelper.IsWindows)
            {
                try
                {
                    IntPtr HostBase = new IntPtr(unchecked((int)Emulator.KUSER_SHARED_DATA));
                    for (int i = 0; i < Page.Length; i++)
                    {
                        Page[i] = Marshal.ReadByte(HostBase, i);
                    }
                }
                catch
                {
                }
                WriteUInt32(Page, OffsetNtBuildNumber, WindowsVersionInfo.BuildNumber);
                WriteUInt32(Page, OffsetNtProductType, WindowsVersionInfo.ProductTypeWinNt);
                Page[OffsetProductTypeIsValid] = 1;
                WriteUInt32(Page, OffsetNtMajorVersion, WindowsVersionInfo.MajorVersion);
                WriteUInt32(Page, OffsetNtMinorVersion, WindowsVersionInfo.MinorVersion);
                WriteUInt32(Page, OffsetCookie, (uint)RandomNumberGenerator.GetInt32(int.MaxValue));

                Page[OffsetQpcData] = 0;
                Page[OffsetQpcData + 1] = 0;

                WriteUInt32(Page, OffsetQpcFrequency, unchecked((uint)QpcFrequency));
                WriteUInt32(Page, OffsetQpcFrequency + 4, unchecked((uint)(QpcFrequency >> 32)));
            }
            else
            {
                void WriteByte(int Offset, byte Value)
                {
                    if ((uint)Offset >= (uint)Page.Length)
                        return;

                    Page[Offset] = Value;
                }

                Random random = new Random();

                void WriteUInt32(int Offset, uint Value)
                {
                    if (Offset < 0 || Offset + 4 > Page.Length)
                        return;

                    BinaryPrimitives.WriteUInt32LittleEndian(Page.AsSpan(Offset, 4), Value);
                }

                void WriteUInt64(int Offset, ulong Value)
                {
                    if (Offset < 0 || Offset + 8 > Page.Length)
                        return;

                    BinaryPrimitives.WriteUInt64LittleEndian(Page.AsSpan(Offset, 8), Value);
                }

                void WriteInt64(int Offset, long Value)
                {
                    if (Offset < 0 || Offset + 8 > Page.Length)
                        return;

                    BinaryPrimitives.WriteInt64LittleEndian(Page.AsSpan(Offset, 8), Value);
                }

                // TickCountLow / TickCountLowDeprecated
                WriteUInt32(OffsetTickCountLowDeprecated, unchecked((uint)Emulator.EmulatedTickCount64));

                // InterruptTime
                WriteInt64(OffsetInterruptTime, TimeSpan.FromHours(random.Next(2, 24)).Ticks);

                // SystemTime
                WriteInt64(OffsetSystemTime, Emulator.GetEmulatedSystemTimeFileTimeUtc());

                if (Emulator._binary.Architecture != BinaryArchitecture.x86)
                    WriteInt64(OffsetQpcFrequency, QpcFrequency);

                // KdDebuggerEnabled
                WriteByte(0x02D4, 0x00);

                // SafeBootMode
                WriteByte(0x02EC, 0x00);

                // NtBuildNumber
                WriteUInt32(OffsetNtBuildNumber, WindowsVersionInfo.BuildNumber);

                // NtProductType (NtProductWinNt)
                WriteUInt32(OffsetNtProductType, WindowsVersionInfo.ProductTypeWinNt);
                WriteByte(OffsetProductTypeIsValid, 1);

                // NtMajorVersion / NtMinorVersion
                WriteUInt32(OffsetNtMajorVersion, WindowsVersionInfo.MajorVersion);
                WriteUInt32(OffsetNtMinorVersion, WindowsVersionInfo.MinorVersion);

                // SystemCall flag
                WriteUInt32(OffsetSystemCallX64, 0);

                // TickCount64
                WriteUInt64(OffsetTickCountQuad, unchecked((ulong)Emulator.EmulatedTickCount64));

                // Cookie
                WriteUInt32(OffsetCookie, unchecked((uint)random.Next()));

                // ActiveProcessorCount
                WriteUInt32(0x03C0, unchecked((uint)Environment.ProcessorCount));
            }

            string SystemRoot = "C:\\Windows";
            Array.Clear(Page, OffsetNtSystemRoot, Math.Min(Page.Length - OffsetNtSystemRoot, 520));
            Span<byte> SystemRootBytes = Page.AsSpan(OffsetNtSystemRoot, Encoding.Unicode.GetByteCount(SystemRoot) + 2);
            Encoding.Unicode.GetBytes(SystemRoot.AsSpan(), SystemRootBytes);
            SystemRootBytes[SystemRootBytes.Length - 2] = 0;
            SystemRootBytes[SystemRootBytes.Length - 1] = 0;

            for (int i = 0; i < 64; i++)
                Page[OffsetProcessorFeatures + i] = 0;

            // Do not leak the host KUSER_SHARED_DATA XState configuration into the guest.
            // Brovan's CPUID surface does not advertise XSAVE/OSXSAVE, and guest ntdll will
            // enter XRSTOR-based context paths if the copied host XState bitmap remains set.
            Array.Clear(Page, OffsetXStateConfiguration, Page.Length - OffsetXStateConfiguration);

            Page[OffsetProcessorFeatures + 6] = 1;  // SSE
            Page[OffsetProcessorFeatures + 10] = 1; // SSE2
            Page[OffsetProcessorFeatures + 13] = 1; // SSE3
            Page[OffsetProcessorFeatures + 12] = 1; // NX
            Page[OffsetProcessorFeatures + 23] = 1; // FASTFAIL
            Page[OffsetProcessorFeatures + 28] = 1; // RDRAND
            Page[OffsetProcessorFeatures + 32] = 1; // RDTSCP

            return Page;
        }

        private static void WriteUInt32(byte[] Buffer, int Offset, uint Value)
        {
            Buffer[Offset + 0] = (byte)(Value & 0xFF);
            Buffer[Offset + 1] = (byte)((Value >> 8) & 0xFF);
            Buffer[Offset + 2] = (byte)((Value >> 16) & 0xFF);
            Buffer[Offset + 3] = (byte)((Value >> 24) & 0xFF);
        }

        private static ulong ReadKsystemTimeFromBuffer(byte[] Buffer, int Offset)
        {
            if (Buffer == null || Buffer.Length < Offset + 12)
                return 0;

            uint Low = BitConverter.ToUInt32(Buffer, Offset + 0);
            uint High1 = BitConverter.ToUInt32(Buffer, Offset + 4);
            return ((ulong)High1 << 32) | Low;
        }

        private void WriteKsystemTimeToMemory(int Offset, ulong Value)
        {
            uint Low = (uint)(Value & 0xFFFFFFFF);
            uint High = (uint)(Value >> 32);

            Span<byte> Tmp = stackalloc byte[12];
            BitConverter.TryWriteBytes(Tmp.Slice(0, 4), Low);
            BitConverter.TryWriteBytes(Tmp.Slice(4, 4), High);
            BitConverter.TryWriteBytes(Tmp.Slice(8, 4), High);
            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)Offset, Tmp);
        }
    }

    internal sealed class PebLdrTracker
    {
        private readonly int PointerSize;
        private readonly int PebOffsetLdr;

        private readonly int PebLdrSize;
        private readonly int PebLdrOffsetInLoadOrder;

        private const int ListEntryOffsetFlink = 0x0;

        private const int LdrEntryOffsetInLoadOrderLinks = 0x00;
        private readonly int LdrEntryOffsetDllBase;
        private readonly int LdrEntryOffsetSizeOfImage;
        private readonly int LdrEntryOffsetFullDllName;
        private readonly int LdrEntryOffsetBaseDllName;
        private readonly int LdrEntrySize;

        private readonly int UnicodeStringSize;
        private const int UnicodeStringOffsetLength = 0x0;
        private readonly int UnicodeStringOffsetBuffer;

        private const int MaxUnicodeStringBytes = 0x800; // hard cap (bytes)

        private readonly BinaryEmulator Emulator;
        private readonly WinSysHelper WinHelper;

        private MemoryHookCallback PebLdrWriteHook;
        private MemoryHookCallback LdrDataWriteHook;
        private CodeHookCallback BlockHook;


        private bool PebHookInstalled;
        private bool BlockHookInstalled;
        private bool PollDriven;

        private readonly HashSet<ulong> HookedLdrDataBases = new HashSet<ulong>();

        private volatile bool PendingRefreshHooks;
        private volatile bool PendingSync;
        private int DelayEdges;

        private long LastPumpTicks;

        private readonly Dictionary<ulong, ModuleInfo> LastSnapshot = new Dictionary<ulong, ModuleInfo>();


        private struct ModuleInfo
        {
            public ulong DllBase;
            public uint SizeOfImage;
            public string BaseName;
            public string FullName;
        }

        internal PebLdrTracker(BinaryEmulator emulator, WinSysHelper winHelper)
        {
            Emulator = emulator;
            WinHelper = winHelper;

            PointerSize = winHelper.PointerSize;

            if (PointerSize == 8)
            {
                PebOffsetLdr = 0x18;
                PebLdrSize = 0x58;
                PebLdrOffsetInLoadOrder = 0x10;
                LdrEntryOffsetDllBase = 0x30;
                LdrEntryOffsetSizeOfImage = 0x40;
                LdrEntryOffsetFullDllName = 0x48;
                LdrEntryOffsetBaseDllName = 0x58;
                LdrEntrySize = 0x80;
                UnicodeStringSize = 0x10;
                UnicodeStringOffsetBuffer = 0x8;
                return;
            }

            PebOffsetLdr = 0x0C;
            PebLdrSize = 0x30;
            PebLdrOffsetInLoadOrder = 0x0C;
            LdrEntryOffsetDllBase = 0x18;
            LdrEntryOffsetSizeOfImage = 0x20;
            LdrEntryOffsetFullDllName = 0x24;
            LdrEntryOffsetBaseDllName = 0x2C;
            LdrEntrySize = 0x40;
            UnicodeStringSize = 0x8;
            UnicodeStringOffsetBuffer = 0x4;
        }

        internal void Install()
        {
            InstallBlockHook();
            PollDriven = !BlockHookInstalled;

            if (!PollDriven)
                InstallPebLdrPointerHook();

            NotifyImageMapped();
        }

        internal void NotifyImageMapped()
        {
            PendingRefreshHooks = true;
            PendingSync = true;
            DelayEdges = 2;
        }

        internal void SyncFromSyscall()
        {
            if (!PollDriven)
                return;

            Drain();
        }

        private void Drain()
        {
            if (!PendingSync && !PendingRefreshHooks)
                return;

            if (DelayEdges > 0)
            {
                DelayEdges--;
                return;
            }

            Pump();
        }

        private void InstallPebLdrPointerHook()
        {
            if (PebHookInstalled)
                return;

            ulong PebLdrPtr = Emulator.PEB + (ulong)PebOffsetLdr;

            PebLdrWriteHook = OnPebLdrPointerWrite;

            if (Emulator._emulator.AddMemoryHook(PebLdrPtr, PebLdrPtr + (ulong)PointerSize - 1, BackendHookType.MemoryWrite, PebLdrWriteHook) == IntPtr.Zero)
            {
                Utils.LogError($"[-] Failed to install PEB->Ldr MEM_WRITE hook. Error: {Emulator.GetLastError()}");
                return;
            }

            PebHookInstalled = true;
        }

        private void InstallBlockHook()
        {
            if (BlockHookInstalled)
                return;

            BlockHook = OnBlock;

            if (Emulator._emulator.AddCodeHook(1, 0, BlockHook) == IntPtr.Zero)
            {
                Utils.LogError($"[-] Failed to install BLOCK hook for LDR tracker. Error: {Emulator.GetLastError()}");
                return;
            }

            BlockHookInstalled = true;
        }

        private bool OnPebLdrPointerWrite(BackendMemoryAccessType type, ulong address, uint size, ulong value)
        {
            PendingRefreshHooks = true;
            PendingSync = true;
            DelayEdges = 2;
            return true;
        }

        private bool OnLdrDataWrite(BackendMemoryAccessType type, ulong address, uint size, ulong value)
        {
            PendingSync = true;
            DelayEdges = 2;
            return true;
        }

        private void OnBlock(ulong address, uint size) => Drain();

        internal void Pump()
        {
            long Now = Stopwatch.GetTimestamp();
            long MinDelta = Stopwatch.Frequency / 2000; // ~0.5ms throttle
            if (LastPumpTicks != 0 && (Now - LastPumpTicks) < MinDelta)
                return;

            LastPumpTicks = Now;

            if (PendingRefreshHooks)
            {
                PendingRefreshHooks = false;
                RefreshLdrHooks();
            }

            if (!PendingSync)
                return;

            if (!TrySnapshotAndApply())
            {
                PendingSync = true;
                DelayEdges = 2;
                return;
            }

            PendingSync = false;
        }

        private void RefreshLdrHooks()
        {
            ulong LdrData = SafeReadPointer(Emulator.PEB + (ulong)PebOffsetLdr);

            if (LdrData == 0 || !Emulator.IsRegionMapped(LdrData, (uint)PebLdrSize))
            {
                PendingRefreshHooks = true;
                return;
            }

            if (HookedLdrDataBases.Contains(LdrData))
                return;

            ulong Begin = LdrData;
            ulong End = LdrData + (ulong)PebLdrSize - 1;

            LdrDataWriteHook = OnLdrDataWrite;

            if (Emulator._emulator.AddMemoryHook(Begin, End, BackendHookType.MemoryWrite, LdrDataWriteHook) == IntPtr.Zero)
            {
                Utils.LogError($"[-] Failed to install PEB_LDR_DATA MEM_WRITE hook. Error: {Emulator.GetLastError()}");
                return;
            }

            HookedLdrDataBases.Add(LdrData);
        }

        private bool TrySnapshotAndApply()
        {
            if (!TryReadSnapshot(out var Snapshot))
                return false;

            foreach (var kv in Snapshot)
            {
                if (LastSnapshot.ContainsKey(kv.Key))
                    continue;

                var info = kv.Value;
                if ((Emulator.Settings.Flags & LogFlags.General) != 0)
                    Emulator.TriggerEventMessage($"[+] Loaded {info.BaseName} at 0x{info.DllBase:X}.", LogFlags.General);

                var existing = WinHelper.WinModules.FirstOrDefault(m => m != null && m.MappedBase == info.DllBase);
                if (existing == null)
                {
                    WinModule MappedView = WinHelper.FindMappedImageViewByAddress(info.DllBase);
                    if (MappedView != null && MappedView.MappedBase == info.DllBase)
                        existing = MappedView;
                }

                if (existing == null)
                {
                    existing = new WinModule
                    {
                        Architecture = Emulator._binary.Architecture,
                        MappedBase = info.DllBase,
                        SizeOfImage = info.SizeOfImage,
                        Name = info.BaseName,
                        Path = string.IsNullOrEmpty(info.FullName) ? null : info.FullName,
                        Initialized = true
                    };
                }
                else
                {
                    existing.SizeOfImage = info.SizeOfImage;
                    existing.Name = info.BaseName;
                    if (!string.IsNullOrEmpty(info.FullName))
                        existing.Path = info.FullName;
                    existing.Initialized = true;
                }

                existing.IsSectionView = false;
                existing.CanonicalImagePath = WinHelper.CanonicalizeImagePath(!string.IsNullOrEmpty(existing.Path) ? existing.Path : existing.Name);
                if (existing.ImageSectionId == 0 && !string.IsNullOrEmpty(existing.CanonicalImagePath))
                    WinHelper.AttachImageSectionIdentity(existing, existing.CanonicalImagePath);

                if (!WinHelper.WinModules.Any(m => m != null && m.MappedBase == existing.MappedBase))
                    WinHelper.WinModules.Add(existing);
            }

            foreach (var kv in LastSnapshot)
            {
                if (Snapshot.ContainsKey(kv.Key))
                    continue;

                var info = kv.Value;
                if ((Emulator.Settings.Flags & LogFlags.General) != 0)
                    Emulator.TriggerEventMessage($"[-] Unloaded {info.BaseName} at 0x{info.DllBase:X}.", LogFlags.General);

                var existing = WinHelper.WinModules.FirstOrDefault(m => m != null && m.MappedBase == info.DllBase);
                if (existing != null)
                    existing.Initialized = false;
            }

            LastSnapshot.Clear();
            foreach (var kv in Snapshot)
                LastSnapshot[kv.Key] = kv.Value;

            return true;
        }

        private bool TryReadSnapshot(out Dictionary<ulong, ModuleInfo> Snapshot)
        {
            Snapshot = new Dictionary<ulong, ModuleInfo>();

            ulong LdrData = SafeReadPointer(Emulator.PEB + (ulong)PebOffsetLdr);
            if (LdrData == 0)
                return false;

            ulong Head = LdrData + (ulong)PebLdrOffsetInLoadOrder;
            if (!Emulator.IsRegionMapped(Head, (uint)(PointerSize * 2)))
                return false;

            ulong Cursor = SafeReadPointer(Head + (ulong)ListEntryOffsetFlink);
            if (Cursor == 0)
                return false;

            int Guard = 0;
            while (Cursor != Head && Cursor != 0 && Guard++ < 2048)
            {
                ulong Entry = Cursor - (ulong)LdrEntryOffsetInLoadOrderLinks;

                if (!Emulator.IsRegionMapped(Entry, (uint)LdrEntrySize))
                    return false;

                ulong DllBase = SafeReadPointer(Entry + (ulong)LdrEntryOffsetDllBase);
                uint SizeOfImage = SafeReadUInt(Entry + (ulong)LdrEntryOffsetSizeOfImage);

                if (!TryReadUnicodeString(Entry + (ulong)LdrEntryOffsetBaseDllName, out string BaseName))
                    return false;

                TryReadUnicodeString(Entry + (ulong)LdrEntryOffsetFullDllName, out string FullName);

                if (DllBase != 0 && SizeOfImage != 0 && !string.IsNullOrEmpty(BaseName))
                {
                    BaseName = BaseName.TrimEnd('\0');
                    FullName = FullName?.TrimEnd('\0');

                    Snapshot[DllBase] = new ModuleInfo
                    {
                        DllBase = DllBase,
                        SizeOfImage = SizeOfImage,
                        BaseName = BaseName,
                        FullName = FullName
                    };
                }

                Cursor = SafeReadPointer(Cursor + (ulong)ListEntryOffsetFlink);
            }

            return true;
        }

        private bool TryReadUnicodeString(ulong unicodeStringAddress, out string Value)
        {
            Value = null;

            try
            {
                if (!Emulator.IsRegionMapped(unicodeStringAddress, (uint)UnicodeStringSize))
                    return false;

                ushort Length = Emulator._emulator.ReadMemoryUShort(unicodeStringAddress + (ulong)UnicodeStringOffsetLength);
                ulong Buffer = SafeReadPointer(unicodeStringAddress + (ulong)UnicodeStringOffsetBuffer);

                if (Length == 0 || Buffer == 0)
                {
                    Value = string.Empty;
                    return true;
                }

                if ((Length & 1) != 0)
                    return false;

                if (Length > MaxUnicodeStringBytes)
                    return false;

                if (!Emulator.IsRegionMapped(Buffer, Length))
                    return false;

                byte[] Data = Emulator.ReadMemory(Buffer, Length);
                Value = Encoding.Unicode.GetString(Data);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private ulong SafeReadPointer(ulong address)
        {
            try
            {
                if (address == 0 || !Emulator.IsRegionMapped(address, (uint)PointerSize))
                    return 0;
                return PointerSize == 8 ? Emulator.ReadMemoryULong(address) : Emulator.ReadMemoryUInt(address);
            }
            catch
            {
                return 0;
            }
        }

        private uint SafeReadUInt(ulong address)
        {
            try
            {
                if (address == 0 || !Emulator.IsRegionMapped(address, 4))
                    return 0;
                return Emulator.ReadMemoryUInt(address);
            }
            catch
            {
                return 0;
            }
        }
    }

    internal static class Win32kMessageOnlyParent
    {
        public const ulong HwndMessage = 0xFFFFFFFFFFFFFFFDUL;

        public static WinWindow Ensure(BinaryEmulator Instance)
        {
            if (Instance == null)
                return null;

            if (Instance.WinHelper.GetWindow(HwndMessage) is WinWindow Existing)
                return Existing;

            WinWindow Window = new WinWindow
            {
                Hwnd = HwndMessage,
                ClassName = "#HWND_MESSAGE_PARENT",
                Title = string.Empty,
                Visible = false,
                Destroyed = false,
                Minimized = false,
                Maximized = false,
                Style = 0,
                ExStyle = 0,
                X = 0,
                Y = 0,
                Width = 0,
                Height = 0,
                OwnerThreadId = 0,
                ParentHwnd = 0,
                OwnerHwnd = 0,
                InstanceHandle = 0,
                MenuHandle = 0,
                CreateParam = 0,
                UserData = 0,
                ClientWindowAddress = 0,
                ClientClassAddress = 0,
                ClientTextAddress = 0,
                ClientTextBytes = 0,
                UserHandleEntryAddress = 0,
                WndProc = 0,
                Dirty = false,
            };

            Instance.WinHelper.WinWindows[HwndMessage] = Window;
            return Window;
        }
    }
}
