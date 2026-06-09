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
        private ulong NextHandle = 0x40;
        private readonly Dictionary<ulong, IHandleObject> HandleToObject = new();
        private readonly Dictionary<ulong, AccessMask> HandleToPermissions = new();
        private readonly Dictionary<ulong, ObjectHandleFlags> HandleToFlags = new();
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

            HandleToObject[handle] = obj;
            HandleToPermissions[handle] = Permissions;
            HandleToFlags[handle] = ObjectHandleFlags.None;

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
            while (HandleToObject.ContainsKey(NextHandle) || IsReservedHandleValue(NextHandle))
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
            if (HandleToFlags.TryGetValue(Handle, out ObjectHandleFlags Flags))
                return Flags;
            return ObjectHandleFlags.None;
        }

        public bool SetHandleFlags(ulong Handle, ObjectHandleFlags Flags)
        {
            if (!HandleToObject.ContainsKey(Handle))
                return false;

            HandleToFlags[Handle] = Flags;
            return true;
        }

        public T? GetObjectByHandle<T>(ulong Handle) where T : class, IHandleObject
        {
            if (HandleToObject.TryGetValue(Handle, out IHandleObject obj) && obj is T typedObj)
                return typedObj;
            return null;
        }

        public IHandleObject? GetObjectByHandle(ulong Handle)
        {
            if (HandleToObject.TryGetValue(Handle, out IHandleObject obj))
                return obj;
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
            if (HandleToPermissions.TryGetValue(Handle, out AccessMask permissions))
                return permissions;
            return AccessMask.None;
        }

        public bool RemoveHandle(ulong Handle)
        {
            if (!HandleToObject.TryGetValue(Handle, out IHandleObject obj))
                return false;

            HandleToObject.Remove(Handle);
            HandleToPermissions.Remove(Handle);
            HandleToFlags.Remove(Handle);

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
            return new List<KeyValuePair<ulong, IHandleObject>>(HandleToObject);
        }

        public void SnapshotHandles(List<KeyValuePair<ulong, IHandleObject>> Destination)
        {
            if (Destination == null)
                return;

            Destination.Clear();
            foreach (KeyValuePair<ulong, IHandleObject> Pair in HandleToObject)
                Destination.Add(Pair);
        }

        public bool HandleExists(ulong Handle)
        {
            return HandleToObject.ContainsKey(Handle);
        }

        public bool HandleExists(ulong Handle, HandleType type)
        {
            if (!HandleExists(Handle))
                return false;
            return HandleToObject.TryGetValue(Handle, out var obj) && obj.ObjectType == type;
        }

        public bool CheckAccess(ulong Handle, AccessMask RequiredAccess)
        {
            if (!HandleToPermissions.TryGetValue(Handle, out AccessMask GrantedAccess))
                return false;

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
        private const int OffsetSystemCallX86 = 0x300;
        private const int OffsetSystemCallX64 = 0x308;
        private const int OffsetTickCountQuad = 0x320;
        private const int OffsetCookie = 0x330;

        private const ulong HundredNsPerDefaultTick = 156_250UL;

        private readonly BinaryEmulator Emulator;
        private MemoryDelegate ReadHook;
        private bool HookInstalled;

        private long LastUpdateTimestamp;

        private ulong BaseInterruptTime;

        public KuserSharedDataManager(BinaryEmulator Emulator)
        {
            this.Emulator = Emulator;
            Initialize();
        }

        public void Initialize()
        {
            if (HookInstalled)
                return;

            if (!Emulator.IsRegionMapped(Emulator.KUSER_SHARED_DATA, PageSize))
            {
                if (Emulator.MapMemoryRegion(Emulator.KUSER_SHARED_DATA, PageSize, MemoryProtection.Read) == 0)
                {
                    Utils.LogError($"[KUSER_MANAGER] Failed to map KUSER_SHARED_DATA. Last Unicorn Error: {Emulator.GetLastError()}");
                }
            }

            byte[] Page = BuildInitialPage();
            if (!Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA, Page))
            {
                Utils.LogError($"[KUSER_MANAGER] Failed write the initial page data to KUSER_SHARED_DATA. Last Unicorn Error: {Emulator.GetLastError()}");
            }

            BaseInterruptTime = ReadKsystemTimeFromBuffer(Page, OffsetInterruptTime);

            LastUpdateTimestamp = 0;

            ReadHook = OnRead;
            if (!Emulator._emulator.AddHook(Emulator.KUSER_SHARED_DATA, Emulator.KUSER_SHARED_DATA + (PageSize - 1), Hooks.UC_HOOK_MEM_READ, Marshal.GetFunctionPointerForDelegate(ReadHook)))
            {
                Utils.LogError($"[KUSER_MANAGER] Failed to add a hook for KUSER_SHARED_DATA to update dynamic fields. Last Unicorn Error: {Emulator.GetLastError()}\n- ReadHook Ptr 0x{ReadHook:X}");
            }

            HookInstalled = true;

            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)GetSystemCallOffset(), 0u, 4);
            UpdateDynamicFields(true);
        }

        private bool OnRead(IntPtr Uc, MemoryType Type, ulong Address, uint Size, ulong Value, IntPtr UserData)
        {
            UpdateDynamicFields(false);
            return true;
        }

        private void UpdateDynamicFields(bool Force)
        {
            long Now = Emulator.EmulatedTickCount64;
            if (!Force && Now == LastUpdateTimestamp)
                return;

            LastUpdateTimestamp = Now;

            ulong Elapsed100Ns = unchecked((ulong)Math.Max(0, Now)) * 10_000UL;

            ulong SystemTime = unchecked((ulong)Emulator.GetEmulatedSystemTimeFileTimeUtc());
            ulong InterruptTime = BaseInterruptTime + Elapsed100Ns;

            WriteKsystemTimeToMemory(OffsetSystemTime, SystemTime);
            WriteKsystemTimeToMemory(OffsetInterruptTime, InterruptTime);

            ulong TickCountQuad = Elapsed100Ns / HundredNsPerDefaultTick;
            WriteKsystemTimeToMemory(OffsetTickCountQuad, TickCountQuad);

            uint TickCountLow = (uint)TickCountQuad;
            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + OffsetTickCountLowDeprecated, TickCountLow, 4);

            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)GetSystemCallOffset(), 0u, 4);
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
        private const int PebOffsetLdr = 0x18;

        private const int PebLdrSize = 0x58;
        private const int PebLdrOffsetInLoadOrder = 0x10;

        private const int ListEntryOffsetFlink = 0x0;

        private const int LdrEntryOffsetInLoadOrderLinks = 0x00;
        private const int LdrEntryOffsetDllBase = 0x30;
        private const int LdrEntryOffsetSizeOfImage = 0x40;
        private const int LdrEntryOffsetFullDllName = 0x48; // UNICODE_STRING
        private const int LdrEntryOffsetBaseDllName = 0x58; // UNICODE_STRING

        private const int UnicodeStringSize = 0x10;
        private const int UnicodeStringOffsetLength = 0x0;
        private const int UnicodeStringOffsetBuffer = 0x8;

        private const int MaxUnicodeStringBytes = 0x800; // hard cap (bytes)

        private readonly BinaryEmulator Emulator;
        private readonly WinSysHelper WinHelper;

        private MemoryDelegate PebLdrWriteHook;
        private MemoryDelegate LdrDataWriteHook;
        private BlockHookDelegate BlockHook;

        private IntPtr PebLdrWriteHookPtr;
        private IntPtr LdrDataWriteHookPtr;
        private IntPtr BlockHookPtr;

        private bool PebHookInstalled;
        private bool BlockHookInstalled;

        private readonly HashSet<ulong> HookedLdrDataBases = new HashSet<ulong>();

        private volatile bool PendingRefreshHooks;
        private volatile bool PendingSync;
        private int DelayBlocks;

        private long LastPumpTicks;

        private readonly Dictionary<ulong, ModuleInfo> LastSnapshot = new Dictionary<ulong, ModuleInfo>();

        private delegate void BlockHookDelegate(IntPtr uc, ulong address, uint size, IntPtr user_data);

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
        }

        internal void Install()
        {
            InstallPebLdrPointerHook();
            InstallBlockHook();

            PendingRefreshHooks = true;
            PendingSync = true;
            DelayBlocks = 2;
        }

        private void InstallPebLdrPointerHook()
        {
            if (PebHookInstalled)
                return;

            ulong PebLdrPtr = Emulator.PEB + (ulong)PebOffsetLdr;

            PebLdrWriteHook = OnPebLdrPointerWrite;
            PebLdrWriteHookPtr = Marshal.GetFunctionPointerForDelegate(PebLdrWriteHook);

            if (!Emulator._emulator.AddHook(PebLdrPtr, PebLdrPtr + 7, Hooks.UC_HOOK_MEM_WRITE, PebLdrWriteHookPtr))
            {
                Utils.LogError($"[-] Failed to install PEB->Ldr MEM_WRITE hook. Last unicorn error: {Emulator.GetLastError()}");
                return;
            }

            PebHookInstalled = true;
        }

        private void InstallBlockHook()
        {
            if (BlockHookInstalled)
                return;

            BlockHook = OnBlock;
            BlockHookPtr = Marshal.GetFunctionPointerForDelegate(BlockHook);

            if (!Emulator._emulator.AddHook(1, 0, Hooks.UC_HOOK_BLOCK, BlockHookPtr))
            {
                Utils.LogError($"[-] Failed to install BLOCK hook for LDR tracker. Last unicorn error: {Emulator.GetLastError()}");
                return;
            }

            BlockHookInstalled = true;
        }

        private bool OnPebLdrPointerWrite(IntPtr uc, MemoryType type, ulong address, uint size, ulong value, IntPtr user_data)
        {
            PendingRefreshHooks = true;
            PendingSync = true;
            DelayBlocks = 2;
            return true;
        }

        private bool OnLdrDataWrite(IntPtr uc, MemoryType type, ulong address, uint size, ulong value, IntPtr user_data)
        {
            PendingSync = true;
            DelayBlocks = 2;
            return true;
        }

        private void OnBlock(IntPtr uc, ulong address, uint size, IntPtr user_data)
        {
            if (!PendingSync && !PendingRefreshHooks)
                return;

            if (DelayBlocks > 0)
            {
                DelayBlocks--;
                return;
            }

            Pump();
        }

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
                DelayBlocks = 2;
                return;
            }

            PendingSync = false;
        }

        private void RefreshLdrHooks()
        {
            ulong LdrData = SafeReadUlong(Emulator.PEB + (ulong)PebOffsetLdr);
            if (LdrData == 0)
                return;

            if (HookedLdrDataBases.Contains(LdrData))
                return;

            if (!Emulator.IsRegionMapped(LdrData, (uint)PebLdrSize))
                return;

            ulong Begin = LdrData;
            ulong End = LdrData + (ulong)PebLdrSize - 1;

            LdrDataWriteHook = OnLdrDataWrite;
            LdrDataWriteHookPtr = Marshal.GetFunctionPointerForDelegate(LdrDataWriteHook);

            if (!Emulator._emulator.AddHook(Begin, End, Hooks.UC_HOOK_MEM_WRITE, LdrDataWriteHookPtr))
            {
                Utils.LogError($"[-] Failed to install PEB_LDR_DATA MEM_WRITE hook. Last unicorn error: {Emulator.GetLastError()}");
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

            ulong LdrData = SafeReadUlong(Emulator.PEB + (ulong)PebOffsetLdr);
            if (LdrData == 0)
                return false;

            ulong Head = LdrData + (ulong)PebLdrOffsetInLoadOrder;
            if (!Emulator.IsRegionMapped(Head, 0x10))
                return false;

            ulong Cursor = SafeReadUlong(Head + (ulong)ListEntryOffsetFlink);
            if (Cursor == 0)
                return false;

            int Guard = 0;
            while (Cursor != Head && Cursor != 0 && Guard++ < 2048)
            {
                ulong Entry = Cursor - (ulong)LdrEntryOffsetInLoadOrderLinks;

                if (!Emulator.IsRegionMapped(Entry, 0x80))
                    return false;

                ulong DllBase = SafeReadUlong(Entry + (ulong)LdrEntryOffsetDllBase);
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

                Cursor = SafeReadUlong(Cursor + (ulong)ListEntryOffsetFlink);
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
                ulong Buffer = Emulator.ReadMemoryULong(unicodeStringAddress + (ulong)UnicodeStringOffsetBuffer);

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

        private ulong SafeReadUlong(ulong address)
        {
            try
            {
                if (address == 0 || !Emulator.IsRegionMapped(address, 8))
                    return 0;
                return Emulator.ReadMemoryULong(address);
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
}
