using static Brovan.Core.Helpers.BinaryHelpers;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using System.Text;
using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Emulation.OS.Windows.Win32k;
using System.IO;

namespace Brovan.Core.Emulation.OS.Windows
{
    public class WinSysHelper
    {
        private static readonly Lazy<IReadOnlyDictionary<string, IWinDevice>> DeviceRegistry = new Lazy<IReadOnlyDictionary<string, IWinDevice>>(BuildDeviceRegistry);

        public WindowsSharedBuffer Shared { get; private set; }

        private Random RandomGen = new Random();
        private Dictionary<uint, bool> PIDs = new Dictionary<uint, bool>();
        private IDisplayConnection DesktopDisplay;
        private IWindow DesktopWindow;
        private string DesktopWindowTitle;

        private static IReadOnlyDictionary<string, IWinDevice> BuildDeviceRegistry()
        {
            Dictionary<string, IWinDevice> Devices = new Dictionary<string, IWinDevice>(StringComparer.OrdinalIgnoreCase);

            foreach (IWinDevice Device in WinDeviceRegistry.CreateAll())
            {
                string DeviceName = NormalizeDevicePath(Device.DeviceName);
                if (string.IsNullOrEmpty(DeviceName))
                    continue;

                Devices[DeviceName] = Device;
            }

            return Devices;
        }

        private static string NormalizeDevicePath(string Path)
        {
            return NormalizeDevicePath(Path, null);
        }

        private static string NormalizeDevicePath(string Path, string VolumeGuid)
        {
            if (string.IsNullOrEmpty(Path))
                return string.Empty;

            string Normalized = Path.Trim().TrimEnd('\0').Replace('/', '\\');

            if (Normalized.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Normalized = Normalized.Substring(4);

            while (Normalized.Length > "\\Device\\".Length && Normalized.EndsWith("\\", StringComparison.Ordinal))
                Normalized = Normalized.Substring(0, Normalized.Length - 1);

            if (Normalized.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) ||
                Normalized.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
            {
                Normalized = Normalized.Substring(4);
            }

            if (Normalized.Equals("BrovVulk", StringComparison.OrdinalIgnoreCase))
                Normalized = "\\Device\\BrovVulk";
            else if (Normalized.Equals("MountPointManager", StringComparison.OrdinalIgnoreCase))
                Normalized = "\\Device\\MountPointManager";
            else if (Normalized.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("NUL:", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("NULL", StringComparison.OrdinalIgnoreCase))
            {
                Normalized = "\\Device\\Null";
            }
            else if (Normalized.Equals("WMIDataDevice", StringComparison.OrdinalIgnoreCase))
                Normalized = "\\Device\\WMIDataDevice";
            else if (Normalized.Equals("PhysicalDrive0", StringComparison.OrdinalIgnoreCase))
                Normalized = WindowsStorageDeviceSupport.PhysicalDiskDeviceName;
            else if (WindowsStorageDeviceSupport.IsVolumeDevicePath(Normalized, VolumeGuid))
                Normalized = WindowsStorageDeviceSupport.VolumeDeviceName;

            return Normalized;
        }

        /// <summary>
        /// Attempts to create a Windows device endpoint by resolving the device path through the generated device registry.
        /// </summary>
        /// <param name="Path">The normalized or raw NT device path.</param>
        /// <param name="EaBuffer">The extended attributes buffer supplied to NtCreateFile, if any.</param>
        /// <param name="InternalPath">The internal path to assign to the opened device handle.</param>
        /// <param name="Handler">The device I/O handler for the opened endpoint.</param>
        /// <param name="Status">The status returned by the matched device factory.</param>
        /// <returns>True if the path matched a registered device.</returns>
        public bool TryCreateDevice(string Path, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler, out NTSTATUS Status)
        {
            InternalPath = null;
            Handler = null;
            Status = NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            string DevicePath = NormalizeDevicePath(Path, SyntheticVolumeGuid);
            if (!DeviceRegistry.Value.TryGetValue(DevicePath, out IWinDevice Device))
                return false;

            Status = Device.Create(Emulator, DevicePath, EaBuffer ?? Array.Empty<byte>(), out InternalPath, out Handler);

            if (Status == NTSTATUS.STATUS_SUCCESS && (string.IsNullOrEmpty(InternalPath) || Handler == null))
                Status = NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            return true;
        }

        /// <summary>
        /// Checks whether the supplied process handle targets the current emulated process and grants the requested access.
        /// </summary>
        /// <param name="ProcessHandle">The process handle or current-process pseudo handle.</param>
        /// <param name="RequiredAccess">The access mask required for the operation.</param>
        /// <returns>True if the handle references the current process and has the requested access.</returns>
        public bool IsCurrentProcessHandle(ulong ProcessHandle, AccessMask RequiredAccess)
        {
            if (HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle) || ProcessHandle == uint.MaxValue)
                return true;

            WinProcess Process = GetProcessByHandle(ProcessHandle, AccessMask.GiveTemp);
            if (Process == null || Process.PID != PID)
                return false;

            AccessMask Granted = HandleManager.GetPermissionsByHandle(ProcessHandle);
            return Granted == AccessMask.GiveTemp ||
                   (Granted & AccessMask.GenericAll) != 0 ||
                   (Granted & AccessMask.ProcessAllAccess) == AccessMask.ProcessAllAccess ||
                   (Granted & RequiredAccess) == RequiredAccess;
        }

        /// <summary>
        /// Returns the address of the syscall instruction that is currently being handled.
        /// </summary>
        /// <param name="Thread">The current emulated thread.</param>
        /// <param name="PreferThreadLastRip">Use the last executed RIP when it is available.</param>
        /// <returns>The syscall instruction address.</returns>
        internal const ulong Int2EInstructionLength = 2;

        public ulong GetSyscallRip(EmulatedThread Thread, bool PreferThreadLastRip)
        {
            if (PreferThreadLastRip && Thread != null && Thread.LastRIP != 0)
                return Thread.LastRIP;

            ulong Ip = Emulator.ReadRegister(Emulator.IPRegister);

            return Emulator.IsX86Guest ? Ip - Int2EInstructionLength : Ip;
        }

        /// <summary>
        /// Converts a Windows timeout pointer into an emulated deadline in milliseconds.
        /// </summary>
        /// <param name="TimeoutPtr">Pointer to a LARGE_INTEGER timeout value, or zero for an infinite wait.</param>
        /// <returns>The emulated deadline, the current tick for an immediate timeout, or -1 for an infinite wait.</returns>
        public long ParseRelativeDeadlineMs(ulong TimeoutPtr)
        {
            if (TimeoutPtr == 0)
                return -1;

            long Timeout = unchecked((long)Emulator._emulator.ReadMemoryULong(TimeoutPtr));
            if (Timeout == 0)
                return Emulator.EmulatedTickCount64;

            long Delta100Ns;
            if (Timeout < 0)
            {
                Delta100Ns = Timeout == long.MinValue ? long.MaxValue : -Timeout;
            }
            else
            {
                long NowFileTime = Emulator.GetEmulatedSystemTimeFileTimeUtc();
                if (Timeout <= NowFileTime)
                    return Emulator.EmulatedTickCount64;

                Delta100Ns = Timeout - NowFileTime;
            }

            long Ms = Delta100Ns / 10000;
            if ((Delta100Ns % 10000) != 0 && Ms < long.MaxValue)
                Ms++;

            return Emulator.CreateEmulatedDeadlineMilliseconds(Ms);
        }

        /// <summary>
        /// Clears the blocked wait state for an emulated thread.
        /// </summary>
        /// <param name="Thread">The emulated thread.</param>
        /// <param name="ClearAlertByThreadId">Also clears NtWaitForAlertByThreadId-specific state.</param>
        public void ClearWaitState(EmulatedThread Thread, bool ClearAlertByThreadId = false)
        {
            if (Thread == null)
                return;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            Thread.WaitActive = false;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = -1;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.ApcAlertable = false;
            State.MsgWaitActive = false;
            State.MsgWaitMask = 0;
            State.GetMessageWaitActive = false;

            if (ClearAlertByThreadId)
            {
                State.AlertByThreadIdWaitActive = false;
                State.AlertByThreadIdAddress = 0;
            }
        }

        /// <summary>
        /// Clears wait, worker-factory, and exception state for a thread that is exiting.
        /// </summary>
        public void ClearTerminationState(EmulatedThread Thread, bool ClearAlertByThreadId = false)
        {
            if (Thread == null)
                return;

            ClearWaitState(Thread, true);

            WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
            if (State == null)
                return;

            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
            State.WaitObjects = null;
            State.DispatchException = false;
            State.IsHandlingException = false;
            State.ExceptionNesting = 0;
            State.ExceptionInformation = null;
            State.WorkerFactoryWaitActive = false;
            State.WorkerFactoryHandle = 0;
            State.WorkerFactoryMiniPackets = 0;
            State.WorkerFactoryPacketsReturned = 0;
            State.WorkerFactoryMaxPackets = 0;
            State.WorkerFactoryReservedEntries?.Clear();
            State.AlertByThreadIdPending = false;
            State.AlertByThreadIdWaitActive = false;
            State.AlertByThreadIdAddress = 0;
        }

        /// <summary>
        /// Writes an IO_STATUS_BLOCK to emulated memory using the guest pointer width.
        /// </summary>
        /// <param name="IoStatusBlockPtr">Address of the IO_STATUS_BLOCK.</param>
        /// <param name="Status">The operation status.</param>
        /// <param name="Information">The operation information value.</param>
        public void WriteIoStatusBlock(ulong IoStatusBlockPtr, NTSTATUS Status, ulong Information)
        {
            WriteIoStatusBlock(Emulator, IoStatusBlockPtr, Status, Information);
        }

        public void WriteIoStatusBlock(BinaryEmulator Instance, ulong IoStatusBlockPtr, NTSTATUS Status, ulong Information)
        {
            if (PointerSize == 8)
            {
                Span<byte> Buffer64 = stackalloc byte[0x10];
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer64.Slice(0x00, 8), (uint)Status);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer64.Slice(0x08, 8), Information);
                Instance._emulator.WriteMemory(IoStatusBlockPtr, Buffer64);
                return;
            }

            Span<byte> Buffer32 = stackalloc byte[0x08];
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer32.Slice(0x00, 4), (uint)Status);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer32.Slice(0x04, 4), (uint)Information);
            Instance._emulator.WriteMemory(IoStatusBlockPtr, Buffer32);
        }

        /// <summary>
        /// Reads guest memory into the reusable Windows syscall scratch buffer.
        /// </summary>
        /// <param name="Address">The guest address to read.</param>
        /// <param name="Size">The number of bytes to read.</param>
        /// <returns>A span over the shared scratch buffer, or an empty span if the read failed.</returns>
        public Span<byte> ReadMemorySpan(ulong Address, uint Size)
        {
            if (Size == 0)
                return Span<byte>.Empty;

            Span<byte> Buffer = Shared.GetSpan(Size);
            return Emulator._emulator.ReadMemory(Address, Buffer, Size) ? Buffer.Slice(0, (int)Size) : Span<byte>.Empty;
        }

        /// <summary>
        /// Writes zero bytes from the reusable Windows syscall scratch buffer.
        /// </summary>
        /// <param name="Address">The guest address to write.</param>
        /// <param name="Size">The number of zero bytes to write.</param>
        /// <returns>True if the write succeeded.</returns>
        public bool WriteZeroMemory(ulong Address, uint Size)
        {
            if (Size == 0)
                return true;

            Span<byte> Buffer = Shared.GetSpan(Size);
            Buffer.Clear();
            return Emulator._emulator.WriteMemory(Address, Buffer, Size);
        }

        /// <summary>
        /// Writes one byte without allocating a temporary byte array.
        /// </summary>
        /// <param name="Address">The guest address to write.</param>
        /// <param name="Value">The byte value to write.</param>
        /// <returns>True if the write succeeded.</returns>
        public bool WriteByte(ulong Address, byte Value)
        {
            Span<byte> Buffer = stackalloc byte[1];
            Buffer[0] = Value;
            return Emulator._emulator.WriteMemory(Address, Buffer);
        }

        /// <summary>
        /// Writes a little-endian 32-bit integer without allocating a temporary byte array.
        /// </summary>
        public bool WriteUInt32(ulong Address, uint Value)
        {
            Span<byte> Buffer = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer, Value);
            return Emulator._emulator.WriteMemory(Address, Buffer);
        }

        /// <summary>
        /// Writes a little-endian 64-bit integer without allocating a temporary byte array.
        /// </summary>
        public bool WriteUInt64(ulong Address, ulong Value)
        {
            Span<byte> Buffer = stackalloc byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer, Value);
            return Emulator._emulator.WriteMemory(Address, Buffer);
        }

        public int PointerSize => Emulator._binary.Architecture == BinaryArchitecture.x64 ? 8 : 4;

        private const uint ObjectAttributes32Size = 0x18;

        public bool TryReadUnicodeString(ulong UnicodeStringPtr, out string Value, out NTSTATUS Status)
        {
            return PointerSize == 8
                ? TryReadUnicodeString64(UnicodeStringPtr, out Value, out Status)
                : TryReadUnicodeString32((uint)UnicodeStringPtr, out Value, out Status);
        }

        public bool TryReadObjectAttributesName(ulong ObjectAttributesPtr, out ulong RootDirectory, out string Name, out string FullName, out NTSTATUS Status)
        {
            if (PointerSize == 8)
            {
                bool Ok64 = TryReadObjectAttributesName64(ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes, out Name, out FullName, out Status);
                RootDirectory = Attributes.RootDirectory;
                return Ok64;
            }

            bool Ok32 = TryReadObjectAttributesName32((uint)ObjectAttributesPtr, out uint Root32, out _, out Name, out FullName, out Status);
            RootDirectory = Root32;
            return Ok32;
        }

        public ulong ReadPointer(ulong Address)
        {
            return PointerSize == 8
                ? Emulator._emulator.ReadMemoryULong(Address)
                : Emulator._emulator.ReadMemoryUInt(Address);
        }

        public bool WritePointer(ulong Address, ulong Value)
        {
            return PointerSize == 8 ? WriteUInt64(Address, Value) : WriteUInt32(Address, (uint)Value);
        }

        public ulong BuildUnicodeString(string Buffer)
        {
            if (Buffer == null)
                return 0;

            ulong StructSize = (ulong)Unsafe.SizeOf<UNICODE_STRING64>();
            ulong Address = Emulator.MapUniqueAddress(StructSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            int ByteLength = Buffer.Length * 2;
            int MaxByteLength = ByteLength + 2;

            ulong StringAddress = Emulator.MapUniqueAddress((ulong)MaxByteLength, MemoryProtection.ReadWrite);
            if (StringAddress == 0)
                return 0;

            Emulator._emulator.WriteMemory(StringAddress, Buffer, Encoding.Unicode);
            Emulator._emulator.WriteMemory(StringAddress + (ulong)ByteLength, (ushort)0, 2);

            Emulator._emulator.WriteMemory(Address + 0, (ushort)ByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 2, (ushort)MaxByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 8, StringAddress);

            return Address;
        }

        /// <summary>
        /// Reads a 32-bit UNICODE_STRING from guest memory and returns the status the caller should propagate on failure.
        /// </summary>
        public bool TryReadUnicodeString32(uint UnicodeStringPtr, out string Value, out NTSTATUS Status)
        {
            Value = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (UnicodeStringPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            uint UnicodeStringSize = (uint)Unsafe.SizeOf<UNICODE_STRING>();
            if (!Emulator.IsRegionMapped(UnicodeStringPtr, UnicodeStringSize))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            if (!StructSerializer.ParseStruct(Emulator, UnicodeStringPtr, out UNICODE_STRING UnicodeString))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            return TryReadUnicodeString32(UnicodeString, out Value, out Status);
        }

        /// <summary>
        /// Reads a parsed 32-bit UNICODE_STRING from guest memory and returns the status the caller should propagate on failure.
        /// </summary>
        public bool TryReadUnicodeString32(UNICODE_STRING UnicodeString, out string Value, out NTSTATUS Status)
        {
            Value = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (UnicodeString.Length > UnicodeString.MaximumLength)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (UnicodeString.Length == 0)
                return true;

            if ((UnicodeString.Length & 1) != 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (UnicodeString.Buffer == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!Emulator.IsRegionMapped(UnicodeString.Buffer, UnicodeString.Length))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            Value = Emulator._emulator.ReadMemoryString(UnicodeString.Buffer, UnicodeString.Length, Encoding.Unicode).TrimEnd('\0');
            return true;
        }

        /// <summary>
        /// Reads a 64-bit UNICODE_STRING from guest memory and returns the status the caller should propagate on failure.
        /// </summary>
        public bool TryReadUnicodeString64(ulong UnicodeStringPtr, out string Value, out NTSTATUS Status)
        {
            Value = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (UnicodeStringPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            uint UnicodeStringSize = (uint)Unsafe.SizeOf<UNICODE_STRING64>();
            if (!Emulator.IsRegionMapped(UnicodeStringPtr, UnicodeStringSize))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            if (!StructSerializer.ParseStruct(Emulator, UnicodeStringPtr, out UNICODE_STRING64 UnicodeString))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            return TryReadUnicodeString64(UnicodeString, out Value, out Status);
        }

        /// <summary>
        /// Reads a parsed 64-bit UNICODE_STRING from guest memory and returns the status the caller should propagate on failure.
        /// </summary>
        public bool TryReadUnicodeString64(UNICODE_STRING64 UnicodeString, out string Value, out NTSTATUS Status)
        {
            Value = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (UnicodeString.Length > UnicodeString.MaximumLength)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (UnicodeString.Length == 0)
                return true;

            if ((UnicodeString.Length & 1) != 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (UnicodeString.Buffer == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!Emulator.IsRegionMapped(UnicodeString.Buffer, UnicodeString.Length))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            Value = Emulator._emulator.ReadMemoryString(UnicodeString.Buffer, UnicodeString.Length, Encoding.Unicode).TrimEnd('\0');
            return true;
        }

        private ulong NextImageSectionId = 1;
        private readonly Dictionary<string, ulong> ImageSectionIdsByPath = new(StringComparer.OrdinalIgnoreCase);

        public ulong GetOrCreateImageSectionId(string Path)
        {
            string CanonicalPath = CanonicalizeImagePath(Path);
            if (string.IsNullOrEmpty(CanonicalPath))
                return 0;

            if (!ImageSectionIdsByPath.TryGetValue(CanonicalPath, out ulong Id))
            {
                Id = NextImageSectionId++;
                ImageSectionIdsByPath[CanonicalPath] = Id;
            }

            return Id;
        }

        public void AttachImageSectionIdentity(WinSection Section, string Path)
        {
            if (Section == null)
                return;

            string CanonicalPath = CanonicalizeImagePath(Path);
            if (string.IsNullOrEmpty(CanonicalPath))
                return;

            Section.ImageSectionId = GetOrCreateImageSectionId(CanonicalPath);
            Section.MappedImageCanonicalPath = CanonicalPath;
        }

        public void AttachImageSectionIdentity(WinModule Module, string Path)
        {
            if (Module == null)
                return;

            string CanonicalPath = CanonicalizeImagePath(Path);
            if (string.IsNullOrEmpty(CanonicalPath))
                return;

            Module.ImageSectionId = GetOrCreateImageSectionId(CanonicalPath);
            Module.CanonicalImagePath = CanonicalPath;
        }

        /// <summary>
        /// Reads a 64-bit OBJECT_ATTRIBUTES value and resolves its object name against known NT object-directory handles.
        /// </summary>
        public bool TryReadObjectAttributesName64(ulong ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes, out string Name, out string FullName, out NTSTATUS Status)
        {
            Attributes = default;
            Name = string.Empty;
            FullName = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (ObjectAttributesPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            uint ObjectAttributesSize = (uint)Unsafe.SizeOf<OBJECT_ATTRIBUTES64>();
            if (!Emulator.IsRegionMapped(ObjectAttributesPtr, ObjectAttributesSize))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            if (!StructSerializer.ParseStruct(Emulator, ObjectAttributesPtr, out Attributes))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            if (Attributes.ObjectName == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!TryReadUnicodeString64(Attributes.ObjectName, out Name, out Status))
                return false;

            FullName = ResolveObjectNameWithRootDirectory(Attributes.RootDirectory, Name);
            if (string.IsNullOrEmpty(FullName))
                FullName = Name;

            return true;
        }

        /// <summary>
        /// Reads a 32-bit OBJECT_ATTRIBUTES value and resolves its object name against known NT object-directory handles.
        /// </summary>
        public bool TryReadObjectAttributesName32(uint ObjectAttributesPtr, out uint RootDirectory, out uint ObjectName, out string Name, out string FullName, out NTSTATUS Status)
        {
            RootDirectory = 0;
            ObjectName = 0;
            Name = string.Empty;
            FullName = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (ObjectAttributesPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!Emulator.IsRegionMapped(ObjectAttributesPtr, ObjectAttributes32Size))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            RootDirectory = Emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x04);
            ObjectName = Emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x08);

            if (ObjectName == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!TryReadUnicodeString32(ObjectName, out Name, out Status))
                return false;

            FullName = ResolveObjectNameWithRootDirectory(RootDirectory, Name);
            if (string.IsNullOrEmpty(FullName))
                FullName = Name;

            return true;
        }

        /// <summary>
        /// Resolves a possibly relative NT object name against one of Brovan's synthetic object-directory handles.
        /// </summary>
        public string ResolveObjectNameWithRootDirectory(ulong RootDirectory, string Name)
        {
            if (!string.IsNullOrEmpty(Name) && Name.StartsWith("\\", StringComparison.Ordinal))
                return Name;

            string RootPath = GetKnownObjectDirectoryPath(RootDirectory);
            if (string.IsNullOrEmpty(RootPath))
                return null;

            if (string.IsNullOrEmpty(Name))
                return RootPath;

            return RootPath.TrimEnd('\\') + "\\" + Name.TrimStart('\\');
        }

        /// <summary>
        /// Returns the NT object-manager path represented by one of Brovan's synthetic object-directory handles.
        /// </summary>
        public string GetKnownObjectDirectoryPath(ulong RootDirectory)
        {
            if (RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY)
                return "\\KnownDlls";

            if (RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY)
                return "\\KnownDlls32";

            if (RootDirectory == HandleManager.BASE_NAMED_OBJECTS_DIRECTORY)
                return "\\Sessions\\1\\BaseNamedObjects";

            if (RootDirectory == HandleManager.RPC_CONTROL_DIRECTORY)
                return "\\RPC Control";

            return null;
        }

        /// <summary>
        /// Gets the synthetic handle for a supported NT object-manager directory path.
        /// </summary>
        public bool TryGetKnownObjectDirectoryHandle(string ObjectName, out ulong Handle)
        {
            Handle = 0;

            if (string.IsNullOrEmpty(ObjectName))
                return false;

            string Normalized = ObjectName.TrimEnd('\0');

            if (Normalized.Equals("\\KnownDlls", StringComparison.OrdinalIgnoreCase))
            {
                Handle = HandleManager.KNOWN_DLLS_DIRECTORY;
                return true;
            }

            if (Normalized.Equals("\\KnownDlls32", StringComparison.OrdinalIgnoreCase))
            {
                Handle = HandleManager.KNOWN_DLLS32_DIRECTORY;
                return true;
            }

            if (Normalized.Equals("\\Sessions\\1\\BaseNamedObjects", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("\\BaseNamedObjects", StringComparison.OrdinalIgnoreCase))
            {
                Handle = HandleManager.BASE_NAMED_OBJECTS_DIRECTORY;
                return true;
            }

            if (Normalized.Equals("\\RPC Control", StringComparison.OrdinalIgnoreCase))
            {
                Handle = HandleManager.RPC_CONTROL_DIRECTORY;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Resolves a 64-bit registry OBJECT_ATTRIBUTES value to a full NT registry path.
        /// </summary>
        public bool TryResolveRegistryObjectPath(ulong ObjectAttributesPtr, NTSTATUS MemoryFailureStatus, NTSTATUS EmptyPathStatus, NTSTATUS InvalidRootStatus, out string KeyPath, out NTSTATUS Status)
        {
            KeyPath = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (ObjectAttributesPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            bool Is64 = PointerSize == 8;
            uint ObjectAttributesSize = Is64 ? (uint)Unsafe.SizeOf<OBJECT_ATTRIBUTES64>() : ObjectAttributes32Size;
            if (!Emulator.IsRegionMapped(ObjectAttributesPtr, ObjectAttributesSize))
            {
                Status = MemoryFailureStatus;
                return false;
            }

            ulong RootDirectory;
            ulong ObjectNamePtr;
            if (Is64)
            {
                if (!StructSerializer.ParseStruct(Emulator, ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes))
                {
                    Status = MemoryFailureStatus;
                    return false;
                }

                RootDirectory = Attributes.RootDirectory;
                ObjectNamePtr = Attributes.ObjectName;
            }
            else
            {
                RootDirectory = Emulator._emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x04);
                ObjectNamePtr = Emulator._emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x08);
            }

            if (ObjectNamePtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            bool ReadName = Is64
                ? TryReadUnicodeString64(ObjectNamePtr, out KeyPath, out Status)
                : TryReadUnicodeString32((uint)ObjectNamePtr, out KeyPath, out Status);

            if (!ReadName)
            {
                if (Status == NTSTATUS.STATUS_ACCESS_VIOLATION)
                    Status = MemoryFailureStatus;
                return false;
            }

            if (RootDirectory != 0)
            {
                WinRegKey ParentKey = HandleManager.GetObjectByHandle<WinRegKey>(RootDirectory);
                if (ParentKey == null || string.IsNullOrEmpty(ParentKey.FullPath))
                {
                    Status = InvalidRootStatus;
                    return false;
                }

                if (string.IsNullOrEmpty(KeyPath))
                {
                    KeyPath = ParentKey.FullPath;
                    return true;
                }

                bool IsAbsoluteNtPath =
                    KeyPath.StartsWith("\\Registry\\", StringComparison.OrdinalIgnoreCase) ||
                    KeyPath.StartsWith("\\REGISTRY\\", StringComparison.OrdinalIgnoreCase);

                if (!IsAbsoluteNtPath)
                {
                    string ParentPath = ParentKey.FullPath.TrimEnd('\\', '\0');
                    string Relative = KeyPath.TrimStart('\\');
                    KeyPath = string.IsNullOrEmpty(Relative) ? ParentPath : ParentPath + "\\" + Relative;
                }
            }
            else if (string.IsNullOrEmpty(KeyPath))
            {
                Status = EmptyPathStatus;
                return false;
            }

            return true;
        }

        public ulong SetUnicodeString(ulong Address, string Buffer)
        {
            if (Buffer == null)
                return 0;

            ulong StructSize = (ulong)Unsafe.SizeOf<UNICODE_STRING64>();
            if (!Emulator.IsRegionMapped(Address, StructSize))
                return 0;

            int ByteLength = Buffer.Length * 2;
            int MaxByteLength = ByteLength + 2;

            ulong StringAddress = Emulator.MapUniqueAddress((ulong)MaxByteLength, MemoryProtection.ReadWrite);
            if (StringAddress == 0)
                return 0;

            Emulator._emulator.WriteMemory(StringAddress, Buffer, Encoding.Unicode);
            Emulator._emulator.WriteMemory(StringAddress + (ulong)ByteLength, (ushort)0, 2);

            Emulator._emulator.WriteMemory(Address + 0, (ushort)ByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 2, (ushort)MaxByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 8, StringAddress, 8);

            return StringAddress;
        }

        public void WriteUnicodeStringRelative(BinaryEmulator Instance, ulong UnicodeStringAddress, ulong BaseAddress, string Value)
        {
            ushort Length = (ushort)(Value.Length * 2);
            ushort MaximumLength = (ushort)(Length + 2);

            ulong BufferAddress = Instance.MapUniqueAddress((ulong)MaximumLength, MemoryProtection.ReadWrite);
            Instance._emulator.WriteMemory(BufferAddress, Value, System.Text.Encoding.Unicode);
            Instance._emulator.WriteMemory(BufferAddress + (ulong)Length, (ushort)0, 2);

            Instance._emulator.WriteMemory(UnicodeStringAddress + 0, Length, 2);
            Instance._emulator.WriteMemory(UnicodeStringAddress + 2, MaximumLength, 2);

            ulong Relative = BufferAddress - BaseAddress;
            Instance._emulator.WriteMemory(UnicodeStringAddress + 8, Relative, 8);
        }

        public uint SetUnicodeString32(uint Address, string Buffer)
        {
            if (Buffer == null)
                return 0;

            ulong StructSize = (ulong)Unsafe.SizeOf<UNICODE_STRING>();
            if (!Emulator.IsRegionMapped(Address, StructSize))
                return 0;

            int ByteLength = Buffer.Length * 2;
            int MaxByteLength = ByteLength + 2;

            uint StringAddress = (uint)Emulator.MapUniqueAddress((ulong)MaxByteLength, MemoryProtection.ReadWrite);
            if (StringAddress == 0)
                return 0;

            Emulator._emulator.WriteMemory(StringAddress, Buffer, Encoding.Unicode);
            Emulator._emulator.WriteMemory((ulong)StringAddress + (ulong)ByteLength, (ushort)0, 2);

            Emulator._emulator.WriteMemory(Address + 0, (ushort)ByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 2, (ushort)MaxByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 4, StringAddress);

            return StringAddress;
        }

        /// <summary>
        /// Gets a x64 argument based on the index.
        /// </summary>
        /// <param name="Index">Index to read from. starting from 0.</param>
        /// <returns></returns>
        public ulong GetArg64(int Index, bool UInt = false)
        {
            if (_argCacheValid)
            {
                switch (Index)
                {
                    case 0: return _argCacheR10;
                    case 1: return _argCacheRDX;
                    case 2: return _argCacheR8;
                    case 3: return _argCacheR9;
                }
                ulong StackArgAddress = _argCacheRSP + 0x28UL + (ulong)((Index - 4) * 8);
                return UInt ? Emulator._emulator.ReadMemoryUInt(StackArgAddress) : Emulator._emulator.ReadMemoryULong(StackArgAddress);
            }

            // Fallback (no cache)
            if (Index == 0) return Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R10);
            if (Index == 1) return Emulator._emulator.ReadRegister(Registers.UC_X86_REG_RDX);
            if (Index == 2) return Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R8);
            if (Index == 3) return Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R9);

            ulong RSP = Emulator._emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong StackArgAddress2 = RSP + 0x28UL + (ulong)((Index - 4) * 8);
            return UInt ? Emulator._emulator.ReadMemoryUInt(StackArgAddress2) : Emulator._emulator.ReadMemoryULong(StackArgAddress2);
        }

        public ulong GetArg(int Index)
        {
            if (Emulator._binary.Architecture == BinaryArchitecture.x64)
                return GetArg64(Index);

            return Emulator._emulator.ReadMemoryUInt(_argCacheArgBase + (ulong)(Index * 4));
        }

        public uint GetArg32(int Index) => (uint)GetArg(Index);

        public uint GenerateRandomPID()
        {
            uint PID = (uint)RandomGen.Next(500, 29999);
            if (PIDs.TryGetValue(PID, out _))
            {
                return GenerateRandomPID();
            }
            PIDs.Add(PID, true);
            return PID;
        }

        private User GenerateRandomSvchostUser()
        {
            int User = RandomGen.Next(0, 2);
            if (User == 0)
                return Windows.User.System;
            else if (User == 1)
                return Windows.User.LocalService;
            else
                return Windows.User.Standard;
        }

        public byte[] GenerateRandomData(int Length)
        {
            if (Length < 0)
                return null;
            byte[] Data = new byte[Length];
            RandomGen.NextBytes(Data);
            return Data;
        }

        public void InitializeProcessTimes(WinProcess Process, long AgeMilliseconds, bool GenerateCpuTimes)
        {
            if (Process == null)
                return;

            long Now = Emulator.GetEmulatedSystemTimeFileTimeUtc();
            long AgeTime = SaturatingMillisecondsToFileTimeDuration(AgeMilliseconds);
            Process.CreationTime = Now >= AgeTime ? Now - AgeTime : Now;
            Process.ExitTime = 0;

            if (!GenerateCpuTimes || AgeMilliseconds <= 0)
                return;

            long MaxCpuMilliseconds = Math.Max(1, AgeMilliseconds / 8);
            int CpuMilliseconds = (int)Math.Min(MaxCpuMilliseconds, int.MaxValue);
            Process.KernelTime = SaturatingMillisecondsToFileTimeDuration(RandomGen.Next(0, CpuMilliseconds));
            Process.UserTime = SaturatingMillisecondsToFileTimeDuration(RandomGen.Next(0, CpuMilliseconds));
        }

        public void UpdateProcessTimes(WinProcess Process)
        {
            if (Process == null)
                return;

            if (Process.CreationTime == 0)
                InitializeProcessTimes(Process, Process.PID == PID ? Emulator.EmulatedTickCount64 : 0, false);

            if (Process.PID == PID && Process.ExitTime == 0)
                Process.UserTime = Math.Max(Process.UserTime, SaturatingMillisecondsToFileTimeDuration(Emulator.EmulatedTickCount64));
        }

        private static long SaturatingMillisecondsToFileTimeDuration(long Milliseconds)
        {
            if (Milliseconds <= 0)
                return 0;

            if (Milliseconds > long.MaxValue / 10000)
                return long.MaxValue;

            return Milliseconds * 10000;
        }

        // Current Process
        public uint PID = 0;
        public uint PPID = 0;
        public WinHandle STD_OUT;
        public WinHandle STD_IN;
        public WinHandle ConsoleHandle;
        public uint CurrentPriority = 0x8; // Default priority (Normal), changes only if the program changed it explicitly.
        public User CurrentUser = User.Standard;
        public string CurrentUserSid = "S-1-5-21-1000-1000-1000-1001";

        // Other
        public List<WinHandle> WinHandles = new List<WinHandle>();
        public List<WinProcess> WinProcesses = new List<WinProcess>();
        public List<WinFile> WinFiles = new List<WinFile>();
        public List<WinMutex> WinMutexes = new List<WinMutex>();
        public List<WinModule> WinModules = new List<WinModule>();
        public List<WinModule> MappedImageViews = new List<WinModule>();
        private readonly Dictionary<string, int> ImageViewCountsByPath = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        internal KuserSharedDataManager KuserSharedData;

        /// <summary>
        /// Current performance counter, in the units <see cref="KuserSharedDataManager.QpcFrequency"/> claims.
        /// </summary>
        internal static ulong QueryPerformanceCounterValue()
        {
            long Ticks = System.Diagnostics.Stopwatch.GetTimestamp();
            long HostFrequency = System.Diagnostics.Stopwatch.Frequency;
            if (HostFrequency == KuserSharedDataManager.QpcFrequency)
                return (ulong)Ticks;

            return (ulong)((decimal)Ticks * KuserSharedDataManager.QpcFrequency / HostFrequency);
        }
        internal HandleManager HandleManager = new HandleManager();
        private static string WinRegPath = Path.Combine(AppContext.BaseDirectory, "WinReg");
        public RegistryManager RegManager = new RegistryManager(WinRegPath);
        public Hive[] RegHives;
        public HashSet<string> TempRegistryKeys = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> DeletedRegistryKeys = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Dictionary<string, ValueNode>> TempRegistryValues = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, HashSet<string>> DeletedRegistryValues = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Hive> TempRegistryKeyHives = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> SyntheticDirectories = new(StringComparer.OrdinalIgnoreCase);
        internal string SyntheticVolumeGuid { get; private set; }
        internal string SyntheticVolumeGuidSymbolicLink { get; private set; }
        internal string SyntheticVolumeWin32GuidPath { get; private set; }
        internal byte[] SyntheticMountDevUniqueId { get; private set; }
        private BinaryEmulator Emulator;

        private bool _argCacheValid;
        private ulong _argCacheR10;
        private ulong _argCacheRDX;
        private ulong _argCacheR8;
        private ulong _argCacheR9;
        private ulong _argCacheRSP;
        private ulong _argCacheArgBase;

        internal bool X86GateArgs = true;

        // Batch register array for GetArg64
        private static readonly int[] WinX64SyscallArgRegs = new int[]
        {
            (int)Registers.UC_X86_REG_R10,
            (int)Registers.UC_X86_REG_RDX,
            (int)Registers.UC_X86_REG_R8,
            (int)Registers.UC_X86_REG_R9,
            (int)Registers.UC_X86_REG_RSP,
        };

        private readonly ulong[] _winX64SyscallArgValues = new ulong[5];

        /// <summary>
        /// the 5 registers (R10, RDX, R8, R9, RSP) in a single batch read.
        /// Called once before the syscall handler
        /// runs; GetArg64 then reads from the cache.
        /// </summary>
        public void BeginSyscall()
        {
            if (Emulator._binary.Architecture != BinaryArchitecture.x64)
            {
                _argCacheValid = false;
                if (Emulator._binary.Architecture == BinaryArchitecture.x86)
                {
                    uint ESP = Emulator._emulator.ReadRegister32(Registers.UC_X86_REG_ESP);
                    _argCacheArgBase = X86GateArgs ? ESP + 8u : ESP + 4u;
                }
                return;
            }
            ulong[] Vals = _winX64SyscallArgValues;
            if (!Emulator._emulator.ReadRegisterBatch(WinX64SyscallArgRegs, Vals, 5))
            {
                // Fallback: individual reads
                Vals[0] = Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R10);
                Vals[1] = Emulator._emulator.ReadRegister(Registers.UC_X86_REG_RDX);
                Vals[2] = Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R8);
                Vals[3] = Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R9);
                Vals[4] = Emulator._emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            }
            _argCacheR10 = Vals[0];
            _argCacheRDX = Vals[1];
            _argCacheR8 = Vals[2];
            _argCacheR9 = Vals[3];
            _argCacheRSP = Vals[4];
            _argCacheValid = true;
        }

        /// <summary>
        /// the syscall handler returns (in a finally block).
        /// </summary>
        public void EndSyscall()
        {
            _argCacheValid = false;
        }

        public List<WinEvent> WinEvents = new List<WinEvent>();
        public List<WinSemaphore> WinSemaphores = new List<WinSemaphore>();
        public List<WinRegistryNotification> RegistryNotifications = new List<WinRegistryNotification>();
        public List<WinSection> WinSections = new List<WinSection>();
        private readonly Dictionary<ulong, int> WinHandleIndex = new Dictionary<ulong, int>();
        internal void AddWinHandle(WinHandle h)
        {
            WinHandles.Add(h);
            WinHandleIndex[h.Handle] = WinHandles.Count - 1;
        }

        internal void RemoveWinHandle(ulong Handle)
        {
            if (!WinHandleIndex.TryGetValue(Handle, out int Idx)) return;
            int Last = WinHandles.Count - 1;
            if (Idx != Last) { var Moved = WinHandles[Last]; WinHandles[Idx] = Moved; WinHandleIndex[Moved.Handle] = Idx; }
            WinHandles.RemoveAt(Last); WinHandleIndex.Remove(Handle);
        }

        public List<WinPort> WinPorts = new List<WinPort>();
        public List<WinEtwRegistration> WinEtwRegistrations = new List<WinEtwRegistration>();
        public List<WinJob> WinJobs = new List<WinJob>();
        public ulong EtwNotificationEventHandle;
        internal PebLdrTracker LdrTracker;
        public readonly Dictionary<ulong, WinWindow> WinWindows = new();
        public readonly Dictionary<ushort, WinWindowClass> WinWindowClassesByAtom = new();
        private readonly Dictionary<string, ushort> WinWindowClassAtomsByKey = new(StringComparer.OrdinalIgnoreCase);
        private ushort NextWindowClassAtom = 0xC000;
        public readonly List<ulong> TopLevelWindows = new();
        private const uint UserHandleEntryCount = 0x200;
        private const uint UserHandleEntrySize = 0x20;
        private const ulong UserWindowObjectSize = 0x200;
        private const ulong UserClassObjectSize = 0x100;
        private const ulong UserDesktopInfoSize = 0x48;
        private const ulong UserPrimaryMonitorSize = 0x1000;
        private const ulong Win32ClientInfoX64Base = 0x800;
        private const ulong Win32ClientInfoX86Base = 0x6CC;
        private const int Win32ClientInfoPDeskInfoSlot = 2;
        private const int Win32ClientInfoDesktopSlot = 4;
        private const int Win32ClientInfoActiveWindowSlot = 8;
        private const int Win32ClientInfoActiveWindowPointerSlot = 9;
        private const ulong UserSharedInfoMirrorSize = 0x1B54;
        private const ulong UserMessageBitmaskSize = 0x80;
        private const uint UserMessageBitmaskMax = 0x3FF;
        private ulong UserMessageBitmask1Address;
        private ulong UserMessageBitmask2Address;
        private const uint GdiHandleEntryCount = 0x1000;
        private const uint GdiHandleEntrySize = 0x18;
        private ulong GdiHandleTableAddress;
        private ushort NextGdiHandleIndex = 1;
        private ushort NextGdiHandleUniq = 0x77;
        private const int SmCxScreen = 0;
        private const int SmCyScreen = 1;
        private const byte UserHandleTypeWindow = 1;
        private ushort NextUserHandleIndex = 1;
        private ushort NextUserHandleUniq = 1;
        private ulong UserServerInfoAddress;
        private ulong UserHandleTableAddress;
        private ulong UserDesktopInfoAddress;
        private ulong UserDesktopOwnerAddress;
        private ulong UserPrimaryMonitorAddress;
        private ulong UserSharedInfoMirrorAddress;
        private ulong UserSharedDelta;
        public ulong ActiveWindow;
        public ulong FocusWindow;
        private readonly Dictionary<string, string> _normalizedPathCache = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Initialize the environment for the helper (Processes, Console, etc).
        /// </summary>
        public WinSysHelper(BinaryEmulator Emulator)
        {
            Shared = new WindowsSharedBuffer();
            this.Emulator = Emulator;
            SyntheticVolumeGuid = Guid.NewGuid().ToString("D").ToLowerInvariant();
            SyntheticVolumeGuidSymbolicLink = $"\\??\\Volume{{{SyntheticVolumeGuid}}}";
            SyntheticVolumeWin32GuidPath = $"\\\\?\\Volume{{{SyntheticVolumeGuid}}}\\";
            SyntheticMountDevUniqueId = Guid.Parse(SyntheticVolumeGuid).ToByteArray();
            KuserSharedData = new KuserSharedDataManager(Emulator);
            PID = GenerateRandomPID();
            PPID = GenerateRandomPID();
            string FileName = null;
            BinaryFile Binary = Emulator._binary;
            if (Binary.Location != null)
            {
                try
                {
                    FileName = Path.GetFileName(Binary.Location);
                }
                catch
                {

                }
            }

            DesktopWindowTitle = string.IsNullOrWhiteSpace(FileName) ? "Brovan" : FileName;

            if (Binary.PE.Subsystem.HasFlag(Subsystem.WindowsCui))
            {
                WinFile STDIN = new WinFile() { Device = true, Path = "\\Device\\ConDrv" };
                WinFile STDOUT = new WinFile() { Device = true, Path = "\\Device\\ConDrv" };
                STD_IN = HandleManager.AddHandle(STDIN, AccessMask.FileReadData);
                STD_OUT = HandleManager.AddHandle(STDOUT, AccessMask.FileWriteData);
            }
            else
            {
                STD_IN = HandleManager.AddHandle(new WinFile(), AccessMask.None);
                STD_OUT = HandleManager.AddHandle(new WinFile(), AccessMask.FileWriteData);
            }
            // Generate some processes for the emulated program to work with
            uint WininitPID = GenerateRandomPID();
            uint ServicesPID = GenerateRandomPID();
            uint WinlogonPID = GenerateRandomPID();
            int MsMpRand = RandomGen.Next();
            uint FirefoxParent = GenerateRandomPID();
            WinProcesses = new List<WinProcess> {
                new WinProcess{ PID = 0, PPID = 0, Name = "System Idle Process", Path = null, Status = ProtectionStatus.Unaccessible, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = 4, PPID = 0, Name = "System", Path = "C:\\Windows\\System32\\ntoskrnl.exe", Status = ProtectionStatus.Full, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = 4, Name = "Secure System", Path = "C:\\Windows\\System32\\securekernel.exe", Status = ProtectionStatus.SecureFull, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = 4, Name = "Registry", Path = "Registry", Status = ProtectionStatus.Full, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = 4, Name = "smss.exe", Path = "C:\\Windows\\System32\\smss.exe", Status = ProtectionStatus.LightTCB, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = 4, Name = "Memory Compression", Path = "MemCompression", Status = ProtectionStatus.Full, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = PID, PPID = PPID, Name = FileName, Path = Binary.Location != null ? Binary.Location : null, Status = ProtectionStatus.None, RunningUser = CurrentUser, Critical = false, Arch = Binary.Architecture, PrimaryToken = new WinToken{SessionId = 1, IsElevated = false, IsRestricted = false, OwningProcessId = PID, OwningThreadId = 0, Type = TokenType.Primary } },
                new WinProcess{ PID = PPID, PPID = GenerateRandomPID(), Name = "explorer.exe", Path = "C:\\Windows\\explorer.exe", Status = ProtectionStatus.None, RunningUser = User.Standard, Critical = false, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = FirefoxParent, PPID = PPID, Name = "firefox.exe", Arch = BinaryArchitecture.x64, Critical = false, Path = "C:\\Program Files\\Mozilla Firefox\\firefox.exe", RunningUser = User.Standard, Status = ProtectionStatus.None},
                new WinProcess{ PID = GenerateRandomPID(), PPID = FirefoxParent, Name = "crashhelper.exe", Arch = BinaryArchitecture.x64, Critical = false, Path = "C:\\Program Files\\Mozilla Firefox\\crashhelper.exe", RunningUser = User.Standard, Status = ProtectionStatus.None},
                new WinProcess{ PID = WininitPID, PPID = GenerateRandomPID(), Name = "wininit.exe", Path = "C:\\Windows\\System32\\wininit.exe", Status = ProtectionStatus.LightTCB, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = ServicesPID, PPID = WininitPID, Name = "services.exe", Path = "C:\\Windows\\System32\\services.exe", Status = ProtectionStatus.LightTCB, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = WinlogonPID, PPID = GenerateRandomPID(), Name = "winlogon.exe", Path = "C:\\Windows\\System32\\winlogon.exe", Status = ProtectionStatus.None, RunningUser = User.System, Critical = false, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = WinlogonPID, Name = "dwm.exe", Path = "C:\\Windows\\System32\\dwm.exe", Status = ProtectionStatus.None, RunningUser = User.WindowManager, Critical = false, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = WinlogonPID, Name = "fontdrvhost.exe", Path = "C:\\Windows\\System32\\fontdrvhost.exe", Status = ProtectionStatus.None, RunningUser = User.FontManager, Critical = false, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = GenerateRandomPID(), Name = "csrss.exe", Path = "C:\\Windows\\System32\\csrss.exe", Status = ProtectionStatus.LightTCB, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = ServicesPID, Name = "MsMpEng.exe", Path = $"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.{MsMpRand.ToString()}\\MsMpEng.exe", Status = ProtectionStatus.LightAM, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = ServicesPID, Name = "MpDefenderCoreService.exe", Path = $"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.{MsMpRand.ToString()}\\MpDefenderCoreService.exe", Status = ProtectionStatus.LightAM, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
            };

            // Generate several random svchost.exe processes
            int RandomSvchostNumber = RandomGen.Next(10, 17);
            for (int i = 0; i < RandomSvchostNumber; i++)
            {
                WinProcesses.Add(new WinProcess { PID = GenerateRandomPID(), PPID = ServicesPID, Name = "svchost.exe", Path = "C:\\Windows\\System32\\svchost.exe", Status = ProtectionStatus.None, RunningUser = GenerateRandomSvchostUser(), Critical = true, Arch = BinaryArchitecture.x64 });
            }

            // Generate several firefox child processes
            int RandomFirefoxNumber = RandomGen.Next(5, 10);
            for (int i = 0; i < RandomFirefoxNumber; i++)
            {
                WinProcesses.Add(new WinProcess { PID = GenerateRandomPID(), PPID = FirefoxParent, Name = "firefox.exe", Path = "C:\\Program Files\\Mozilla Firefox\\firefox.exe", Status = ProtectionStatus.None, RunningUser = User.Standard, Critical = false, Arch = BinaryArchitecture.x64 });
            }

            foreach (WinProcess Process in WinProcesses)
            {
                if (Process.PID == PID)
                    InitializeProcessTimes(Process, Emulator.EmulatedTickCount64, false);
                else
                    InitializeProcessTimes(Process, RandomGen.Next(60 * 1000, 2 * 60 * 60 * 1000), true);
            }

            // Prepare Devices
            WinFile hConsoleHandle = new WinFile();
            hConsoleHandle.Device = true;
            hConsoleHandle.Path = "\\Device\\ConDrv";
            hConsoleHandle.Handler = ConsoleServer.Handle;
            ConsoleHandle = HandleManager.AddHandle(hConsoleHandle, AccessMask.GenericRead | AccessMask.GenericWrite);
            List<Hive> Hives = new List<Hive>();
            if (Directory.Exists(WinRegPath))
            {
                foreach (string HiveFile in Directory.GetFiles(WinRegPath))
                {
                    try
                    {
                        string Name = Path.GetFileName(HiveFile);
                        Hive Loaded = RegManager.LoadHive(Name);
                        if (Loaded == null)
                            continue;
                        Hives.Add(Loaded);
                    }
                    catch
                    {

                    }
                }
            }
            RegHives = Hives.ToArray();
            InitializeSyntheticRegistryDefaults();

            const ulong PreAllocSharedSectionSize = 0x10000;
            ulong PreAllocSharedBase = Emulator.MapUniqueAddress(PreAllocSharedSectionSize, MemoryProtection.ReadWrite);
            if (PreAllocSharedBase != 0)
            {
                WinSections.Add(new WinSection
                {
                    Name = "\\Windows\\SharedSection",
                    Size = PreAllocSharedSectionSize,
                    Protection = 0x04,
                    Attributes = 0,
                    BackingAddress = PreAllocSharedBase,
                    Initialized = false
                });
            }

            foreach (string PortName in new[]
            {
                "\\Windows\\ApiPort",
                "\\Windows\\SbApiPort",
                "\\RPC Control\\ntsvcs",
                "\\RPC Control\\lsarpc",
                "\\RPC Control\\samr",
                "\\RPC Control\\srvsvc",
                "\\RPC Control\\epmapper",
                "\\RPC Control\\svcctl",
                "\\RPC Control\\wkssvc",
                "\\RPC Control\\netlogon",
                "\\RPC Control\\winreg",
                "\\RPC Control\\atsvc",
                "\\RPC Control\\plugplay",
                "\\RPC Control\\tapsrv",
                "\\RPC Control\\keysvc",
            })
            {
                WinPorts.Add(new WinPort
                {
                    Name = PortName,
                    Handler = RPC.Ports.CsrssPortHandler.Handle
                });
            }
        }

        public enum ExceptionType
        {
            Read = 0,
            Write = 1,
            Execute = 8
        }

        public class ExceptionInformation
        {
            public ulong Address;
            public ExceptionType Type;
            public NTSTATUS Status;
            public ulong[] CustomParameters;
            public ulong[] Parameters
            {
                get
                {
                    if (CustomParameters != null && CustomParameters.Length != 0)
                        return CustomParameters;

                    if (Type != 0 || Address != 0)
                        return new[] { (ulong)Type, Address };

                    return Array.Empty<ulong>();
                }
            }
        }

        public bool UnmapViewOfSection(ulong BaseAddress)
        {
            if (BaseAddress == 0)
                return false;

            WinModule Module = FindMappedImageViewByAddress(BaseAddress);
            if (Module != null)
            {
                ulong ViewBase = Module.MappedBase;
                ulong End = ViewBase + Module.SizeOfImage;

                List<MemoryRegion> RegionsToUnmap = Emulator._memory
                    .Where(R => R.BaseAddress >= ViewBase && R.BaseAddress < End)
                    .OrderByDescending(R => R.BaseAddress)
                    .ToList();

                bool UnmappedAny = false;
                for (int i = 0; i < RegionsToUnmap.Count; i++)
                {
                    MemoryRegion Region = RegionsToUnmap[i];
                    ulong Size = Region.Size != 0 ? Region.Size : (Region.RequestedSize + 0xFFF) & ~0xFFFUL;
                    if (Size == 0)
                        continue;

                    if (Emulator._emulator.UnmapMemory(Region.BaseAddress, Size))
                    {
                        if (Emulator.TryFindMemoryRegionByBase(Region.BaseAddress, out int MemIndex, out _))
                            Emulator.RemoveMemoryRegionAt(MemIndex);

                        Emulator.AddFreedRegion(Region.BaseAddress, Size);
                        UnmappedAny = true;
                    }
                }

                if (UnmappedAny)
                {
                    UnregisterMappedImageView(Module);

                    if (!Module.IsSectionView)
                    {
                        WinModule LoadedModule = WinModules?.FirstOrDefault(M => M != null && M.MappedBase == Module.MappedBase);
                        if (LoadedModule != null)
                            LoadedModule.Initialized = false;
                    }
                }

                return UnmappedAny;
            }

            if (!Emulator.TryFindMemoryRegion(BaseAddress, out MemoryRegion ViewRegion))
                return false;

            return Emulator.UnmapMemoryRegion(ViewRegion.BaseAddress);
        }

        /// <summary>
        /// Invoke KiUserExceptionDispatcher with the specified exception.
        /// </summary>
        /// <param name="Exception">NTSTATUS exception code.</param>
        /// <param name="ExceptionInformation">Optional exception parameters (up to 15).</param>
        public void InvokeException(NTSTATUS Exception, ExceptionInformation ExceptionInformation = null)
        {
            if (Emulator == null)
                return;

            if (Emulator._binary == null)
                return;

            if (ExceptionInformation == null)
                ExceptionInformation = new ExceptionInformation { Status = Exception };
            else
                ExceptionInformation.Status = Exception;


            WinModule ntdll = WinModules.FirstOrDefault(m => m.Name != null && m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
            if (ntdll == null)
            {
                Emulator.TriggerEventMessage("[-] InvokeException failed: ntdll.dll is not loaded.", LogFlags.Issues);
                return;
            }

            ulong dispatcher = WinEmulatedThread.GetState(Emulator.CurrentThread).ExceptionFunc;
            if (dispatcher == 0)
            {
                dispatcher = GetExportAddress(ntdll, "KiUserExceptionDispatcher");
                if (dispatcher == 0 && ntdll.ExportsByName != null && ntdll.ExportsByName.TryGetValue("KiUserExceptionDispatcher", out ulong originalVa))
                {
                    dispatcher = Emulator.TranslateVirtualAddress(originalVa, "ntdll.dll");
                }
                WinEmulatedThread.GetState(Emulator.CurrentThread).ExceptionFunc = dispatcher;
            }

            if (dispatcher == 0)
            {
                Emulator.TriggerEventMessage("[-] InvokeException failed: KiUserExceptionDispatcher export was not found.", LogFlags.Issues);
                return;
            }

            if (PointerSize == 4)
                DispatchExceptionX86(dispatcher, Exception, ExceptionInformation);
            else
                DispatchExceptionX64(dispatcher, Exception, ExceptionInformation);
        }

        private static ulong AlignDown(ulong Value, ulong Align)
        {
            return Value & ~(Align - 1);
        }

        private static void WriteUInt16(Span<byte> Buffer, int Offset, ushort Value)
        {
            if (Offset < 0 || Offset + 2 > Buffer.Length)
                return;

            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(Offset, 2), Value);
        }

        private static void WriteUInt32(Span<byte> Buffer, int Offset, uint Value)
        {
            if (Offset < 0 || Offset + 4 > Buffer.Length)
                return;

            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        private static void WriteUInt64(Span<byte> Buffer, int Offset, ulong Value)
        {
            if (Offset < 0 || Offset + 8 > Buffer.Length)
                return;

            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
        }

        private uint GuessContextSizeFromDispatcher(ulong DispatcherAddress)
        {
            try
            {
                Span<byte> Code = stackalloc byte[0x80];
                if (!Emulator._emulator.ReadMemory(DispatcherAddress, Code, 0x80))
                    return 0;

                for (int i = 0; i + 8 <= Code.Length; i++)
                {
                    // lea rcx, [rsp + imm32]
                    if (Code[i] == 0x48 && Code[i + 1] == 0x8D && Code[i + 2] == 0x8C && Code[i + 3] == 0x24)
                    {
                        uint Disp = BinaryPrimitives.ReadUInt32LittleEndian(Code.Slice(i + 4, 4));

                        if (Disp >= 0x400 && Disp <= 0x600 && (Disp % 0x10) == 0)
                            return Disp;
                    }
                    // add rcx, imm32 (typically have the size according to ntdll analysis in IDA to multiple versions)
                    else if (Code[i] == 0x48 && Code[i + 1] == 0x81 && Code[i + 2] == 0xC1)
                    {
                        uint Disp = BinaryPrimitives.ReadUInt32LittleEndian(Code.Slice(i + 3, 4));

                        if (Disp >= 0x400 && Disp <= 0x600 && (Disp % 0x10) == 0)
                            return Disp;
                    }
                }
            }
            catch
            {
                // Ignore and fall back to a default.
            }

            return 0;
        }

        private void DispatchExceptionX86(ulong DispatcherAddress, NTSTATUS Exception, ExceptionInformation ExceptionInformation)
        {
            const uint ExceptionRecordSize = 0x50;
            const uint ContextSize = 0x2CC;
            const uint CONTEXT_I386 = 0x00010000;
            const uint CONTEXT_CONTROL = 0x00000001;
            const uint CONTEXT_INTEGER = 0x00000002;
            const uint CONTEXT_SEGMENTS = 0x00000004;

            uint InitialEsp = Emulator.ReadRegister32(Registers.UC_X86_REG_ESP);
            uint InitialEip = Emulator.ReadRegister32(Registers.UC_X86_REG_EIP);
            uint InitialEFlags = Emulator.ReadRegister32(Registers.UC_X86_REG_EFLAGS);

            uint AllocationSize = ContextSize + ExceptionRecordSize + 0x20;
            uint NewEsp = (uint)AlignDown(InitialEsp - AllocationSize, 0x10);

            if (!Emulator.IsRegionMapped(NewEsp, AllocationSize))
            {
                ulong PageStart = NewEsp & ~0xFFFUL;
                ulong PageEnd = BinaryEmulator.AlignUp((ulong)NewEsp + AllocationSize, 0x1000);

                for (ulong Page = PageStart; Page < PageEnd; Page += 0x1000)
                {
                    if (!Emulator.IsRegionMapped(Page, 1))
                        Emulator._emulator.MapMemory(Page, 0x1000, MemoryProtection.ReadWrite);
                    else
                        Emulator._emulator.SetMemoryProtection(Page, 0x1000, MemoryProtection.ReadWrite);
                }

                if (!Emulator.IsRegionMapped(NewEsp, AllocationSize))
                {
                    Emulator.TriggerEventMessage($"[-] InvokeException failed: 32-bit exception frame not mapped (ESP=0x{NewEsp:X}).", LogFlags.Issues);
                    return;
                }
            }

            uint ContextAddress = NewEsp + 0x10;
            uint ExceptionRecordAddress = ContextAddress + ContextSize;

            Span<byte> Context = Shared.GetSpan(ContextSize);
            Context.Clear();
            WriteUInt32(Context, 0x00, CONTEXT_I386 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS);
            WriteUInt32(Context, 0x8C, Emulator.ReadRegister32(Registers.UC_X86_REG_GS));
            WriteUInt32(Context, 0x90, Emulator.ReadRegister32(Registers.UC_X86_REG_FS));
            WriteUInt32(Context, 0x94, Emulator.ReadRegister32(Registers.UC_X86_REG_ES));
            WriteUInt32(Context, 0x98, Emulator.ReadRegister32(Registers.UC_X86_REG_DS));
            WriteUInt32(Context, 0x9C, Emulator.ReadRegister32(Registers.UC_X86_REG_EDI));
            WriteUInt32(Context, 0xA0, Emulator.ReadRegister32(Registers.UC_X86_REG_ESI));
            WriteUInt32(Context, 0xA4, Emulator.ReadRegister32(Registers.UC_X86_REG_EBX));
            WriteUInt32(Context, 0xA8, Emulator.ReadRegister32(Registers.UC_X86_REG_EDX));
            WriteUInt32(Context, 0xAC, Emulator.ReadRegister32(Registers.UC_X86_REG_ECX));
            WriteUInt32(Context, 0xB0, Emulator.ReadRegister32(Registers.UC_X86_REG_EAX));
            WriteUInt32(Context, 0xB4, Emulator.ReadRegister32(Registers.UC_X86_REG_EBP));
            WriteUInt32(Context, 0xB8, InitialEip);
            WriteUInt32(Context, 0xBC, Emulator.ReadRegister32(Registers.UC_X86_REG_CS));
            WriteUInt32(Context, 0xC0, InitialEFlags);
            WriteUInt32(Context, 0xC4, InitialEsp);
            WriteUInt32(Context, 0xC8, Emulator.ReadRegister32(Registers.UC_X86_REG_SS));
            Emulator._emulator.WriteMemory(ContextAddress, Context.Slice(0, (int)ContextSize));

            Span<byte> Record = Shared.GetSpan(ExceptionRecordSize);
            Record.Clear();
            WriteUInt32(Record, 0x00, (uint)Exception);
            WriteUInt32(Record, 0x04, 0);
            WriteUInt32(Record, 0x08, 0);
            WriteUInt32(Record, 0x0C, InitialEip);

            ulong[] Parameters = ExceptionInformation?.Parameters ?? Array.Empty<ulong>();
            uint NumberParameters = (uint)Math.Min(Parameters.Length, 15);
            WriteUInt32(Record, 0x10, NumberParameters);
            for (int i = 0; i < (int)NumberParameters; i++)
                WriteUInt32(Record, 0x14 + (i * 4), (uint)Parameters[i]);

            Emulator._emulator.WriteMemory(ExceptionRecordAddress, Record.Slice(0, (int)ExceptionRecordSize));

            WriteUInt32(NewEsp, ExceptionRecordAddress);
            WriteUInt32(NewEsp + 4, ContextAddress);

            Emulator.WriteRegister32(Registers.UC_X86_REG_ESP, NewEsp);
            Emulator.WriteRegister32(Registers.UC_X86_REG_EIP, (uint)DispatcherAddress);
        }

        private void DispatchExceptionX64(ulong DispatcherAddress, NTSTATUS Exception, ExceptionInformation ExceptionInformation)
        {
            const uint ExceptionRecordSize = 0x98;
            const uint MachineFrameSize = 0x40;

            ulong InitialRsp = Emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong InitialRip = Emulator.ReadRegister(Registers.UC_X86_REG_RIP);
            ulong InitialEFlags = Emulator.ReadRegister(Registers.UC_X86_REG_EFLAGS);

            uint ContextSize = GuessContextSizeFromDispatcher(DispatcherAddress);
            if (ContextSize == 0)
                ContextSize = 0x4F0; // Common on many builds; field offsets remain fixed.
            ContextSize = (uint)BinaryEmulator.AlignUp(ContextSize, 0x10);

            ulong CombinedSize = BinaryEmulator.AlignUp((ulong)ContextSize + ExceptionRecordSize, 0x10);
            ulong AllocationSize = CombinedSize + MachineFrameSize;

            ulong NewRsp = AlignDown(InitialRsp - AllocationSize, 0x100);

            // Validate that the exception frame stays within the mapped stack.
            EmulatedThread Thread = Emulator.CurrentThread;
            if (Thread != null)
            {
                ulong StackLow = Thread.StackAddress;
                ulong StackHigh = Thread.StackAddress + Thread.StackSize;

                if (NewRsp < StackLow || (NewRsp + AllocationSize) > StackHigh)
                {
                    if ((Emulator.Settings.Flags & LogFlags.Issues) != 0)
                        Emulator.TriggerEventMessage($"[-] InvokeException failed: insufficient stack space (RSP=0x{InitialRsp:X}, NewRSP=0x{NewRsp:X}, Need=0x{AllocationSize:X}).", LogFlags.Issues);
                    return;
                }
            }

            if (!Emulator.IsRegionMapped(NewRsp, AllocationSize))
            {
                // Commit stack pages in the current thread's stack reserve for the exception frame.
                if (Thread != null)
                {
                    ulong StackLow = Thread.StackAddress;
                    ulong StackHigh = Thread.StackAddress + Thread.StackSize;

                    if (NewRsp >= StackLow && (NewRsp + AllocationSize) <= StackHigh)
                    {
                        ulong PageStart = NewRsp & ~0xFFFUL;
                        ulong PageEnd = BinaryEmulator.AlignUp(NewRsp + AllocationSize, 0x1000);

                        for (ulong Page = PageStart; Page < PageEnd; Page += 0x1000)
                        {
                            if (!Emulator.IsRegionMapped(Page, 1))
                            {
                                Emulator._emulator.MapMemory(Page, 0x1000, MemoryProtection.ReadWrite);
                            }
                            else
                            {
                                Emulator._emulator.SetMemoryProtection(Page, 0x1000, MemoryProtection.ReadWrite);
                            }
                        }
                    }
                }

                if (!Emulator.IsRegionMapped(NewRsp, AllocationSize))
                {
                    if ((Emulator.Settings.Flags & LogFlags.Issues) != 0)
                        Emulator.TriggerEventMessage($"[-] InvokeException failed: exception stack frame is not mapped (NewRSP=0x{NewRsp:X}, Size=0x{AllocationSize:X}).", LogFlags.Issues);
                    return;
                }
            }

            ulong ClearLen = InitialRsp > NewRsp ? (InitialRsp - NewRsp) : AllocationSize;
            if (ClearLen > 0x2000)
                ClearLen = 0x2000;

            WriteZeroMemory(NewRsp, (uint)ClearLen);

            ulong ContextAddress = NewRsp;
            ulong ExceptionRecordAddress = NewRsp + ContextSize;
            ulong MachineFrameAddress = NewRsp + CombinedSize;

            Span<byte> Context = Shared.GetSpan(ContextSize);
            Context.Clear();

            const uint CONTEXT_AMD64 = 0x00100000;
            const uint CONTEXT_CONTROL = 0x00000001;
            const uint CONTEXT_INTEGER = 0x00000002;
            const uint CONTEXT_SEGMENTS = 0x00000004;
            const uint CONTEXT_DEBUG_REGISTERS = 0x00000010;

            // Only advertise what we actually populate.
            uint Flags = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS;
            WriteUInt32(Context, 0x30, Flags);

            WriteUInt32(Context, 0x34, (uint)Emulator.ReadRegister(Registers.UC_X86_REG_MXCSR));

            WriteUInt16(Context, 0x38, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_CS));
            WriteUInt16(Context, 0x3A, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_DS));
            WriteUInt16(Context, 0x3C, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_ES));
            WriteUInt16(Context, 0x3E, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_FS));
            WriteUInt16(Context, 0x40, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_GS));
            WriteUInt16(Context, 0x42, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_SS));
            WriteUInt32(Context, 0x44, (uint)InitialEFlags);

            WriteUInt64(Context, 0x48, Emulator.ReadRegister(Registers.UC_X86_REG_DR0));
            WriteUInt64(Context, 0x50, Emulator.ReadRegister(Registers.UC_X86_REG_DR1));
            WriteUInt64(Context, 0x58, Emulator.ReadRegister(Registers.UC_X86_REG_DR2));
            WriteUInt64(Context, 0x60, Emulator.ReadRegister(Registers.UC_X86_REG_DR3));
            WriteUInt64(Context, 0x68, Emulator.ReadRegister(Registers.UC_X86_REG_DR6));
            WriteUInt64(Context, 0x70, Emulator.ReadRegister(Registers.UC_X86_REG_DR7));

            WriteUInt64(Context, 0x78, Emulator.ReadRegister(Registers.UC_X86_REG_RAX));
            WriteUInt64(Context, 0x80, Emulator.ReadRegister(Registers.UC_X86_REG_RCX));
            WriteUInt64(Context, 0x88, Emulator.ReadRegister(Registers.UC_X86_REG_RDX));
            WriteUInt64(Context, 0x90, Emulator.ReadRegister(Registers.UC_X86_REG_RBX));
            WriteUInt64(Context, 0x98, InitialRsp);
            WriteUInt64(Context, 0xA0, Emulator.ReadRegister(Registers.UC_X86_REG_RBP));
            WriteUInt64(Context, 0xA8, Emulator.ReadRegister(Registers.UC_X86_REG_RSI));
            WriteUInt64(Context, 0xB0, Emulator.ReadRegister(Registers.UC_X86_REG_RDI));
            WriteUInt64(Context, 0xB8, Emulator.ReadRegister(Registers.UC_X86_REG_R8));
            WriteUInt64(Context, 0xC0, Emulator.ReadRegister(Registers.UC_X86_REG_R9));
            WriteUInt64(Context, 0xC8, Emulator.ReadRegister(Registers.UC_X86_REG_R10));
            WriteUInt64(Context, 0xD0, Emulator.ReadRegister(Registers.UC_X86_REG_R11));
            WriteUInt64(Context, 0xD8, Emulator.ReadRegister(Registers.UC_X86_REG_R12));
            WriteUInt64(Context, 0xE0, Emulator.ReadRegister(Registers.UC_X86_REG_R13));
            WriteUInt64(Context, 0xE8, Emulator.ReadRegister(Registers.UC_X86_REG_R14));
            WriteUInt64(Context, 0xF0, Emulator.ReadRegister(Registers.UC_X86_REG_R15));
            WriteUInt64(Context, 0xF8, InitialRip);

            Emulator.WriteMemory(ContextAddress, Context);

            // Build EXCEPTION_RECORD.
            Span<byte> Record = Shared.GetSpan(ExceptionRecordSize);
            Record.Clear();
            WriteUInt32(Record, 0x00, (uint)Exception);
            WriteUInt32(Record, 0x04, 0u);   // ExceptionFlags
            WriteUInt64(Record, 0x08, 0UL);  // ExceptionRecord (chained)
            WriteUInt64(Record, 0x10, InitialRip); // ExceptionAddress

            // Generic ExceptionInformation vector (0..15 QWORDs)
            ulong[] Parameters = ExceptionInformation?.Parameters ?? Array.Empty<ulong>();
            int Count = Parameters.Length;
            if (Count > 15)
                Count = 15;

            WriteUInt32(Record, 0x18, (uint)Count); // NumberParameters
            WriteUInt32(Record, 0x1C, 0u); // __unusedAlignment

            for (int i = 0; i < Count; i++)
                WriteUInt64(Record, 0x20 + (i * 8), Parameters[i]);

            Emulator.WriteMemory(ExceptionRecordAddress, Record);

            // Build MACHINE_FRAME (as the kernel would).
            Span<byte> Frame = Shared.GetSpan(MachineFrameSize);
            Frame.Clear();
            WriteUInt64(Frame, 0x00, InitialRip);
            WriteUInt64(Frame, 0x08, (ulong)(ushort)Emulator.ReadRegister(Registers.UC_X86_REG_CS));
            WriteUInt64(Frame, 0x10, InitialEFlags);
            WriteUInt64(Frame, 0x18, InitialRsp);
            WriteUInt64(Frame, 0x20, (ulong)(ushort)Emulator.ReadRegister(Registers.UC_X86_REG_SS));

            Emulator.WriteMemory(MachineFrameAddress, Frame);

            // Enter KiUserExceptionDispatcher exactly like the kernel does: RSP points at CONTEXT, RIP = dispatcher.
            Emulator.WriteRegister(Registers.UC_X86_REG_RSP, ContextAddress);
            Emulator.WriteRegister(Registers.UC_X86_REG_RIP, DispatcherAddress);
            EmulatedThread EmuThread = Emulator.CurrentThread;
            WinEmulatedThread.GetState(EmuThread).DispatchException = true;
            WinEmulatedThread.GetState(EmuThread).IsHandlingException = true;
            if (WinEmulatedThread.GetState(EmuThread).ExceptionNesting <= 0)
                WinEmulatedThread.GetState(EmuThread).ExceptionNesting = 1;
            WinEmulatedThread.GetState(EmuThread).ExceptionInformation = ExceptionInformation;
            EmuThread.ExitCode = (int)Exception;
            Emulator.Threads[(uint)Emulator.CurrentThreadId] = EmuThread;
        }

        /// <summary>
        /// Determines whether or not the thread is in a state where it can dispatch a user APC.
        /// </summary>
        /// <param name="Thread">Thread to check.</param>
        /// <returns>returns true if the thread can dispatch an APC, otherwise false.</returns>
        public bool CanDispatchUserApc(EmulatedThread Thread)
        {
            return CanDispatchUserApc(Thread, false);
        }

        /// <summary>
        /// Determines whether or not the thread is in a state where it can dispatch a user APC.
        /// </summary>
        /// <param name="Thread">Thread to check.</param>
        /// <param name="ForceAlert">true to emulate NtTestAlert/NtContinue(TestAlert) draining the user APC queue.</param>
        /// <returns>returns true if the thread can dispatch an APC, otherwise false.</returns>
        public bool CanDispatchUserApc(EmulatedThread Thread, bool ForceAlert)
        {
            return GetDispatchableUserApcIndex(Thread, ForceAlert) >= 0;
        }

        private int GetDispatchableUserApcIndex(EmulatedThread Thread, bool ForceAlert)
        {
            if (Thread == null)
                return -1;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.PendingUserApcs == null || State.PendingUserApcs.Count == 0)
                return -1;

            if (ForceAlert || State.ApcAlertable)
                return 0;

            for (int i = 0; i < State.PendingUserApcs.Count; i++)
            {
                WinPendingUserApc Apc = State.PendingUserApcs[i];
                if (Apc != null && Apc.IsSpecial)
                    return i;
            }

            return -1;
        }

        private static void WriteInt32(Span<byte> Buffer, int Offset, int Value)
        {
            if (Offset < 0 || Offset + 4 > Buffer.Length)
                return;

            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        /// <summary>
        /// returns KiUserApcDispatcher.
        /// </summary>
        /// <param name="Thread">Thread to set the ApcFunc for.</param>
        /// <returns>returns the Dispatcher address.</returns>
        public ulong GetUserApcDispatcher(EmulatedThread Thread)
        {
            if (Thread == null)
                return 0;

            if (WinEmulatedThread.GetState(Thread).ApcFunc != 0)
                return WinEmulatedThread.GetState(Thread).ApcFunc;

            WinModule ntdll = WinModules.FirstOrDefault(m => m.Name != null && m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
            if (ntdll == null)
                return 0;

            ulong Dispatcher = GetExportAddress(ntdll, "KiUserApcDispatcher");
            if (Dispatcher == 0 && ntdll.ExportsByName != null && ntdll.ExportsByName.TryGetValue("KiUserApcDispatcher", out ulong OriginalVa))
                Dispatcher = Emulator.TranslateVirtualAddress(OriginalVa, "ntdll.dll");

            WinEmulatedThread.GetState(Thread).ApcFunc = Dispatcher;
            return Dispatcher;
        }

        private void InterruptAlertableWaitWithUserApc(EmulatedThread Thread)
        {
            if (Thread == null || !Thread.WaitActive)
                return;

            Thread.WaitActive = false;
            Thread.WaitHandles = null;
            Thread.WaitDeadline = -1;
            Thread.WaitAll = false;
            WinEmulatedThread.GetState(Thread).WaitAlertable = false;
            WinEmulatedThread.GetState(Thread).ApcAlertable = false;

            ulong ResumeRip = WinEmulatedThread.GetState(Thread).WaitReturnRIP != 0 ? WinEmulatedThread.GetState(Thread).WaitReturnRIP : (WinEmulatedThread.GetState(Thread).WaitResumeRIP != 0 ? WinEmulatedThread.GetState(Thread).WaitResumeRIP + 2 : Thread.Context.RIP);
            Thread.Context.RIP = ResumeRip;
            Thread.Context.RAX = (ulong)NTSTATUS.STATUS_USER_APC;
            WinEmulatedThread.GetState(Thread).WaitResumeRIP = 0;
            WinEmulatedThread.GetState(Thread).WaitReturnRIP = 0;
            if (Emulator.CurrentThread == Thread)
            {
                Emulator.WriteRegister(Registers.UC_X86_REG_RIP, Thread.Context.RIP);
                Emulator.WriteRegister(Registers.UC_X86_REG_RAX, Thread.Context.RAX);
            }
        }

        public bool DispatchNextUserApc(EmulatedThread Thread)
        {
            return DispatchNextUserApc(Thread, false);
        }

        /// <summary>
        /// Dispatches the next user APC for a thread.
        /// </summary>
        /// <param name="Thread">Thread to dispatch the APC on.</param>
        /// <param name="ForceAlert">true to drain a normal user APC without requiring an alertable wait.</param>
        /// <returns>returns true if an APC was dispatched, otherwise false.</returns>
        public bool DispatchNextUserApc(EmulatedThread Thread, bool ForceAlert)
        {
            if (Emulator == null || Emulator._binary == null)
                return false;

            int ApcIndex = GetDispatchableUserApcIndex(Thread, ForceAlert);
            if (ApcIndex < 0)
                return false;

            ulong Dispatcher = GetUserApcDispatcher(Thread);
            if (Dispatcher == 0)
            {
                Emulator.TriggerEventMessage("[-] DispatchNextUserApc failed: KiUserApcDispatcher export was not found.", LogFlags.Issues);
                WinEmulatedThread.GetState(Thread).ApcAlertable = false;
                return false;
            }

            if (Emulator.CurrentThread == Thread)
                Emulator.SaveContext(Thread);

            if (Thread.WaitActive)
                InterruptAlertableWaitWithUserApc(Thread);

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            WinPendingUserApc Apc = State.PendingUserApcs[ApcIndex];
            State.ApcAlertable = false;

            if (PointerSize == 4)
                return DispatchUserApcX86(Thread, State, ApcIndex, Apc, Dispatcher);

            const int ContinueOffset = 0x4F0;
            const int StackLayoutSize = 0x508;

            ulong InitialRsp = Emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong InitialRip = Emulator.ReadRegister(Registers.UC_X86_REG_RIP);
            ulong InitialEFlags = Emulator.ReadRegister(Registers.UC_X86_REG_EFLAGS);

            ulong NewRsp = AlignDown(InitialRsp - (ulong)StackLayoutSize, 0x100);

            ulong AllocationSize = (ulong)StackLayoutSize;
            if (Thread != null)
            {
                ulong StackLow = Thread.StackAddress;
                ulong StackHigh = Thread.StackAddress + Thread.StackSize;

                if (NewRsp < StackLow || (NewRsp + AllocationSize) > StackHigh)
                {
                    if ((Emulator.Settings.Flags & LogFlags.Issues) != 0)
                        Emulator.TriggerEventMessage($"[-] DispatchNextUserApc failed: insufficient stack space (RSP=0x{InitialRsp:X}, NewRSP=0x{NewRsp:X}, Need=0x{AllocationSize:X}).", LogFlags.Issues);
                    return false;
                }
            }

            if (!Emulator.IsRegionMapped(NewRsp, AllocationSize))
            {
                ulong PageStart = NewRsp & ~0xFFFUL;
                ulong PageEnd = BinaryEmulator.AlignUp(NewRsp + AllocationSize, 0x1000);

                for (ulong Page = PageStart; Page < PageEnd; Page += 0x1000)
                {
                    if (!Emulator.IsRegionMapped(Page, 1))
                        Emulator._emulator.MapMemory(Page, 0x1000, MemoryProtection.ReadWrite);
                    else
                        Emulator._emulator.SetMemoryProtection(Page, 0x1000, MemoryProtection.ReadWrite);
                }
            }

            if (!Emulator.IsRegionMapped(NewRsp, AllocationSize))
            {
                if ((Emulator.Settings.Flags & LogFlags.Issues) != 0)
                    Emulator.TriggerEventMessage($"[-] DispatchNextUserApc failed: APC stack frame is not mapped (NewRSP=0x{NewRsp:X}, Size=0x{AllocationSize:X}).", LogFlags.Issues);
                return false;
            }

            Span<byte> StackLayout = Shared.GetSpan((uint)StackLayoutSize);
            StackLayout.Clear();

            const uint ContextAmd64 = 0x00100000;
            const uint ContextControl = 0x00000001;
            const uint ContextInteger = 0x00000002;
            const uint ContextSegments = 0x00000004;
            const uint ContextDebugRegisters = 0x00000010;

            WriteUInt64(StackLayout, 0x00, Apc.ApcArgument1);
            WriteUInt64(StackLayout, 0x08, Apc.ApcArgument2);
            WriteUInt64(StackLayout, 0x10, Apc.ApcArgument3);
            WriteUInt64(StackLayout, 0x18, Apc.ApcRoutine);
            WriteUInt32(StackLayout, 0x30, ContextAmd64 | ContextControl | ContextInteger | ContextSegments | ContextDebugRegisters);
            WriteUInt32(StackLayout, 0x34, (uint)Emulator.ReadRegister(Registers.UC_X86_REG_MXCSR));
            WriteUInt16(StackLayout, 0x38, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_CS));
            WriteUInt16(StackLayout, 0x3A, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_DS));
            WriteUInt16(StackLayout, 0x3C, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_ES));
            WriteUInt16(StackLayout, 0x3E, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_FS));
            WriteUInt16(StackLayout, 0x40, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_GS));
            WriteUInt16(StackLayout, 0x42, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_SS));
            WriteUInt32(StackLayout, 0x44, (uint)InitialEFlags);
            WriteUInt64(StackLayout, 0x48, Emulator.ReadRegister(Registers.UC_X86_REG_DR0));
            WriteUInt64(StackLayout, 0x50, Emulator.ReadRegister(Registers.UC_X86_REG_DR1));
            WriteUInt64(StackLayout, 0x58, Emulator.ReadRegister(Registers.UC_X86_REG_DR2));
            WriteUInt64(StackLayout, 0x60, Emulator.ReadRegister(Registers.UC_X86_REG_DR3));
            WriteUInt64(StackLayout, 0x68, Emulator.ReadRegister(Registers.UC_X86_REG_DR6));
            WriteUInt64(StackLayout, 0x70, Emulator.ReadRegister(Registers.UC_X86_REG_DR7));
            WriteUInt64(StackLayout, 0x78, Emulator.ReadRegister(Registers.UC_X86_REG_RAX));
            WriteUInt64(StackLayout, 0x80, Emulator.ReadRegister(Registers.UC_X86_REG_RCX));
            WriteUInt64(StackLayout, 0x88, Emulator.ReadRegister(Registers.UC_X86_REG_RDX));
            WriteUInt64(StackLayout, 0x90, Emulator.ReadRegister(Registers.UC_X86_REG_RBX));
            WriteUInt64(StackLayout, 0x98, InitialRsp);
            WriteUInt64(StackLayout, 0xA0, Emulator.ReadRegister(Registers.UC_X86_REG_RBP));
            WriteUInt64(StackLayout, 0xA8, Emulator.ReadRegister(Registers.UC_X86_REG_RSI));
            WriteUInt64(StackLayout, 0xB0, Emulator.ReadRegister(Registers.UC_X86_REG_RDI));
            WriteUInt64(StackLayout, 0xB8, Emulator.ReadRegister(Registers.UC_X86_REG_R8));
            WriteUInt64(StackLayout, 0xC0, Emulator.ReadRegister(Registers.UC_X86_REG_R9));
            WriteUInt64(StackLayout, 0xC8, Emulator.ReadRegister(Registers.UC_X86_REG_R10));
            WriteUInt64(StackLayout, 0xD0, Emulator.ReadRegister(Registers.UC_X86_REG_R11));
            WriteUInt64(StackLayout, 0xD8, Emulator.ReadRegister(Registers.UC_X86_REG_R12));
            WriteUInt64(StackLayout, 0xE0, Emulator.ReadRegister(Registers.UC_X86_REG_R13));
            WriteUInt64(StackLayout, 0xE8, Emulator.ReadRegister(Registers.UC_X86_REG_R14));
            WriteUInt64(StackLayout, 0xF0, Emulator.ReadRegister(Registers.UC_X86_REG_R15));
            WriteUInt64(StackLayout, 0xF8, InitialRip);
            WriteInt32(StackLayout, ContinueOffset, 1);
            WriteInt32(StackLayout, ContinueOffset + 0x4, 1);

            Emulator.WriteMemory(NewRsp, StackLayout);
            State.PendingUserApcs.RemoveAt(ApcIndex);
            Thread.Context.RSP = NewRsp;
            Thread.Context.RIP = Dispatcher;
            Emulator.WriteRegister(Registers.UC_X86_REG_RSP, NewRsp);
            Emulator.WriteRegister(Registers.UC_X86_REG_RIP, Dispatcher);
            return true;
        }

        private bool DispatchUserApcX86(EmulatedThread Thread, WindowsThreadState State, int ApcIndex, WinPendingUserApc Apc, ulong Dispatcher)
        {
            const uint ContextOffset = 0x14;
            const uint ContextSize = 0x2CC;
            const uint ExceptionRegistrationOffset = 0x310;
            const uint FrameSize = ExceptionRegistrationOffset + 0x10;
            const uint ContextI386 = 0x00010000;
            const uint ContextControl = 0x00000001;
            const uint ContextInteger = 0x00000002;
            const uint ContextSegments = 0x00000004;

            CpuContext Ctx = Thread.Context ?? new CpuContext();
            uint InitialEsp = (uint)Ctx.RSP;
            uint InitialEip = (uint)Ctx.RIP;
            uint InitialEFlags = (uint)Ctx.RFLAGS;

            uint NewEsp = (uint)AlignDown(InitialEsp - FrameSize, 0x10);

            if (Thread.StackSize != 0 && (NewEsp < Thread.StackAddress || (ulong)NewEsp + FrameSize > Thread.StackAddress + Thread.StackSize))
            {
                if ((Emulator.Settings.Flags & LogFlags.Issues) != 0)
                    Emulator.TriggerEventMessage($"[-] DispatchNextUserApc failed: insufficient stack space (ESP=0x{InitialEsp:X}, NewESP=0x{NewEsp:X}).", LogFlags.Issues);
                return false;
            }

            if (!Emulator.IsRegionMapped(NewEsp, FrameSize))
            {
                ulong PageStart = NewEsp & ~0xFFFUL;
                ulong PageEnd = BinaryEmulator.AlignUp((ulong)NewEsp + FrameSize, 0x1000);

                for (ulong Page = PageStart; Page < PageEnd; Page += 0x1000)
                {
                    if (!Emulator.IsRegionMapped(Page, 1))
                        Emulator._emulator.MapMemory(Page, 0x1000, MemoryProtection.ReadWrite);
                    else
                        Emulator._emulator.SetMemoryProtection(Page, 0x1000, MemoryProtection.ReadWrite);
                }

                if (!Emulator.IsRegionMapped(NewEsp, FrameSize))
                {
                    if ((Emulator.Settings.Flags & LogFlags.Issues) != 0)
                        Emulator.TriggerEventMessage($"[-] DispatchNextUserApc failed: APC stack frame is not mapped (NewESP=0x{NewEsp:X}).", LogFlags.Issues);
                    return false;
                }
            }

            Span<byte> Frame = Shared.GetSpan(FrameSize);
            Frame.Clear();

            WriteUInt32(Frame, 0x00, (uint)Apc.ApcRoutine);
            WriteUInt32(Frame, 0x04, (uint)Apc.ApcArgument1);
            WriteUInt32(Frame, 0x08, (uint)Apc.ApcArgument2);
            WriteUInt32(Frame, 0x0C, (uint)Apc.ApcArgument3);
            WriteUInt32(Frame, 0x10, 1);

            int Context = (int)ContextOffset;
            WriteUInt32(Frame, Context + 0x00, ContextI386 | ContextControl | ContextInteger | ContextSegments);
            WriteUInt32(Frame, Context + 0x8C, (uint)Ctx.GS);
            WriteUInt32(Frame, Context + 0x90, (uint)Ctx.FS);
            WriteUInt32(Frame, Context + 0x94, (uint)Ctx.ES);
            WriteUInt32(Frame, Context + 0x98, (uint)Ctx.DS);
            WriteUInt32(Frame, Context + 0x9C, (uint)Ctx.RDI);
            WriteUInt32(Frame, Context + 0xA0, (uint)Ctx.RSI);
            WriteUInt32(Frame, Context + 0xA4, (uint)Ctx.RBX);
            WriteUInt32(Frame, Context + 0xA8, (uint)Ctx.RDX);
            WriteUInt32(Frame, Context + 0xAC, (uint)Ctx.RCX);
            WriteUInt32(Frame, Context + 0xB0, (uint)Ctx.RAX);
            WriteUInt32(Frame, Context + 0xB4, (uint)Ctx.RBP);
            WriteUInt32(Frame, Context + 0xB8, InitialEip);
            WriteUInt32(Frame, Context + 0xBC, (uint)Ctx.CS);
            WriteUInt32(Frame, Context + 0xC0, InitialEFlags);
            WriteUInt32(Frame, Context + 0xC4, InitialEsp);
            WriteUInt32(Frame, Context + 0xC8, (uint)Ctx.SS);

            _ = ContextSize;

            WriteUInt32(Frame, (int)ExceptionRegistrationOffset, 0xFFFFFFFF);

            Emulator.WriteMemory(NewEsp, Frame);
            State.PendingUserApcs.RemoveAt(ApcIndex);

            if (Thread.Context == null)
                Thread.Context = new CpuContext();
            Thread.Context.RSP = NewEsp;
            Thread.Context.RIP = Dispatcher;

            if (Emulator.CurrentThread == Thread)
            {
                Emulator.WriteRegister32(Registers.UC_X86_REG_ESP, NewEsp);
                Emulator.WriteRegister32(Registers.UC_X86_REG_EIP, (uint)Dispatcher);
            }
            return true;
        }

        /// <summary>
        /// Canonicalizes an image path for section identity checks.
        /// </summary>
        /// <param name="Path">Guest or host path for the image.</param>
        /// <returns>A stable, case-insensitive identity string for the image.</returns>
        public string CanonicalizeImagePath(string Path)
        {
            string Value = NormalizeWindowsImagePath(Path);
            if (string.IsNullOrEmpty(Value))
                return string.Empty;

            string Lower = Value.ToLowerInvariant();

            int System32Index = Lower.LastIndexOf("\\windows\\system32\\", StringComparison.OrdinalIgnoreCase);
            if (System32Index >= 0)
                return "system32\\" + Lower.Substring(System32Index + "\\windows\\system32\\".Length);

            int SysWow64Index = Lower.LastIndexOf("\\windows\\syswow64\\", StringComparison.OrdinalIgnoreCase);
            if (SysWow64Index >= 0)
                return "syswow64\\" + Lower.Substring(SysWow64Index + "\\windows\\syswow64\\".Length);

            return Lower;
        }

        public string NormalizeWindowsImagePath(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return string.Empty;

            string Value = CleanWindowsPath(Path);

            if (Value.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\" + Value.Substring("\\SystemRoot\\".Length);

            if (Value.StartsWith("SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\" + Value.Substring("SystemRoot\\".Length);

            if (Value.StartsWith("\\KnownDlls32\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("KnownDlls32\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\SysWOW64\\" + FileNameOf(Value);

            if (Value.StartsWith("\\KnownDlls\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("KnownDlls\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\System32\\" + FileNameOf(Value);

            string Relative = Value.TrimStart('\\');
            if (Relative.StartsWith("System32\\", StringComparison.OrdinalIgnoreCase) ||
                Relative.Equals("System32", StringComparison.OrdinalIgnoreCase) ||
                Relative.StartsWith("SysWOW64\\", StringComparison.OrdinalIgnoreCase) ||
                Relative.Equals("SysWOW64", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\" + Relative;

            if (Relative.StartsWith("Windows\\", StringComparison.OrdinalIgnoreCase) ||
                Relative.Equals("Windows", StringComparison.OrdinalIgnoreCase))
                return "C:\\" + Relative;

            return Value;
        }

        public string ResolveWindowsFilePath(string Path, ulong RootDirectory = 0)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return string.Empty;

            string Value = CleanWindowsPath(Path);

            if (Value.StartsWith("UNC\\", StringComparison.OrdinalIgnoreCase))
                return "\\\\" + Value.Substring(4);

            if (Value.StartsWith("GLOBALROOT\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring("GLOBALROOT\\".Length);
            else if (Value.StartsWith("\\GLOBALROOT\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring("\\GLOBALROOT\\".Length);

            if (TryResolveNtDeviceFilePath(Value, out string DevicePath))
                return DevicePath;

            if (TryResolveVolumeGuidPath(Value, out string VolumeGuidPath))
                return VolumeGuidPath;

            if (Value.Length == 2 && char.IsLetter(Value[0]) && Value[1] == ':')
                return char.ToUpperInvariant(Value[0]).ToString() + ":\\";

            if (RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY ||
                Value.StartsWith("\\KnownDlls\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("KnownDlls\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\System32\\" + FileNameOf(Value);

            if (RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY ||
                Value.StartsWith("\\KnownDlls32\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("KnownDlls32\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\SysWOW64\\" + FileNameOf(Value);

            if (Value.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                Value = "C:\\Windows\\" + Value.Substring("\\SystemRoot\\".Length);
            else if (Value.StartsWith("SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                Value = "C:\\Windows\\" + Value.Substring("SystemRoot\\".Length);
            else if (Value.StartsWith("\\Windows\\", StringComparison.OrdinalIgnoreCase))
                Value = "C:\\" + Value.TrimStart('\\');
            else if (Value.Equals("\\Windows", StringComparison.OrdinalIgnoreCase))
                Value = "C:\\Windows";

            return Value.Length >= 3 && char.IsLetter(Value[0]) && Value[1] == ':' && Value[2] == '\\' ? Value : string.Empty;
        }

        private static string CleanWindowsPath(string Path)
        {
            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\');

            if (Value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);

            while (Value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);

            while (Value.Contains("\\\\", StringComparison.Ordinal) && !Value.StartsWith("\\\\", StringComparison.Ordinal))
                Value = Value.Replace("\\\\", "\\", StringComparison.Ordinal);

            return Value;
        }

        private bool TryResolveVolumeGuidPath(string Path, out string DosPath)
        {
            DosPath = string.Empty;

            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\').TrimStart('\\');
            const string Prefix = "Volume{";
            if (!Value.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
                return false;

            int CloseBrace = Value.IndexOf('}');
            if (CloseBrace < Prefix.Length)
                return false;

            string GuidText = Value.Substring(Prefix.Length, CloseBrace - Prefix.Length);
            if (!GuidText.Equals(SyntheticVolumeGuid, StringComparison.OrdinalIgnoreCase))
                return false;

            string Rest = Value.Substring(CloseBrace + 1).TrimStart('\\');
            DosPath = string.IsNullOrEmpty(Rest) ? "C:\\" : "C:\\" + Rest;
            return true;
        }

        private static bool TryResolveNtDeviceFilePath(string Path, out string DosPath)
        {
            DosPath = string.Empty;

            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\');
            if (Value.StartsWith("Device\\", StringComparison.OrdinalIgnoreCase))
                Value = "\\" + Value;


            if (Value.StartsWith("\\Device\\Mup\\", StringComparison.OrdinalIgnoreCase))
            {
                string UncRest = Value.Substring("\\Device\\Mup\\".Length).TrimStart('\\');
                DosPath = "\\\\" + UncRest;
                return true;
            }

            const string VolumePrefix = "\\Device\\HarddiskVolume";
            if (!Value.StartsWith(VolumePrefix, StringComparison.OrdinalIgnoreCase))
                return false;

            int RestIndex = VolumePrefix.Length;
            while (RestIndex < Value.Length && char.IsDigit(Value[RestIndex]))
                RestIndex++;

            if (RestIndex >= Value.Length)
            {
                DosPath = "C:\\";
                return true;
            }

            if (Value[RestIndex] != '\\')
                return false;

            string Relative = Value.Substring(RestIndex).TrimStart('\\');
            DosPath = string.IsNullOrEmpty(Relative) ? "C:\\" : "C:\\" + Relative;
            return true;
        }

        private static string FileNameOf(string Path)
        {
            int Slash = Path.LastIndexOf('\\');
            return Slash >= 0 ? Path.Substring(Slash + 1) : Path;
        }

        /// <summary>
        /// Records a mapped image view and returns that image's mapping ordinal for its canonical path.
        /// </summary>
        /// <param name="Module">Mapped image view.</param>
        /// <param name="IsSectionView">Whether the image was mapped by NtMapViewOfSection rather than initial emulator loading.</param>
        /// <returns>One-based mapping ordinal for this canonical image path.</returns>
        public int RegisterMappedImageView(WinModule Module, bool IsSectionView)
        {
            if (Module == null)
                return 0;

            string CanonicalPath = CanonicalizeImagePath(!string.IsNullOrEmpty(Module.Path) ? Module.Path : Module.Name);
            Module.CanonicalImagePath = CanonicalPath;
            if (Module.ImageSectionId == 0 && !string.IsNullOrEmpty(CanonicalPath))
                AttachImageSectionIdentity(Module, CanonicalPath);
            Module.IsSectionView = IsSectionView;

            int Ordinal = 1;
            if (!string.IsNullOrEmpty(CanonicalPath))
            {
                ImageViewCountsByPath.TryGetValue(CanonicalPath, out int ExistingCount);
                Ordinal = ExistingCount + 1;
                ImageViewCountsByPath[CanonicalPath] = Ordinal;
            }

            Module.ImageMapOrdinal = Ordinal;
            MappedImageViews.Add(Module);
            return Ordinal;
        }

        /// <summary>
        /// Removes a mapped image view from section-view identity tracking.
        /// </summary>
        /// <param name="Module">Mapped image view to remove.</param>
        public void UnregisterMappedImageView(WinModule Module)
        {
            if (Module == null)
                return;

            MappedImageViews.RemoveAll(M => ReferenceEquals(M, Module) ||
                                            (M != null && M.MappedBase == Module.MappedBase));

            string CanonicalPath = Module.CanonicalImagePath;
            if (string.IsNullOrEmpty(CanonicalPath))
                CanonicalPath = CanonicalizeImagePath(!string.IsNullOrEmpty(Module.Path) ? Module.Path : Module.Name);

            if (!string.IsNullOrEmpty(CanonicalPath))
            {
                int ActiveCount = MappedImageViews.Count(M => M != null &&
                                                              !string.IsNullOrEmpty(M.CanonicalImagePath) &&
                                                              string.Equals(M.CanonicalImagePath, CanonicalPath, StringComparison.OrdinalIgnoreCase));

                if (ActiveCount == 0)
                    ImageViewCountsByPath.Remove(CanonicalPath);
                else
                    ImageViewCountsByPath[CanonicalPath] = ActiveCount;
            }
        }

        /// <summary>
        /// Finds the image view that contains a guest address.
        /// </summary>
        /// <param name="Address">Guest virtual address.</param>
        /// <returns>The matching mapped image view, or null when the address does not belong to a tracked image.</returns>
        public WinModule FindMappedImageViewByAddress(ulong Address)
        {
            for (int Index = MappedImageViews.Count - 1; Index >= 0; Index--)
            {
                WinModule Module = MappedImageViews[Index];
                if (Module == null || Module.MappedBase == 0 || Module.SizeOfImage == 0)
                    continue;

                ulong End = Module.MappedBase + Module.SizeOfImage;
                if (Address >= Module.MappedBase && Address < End)
                    return Module;
            }

            for (int Index = WinModules.Count - 1; Index >= 0; Index--)
            {
                WinModule Module = WinModules[Index];
                if (Module == null || Module.MappedBase == 0 || Module.SizeOfImage == 0)
                    continue;

                ulong End = Module.MappedBase + Module.SizeOfImage;
                if (Address >= Module.MappedBase && Address < End)
                    return Module;
            }

            return null;
        }

        /// <summary>
        /// Adds a module to the emulated process.
        /// </summary>
        /// <param name="Module">Module to add.</param>
        public void AddModule(WinModule Module, bool TriggerMessage)
        {
            bool Finished = false;

            LdrTracker?.NotifyImageMapped();

            try
            {
                Finished = true;
                if (TriggerMessage)
                    if ((Emulator.Settings.Flags & LogFlags.General) != 0)
                        Emulator.TriggerEventMessage($"[+] Loaded {Module.Name} at 0x{Module.MappedBase:X}.", LogFlags.General);
            }
            finally
            {
                Module.Initialized = Finished;

                WinModule Existing = WinModules.FirstOrDefault(m => m != null && m.MappedBase == Module.MappedBase);
                if (Existing == null)
                    WinModules.Add(Module);
                else
                {
                    Existing.Architecture = Module.Architecture;
                    Existing.EntryPoint = Module.EntryPoint;
                    Existing.OriginalBase = Module.OriginalBase;
                    Existing.SizeOfImage = Module.SizeOfImage;
                    Existing.Name = Module.Name;
                    Existing.Path = Module.Path;
                    Existing.CanonicalImagePath = Module.CanonicalImagePath;
                    Existing.ImageSectionId = Module.ImageSectionId;
                    Existing.ImageMapOrdinal = Module.ImageMapOrdinal;
                    Existing.IsSectionView = Module.IsSectionView;
                    Existing.Initialized = Module.Initialized;
                    Existing.Exports = Module.Exports;
                    Existing.ExportsByName = Module.ExportsByName;
                    Existing.Sections = Module.Sections;
                }
            }
        }

        public ulong GetExportAddress(WinModule Module, string ExportName)
        {
            if (Module.Exports == null || Module.Exports.Count == 0 || string.IsNullOrEmpty(ExportName))
                return 0;

            foreach (var Exp in Module.Exports)
            {
                if (string.Equals(Exp.Value, ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    return Exp.Key - Module.OriginalBase + Module.MappedBase;
                }
            }

            return 0;
        }

        private ulong _cachedKiUserCallbackDispatcher;
        private ulong _cachedFnDWORDOPTINLPMSG;

        public ulong GetKiUserCallbackDispatcher()
        {
            if (_cachedKiUserCallbackDispatcher != 0)
                return _cachedKiUserCallbackDispatcher;

            WinModule Ntdll = WinModules.FirstOrDefault(m => m != null && m.Name != null && m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
            if (Ntdll == null)
                return 0;

            _cachedKiUserCallbackDispatcher = GetExportAddress(Ntdll, "KiUserCallbackDispatcher");
            return _cachedKiUserCallbackDispatcher;
        }

        public ulong GetFnDWORDOPTINLPMSG()
        {
            if (_cachedFnDWORDOPTINLPMSG != 0)
                return _cachedFnDWORDOPTINLPMSG;

            ulong Peb = Emulator.PEB;
            if (Peb == 0)
                return 0;

            ulong KernelCallbackTable = Emulator.ReadMemoryULong(Peb + 0x58);
            if (KernelCallbackTable == 0)
                return 0;

            const uint FN_DWORDOPTINLPMSG_INDEX = 4;
            _cachedFnDWORDOPTINLPMSG = Emulator.ReadMemoryULong(KernelCallbackTable + FN_DWORDOPTINLPMSG_INDEX * 8);
            return _cachedFnDWORDOPTINLPMSG;
        }

        public bool InvokeUserCallback(ulong CallbackIndex, ulong ArgumentBuffer, ulong ArgumentBufferSize)
        {
            ulong Dispatcher = GetKiUserCallbackDispatcher();
            if (Dispatcher == 0)
                return false;

            EmulatedThread Thread = Emulator.CurrentThread;
            if (Thread == null)
                return false;

            ulong CurrentRsp = Emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong CurrentReturnAddress = Emulator.ReadMemoryULong(CurrentRsp);

            WinUserCallbackFrame Frame = new WinUserCallbackFrame
            {
                SavedRsp = CurrentRsp,
                SavedReturnAddress = CurrentReturnAddress,
            };
            WinEmulatedThread.GetState(Thread).UserCallbackFrames.Push(Frame);

            ulong FrameSize = 0x40;
            ulong NewRsp = (CurrentRsp - FrameSize) & ~0xFUL;

            for (ulong i = NewRsp; i < CurrentRsp; i += 8)
                Emulator._emulator.WriteMemory(i, 0UL, 8);

            Emulator._emulator.WriteMemory(NewRsp + 0x20, ArgumentBuffer, 8);
            Emulator._emulator.WriteMemory(NewRsp + 0x28, 0u, 4);
            Emulator._emulator.WriteMemory(NewRsp + 0x2C, (uint)CallbackIndex, 4);

            Emulator.WriteRegister(Registers.UC_X86_REG_RSP, NewRsp - 8);
            Emulator.WriteRegister(Emulator.IPRegister, Dispatcher);
            return true;
        }

        public bool CompleteUserCallback(ulong ResultAddress, uint ResultLength)
        {
            EmulatedThread Thread = Emulator.CurrentThread;
            if (Thread == null)
                return false;

            Stack<WinUserCallbackFrame> Frames = WinEmulatedThread.GetState(Thread).UserCallbackFrames;
            if (Frames.Count == 0)
                return false;

            WinUserCallbackFrame Frame = Frames.Pop();

            ulong ResultValue = 0;
            if (ResultAddress != 0 && ResultLength >= 8 && Emulator.IsRegionMapped(ResultAddress, 8))
                ResultValue = Emulator.ReadMemoryULong(ResultAddress);

            Emulator.WriteRegister(Registers.UC_X86_REG_RSP, Frame.SavedRsp + 8);
            Emulator.WriteRegister(Emulator.IPRegister, Frame.SavedReturnAddress - 2);
            Emulator.WriteRegister(Registers.UC_X86_REG_RAX, ResultValue);
            Emulator.SuppressSyscallStatusWrite = true;
            return true;
        }

        /// <summary>
        /// Convert windows memory protection to the internal enum.
        /// </summary>
        /// <param name="Protect">Protection to convert.</param>
        /// <returns>Internal memory protection enum with the Protect options.</returns>
        public MemoryProtection ConvertWinProtectToInternal(ulong Protect)
        {
            Protect &= 0xFF; // exclude PAGE_GUARD

            switch (Protect)
            {
                case 0x01: // PAGE_NOACCESS
                    return MemoryProtection.None;
                case 0x02: // PAGE_READONLY
                    return MemoryProtection.Read;
                case 0x04: // PAGE_READWRITE
                case 0x08: // PAGE_WRITECOPY -> treat as ReadWrite
                    return MemoryProtection.ReadWrite;
                case 0x10: // PAGE_EXECUTE
                    return MemoryProtection.Execute;
                case 0x20: // PAGE_EXECUTE_READ
                    return MemoryProtection.ReadExecute;
                case 0x40: // PAGE_EXECUTE_READWRITE
                case 0x80: // PAGE_EXECUTE_WRITECOPY -> treat as ExecuteReadWrite
                    return MemoryProtection.All;
                default:
                    return MemoryProtection.None;
            }
        }

        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        public ulong ConvertInternalToWinProtect(MemoryProtection Protection)
        {
            bool HasExec = (Protection & MemoryProtection.Execute) != 0;
            bool HasRead = (Protection & MemoryProtection.Read) != 0;
            bool HasWrite = (Protection & MemoryProtection.Write) != 0;

            if (HasExec && HasWrite)
                return PAGE_EXECUTE_READWRITE;

            if (HasExec && HasRead)
                return PAGE_EXECUTE_READ;

            if (HasExec)
                return PAGE_EXECUTE;

            if (HasWrite)
                return PAGE_READWRITE;

            if (HasRead)
                return PAGE_READONLY;

            return PAGE_NOACCESS;
        }

        /// <summary>
        /// Convert allocation type to <see cref="AllocationType"/>.
        /// </summary>
        /// <param name="AllocTypes">Allocation types.</param>
        /// <returns>returns the <see cref="AllocationType"/> enum.</returns>
        public AllocationType ConvertWinAllocType(ulong AllocTypes)
        {
            AllocationType Flags = AllocationType.None;

            if ((AllocTypes & 0x1000) != 0) // MEM_COMMIT
                Flags |= AllocationType.Commited;

            if ((AllocTypes & 0x2000) != 0) // MEM_RESERVE
                Flags |= AllocationType.Reserved;

            if ((AllocTypes & 0x1000000) != 0) // MEM_IMAGE
                Flags |= AllocationType.Image;

            return Flags;
        }

        public ulong ConvertTypeToWinAlloc(AllocationType Type)
        {
            switch (Type)
            {
                case AllocationType.Image:
                    return 0x1000000;
                case AllocationType.Commited:
                    return 0x1000;
                case AllocationType.Reserved:
                    return 0x2000;
                default:
                    return 0x00020000;
            }
        }

        public bool IsProtectedStatus(ProtectionStatus Status)
        {
            if (Status != ProtectionStatus.None) return true;
            return false;
        }

        public bool HandleExists(ulong Handle)
        {
            return HandleManager.HandleExists(Handle);
        }

        public bool HandleExists(ulong Handle, HandleType Type)
        {
            return HandleManager.HandleExists(Handle, Type);
        }

        public WinHandle OpenProcessHandle(uint PID, AccessMask Permissions)
        {
            WinProcess Process = WinProcesses.FirstOrDefault(p => p.PID == PID);
            if (Process == null)
                return new WinHandle();

            WinHandle Handle = HandleManager.AddHandle(Process, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinProcess? GetProcessByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.ProcessHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinProcess>(Handle);
        }

        public bool ValidProcessHandle(ulong Handle)
        {
            if (HandleExists(Handle, HandleType.ProcessHandle))
            {
                WinProcess Target = HandleManager.GetObjectByHandle<WinProcess>(Handle);
                if (Target != null)
                {
                    if (WinProcesses.FirstOrDefault(p => p.PID == Target.PID) != null)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public List<WinProcess> GetProcessList()
        {
            return WinProcesses;
        }

        public ulong AllocateUserHandle()
        {
            EnsureUserSharedInfo(out _, out _, out _);

            if (NextUserHandleIndex == 0 || NextUserHandleIndex >= UserHandleEntryCount)
                return 0;

            ushort Index = NextUserHandleIndex++;
            ushort Uniq = NextUserHandleUniq++;

            if (NextUserHandleUniq == 0 || NextUserHandleUniq >= 0x7FFF)
                NextUserHandleUniq = 1;

            return ((ulong)Uniq << 16) | Index;
        }

        public bool EnsureUserMessageBitmasks(out ulong Bitmask1, out ulong Bitmask2)
        {
            Bitmask1 = EnsureUserMessageBitmask(ref UserMessageBitmask1Address);
            Bitmask2 = EnsureUserMessageBitmask(ref UserMessageBitmask2Address);
            return Bitmask1 != 0 && Bitmask2 != 0;
        }

        private ulong EnsureUserMessageBitmask(ref ulong Cached)
        {
            if (Cached != 0 && Emulator.IsRegionMapped(Cached, UserMessageBitmaskSize))
                return Cached;

            ulong Address = Emulator.MapUniqueAddress(UserMessageBitmaskSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            Span<byte> Buffer = Shared.GetSpan((int)UserMessageBitmaskSize);
            Buffer.Fill(0xFF);
            if (!Emulator._emulator.WriteMemory(Address, Buffer))
                return 0;

            Cached = Address;
            return Cached;
        }

        private void EnsureGdiHandleTable()
        {
            if (GdiHandleTableAddress != 0 && Emulator.IsRegionMapped(GdiHandleTableAddress, GdiHandleEntryCount * GdiHandleEntrySize))
                return;

            ulong Peb = Emulator.PEB;
            if (Peb == 0)
                return;

            GdiHandleTableAddress = Emulator.ReadMemoryULong(Peb + 0xF8);
        }

        public bool EnsureUserSharedInfo(out ulong ServerInfo, out ulong HandleTable, out uint EntrySize)
        {
            ServerInfo = EnsureUserServerInfo();
            HandleTable = EnsureUserHandleTable();
            EntrySize = UserHandleEntrySize;
            EnsureUserMessageBitmasks(out _, out _);
            EnsureGdiHandleTable();

            return ServerInfo != 0 && HandleTable != 0;
        }

        public ulong AllocateGdiHandle(byte type)
        {
            EnsureGdiHandleTable();
            if (GdiHandleTableAddress == 0)
                return 0;

            if (NextGdiHandleIndex == 0 || NextGdiHandleIndex >= GdiHandleEntryCount)
                return 0;

            ushort Index = NextGdiHandleIndex++;

            ulong Entry = GdiHandleTableAddress + (ulong)Index * GdiHandleEntrySize;

            for (uint i = 0; i < GdiHandleEntrySize; i += 8)
                Emulator._emulator.WriteMemory(Entry + i, 0UL, 8);

            uint W32Pid = PID & 0xFFFFFFFCu;
            Emulator._emulator.WriteMemory(Entry + 0x08, W32Pid, 4);
            Emulator._emulator.WriteMemory(Entry + 0x0C, type, 1);

            Emulator._emulator.WriteMemory(Entry + 0x0E, (byte)(type & 0x1F), 1);

            if (type == 1)
            {
                ulong DcAttr = Emulator.MapUniqueAddress(0x600, MemoryProtection.ReadWrite);
                if (DcAttr != 0)
                {
                    Span<byte> Zeroed = Shared.GetSpan(0x600);
                    Zeroed.Clear();
                    Emulator._emulator.WriteMemory(DcAttr, Zeroed);

                    Emulator._emulator.WriteMemory(DcAttr, 1, 1);
                    Emulator._emulator.WriteMemory(DcAttr + 0x68, 1, 4);
                    Emulator._emulator.WriteMemory(DcAttr + 0x128, 0x00010001UL, 8);
                    Emulator._emulator.WriteMemory(DcAttr + 0x140, 1, 4);
                    Emulator._emulator.WriteMemory(DcAttr + 0x14C, 1, 4);
                    Emulator._emulator.WriteMemory(DcAttr + 0x150, 1, 4);

                    ulong Encrypted = EncryptGdiPointer(DcAttr);
                    Emulator._emulator.WriteMemory(Entry + 0x10, Encrypted, 8);
                }
            }

            return ((ulong)type << 16) | Index;
        }

        private static ulong EncryptGdiPointer(ulong Pointer)
        {
            ulong Cookie = 1;
            ulong Xored = Pointer ^ Cookie;
            return ((Xored << 63) | (Xored >> 1));
        }

        private static ulong DecryptGdiPointer(ulong Encrypted)
        {
            ulong RotatedBack = (Encrypted << 1) | (Encrypted >> 63);
            return RotatedBack ^ 1;
        }

        private const int DcAttrSelectedBrushOffset = 0xA0;
        private const int DcAttrSelectedPenOffset = 0xA8;
        private const int DcAttrCurrentPosXOffset = 0xD8;
        private const int DcAttrCurrentPosYOffset = 0xDC;

        public ulong GetDcAttributeAddress(ulong Hdc)
        {
            if (Hdc == 0 || ((Hdc >> 16) & 0xFF) != 1 || !ValidateGdiHandle(Hdc))
                return 0;

            ushort Index = (ushort)(Hdc & 0xFFFF);
            ulong Entry = GdiHandleTableAddress + (ulong)Index * GdiHandleEntrySize;
            ulong Encrypted = Emulator.ReadMemoryULong(Entry + 0x10);
            return Encrypted == 0 ? 0 : DecryptGdiPointer(Encrypted);
        }

        public bool ReadDcCurrentPosition(ulong Hdc, out int X, out int Y)
        {
            X = 0;
            Y = 0;

            ulong DcAttr = GetDcAttributeAddress(Hdc);
            if (DcAttr == 0)
                return false;

            X = unchecked((int)Emulator.ReadMemoryUInt(DcAttr + DcAttrCurrentPosXOffset));
            Y = unchecked((int)Emulator.ReadMemoryUInt(DcAttr + DcAttrCurrentPosYOffset));
            return true;
        }

        public void WriteDcCurrentPosition(ulong Hdc, int X, int Y)
        {
            ulong DcAttr = GetDcAttributeAddress(Hdc);
            if (DcAttr == 0)
                return;

            Emulator._emulator.WriteMemory(DcAttr + DcAttrCurrentPosXOffset, unchecked((uint)X), 4);
            Emulator._emulator.WriteMemory(DcAttr + DcAttrCurrentPosYOffset, unchecked((uint)Y), 4);
        }

        public ulong ReadDcSelectedPen(ulong Hdc)
        {
            ulong DcAttr = GetDcAttributeAddress(Hdc);
            return DcAttr == 0 ? 0 : Emulator.ReadMemoryULong(DcAttr + DcAttrSelectedPenOffset);
        }

        public ulong ReadDcSelectedBrush(ulong Hdc)
        {
            ulong DcAttr = GetDcAttributeAddress(Hdc);
            return DcAttr == 0 ? 0 : Emulator.ReadMemoryULong(DcAttr + DcAttrSelectedBrushOffset);
        }

        public bool ValidateGdiHandle(ulong Handle)
        {
            if (Handle == 0 || GdiHandleTableAddress == 0)
                return false;

            ushort Index = (ushort)(Handle & 0xFFFF);
            byte Uniq = (byte)((Handle >> 16) & 0xFF);

            if (Index == 0 || Index >= GdiHandleEntryCount)
                return false;

            ulong Entry = GdiHandleTableAddress + (ulong)Index * GdiHandleEntrySize;
            byte StoredUniq = (byte)Emulator.ReadMemoryUInt(Entry + 0x0C);
            return StoredUniq == Uniq;
        }

        public ulong GetGdiHandleTableAddress()
        {
            EnsureGdiHandleTable();
            return GdiHandleTableAddress;
        }

        private const ulong TebGdiBatchOffsetOffset = 0x0FE8;
        private const ulong TebGdiBatchHdcOffset = 0x0FF0;
        private const ulong TebGdiBatchBufferOffset = 0x0FF8;
        private const uint GdiBatchBufferSize = 310;
        private const ushort GdiBatchCmdTextOut = 2;
        private const uint GdiBatchNoRectFlag = 0x80000000u;
        private const int GdiBatchTextOutStringOffset = 0x54;

        public void FlushGdiBatch()
        {
            ulong Teb = Emulator.TEB;
            if (Teb == 0)
                return;

            uint BatchOffset = Emulator.ReadMemoryUInt(Teb + TebGdiBatchOffsetOffset);
            uint RealBatchOffset = BatchOffset & ~GdiBatchNoRectFlag;
            if (RealBatchOffset == 0 || RealBatchOffset > GdiBatchBufferSize * 4)
            {
                Emulator._emulator.WriteMemory(Teb + TebGdiBatchOffsetOffset, 0u, 4);
                return;
            }

            ulong BatchHdc = Emulator.ReadMemoryULong(Teb + TebGdiBatchHdcOffset);
            ulong BufferAddr = Teb + TebGdiBatchBufferOffset;

            Span<byte> BatchBuffer = Shared.GetSpan((ulong)(GdiBatchBufferSize * 4));
            if (!Emulator.ReadMemory(BufferAddr, BatchBuffer.Slice(0, (int)(GdiBatchBufferSize * 4)), GdiBatchBufferSize * 4))
            {
                Emulator._emulator.WriteMemory(Teb + TebGdiBatchOffsetOffset, 0u, 4);
                return;
            }

            int Offset = 0;
            while (Offset + 4 <= (int)RealBatchOffset)
            {
                short Size = (short)(BatchBuffer[Offset] | (BatchBuffer[Offset + 1] << 8));
                short Cmd = (short)(BatchBuffer[Offset + 2] | (BatchBuffer[Offset + 3] << 8));

                if (Size <= 0 || Offset + Size > (int)RealBatchOffset)
                    break;

                if (Cmd == GdiBatchCmdTextOut && Size >= GdiBatchTextOutStringOffset)
                {
                    int X = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(BatchBuffer.Slice(Offset + 0x18, 4));
                    int Y = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(BatchBuffer.Slice(Offset + 0x1C, 4));
                    uint Options = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(BatchBuffer.Slice(Offset + 0x20, 4));
                    int RectLeft = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(BatchBuffer.Slice(Offset + 0x24, 4));
                    int RectTop = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(BatchBuffer.Slice(Offset + 0x28, 4));
                    int RectRight = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(BatchBuffer.Slice(Offset + 0x2C, 4));
                    int RectBottom = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(BatchBuffer.Slice(Offset + 0x30, 4));
                    uint Count = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(BatchBuffer.Slice(Offset + 0x38, 4));
                    uint DxSize = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(BatchBuffer.Slice(Offset + 0x3C, 4));
                    int VpOrgX = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(BatchBuffer.Slice(Offset + 0x4C, 4));
                    int VpOrgY = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(BatchBuffer.Slice(Offset + 0x50, 4));

                    bool HasRect = (Options & GdiBatchNoRectFlag) == 0;
                    if (!HasRect)
                    {
                        RectLeft = 0;
                        RectTop = 0;
                        RectRight = 0;
                        RectBottom = 0;
                    }

                    if (Count > 0 && BatchHdc != 0)
                    {
                        int PayloadSize = Size - GdiBatchTextOutStringOffset;
                        int DxBytes = (int)DxSize;
                        int TextBytes = (int)(Count * 2);

                        if (DxBytes <= PayloadSize && TextBytes <= PayloadSize - DxBytes)
                        {
                            int StringStart = Offset + GdiBatchTextOutStringOffset + DxBytes;
                            string Text = string.Empty;
                            if (TextBytes > 0)
                            {
                                Span<byte> Raw = BatchBuffer.Slice(StringStart, TextBytes);
                                char[] Chars = new char[Count];
                                for (int i = 0; i < Count; i++)
                                    Chars[i] = (char)(Raw[i * 2] | (Raw[i * 2 + 1] << 8));
                                Text = new string(Chars);
                            }

                            ulong Hwnd = Win32kHelper.GetHwndFromDc(Emulator, BatchHdc);
                            if (Hwnd != 0)
                            {
                                int FinalX = X + VpOrgX;
                                int FinalY = Y + VpOrgY;
                                EnqueueTextRender(Hwnd, Text, FinalX, FinalY, RectLeft, RectTop, RectRight, RectBottom, Options);
                            }
                        }
                    }
                }

                Offset += Size;
            }

            Emulator._emulator.WriteMemory(Teb + TebGdiBatchOffsetOffset, 0u, 4);
            Emulator._emulator.WriteMemory(Teb + TebGdiBatchHdcOffset, 0UL, 8);
        }

        public bool FreeGdiHandle(ulong Handle)
        {
            if (Handle == 0)
                return false;

            EnsureGdiHandleTable();
            if (GdiHandleTableAddress == 0)
                return false;

            ushort Index = (ushort)(Handle & 0xFFFF);
            if (Index == 0 || Index >= GdiHandleEntryCount)
                return false;

            ulong Entry = GdiHandleTableAddress + (ulong)Index * GdiHandleEntrySize;
            for (uint i = 0; i < GdiHandleEntrySize; i += 8)
                Emulator._emulator.WriteMemory(Entry + i, 0UL, 8);

            return true;
        }

        public bool AttachGdiKernelObject(ulong Handle, ulong KernelObject)
        {
            if (Handle == 0 || KernelObject == 0)
                return false;

            EnsureGdiHandleTable();
            if (GdiHandleTableAddress == 0)
                return false;

            ushort Index = (ushort)(Handle & 0xFFFF);
            if (Index == 0 || Index >= GdiHandleEntryCount)
                return false;

            ulong Entry = GdiHandleTableAddress + (ulong)Index * GdiHandleEntrySize;
            ulong Encrypted = EncryptGdiPointer(KernelObject);
            Emulator._emulator.WriteMemory(Entry + 0x10, Encrypted, 8);
            return true;
        }

        public ulong GetHwndFromDc(ulong Hdc)
        {
            return Win32kHelper.GetHwndFromDc(Emulator, Hdc);
        }

        public void EnqueueTextRender(ulong Hwnd, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options)
        {
            if (DesktopDisplay is GuiThreadManager guiManager)
                guiManager.EnqueueTextRender(Hwnd, text, x, y, rectLeft, rectTop, rectRight, rectBottom, options);
        }

        public void EnqueueGdiLine(ulong Hwnd, int X1, int Y1, int X2, int Y2, uint PenColor, int PenWidth)
        {
            if (DesktopDisplay is GuiThreadManager guiManager)
                guiManager.EnqueueGdiPrimitive(new GdiPrimitive
                {
                    Kind = GdiPrimitiveKind.Line,
                    X1 = X1,
                    Y1 = Y1,
                    X2 = X2,
                    Y2 = Y2,
                    Pen = new GdiPenDescriptor { ColorRef = PenColor, Width = PenWidth },
                    HasPen = true,
                });
        }

        public void EnqueueGdiFillRect(ulong Hwnd, int Left, int Top, int Right, int Bottom, uint BrushColor, uint Rop)
        {
            if (DesktopDisplay is GuiThreadManager guiManager)
                guiManager.EnqueueGdiPrimitive(new GdiPrimitive
                {
                    Kind = GdiPrimitiveKind.FillRect,
                    X1 = Left,
                    Y1 = Top,
                    X2 = Right,
                    Y2 = Bottom,
                    Rop = Rop,
                    Brush = new GdiBrushDescriptor { ColorRef = BrushColor },
                    HasBrush = true,
                });
        }

        public void EnqueueGdiShape(ulong Hwnd, GdiPrimitiveKind Kind, int Left, int Top, int Right, int Bottom, uint PenColor, int PenWidth, uint BrushColor, int RoundedWidth = 0, int RoundedHeight = 0)
        {
            if (DesktopDisplay is GuiThreadManager guiManager)
                guiManager.EnqueueGdiPrimitive(new GdiPrimitive
                {
                    Kind = Kind,
                    X1 = Left,
                    Y1 = Top,
                    X2 = Right,
                    Y2 = Bottom,
                    RoundedWidth = RoundedWidth,
                    RoundedHeight = RoundedHeight,
                    Pen = new GdiPenDescriptor { ColorRef = PenColor, Width = PenWidth },
                    Brush = new GdiBrushDescriptor { ColorRef = BrushColor },
                    HasPen = true,
                    HasBrush = true,
                });
        }

        public void EnqueueGdiPoly(ulong Hwnd, GdiPrimitiveKind Kind, GdiPoint[] Points, uint PenColor, int PenWidth, uint BrushColor, bool HasBrush)
        {
            if (DesktopDisplay is GuiThreadManager guiManager)
                guiManager.EnqueueGdiPrimitive(new GdiPrimitive
                {
                    Kind = Kind,
                    Points = Points,
                    Pen = new GdiPenDescriptor { ColorRef = PenColor, Width = PenWidth },
                    Brush = new GdiBrushDescriptor { ColorRef = BrushColor },
                    HasPen = true,
                    HasBrush = HasBrush,
                });
        }

        public bool TranslateVirtualKey(uint VirtualKey, uint ScanCode, out char Character)
        {
            Character = '\0';

            EnsureDesktopDisplay();
            if (DesktopDisplay is GuiThreadManager guiManager)
                return guiManager.TranslateVirtualKey(VirtualKey, ScanCode, out Character);

            return false;
        }

        public bool MeasureText(string Text, out int Width, out int Height)
        {
            Width = 0;
            Height = 0;

            EnsureDesktopDisplay();
            if (DesktopDisplay is GuiThreadManager guiManager)
                return guiManager.MeasureText(Text ?? string.Empty, out Width, out Height);

            return false;
        }

        public bool GetTextMetrics(out TextMetricsData Metrics)
        {
            Metrics = default;

            EnsureDesktopDisplay();
            if (DesktopDisplay is GuiThreadManager guiManager)
                return guiManager.GetTextMetrics(out Metrics);

            return false;
        }

        public bool TryBuildUserConnectData(uint Version, uint DispatchCount, uint RequestedSize, out byte[] Data)
        {
            Data = null;

            if (!EnsureUserSharedInfo(out ulong ServerInfo, out ulong HandleTable, out _))
                return false;

            ulong DisplayInfo = EnsureUserDesktopInfo();
            if (DisplayInfo == 0)
                return false;

            ulong SharedDelta = ComputeUserSharedDelta(ServerInfo, HandleTable, DisplayInfo);
            if (SharedDelta == 0)
                SharedDelta = 0x1000;

            int PointerSize = Emulator._binary.Architecture == BinaryArchitecture.x64 ? 8 : 4;
            int HeaderSize = PointerSize == 8 ? 0x10 : 0x0C;
            int MinimumSize = HeaderSize + (PointerSize * 4);
            int BufferSize = RequestedSize > (uint)MinimumSize ? (int)RequestedSize : MinimumSize;

            Data = new byte[BufferSize];
            WriteU32(Data, 0x00, Version);
            WriteU32(Data, 0x04, 0u);
            WriteU32(Data, 0x08, DispatchCount);

            if (PointerSize == 8)
            {
                WriteU64(Data, 0x10, ServerInfo);
                WriteU64(Data, 0x18, HandleTable);
                WriteU64(Data, 0x20, DisplayInfo);
                WriteU64(Data, 0x28, SharedDelta);
            }
            else
            {
                WriteU32(Data, 0x0C, (uint)ServerInfo);
                WriteU32(Data, 0x10, (uint)HandleTable);
                WriteU32(Data, 0x14, (uint)DisplayInfo);
                WriteU32(Data, 0x18, (uint)SharedDelta);
            }

            UserSharedDelta = SharedDelta;
            return true;
        }

        private ulong EnsureUserServerInfo()
        {
            if (UserServerInfoAddress != 0 && Emulator.IsRegionMapped(UserServerInfoAddress, UserSharedInfoMirrorSize))
                return UserServerInfoAddress;

            const ulong Size = 0x2000;
            ulong Address = Emulator.MapUniqueAddress(Size, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            if (!WriteZeroMemory(Address, (uint)Size))
                return 0;

            Emulator._emulator.WriteMemory(Address + 0x08, (ulong)UserHandleEntryCount, 8);

            UserServerInfoAddress = Address;
            return UserServerInfoAddress;
        }

        private ulong EnsureUserHandleTable()
        {
            ulong TableSize = UserHandleEntryCount * UserHandleEntrySize;

            if (UserHandleTableAddress != 0 && Emulator.IsRegionMapped(UserHandleTableAddress, TableSize))
                return UserHandleTableAddress;

            ulong Address = Emulator.MapUniqueAddress(TableSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            if (!WriteZeroMemory(Address, (uint)TableSize))
                return 0;

            UserHandleTableAddress = Address;
            return UserHandleTableAddress;
        }

        /// <summary>
        /// Ensures the current thread has the minimal user32 client desktop fields needed for handle validation.
        /// </summary>
        public void EnsureUserClientThreadInfo(EmulatedThread Thread, ulong ThreadInfo)
        {
            if (Thread == null)
                return;

            ulong Teb = WinEmulatedThread.GetState(Thread).Teb;
            if (Teb == 0)
                return;

            ulong DesktopInfo = EnsureUserDesktopInfo();
            if (DesktopInfo == 0)
                return;

            WriteWin32ClientInfoSlot(Teb, Win32ClientInfoPDeskInfoSlot, DesktopInfo);
            WriteWin32ClientInfoSlot(Teb, Win32ClientInfoDesktopSlot, DesktopInfo);
        }

        public void SetThreadWindowContext(WinWindow Window)
        {
            if (Window == null)
                return;

            EmulatedThread Thread = Emulator.CurrentThread;
            if (Thread == null)
                return;

            ulong ClientWindow = Window.ClientWindowAddress != 0 ? Window.ClientWindowAddress : GetUserWindowClientAddress(Window);
            if (ClientWindow == 0)
                return;

            SetThreadWindowContext(Thread, Window.Hwnd, ClientWindow);
        }

        public void SetThreadWindowContext(EmulatedThread Thread, ulong ActiveHandle, ulong ActiveWindowPointer)
        {
            if (Thread == null)
                return;

            ulong Teb = WinEmulatedThread.GetState(Thread).Teb;
            if (Teb == 0)
                return;

            EnsureUserClientThreadInfo(Thread, 0);
            WriteWin32ClientInfoSlot(Teb, Win32ClientInfoActiveWindowSlot, ActiveHandle);
            WriteWin32ClientInfoSlot(Teb, Win32ClientInfoActiveWindowPointerSlot, ActiveWindowPointer);
        }

        private void WriteWin32ClientInfoSlot(ulong Teb, int Slot, ulong Value)
        {
            if (Teb == 0)
                return;

            if (Emulator._binary.Architecture == BinaryArchitecture.x64)
            {
                Emulator._emulator.WriteMemory(Teb + Win32ClientInfoX64Base + ((ulong)Slot * 8UL), Value, 8);
                return;
            }

            Emulator._emulator.WriteMemory(Teb + Win32ClientInfoX86Base + ((ulong)Slot * 4UL), (uint)Value, 4);
        }

        private ulong ComputeUserSharedDelta(ulong ServerInfo, ulong HandleTable, ulong DisplayInfo)
        {
            ulong Delta = 0;

            if (ServerInfo != 0 && HandleTable != 0)
            {
                Delta = HandleTable > ServerInfo ? HandleTable - ServerInfo : ServerInfo - HandleTable;
            }

            if (Delta == 0 && ServerInfo != 0 && DisplayInfo != 0)
            {
                Delta = DisplayInfo > ServerInfo ? DisplayInfo - ServerInfo : ServerInfo - DisplayInfo;
            }

            if (Delta == 0 && HandleTable != 0 && DisplayInfo != 0)
            {
                Delta = HandleTable > DisplayInfo ? HandleTable - DisplayInfo : DisplayInfo - HandleTable;
            }

            return Delta;
        }

        private ulong EnsureUserPrimaryMonitor()
        {
            if (UserPrimaryMonitorAddress != 0 && Emulator.IsRegionMapped(UserPrimaryMonitorAddress, UserPrimaryMonitorSize))
                return UserPrimaryMonitorAddress;

            ulong Monitor = Emulator.MapUniqueAddress(UserPrimaryMonitorSize, MemoryProtection.ReadWrite);
            if (Monitor == 0)
                return 0;

            if (!WriteZeroMemory(Monitor, (uint)UserPrimaryMonitorSize))
                return 0;

            (int Width, int Height) = GetHostPrimaryMonitorSize();

            UserPrimaryMonitorInfo MonitorInfo = new UserPrimaryMonitorInfo
            {
                Header = 1UL,
                MonitorLeft = 0,
                MonitorTop = 0,
                MonitorRight = Width,
                MonitorBottom = Height,
                WorkLeft = 0,
                WorkTop = 0,
                WorkRight = Width,
                WorkBottom = Height,
                DpiX = 96,
                DpiY = 96
            };

            Span<byte> Buffer = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref MonitorInfo, 1));
            if (!Emulator._emulator.WriteMemory(Monitor, Buffer))
                return 0;

            UserPrimaryMonitorAddress = Monitor;
            return UserPrimaryMonitorAddress;
        }

        private static (int Width, int Height) GetHostPrimaryMonitorSize()
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    int Width = NativeWinImports.GetSystemMetrics(SmCxScreen);
                    int Height = NativeWinImports.GetSystemMetrics(SmCyScreen);

                    if (Width > 0 && Height > 0)
                        return (Width, Height);
                }
            }
            catch
            {
            }

            return (1920, 1080);
        }

        public ulong EnsureUserDesktopInfo()
        {
            if (UserDesktopInfoAddress != 0 && Emulator.IsRegionMapped(UserDesktopInfoAddress, UserDesktopInfoSize))
                return UserDesktopInfoAddress;

            if (UserDesktopOwnerAddress == 0 || !Emulator.IsRegionMapped(UserDesktopOwnerAddress, 8))
            {
                UserDesktopOwnerAddress = Emulator.MapUniqueAddress(0x1000, MemoryProtection.ReadWrite);
                if (UserDesktopOwnerAddress == 0)
                    return 0;

                WriteZeroMemory(UserDesktopOwnerAddress, 0x1000);
            }

            ulong PrimaryMonitor = EnsureUserPrimaryMonitor();
            if (PrimaryMonitor == 0)
                return 0;

            ulong DesktopInfo = Emulator.MapUniqueAddress(0x1000, MemoryProtection.ReadWrite);
            if (DesktopInfo == 0)
                return 0;

            if (!WriteZeroMemory(DesktopInfo, 0x1000))
                return 0;

            UserSharedDisplayInfo DisplayInfo = new UserSharedDisplayInfo
            {
                Type = 1u,
                PrimaryMonitor = PrimaryMonitor
            };

            Span<byte> Buffer = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref DisplayInfo, 1));
            if (!Emulator._emulator.WriteMemory(DesktopInfo, Buffer))
                return 0;

            UserDesktopInfoAddress = DesktopInfo;
            return UserDesktopInfoAddress;
        }

        /// <summary>
        /// Creates or refreshes the shared handle-table entry and minimal client-side tagWND memory for a window.
        /// </summary>
        public bool MaterializeUserWindow(WinWindow Window)
        {
            if (Window == null || Window.Hwnd == 0)
                return false;

            if (!EnsureUserSharedInfo(out _, out ulong HandleTable, out uint EntrySize))
                return false;

            ushort Index = (ushort)(Window.Hwnd & 0xFFFF);
            ushort Uniq = (ushort)((Window.Hwnd >> 16) & 0x7FFF);
            if (Index == 0 || Index >= UserHandleEntryCount)
                return false;

            ulong ClientWindow = EnsureUserWindowObject(Window);
            ulong ThreadInfo = EnsureCurrentUserThreadInfo();
            ulong DesktopInfo = EnsureUserDesktopInfo();
            if (ClientWindow == 0 || ThreadInfo == 0 || DesktopInfo == 0)
                return false;

            ulong Entry = HandleTable + (ulong)Index * EntrySize;
            Window.UserHandleEntryAddress = Entry;

            Span<byte> Data = Shared.GetSpan(0x20);
            Data.Slice(0, 0x20).Clear();
            WriteU64(Data, 0x00, ClientWindow);
            WriteU64(Data, 0x08, ThreadInfo);
            WriteU64(Data, 0x10, UserDesktopOwnerAddress);
            Data[0x18] = UserHandleTypeWindow;
            Data[0x19] = 0;
            WriteU16(Data, 0x1A, Uniq);

            return Emulator._emulator.WriteMemory(Entry, Data.Slice(0, 0x20));
        }

        private void ClearUserWindowHandleEntry(WinWindow Window)
        {
            if (Window == null || Window.UserHandleEntryAddress == 0)
                return;

            if (Emulator.IsRegionMapped(Window.UserHandleEntryAddress, UserHandleEntrySize))
                WriteZeroMemory(Window.UserHandleEntryAddress, UserHandleEntrySize);

            Window.UserHandleEntryAddress = 0;
        }

        private ulong EnsureCurrentUserThreadInfo()
        {
            EmulatedThread Thread = Emulator.CurrentThread;
            if (Thread == null)
                return 0;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            ulong ThreadInfo = State.Win32ThreadInfo;
            ulong Teb = State.Teb;

            if (ThreadInfo == 0 && Teb != 0)
                ThreadInfo = Emulator.ReadMemoryULong(Teb + 0x78);

            if (ThreadInfo == 0 && Teb != 0)
            {
                ulong SlabSize = Emulator._binary.Architecture == BinaryArchitecture.x64 ? 0x2000UL : 0x1000UL;
                ulong Bias = Emulator._binary.Architecture == BinaryArchitecture.x64 ? 0x800UL : 0x400UL;
                ulong SlabBase = Emulator.MapUniqueAddress(SlabSize, MemoryProtection.ReadWrite);

                if (SlabBase != 0 && WriteZeroMemory(SlabBase, (uint)SlabSize))
                    ThreadInfo = SlabBase + Bias;
            }

            if (ThreadInfo != 0)
            {
                State.Win32ThreadInfo = ThreadInfo;

                if (Emulator._binary.Architecture == BinaryArchitecture.x64)
                {
                    uint Low = (uint)(ThreadInfo & 0xFFFFFFFFUL);
                    uint High = (uint)(ThreadInfo >> 32);
                    Emulator._emulator.WriteMemory(Teb + 0x78, ThreadInfo, 8);
                    Emulator._emulator.WriteMemory(Teb + 0xE8, Low, 4);
                    Emulator._emulator.WriteMemory(Teb + 0xF0, High, 4);
                }
                else
                {
                    uint ThreadInfo32 = (uint)ThreadInfo;
                    Emulator._emulator.WriteMemory(Teb + 0x40, ThreadInfo32, 4);
                    Emulator._emulator.WriteMemory(Teb + 0x78, ThreadInfo32, 4);
                    Emulator._emulator.WriteMemory(Teb + 0x7C, 0u, 4);
                }

                EnsureUserClientThreadInfo(Thread, ThreadInfo);
            }

            return ThreadInfo;
        }


        /// <summary>
        /// Returns the client-side tagWND address for a tracked window.
        /// </summary>
        public ulong GetUserWindowClientAddress(WinWindow Window)
        {
            if (Window == null)
                return 0;

            ulong Address = EnsureUserWindowObject(Window);
            MaterializeUserWindow(Window);
            return Address;
        }

        private ulong EnsureUserWindowObject(WinWindow Window)
        {
            if (Window.ClientWindowAddress != 0 && Emulator.IsRegionMapped(Window.ClientWindowAddress, UserWindowObjectSize))
            {
                RefreshUserWindowObject(Window);
                return Window.ClientWindowAddress;
            }

            ulong Address = Emulator.MapUniqueAddress(UserWindowObjectSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            if (!WriteZeroMemory(Address, (uint)UserWindowObjectSize))
                return 0;

            Window.ClientWindowAddress = Address;
            RefreshUserWindowObject(Window);
            return Window.ClientWindowAddress;
        }

        private void RefreshUserWindowObject(WinWindow Window)
        {
            ulong ClassObject = EnsureUserClassObject(Window);
            ulong TextObject = EnsureUserWindowText(Window);

            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x00, Window.Hwnd, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x08, Window.ClientWindowAddress, 8);

            int OuterLeft = Window.X == unchecked((int)0x80000000) ? 0 : Window.X;
            int OuterTop = Window.Y == unchecked((int)0x80000000) ? 0 : Window.Y;
            int OuterWidth = (int)Window.Width;
            int OuterHeight = (int)Window.Height;
            int OuterRight = OuterLeft + OuterWidth;
            int OuterBottom = OuterTop + OuterHeight;

            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x58, (uint)OuterLeft, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x5C, (uint)OuterTop, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x60, (uint)OuterRight, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x64, (uint)OuterBottom, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x68, (uint)OuterLeft, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x6C, (uint)OuterTop, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x70, (uint)OuterRight, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x74, (uint)OuterBottom, 4);

            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x78, Window.WndProc, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x80, ClassObject, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0xB8, Window.ClientTextBytes, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0xC0, TextObject, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0xE0, 0UL, 8);
        }

        private ulong EnsureUserClassObject(WinWindow Window)
        {
            if (Window.ClientClassAddress != 0 && Emulator.IsRegionMapped(Window.ClientClassAddress, UserClassObjectSize))
                return Window.ClientClassAddress;

            ulong Address = Emulator.MapUniqueAddress(UserClassObjectSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            if (!WriteZeroMemory(Address, (uint)UserClassObjectSize))
                return 0;

            Window.ClientClassAddress = Address;
            Emulator._emulator.WriteMemory(Address + 0x00, Window.ClassAtom, 2);
            Emulator._emulator.WriteMemory(Address + 0x04, (ushort)0, 2);
            return Window.ClientClassAddress;
        }

        private ulong EnsureUserWindowText(WinWindow Window)
        {
            string Title = Window.Title ?? string.Empty;
            int TextBytes = Encoding.Unicode.GetByteCount(Title);
            uint RequiredBytes = checked((uint)TextBytes + 2);

            if (Window.ClientTextAddress == 0 || Window.ClientTextBytes + 2 < RequiredBytes ||
                !Emulator.IsRegionMapped(Window.ClientTextAddress, RequiredBytes))
            {
                ulong AllocationSize = Math.Max(RequiredBytes, 0x100u);
                ulong Address = Emulator.MapUniqueAddress(AllocationSize, MemoryProtection.ReadWrite);
                if (Address == 0)
                    return 0;

                if (!WriteZeroMemory(Address, (uint)AllocationSize))
                    return 0;

                Window.ClientTextAddress = Address;
            }

            Span<byte> Buffer = Shared.GetSpan(RequiredBytes);
            Buffer.Slice(0, (int)RequiredBytes).Clear();
            Encoding.Unicode.GetBytes(Title, Buffer.Slice(0, TextBytes));

            if (!Emulator._emulator.WriteMemory(Window.ClientTextAddress, Buffer.Slice(0, (int)RequiredBytes)))
                return 0;

            Window.ClientTextBytes = (uint)TextBytes;
            return Window.ClientTextAddress;
        }

        public void SetUserCaptureActive(bool Active)
        {
            uint Value = Active ? 1u : 0u;
            ulong ServerInfo = EnsureUserServerInfo();
            WriteUserCaptureActiveFlag(ServerInfo, Value);

            foreach (ulong Mirror in EnumerateUserSharedInfoMirrors())
                WriteUserCaptureActiveFlag(Mirror, Value);
        }

        private void WriteUserCaptureActiveFlag(ulong BaseAddress, uint Value)
        {
            if (BaseAddress != 0 && Emulator.IsRegionMapped(BaseAddress + 0x1B50, 4))
                Emulator._emulator.WriteMemory(BaseAddress + 0x1B50, Value, 4);
        }

        private IEnumerable<ulong> EnumerateUserSharedInfoMirrors()
        {
            if (UserSharedInfoMirrorAddress != 0 && Emulator.IsRegionMapped(UserSharedInfoMirrorAddress, UserSharedInfoMirrorSize))
            {
                yield return UserSharedInfoMirrorAddress;
                yield break;
            }

            if (UserServerInfoAddress == 0)
                yield break;

            WinModule User32 = WinModules.FirstOrDefault(Module =>
                Module != null &&
                Module.MappedBase != 0 &&
                Module.SizeOfImage != 0 &&
                string.Equals(Module.Name, "user32.dll", StringComparison.OrdinalIgnoreCase));

            if (User32 == null)
                yield break;

            ulong End = User32.MappedBase + User32.SizeOfImage;
            for (ulong Address = User32.MappedBase; Address + 8 <= End; Address += 8)
            {
                if (!Emulator.IsRegionMapped(Address, 8))
                    continue;

                if (Emulator.ReadMemoryULong(Address) != UserServerInfoAddress)
                    continue;

                if (!Emulator.IsRegionMapped(Address + 0x1B54, 4))
                    continue;

                UserSharedInfoMirrorAddress = Address;
                yield return Address;
                yield break;
            }
        }

        private static void WriteU16(Span<byte> Data, int Offset, ushort Value)
        {
            Data[Offset + 0] = (byte)Value;
            Data[Offset + 1] = (byte)(Value >> 8);
        }

        private static void WriteU32(Span<byte> Data, int Offset, uint Value)
        {
            for (int i = 0; i < 4; i++)
                Data[Offset + i] = (byte)(Value >> (i * 8));
        }

        private static void WriteU64(Span<byte> Data, int Offset, ulong Value)
        {
            for (int i = 0; i < 8; i++)
                Data[Offset + i] = (byte)(Value >> (i * 8));
        }

        public WinWindowClass RegisterWindowClass(WinWindowClass WindowClass)
        {
            if (WindowClass == null || string.IsNullOrEmpty(WindowClass.Name))
                return null;

            string Key = BuildWindowClassKey(WindowClass.InstanceHandle, WindowClass.Name, WindowClass.Version);
            if (WinWindowClassAtomsByKey.TryGetValue(Key, out ushort ExistingAtom))
                return WinWindowClassesByAtom.TryGetValue(ExistingAtom, out WinWindowClass ExistingClass) ? ExistingClass : null;

            ushort Atom = NextWindowClassAtom++;
            if (NextWindowClassAtom < 0xC000)
                NextWindowClassAtom = 0xC000;

            WindowClass.Atom = Atom;
            WinWindowClassesByAtom[Atom] = WindowClass;
            WinWindowClassAtomsByKey[Key] = Atom;
            return WindowClass;
        }

        public WinWindowClass GetWindowClass(ulong InstanceHandle, string Name, string Version)
        {
            if (string.IsNullOrEmpty(Name))
                return null;

            string Key = BuildWindowClassKey(InstanceHandle, Name, Version);
            if (WinWindowClassAtomsByKey.TryGetValue(Key, out ushort Atom) && WinWindowClassesByAtom.TryGetValue(Atom, out WinWindowClass WindowClass))
                return WindowClass;

            Key = BuildWindowClassKey(0, Name, Version);
            if (WinWindowClassAtomsByKey.TryGetValue(Key, out Atom) && WinWindowClassesByAtom.TryGetValue(Atom, out WindowClass))
                return WindowClass;

            foreach (WinWindowClass Candidate in WinWindowClassesByAtom.Values)
            {
                if (!string.Equals(Candidate.Name, Name, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (string.IsNullOrEmpty(Version) || string.IsNullOrEmpty(Candidate.Version) ||
                    string.Equals(Candidate.Version, Version, StringComparison.OrdinalIgnoreCase))
                    return Candidate;
            }

            return null;
        }

        public WinWindowClass GetWindowClass(ushort Atom)
        {
            return WinWindowClassesByAtom.TryGetValue(Atom, out WinWindowClass WindowClass) ? WindowClass : null;
        }

        private static string BuildWindowClassKey(ulong InstanceHandle, string Name, string Version)
        {
            return $"{InstanceHandle:X}:{Name ?? string.Empty}:{Version ?? string.Empty}";
        }

        public void UpdateTopLevelWindowZOrder(ulong Hwnd, ulong InsertAfter)
        {
            const ulong HWND_TOP = 0;
            const ulong HWND_BOTTOM = 1;
            const ulong HWND_TOPMOST = 0xFFFFFFFFFFFFFFFF;
            const ulong HWND_NOTOPMOST = 0xFFFFFFFFFFFFFFFE;

            if (!WinWindows.TryGetValue(Hwnd, out WinWindow Window))
                return;

            if (Window.ParentHwnd != 0)
                return;

            TopLevelWindows.Remove(Hwnd);

            if (InsertAfter == HWND_BOTTOM)
            {
                TopLevelWindows.Insert(0, Hwnd);
                return;
            }

            if (InsertAfter == HWND_TOP || InsertAfter == HWND_TOPMOST || InsertAfter == HWND_NOTOPMOST)
            {
                TopLevelWindows.Add(Hwnd);
                return;
            }

            int Index = TopLevelWindows.IndexOf(InsertAfter);
            if (Index == -1)
            {
                TopLevelWindows.Add(Hwnd);
                return;
            }

            TopLevelWindows.Insert(Index + 1, Hwnd);
        }

        public ulong GetForegroundWindow()
        {
            for (int i = TopLevelWindows.Count - 1; i >= 0; i--)
            {
                ulong Hwnd = TopLevelWindows[i];

                if (!WinWindows.TryGetValue(Hwnd, out WinWindow Window))
                    continue;

                if (Window.Destroyed)
                    continue;

                if (!Window.Visible)
                    continue;

                return Hwnd;
            }

            return 0;
        }

        /// <summary>
        /// Retained as a presentation boundary for future renderers. Window state is tracked in WinWindows and TopLevelWindows only.
        /// </summary>
        public void CompositeDesktop()
        {
        }

        /// <summary>
        /// Presents the current foreground Win32k window through the host window manager.
        /// </summary>
        public void PresentDesktop()
        {
            try
            {
                EnsureDesktopWindow();
                if (DesktopDisplay is not GuiThreadManager guiManager)
                    return;

                WinWindow Window = GetWindow(GetForegroundWindow());
                if (Window == null)
                    Window = GetTopLevelWindow();

                string title;
                int width;
                int height;
                bool visible;
                WindowState state;

                if (Window != null)
                {
                    title = string.IsNullOrWhiteSpace(Window.Title) ? DesktopWindowTitle : Window.Title;
                    width = Math.Max((int)Window.Width, 1);
                    height = Math.Max((int)Window.Height, 1);
                    visible = Window.Visible && !Window.Destroyed;
                    state = Window.Minimized ? WindowState.Minimized : Window.Maximized ? WindowState.Maximized : WindowState.Normal;
                }
                else
                {
                    title = DesktopWindowTitle;
                    width = 0;
                    height = 0;
                    visible = false;
                    state = WindowState.Normal;
                }

                guiManager.EnqueuePresent(title, width, height, visible, state);
            }
            catch
            {
            }
        }

        private void EnsureDesktopDisplay()
        {
            if (DesktopDisplay != null)
                return;

            try
            {
                DesktopDisplay = WindowManagerFactory.Create();
            }
            catch
            {
            }
        }

        private void EnsureDesktopWindow()
        {
            if (DesktopWindow != null)
                return;

            EnsureDesktopDisplay();
            if (DesktopDisplay == null)
                return;

            DesktopWindow = DesktopDisplay.CreateWindow(new WindowOptions
            {
                Title = DesktopWindowTitle,
                AppId = "Brovan",
                Width = 1280,
                Height = 720,
                Visible = true,
                Resizable = true,
                Decorated = true,
                Center = true,
                State = WindowState.Normal,
            });
        }

        /// <summary>
        /// Ensures the single host desktop window exists and returns its native handle (an HWND on
        /// Windows), or IntPtr.Zero if no host window backend is available. BrovVulk binds a Vulkan
        /// surface to THIS real on-screen window rather than any guest-side HWND, so DXVK's swapchain
        /// presents to the actual Brovan window.
        /// </summary>
        public IntPtr EnsureHostWindowHandle()
        {
            EnsureDesktopWindow();
            return DesktopWindow?.NativeHandle ?? IntPtr.Zero;
        }

        public void EnsureHostXlibSurfaceHandles(out IntPtr connection, out IntPtr window)
        {
            if (!GeneralHelper.IsLinux)
            {
                connection = IntPtr.Zero;
                window = IntPtr.Zero;
                return;
            }

            EnsureDesktopDisplay();
            EnsureDesktopWindow();
            if (DesktopDisplay == null || DesktopWindow == null)
            {
                connection = IntPtr.Zero;
                window = IntPtr.Zero;
                return;
            }

            IntPtr xDisplay = DesktopDisplay.NativeHandle;
            connection = BrovVulkLinuxWsi.XGetXCBConnection(xDisplay);
            window = DesktopWindow.NativeHandle;
        }


        private WinWindow GetTopLevelWindow()
        {
            for (int i = TopLevelWindows.Count - 1; i >= 0; i--)
            {
                ulong Hwnd = TopLevelWindows[i];
                if (WinWindows.TryGetValue(Hwnd, out WinWindow Window) && Window != null && !Window.Destroyed)
                    return Window;
            }

            return null;
        }

        public WinWindow GetWindow(ulong Hwnd)
        {
            if (Hwnd == 0)
                return null;

            if (WinWindows.TryGetValue(Hwnd, out WinWindow Window))
                return Window;

            return null;
        }

        public void RegisterWindow(WinWindow Window)
        {
            MaterializeUserWindow(Window);
            WinWindows[Window.Hwnd] = Window;

            if (Window.Visible)
            {
                if (ActiveWindow == 0)
                    ActiveWindow = Window.Hwnd;

                if (FocusWindow == 0)
                    FocusWindow = Window.Hwnd;
            }

            if (Window.ParentHwnd != 0 && WinWindows.TryGetValue(Window.ParentHwnd, out WinWindow Parent))
            {
                if (!Parent.Children.Contains(Window.Hwnd))
                    Parent.Children.Add(Window.Hwnd);
            }
            else
            {
                if (!TopLevelWindows.Contains(Window.Hwnd))
                    TopLevelWindows.Add(Window.Hwnd);
            }

            if (Window.Visible && Window.ParentHwnd == 0)
                SetThreadWindowContext(Window);

            Window.Dirty = true;
            MaterializeUserWindow(Window);
            PresentDesktop();
        }

        public bool DestroyWindow(ulong Hwnd)
        {
            if (Hwnd == Win32kMessageOnlyParent.HwndMessage)
                return false;

            if (!WinWindows.TryGetValue(Hwnd, out WinWindow Window))
                return false;

            if (ActiveWindow == Hwnd)
                ActiveWindow = 0;

            if (FocusWindow == Hwnd)
                FocusWindow = 0;

            foreach (ulong Child in Window.Children.ToArray())
            {
                DestroyWindow(Child);
            }

            if (Window.ParentHwnd != 0 && WinWindows.TryGetValue(Window.ParentHwnd, out WinWindow Parent))
            {
                Parent.Children.Remove(Hwnd);
            }
            else
            {
                TopLevelWindows.Remove(Hwnd);
            }

            Window.Destroyed = true;
            ClearUserWindowHandleEntry(Window);
            WinWindows.Remove(Hwnd);
            PresentDesktop();
            return true;
        }

        public WinHandle OpenFileHandle(string Path, bool FSAccess, AccessMask Permissions)
        {
            WinFile hFile = null;
            if (FSAccess)
            {
                if (File.Exists(Path))
                    hFile = new WinFile { Path = Path, Device = (Path.StartsWith("\\\\.\\") || Path.ToLower().StartsWith("\\device\\")) };
                else
                    return null;
            }
            else
            {
                hFile = WinFiles.FirstOrDefault(f => f.Path.Equals(Path, StringComparison.OrdinalIgnoreCase));
                if (hFile == null)
                {
                    hFile = new WinFile { Path = Path, Device = (Path.StartsWith("\\\\.\\") || Path.ToLower().StartsWith("\\device\\")) };
                    WinFiles.Add(hFile);
                }
            }

            WinHandle Handle = HandleManager.AddHandle(hFile, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinFile? GetFileByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.TryGetHandle(Handle, out HandleEntry Entry))
                return null;
            if (Entry.Object == null || Entry.Object.ObjectType != HandleType.FileHandle)
                return null;
            if (Purpose != AccessMask.GiveTemp)
            {
                AccessMask Granted = Entry.Permissions;
                if ((Granted & AccessMask.MaximumAllowed) == 0 && (Granted & AccessMask.GenericAll) == 0)
                {
                    if ((Granted & Purpose) != Purpose)
                        return null;
                }
            }
            return Entry.Object as WinFile;
        }

        public bool ValidFileHandle(ulong Handle)
        {
            if (HandleExists(Handle, HandleType.FileHandle))
            {
                WinFile Target = HandleManager.GetObjectByHandle<WinFile>(Handle);
                if (Target != null)
                {
                    if (WinFiles.FirstOrDefault(f => f.Path == Target.Path) != null)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public bool IsValidFileLockRange(ulong Offset, ulong Length)
        {
            if (Length == 0)
                return false;

            ulong End = Offset + Length - 1;
            return !(End < Offset);
        }

        /// <summary>
        /// Reads and validates a Windows file lock byte range from emulated memory.
        /// </summary>
        /// <param name="ByteOffsetPtr">Pointer to the lock offset.</param>
        /// <param name="LengthPtr">Pointer to the lock length.</param>
        /// <param name="Offset">Receives the lock offset.</param>
        /// <param name="Length">Receives the lock length.</param>
        /// <param name="Status">Receives the validation status.</param>
        /// <returns>True if the lock range was read and is valid.</returns>
        public bool TryReadFileLockRange(ulong ByteOffsetPtr, ulong LengthPtr, out ulong Offset, out ulong Length, out NTSTATUS Status)
        {
            Offset = 0;
            Length = 0;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (!Emulator.IsRegionMapped(ByteOffsetPtr, 8) || !Emulator.IsRegionMapped(LengthPtr, 8))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            long SignedOffset = unchecked((long)Emulator._emulator.ReadMemoryULong(ByteOffsetPtr));
            long SignedLength = unchecked((long)Emulator._emulator.ReadMemoryULong(LengthPtr));
            if (SignedOffset < 0 || SignedLength < 0)
            {
                Status = NTSTATUS.STATUS_INVALID_LOCK_RANGE;
                return false;
            }

            Offset = (ulong)SignedOffset;
            Length = (ulong)SignedLength;

            if (!IsValidFileLockRange(Offset, Length))
            {
                Status = NTSTATUS.STATUS_INVALID_LOCK_RANGE;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Reads an optional Windows file byte offset from emulated memory.
        /// </summary>
        /// <param name="ByteOffsetPtr">Pointer to a LARGE_INTEGER byte offset, or zero to use the current file position.</param>
        /// <param name="CurrentPosition">The current file position.</param>
        /// <returns>The requested file offset, or the current file position if no valid pointer was supplied.</returns>
        public long GetEffectiveFileOffset(ulong ByteOffsetPtr, long CurrentPosition)
        {
            if (ByteOffsetPtr == 0)
                return CurrentPosition;

            if (!Emulator.IsRegionMapped(ByteOffsetPtr, 8))
                return CurrentPosition;

            return unchecked((long)Emulator._emulator.ReadMemoryULong(ByteOffsetPtr));
        }

        public WinHandle CreateMutexHandle(string Name, AccessMask Permissions)
        {
            WinMutex Mutex = null;

            if (!string.IsNullOrEmpty(Name))
                Mutex = WinMutexes.FirstOrDefault(m => m.Name.Equals(Name, StringComparison.OrdinalIgnoreCase));

            if (Mutex == null)
            {
                Mutex = new WinMutex { Name = string.IsNullOrEmpty(Name) ? $"\\UnnamedMutant\\{WinMutexes.Count:X}" : Name, Signaled = true };
                WinMutexes.Add(Mutex);
            }

            WinHandle Handle = HandleManager.AddHandle(Mutex, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinMutex? GetMutexByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.MutexHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinMutex>(Handle);
        }

        public void AbandonMutexesOwnedByThread(uint ThreadId)
        {
            if (ThreadId == 0)
                return;

            foreach (WinMutex Mutex in WinMutexes)
            {
                if (Mutex.OwnerThreadId != ThreadId || Mutex.RecursionCount <= 0)
                    continue;

                Mutex.OwnerThreadId = 0;
                Mutex.RecursionCount = 0;
                Mutex.Signaled = true;
                Mutex.Abandoned = true;
            }
        }

        private Hive GetHiveByNtPath(string NtPath)
        {
            return RegManager.GetHiveByNtPath(RegHives, NtPath);
        }

        private string FixupNtRegistryPath(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return NtPath;

            NtPath = NtPath.TrimEnd('\0').Trim();
            if (NtPath.Length == 0)
                return NtPath;

            NtPath = NtPath.Replace('/', '\\');

            while (NtPath.Contains("\\\\", StringComparison.Ordinal))
                NtPath = NtPath.Replace("\\\\", "\\", StringComparison.Ordinal);

            if (!NtPath.StartsWith("\\", StringComparison.Ordinal))
                NtPath = "\\" + NtPath;

            if (NtPath.Equals("\\HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase) || NtPath.Equals("\\HKLM", StringComparison.OrdinalIgnoreCase))
                NtPath = "\\Registry\\Machine";

            if (NtPath.StartsWith("\\HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase))
                NtPath = "\\Registry\\Machine\\" + NtPath.Substring("\\HKEY_LOCAL_MACHINE\\".Length);

            if (NtPath.StartsWith("\\HKLM\\", StringComparison.OrdinalIgnoreCase))
                NtPath = "\\Registry\\Machine\\" + NtPath.Substring("\\HKLM\\".Length);

            if (NtPath.Equals("\\HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) || NtPath.Equals("\\HKCU", StringComparison.OrdinalIgnoreCase))
                NtPath = $"\\Registry\\User\\{CurrentUserSid}";

            if (NtPath.StartsWith("\\HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase))
                NtPath = $"\\Registry\\User\\{CurrentUserSid}\\" + NtPath.Substring("\\HKEY_CURRENT_USER\\".Length);

            if (NtPath.StartsWith("\\HKCU\\", StringComparison.OrdinalIgnoreCase))
                NtPath = $"\\Registry\\User\\{CurrentUserSid}\\" + NtPath.Substring("\\HKCU\\".Length);

            if (NtPath.StartsWith("\\Registry\\Machine\\", StringComparison.OrdinalIgnoreCase))
            {
                string Rest = NtPath.Substring("\\Registry\\Machine\\".Length);

                if (Rest.Length == 0)
                    return NtPath;

                int Sep = Rest.IndexOf('\\');
                string First = Sep == -1 ? Rest : Rest.Substring(0, Sep);

                if (First.Equals("SOFTWARE", StringComparison.OrdinalIgnoreCase) || First.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) || First.Equals("SAM", StringComparison.OrdinalIgnoreCase) || First.Equals("SECURITY", StringComparison.OrdinalIgnoreCase) || First.Equals("HARDWARE", StringComparison.OrdinalIgnoreCase))
                {
                    return NtPath;
                }

                return "\\Registry\\Machine\\SOFTWARE\\" + Rest;
            }

            if (NtPath.Equals("\\Registry\\User", StringComparison.OrdinalIgnoreCase))
                return "\\Registry\\User";

            if (NtPath.StartsWith("\\Registry\\User\\", StringComparison.OrdinalIgnoreCase))
            {
                string Rest = NtPath.Substring("\\Registry\\User\\".Length);
                if (Rest.Length == 0)
                    return $"\\Registry\\User\\{CurrentUserSid}";

                int Sep = Rest.IndexOf('\\');
                string First = Sep == -1 ? Rest : Rest.Substring(0, Sep);
                string Tail = Sep == -1 ? string.Empty : Rest.Substring(Sep);

                if (First.Equals(".DEFAULT", StringComparison.OrdinalIgnoreCase))
                    return "\\Registry\\User\\.DEFAULT" + Tail;

                if (First.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
                    return $"\\Registry\\User\\{CurrentUserSid}{Tail}";

                return $"\\Registry\\User\\{CurrentUserSid}\\{Rest}";
            }

            if (NtPath.StartsWith("\\SOFTWARE\\", StringComparison.OrdinalIgnoreCase))
                return "\\Registry\\Machine" + NtPath;

            if (NtPath.Equals("\\SOFTWARE", StringComparison.OrdinalIgnoreCase))
                return "\\Registry\\Machine\\SOFTWARE";

            return NtPath;
        }

        private static string NormalizeKeyPath(string Path)
        {
            return RegistryManager.NormalizeKeyPath(Path);
        }

        public string NormalizeNtRegistryPath(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return null;

            if (_normalizedPathCache.TryGetValue(NtPath, out string Cached))
                return Cached;

            NtPath = FixupNtRegistryPath(NtPath);
            NtPath = NormalizeKeyPath(NtPath);
            _normalizedPathCache[NtPath] = NtPath;
            return NtPath;
        }

        private bool IsVirtualRegistryRoot(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return false;

            NtPath = NormalizeKeyPath(NtPath);
            return NtPath.Equals("\\Registry\\Machine", StringComparison.OrdinalIgnoreCase) ||
                   NtPath.Equals("\\Registry\\User", StringComparison.OrdinalIgnoreCase);
        }

        private void AddVirtualRegistrySubKeys(string NtPath, List<string> Names)
        {
            if (string.IsNullOrEmpty(NtPath) || Names == null)
                return;

            NtPath = NormalizeKeyPath(NtPath);

            if (NtPath.Equals("\\Registry\\Machine", StringComparison.OrdinalIgnoreCase))
            {
                Names.Add("HARDWARE");
                Names.Add("SAM");
                Names.Add("SECURITY");
                Names.Add("SOFTWARE");
                Names.Add("SYSTEM");
                return;
            }

            if (NtPath.Equals("\\Registry\\User", StringComparison.OrdinalIgnoreCase))
            {
                Names.Add(CurrentUserSid);
                Names.Add(".DEFAULT");
                return;
            }
        }

        private void InitializeSyntheticRegistryDefaults()
        {
            Dictionary<string, bool> KeyCache = new Dictionary<string, bool>(128, StringComparer.OrdinalIgnoreCase);
            Hive DefaultHive = RegHives != null && RegHives.Length != 0 ? RegHives[0] : null;
            string UserProfile = "C:\\Users\\User";
            string UserRoot = "\\Registry\\User\\" + CurrentUserSid;
            string ExplorerRoot = UserRoot + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";

            AddSyntheticRegistryKeyTrusted("\\Registry\\User", KeyCache, DefaultHive);
            AddSyntheticRegistryKeyTrusted(UserRoot, KeyCache, DefaultHive);
            AddSyntheticRegistryKeyTrusted("\\Registry\\User\\.DEFAULT", KeyCache, DefaultHive);
            AddSyntheticRegistryKeyTrusted(UserRoot + "\\" + CurrentUserSid, KeyCache, DefaultHive);
            AddSyntheticRegistryKeyTrusted(ExplorerRoot + "\\SessionInfo\\0", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(UserRoot + "\\Volatile Environment", "USERPROFILE", 2, UserProfile, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(UserRoot + "\\Volatile Environment", "HOMEDRIVE", 1, "C:", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(UserRoot + "\\Volatile Environment", "HOMEPATH", 1, "\\Users\\User", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(UserRoot + "\\Volatile Environment", "APPDATA", 2, "%USERPROFILE%\\AppData\\Roaming", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(UserRoot + "\\Volatile Environment", "LOCALAPPDATA", 2, "%USERPROFILE%\\AppData\\Local", KeyCache, DefaultHive);

            string ProfileListKey = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + CurrentUserSid;
            AddSyntheticRegistryKeyTrusted(ProfileListKey, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(ProfileListKey, "ProfileImagePath", 2, "%SystemDrive%\\Users\\User", KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(ProfileListKey, "Flags", 0, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(ProfileListKey, "State", 0, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(ProfileListKey, "RefCount", 0, KeyCache, DefaultHive);

            InitializeSyntheticWindowsVersionRegistryDefaults(KeyCache, DefaultHive);
            InitializeSyntheticKnownFolderDescriptions(UserProfile, KeyCache, DefaultHive);

            string KnownFolderSettings = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\KnownFolderSettings";
            AddSyntheticRegistryKeyTrusted(KnownFolderSettings, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(KnownFolderSettings, "CacheTimeout", 0, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(KnownFolderSettings, "BackgroundRetryInterval", 0, KeyCache, DefaultHive);

            AddSyntheticDirectory(UserProfile);
            AddSyntheticDirectory(UserProfile + "\\AppData");
            AddSyntheticDirectory(UserProfile + "\\AppData\\Local");
            AddSyntheticDirectory(UserProfile + "\\AppData\\Roaming");
            AddSyntheticDirectory(UserProfile + "\\Desktop");
            AddSyntheticDirectory(UserProfile + "\\Documents");
            AddSyntheticDirectory(UserProfile + "\\Downloads");
            AddSyntheticDirectory("C:\\ProgramData");
            AddSyntheticDirectory("C:\\Users\\Public");
            AddSyntheticDirectory("C:\\Users\\Public\\Desktop");
            AddSyntheticDirectory("C:\\Users\\Public\\Documents");

            string UserShellFolders = ExplorerRoot + "\\User Shell Folders";
            string ShellFolders = ExplorerRoot + "\\Shell Folders";

            AddSyntheticRegistryKeyTrusted(UserShellFolders, KeyCache, DefaultHive);
            AddSyntheticRegistryKeyTrusted(ShellFolders, KeyCache, DefaultHive);

            (string Name, string ExpandValue, string ResolvedValue)[] Folders =
            {
                ("AppData", "%USERPROFILE%\\AppData\\Roaming", UserProfile + "\\AppData\\Roaming"),
                ("Local AppData", "%USERPROFILE%\\AppData\\Local", UserProfile + "\\AppData\\Local"),
                ("Desktop", "%USERPROFILE%\\Desktop", UserProfile + "\\Desktop"),
                ("Personal", "%USERPROFILE%\\Documents", UserProfile + "\\Documents"),
                ("My Pictures", "%USERPROFILE%\\Pictures", UserProfile + "\\Pictures"),
                ("My Music", "%USERPROFILE%\\Music", UserProfile + "\\Music"),
                ("My Video", "%USERPROFILE%\\Videos", UserProfile + "\\Videos"),
                ("Favorites", "%USERPROFILE%\\Favorites", UserProfile + "\\Favorites"),
                ("Start Menu", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"),
                ("Programs", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"),
                ("Startup", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                ("Recent", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent"),
                ("SendTo", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\SendTo", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\SendTo"),
                ("Templates", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Templates", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Templates"),
                ("Cache", "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCache", UserProfile + "\\AppData\\Local\\Microsoft\\Windows\\INetCache"),
                ("Cookies", "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCookies", UserProfile + "\\AppData\\Local\\Microsoft\\Windows\\INetCookies"),
                ("History", "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\History", UserProfile + "\\AppData\\Local\\Microsoft\\Windows\\History")
            };

            foreach ((string Name, string ExpandValue, string ResolvedValue) in Folders)
            {
                SetSyntheticRegistryStringTrusted(UserShellFolders, Name, 2, ExpandValue, KeyCache, DefaultHive);
                SetSyntheticRegistryStringTrusted(ShellFolders, Name, 1, ResolvedValue, KeyCache, DefaultHive);
                AddSyntheticDirectory(ResolvedValue);
            }

            string MachineExplorerRoot = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";
            string CommonUserShellFolders = MachineExplorerRoot + "\\User Shell Folders";
            string CommonShellFolders = MachineExplorerRoot + "\\Shell Folders";
            AddSyntheticRegistryKeyTrusted(CommonUserShellFolders, KeyCache, DefaultHive);
            AddSyntheticRegistryKeyTrusted(CommonShellFolders, KeyCache, DefaultHive);

            SetSyntheticRegistryStringTrusted(CommonUserShellFolders, "Common AppData", 2, "%ProgramData%", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonShellFolders, "Common AppData", 1, "C:\\ProgramData", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonUserShellFolders, "Common Desktop", 2, "%PUBLIC%\\Desktop", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonShellFolders, "Common Desktop", 1, "C:\\Users\\Public\\Desktop", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonUserShellFolders, "Common Documents", 2, "%PUBLIC%\\Documents", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonShellFolders, "Common Documents", 1, "C:\\Users\\Public\\Documents", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonUserShellFolders, "Common Programs", 2, "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonShellFolders, "Common Programs", 1, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonUserShellFolders, "Common Start Menu", 2, "%ProgramData%\\Microsoft\\Windows\\Start Menu", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonShellFolders, "Common Start Menu", 1, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonUserShellFolders, "Common Startup", 2, "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonShellFolders, "Common Startup", 1, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonUserShellFolders, "Common Templates", 2, "%ProgramData%\\Microsoft\\Windows\\Templates", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CommonShellFolders, "Common Templates", 1, "C:\\ProgramData\\Microsoft\\Windows\\Templates", KeyCache, DefaultHive);
        }

        private void InitializeSyntheticWindowsVersionRegistryDefaults(Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            const string CurrentVersionKey = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion";
            AddSyntheticRegistryKeyTrusted(CurrentVersionKey, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "ProductName", 1, WindowsVersionInfo.ProductName, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "EditionID", 1, WindowsVersionInfo.EditionId, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "CompositionEditionID", 1, WindowsVersionInfo.EditionId, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "InstallationType", 1, WindowsVersionInfo.InstallationType, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "DisplayVersion", 1, WindowsVersionInfo.DisplayVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "ReleaseId", 1, WindowsVersionInfo.DisplayVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "CurrentVersion", 1, WindowsVersionInfo.CurrentVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "CurrentBuild", 1, WindowsVersionInfo.BuildNumber.ToString(), KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "CurrentBuildNumber", 1, WindowsVersionInfo.BuildNumber.ToString(), KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(CurrentVersionKey, "CurrentMajorVersionNumber", WindowsVersionInfo.MajorVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(CurrentVersionKey, "CurrentMinorVersionNumber", WindowsVersionInfo.MinorVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(CurrentVersionKey, "UBR", WindowsVersionInfo.UpdateBuildRevision, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "BuildBranch", 1, WindowsVersionInfo.BuildBranch, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "BuildLab", 1, WindowsVersionInfo.BuildLab, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "BuildLabEx", 1, WindowsVersionInfo.BuildLabEx, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(CurrentVersionKey, "CurrentType", 1, "Multiprocessor Free", KeyCache, DefaultHive);

            const string ProductOptionsKey = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions";
            AddSyntheticRegistryKeyTrusted(ProductOptionsKey, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(ProductOptionsKey, "ProductType", 1, WindowsVersionInfo.RegistryProductType, KeyCache, DefaultHive);
        }

        private void AddSyntheticRegistryKey(string NtPath, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return;

            string[] Parts = NtPath.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
            string Current = string.Empty;

            foreach (string Part in Parts)
            {
                Current += "\\" + Part;
                if (Current.Equals("\\Registry", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (TempRegistryKeys.Contains(Current))
                {
                    KeyCache[Current] = true;
                    continue;
                }

                if (!KeyCache.TryGetValue(Current, out bool Exists))
                {
                    Exists = RegistryKeyExists(Current, out _, out _, out _);
                    KeyCache[Current] = Exists;
                }

                if (Exists)
                    continue;

                TempRegistryKeys.Add(Current);
                DeletedRegistryKeys.Remove(Current);
                Hive Hive = GetHiveByNtPath(Current) ?? DefaultHive;
                if (Hive != null)
                    TempRegistryKeyHives[Current] = Hive;
                KeyCache[Current] = true;
            }
        }
        private void AddSyntheticRegistryKeyTrusted(string NtPath, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return;

            string[] Parts = NtPath.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
            string Current = string.Empty;

            foreach (string Part in Parts)
            {
                Current += "\\" + Part;
                if (Current.Equals("\\Registry", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (TempRegistryKeys.Contains(Current))
                {
                    KeyCache[Current] = true;
                    continue;
                }

                if (KeyCache.TryGetValue(Current, out bool Exists) && Exists)
                    continue;

                TempRegistryKeys.Add(Current);
                DeletedRegistryKeys.Remove(Current);
                Hive Hive = GetHiveByNtPath(Current) ?? DefaultHive;
                if (Hive != null)
                    TempRegistryKeyHives[Current] = Hive;
                KeyCache[Current] = true;
            }
        }

        private void SetSyntheticRegistryStringTrusted(string NtPath, string ValueName, int Type, string Value, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            byte[] Data = Encoding.Unicode.GetBytes((Value ?? string.Empty) + "\0");
            SetSyntheticRegistryValueTrusted(NtPath, ValueName, Type, Data, KeyCache, DefaultHive);
        }

        private void SetSyntheticRegistryDwordTrusted(string NtPath, string ValueName, uint Value, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            byte[] Data = BitConverter.GetBytes(Value);
            SetSyntheticRegistryValueTrusted(NtPath, ValueName, 4, Data, KeyCache, DefaultHive);
        }

        private void SetSyntheticRegistryValueTrusted(string NtPath, string ValueName, int Type, byte[] Data, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            AddSyntheticRegistryKeyTrusted(NtPath, KeyCache, DefaultHive);

            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return;

            if (ValueName == null)
                ValueName = string.Empty;

            if (!TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values))
            {
                Values = new Dictionary<string, ValueNode>(StringComparer.OrdinalIgnoreCase);
                TempRegistryValues[NtPath] = Values;
            }

            Values[ValueName] = new ValueNode { Name = ValueName, Type = Type, Data = Data ?? Array.Empty<byte>() };

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
                DeletedValues.Remove(ValueName);
        }


        private void AddSyntheticDirectory(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return;

            string Normalized = Path.Replace('/', '\\').TrimEnd('\\');
            if (Normalized.Length == 2 && Normalized[1] == ':')
                Normalized += "\\";

            SyntheticDirectories.Add(Normalized);
        }

        public bool IsSyntheticDirectory(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Normalized = Path.Replace('/', '\\').TrimEnd('\\');
            if (Normalized.Length == 2 && Normalized[1] == ':')
                Normalized += "\\";

            if (SyntheticDirectories.Contains(Normalized))
                return true;

            return false;
        }

        private void SetSyntheticRegistryString(string NtPath, string ValueName, int Type, string Value, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            byte[] Data = Encoding.Unicode.GetBytes((Value ?? string.Empty) + "\0");
            SetSyntheticRegistryValue(NtPath, ValueName, Type, Data, KeyCache, DefaultHive);
        }

        private void SetSyntheticRegistryDword(string NtPath, string ValueName, uint Value, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            byte[] Data = BitConverter.GetBytes(Value);
            SetSyntheticRegistryValue(NtPath, ValueName, 4, Data, KeyCache, DefaultHive);
        }

        private void SetSyntheticRegistryValue(string NtPath, string ValueName, int Type, byte[] Data, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            AddSyntheticRegistryKey(NtPath, KeyCache, DefaultHive);

            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return;

            if (ValueName == null)
                ValueName = string.Empty;

            if (!TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values))
            {
                Values = new Dictionary<string, ValueNode>(StringComparer.OrdinalIgnoreCase);
                TempRegistryValues[NtPath] = Values;
            }

            Values[ValueName] = new ValueNode { Name = ValueName, Type = Type, Data = Data ?? Array.Empty<byte>() };

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
                DeletedValues.Remove(ValueName);
        }

        private void InitializeSyntheticKnownFolderDescriptions(string UserProfile, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            const string Root = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FolderDescriptions";
            AddSyntheticRegistryKeyTrusted(Root, KeyCache, DefaultHive);

            AddSyntheticKnownFolder(Root, "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Profile", string.Empty, UserProfile, 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", "Local AppData", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "AppData\\Local", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}", "Roaming AppData", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "AppData\\Roaming", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "Documents", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Documents", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Desktop", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{374DE290-123F-4565-9164-39C4925E467B}", "Downloads", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Downloads", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{33E28130-4E1E-4676-835A-98395C3BC3BB}", "Pictures", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Pictures", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{4BD8D571-6D19-48D3-BE97-422220080E43}", "Music", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Music", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}", "Videos", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Videos", 4, KeyCache, DefaultHive);
        }

        private void AddSyntheticKnownFolder(string Root, string Guid, string Name, string ParentFolder, string RelativePath, uint Category, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            string Key = Root + "\\" + Guid;
            AddSyntheticRegistryKeyTrusted(Key, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(Key, "Name", 1, Name, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(Key, "Category", Category, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(Key, "Attributes", 0x10, KeyCache, DefaultHive);
            SetSyntheticRegistryDwordTrusted(Key, "DefinitionFlags", 0, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(Key, "LocalizedName", 2, Name, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(Key, "Tooltip", 2, Name, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(Key, "Icon", 2, "%SystemRoot%\\system32\\imageres.dll,-3", KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(Key, "Security", 1, string.Empty, KeyCache, DefaultHive);

            if (!string.IsNullOrEmpty(ParentFolder))
                SetSyntheticRegistryStringTrusted(Key, "ParentFolder", 1, ParentFolder, KeyCache, DefaultHive);

            if (!string.IsNullOrEmpty(RelativePath))
                SetSyntheticRegistryStringTrusted(Key, "RelativePath", 1, RelativePath, KeyCache, DefaultHive);

            string PropertyBag = Key + "\\PropertyBag";
            AddSyntheticRegistryKeyTrusted(PropertyBag, KeyCache, DefaultHive);
            SetSyntheticRegistryStringTrusted(PropertyBag, "ThisPCPolicy", 1, "Show", KeyCache, DefaultHive);
        }

        private bool IsRegistryPathDeleted(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return true;

            NtPath = NormalizeKeyPath(NtPath);

            foreach (string DeletedKey in DeletedRegistryKeys)
            {
                if (NtPath.Equals(DeletedKey, StringComparison.OrdinalIgnoreCase) || NtPath.StartsWith(DeletedKey + "\\", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public bool RegistryKeyExists(string NtPath, out Hive Hive, out RegistryHiveReader.HiveKey Key, out bool TempOnly)
        {
            Hive = null;
            Key = default;
            TempOnly = false;

            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            if (IsRegistryPathDeleted(NtPath))
                return false;

            if (IsVirtualRegistryRoot(NtPath))
            {
                TempOnly = true;
                return true;
            }

            bool HasTempKey = TempRegistryKeys.Contains(NtPath);
            Hive = GetHiveByNtPath(NtPath);
            if (Hive == null)
            {
                if (!HasTempKey)
                    return false;

                TempOnly = true;
                TempRegistryKeyHives.TryGetValue(NtPath, out Hive TempHive);
                Hive = TempHive ?? RegHives.FirstOrDefault();
                return true;
            }

            if (HasTempKey)
            {
                TempOnly = true;
                TempRegistryKeyHives.TryGetValue(NtPath, out Hive TempHive);
                if (TempHive != null)
                    Hive = TempHive;
            }

            if (Hive.Reader != null)
            {
                string KeyPath = RegManager.NormalizeNtRegistryPath(Hive, NtPath);
                if (string.IsNullOrEmpty(KeyPath))
                    KeyPath = "\\";

                if (Hive.Reader.TryOpenPath(KeyPath, out Key))
                    return true;
            }

            return TempOnly;
        }

        private string GetRegistryParentPath(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return null;

            NtPath = NormalizeKeyPath(NtPath);
            int Index = NtPath.LastIndexOf('\\');
            if (Index <= 0)
                return null;

            return NtPath.Substring(0, Index);
        }

        private bool TryGetRegistryValues(WinRegKey RegKey, out List<ValueNode> Values)
        {
            Values = new List<ValueNode>();

            if (RegKey == null)
                return false;

            string NtPath = NormalizeNtRegistryPath(RegKey.FullPath);
            if (string.IsNullOrEmpty(NtPath) || IsRegistryPathDeleted(NtPath))
                return false;

            Dictionary<string, ValueNode> Merged = new(StringComparer.OrdinalIgnoreCase);

            if (RegKey.Hive != null && RegKey.Hive.Reader != null && RegKey.HasParsedKey)
            {
                for (int i = 0; RegKey.Hive.Reader.TryEnumerateValueFull(RegKey.ParsedKey, i, out string Name, out int Type, out byte[] Data); i++)
                {
                    if (Name == null)
                        Name = string.Empty;

                    Merged[Name] = new ValueNode { Name = Name, Type = Type, Data = Data ?? Array.Empty<byte>() };
                }
            }

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
            {
                foreach (string Name in DeletedValues)
                    Merged.Remove(Name);
            }

            if (TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> TempValues))
            {
                foreach (var Pair in TempValues)
                {
                    ValueNode Value = Pair.Value;
                    Merged[Pair.Key] = new ValueNode { Name = Value.Name, Type = Value.Type, Data = Value.Data == null ? Array.Empty<byte>() : (byte[])Value.Data.Clone() };
                }
            }

            Values = Merged.Values.OrderBy(v => v.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase).ToList();
            return true;
        }

        public bool TryEnumerateRegistrySubKey(WinRegKey RegKey, int Index, out string Name)
        {
            Name = null;

            if (RegKey == null || Index < 0)
                return false;

            string NtPath = NormalizeNtRegistryPath(RegKey.FullPath);
            if (string.IsNullOrEmpty(NtPath) || IsRegistryPathDeleted(NtPath))
                return false;

            List<string> Names = new List<string>();
            AddVirtualRegistrySubKeys(NtPath, Names);

            if (RegKey.Hive != null && RegKey.Hive.Reader != null && RegKey.HasParsedKey)
            {
                for (int i = 0; RegKey.Hive.Reader.TryEnumerateSubKey(RegKey.ParsedKey, i, out string SubKeyName); i++)
                {
                    string ChildFullPath = NormalizeKeyPath(NtPath + "\\" + SubKeyName);
                    if (!DeletedRegistryKeys.Contains(ChildFullPath))
                        Names.Add(SubKeyName);
                }
            }

            foreach (string TempKey in TempRegistryKeys)
            {
                if (DeletedRegistryKeys.Contains(TempKey))
                    continue;

                if (IsDirectRegistryChild(NtPath, TempKey, out string ChildName))
                    Names.Add(ChildName);
            }

            if (Index >= Names.Count)
                return false;

            Names.Sort(StringComparer.OrdinalIgnoreCase);
            Name = Names[Index];
            return true;
        }

        private bool IsDirectRegistryChild(string ParentPath, string ChildPath, out string ChildName)
        {
            ChildName = null;

            if (string.IsNullOrEmpty(ParentPath) || string.IsNullOrEmpty(ChildPath))
                return false;

            ParentPath = NormalizeKeyPath(ParentPath);
            ChildPath = NormalizeKeyPath(ChildPath);

            if (!ChildPath.StartsWith(ParentPath + "\\", StringComparison.OrdinalIgnoreCase))
                return false;

            string Rest = ChildPath.Substring(ParentPath.Length + 1);
            if (string.IsNullOrEmpty(Rest) || Rest.Contains("\\", StringComparison.Ordinal))
                return false;

            ChildName = Rest;
            return true;
        }

        private string GetRegistryKeyNameFromPath(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return string.Empty;

            NtPath = NormalizeKeyPath(NtPath);
            int Index = NtPath.LastIndexOf('\\');
            if (Index < 0 || Index == NtPath.Length - 1)
                return NtPath.Trim('\\');

            return NtPath.Substring(Index + 1);
        }

        public bool TryQueryRegistryKeyFullInfo(WinRegKey RegKey, out int SubKeyCount, out int ValueCount, out int MaxSubKeyNameChars, out int MaxValueNameChars, out int MaxValueDataBytes)
        {
            return TryQueryRegistryKeyFullInfo(RegKey, out SubKeyCount, out ValueCount, out MaxSubKeyNameChars, out MaxValueNameChars, out MaxValueDataBytes, out _);
        }

        public bool TryQueryRegistryKeyFullInfo(WinRegKey RegKey, out int SubKeyCount, out int ValueCount, out int MaxSubKeyNameChars, out int MaxValueNameChars, out int MaxValueDataBytes, out string Name)
        {
            SubKeyCount = 0;
            ValueCount = 0;
            MaxSubKeyNameChars = 0;
            MaxValueNameChars = 0;
            MaxValueDataBytes = 0;
            Name = null;

            if (!TryQueryRegistryKeyHeader(RegKey, out SubKeyCount, out ValueCount, out Name))
                return false;

            for (int i = 0; TryEnumerateRegistrySubKey(RegKey, i, out string SubKeyName); i++)
            {
                if (!string.IsNullOrEmpty(SubKeyName) && SubKeyName.Length > MaxSubKeyNameChars)
                    MaxSubKeyNameChars = SubKeyName.Length;
            }

            if (TryGetRegistryValues(RegKey, out List<ValueNode> Values))
            {
                foreach (ValueNode Value in Values)
                {
                    string ValueName = Value.Name ?? string.Empty;
                    int DataLength = Value.Data == null ? 0 : Value.Data.Length;
                    if (ValueName.Length > MaxValueNameChars)
                        MaxValueNameChars = ValueName.Length;
                    if (DataLength > MaxValueDataBytes)
                        MaxValueDataBytes = DataLength;
                }
            }

            return true;
        }

        public bool TryGetRegistryValue(WinRegKey RegKey, string ValueName, out ValueNode Value)
        {
            Value = null;

            if (RegKey == null)
                return false;

            string NtPath = NormalizeNtRegistryPath(RegKey.FullPath);
            if (string.IsNullOrEmpty(NtPath) || IsRegistryPathDeleted(NtPath))
                return false;

            if (ValueName == null)
                ValueName = string.Empty;

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues) && DeletedValues.Contains(ValueName))
                return false;

            if (TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values) && Values.TryGetValue(ValueName, out ValueNode TempValue))
            {
                Value = new ValueNode { Name = TempValue.Name, Type = TempValue.Type, Data = TempValue.Data == null ? Array.Empty<byte>() : (byte[])TempValue.Data.Clone() };
                return true;
            }

            if (RegKey.Hive != null && RegKey.Hive.Reader != null && RegKey.HasParsedKey)
                return RegKey.Hive.Reader.TryGetValue(RegKey.ParsedKey, ValueName, out Value);

            return false;
        }

        public bool TryQueryRegistryKeyHeader(WinRegKey RegKey, out int SubKeyCount, out int ValueCount, out string Name)
        {
            SubKeyCount = 0;
            ValueCount = 0;
            Name = null;

            if (RegKey == null)
                return false;

            string NtPath = NormalizeNtRegistryPath(RegKey.FullPath);
            if (string.IsNullOrEmpty(NtPath) || IsRegistryPathDeleted(NtPath))
                return false;

            Name = GetRegistryKeyNameFromPath(NtPath);
            if (string.IsNullOrEmpty(Name) && RegKey.Hive != null && RegKey.Hive.Reader != null && RegKey.HasParsedKey)
                RegKey.Hive.Reader.TryQueryKeyHeader(RegKey.ParsedKey, out _, out _, out Name);

            for (int i = 0; TryEnumerateRegistrySubKey(RegKey, i, out _); i++)
                SubKeyCount++;

            if (TryGetRegistryValues(RegKey, out List<ValueNode> Values))
                ValueCount = Values.Count;

            return true;
        }

        public bool TryEnumerateRegistryValueBasic(WinRegKey RegKey, int Index, out string ValueName, out int ValueType, out int DataLength)
        {
            ValueName = null;
            ValueType = 0;
            DataLength = 0;

            if (!TryGetRegistryValues(RegKey, out List<ValueNode> Values) || Index < 0 || Index >= Values.Count)
                return false;

            ValueNode Value = Values[Index];
            ValueName = Value.Name ?? string.Empty;
            ValueType = Value.Type;
            DataLength = Value.Data == null ? 0 : Value.Data.Length;
            return true;
        }

        public bool TryEnumerateRegistryValueFull(WinRegKey RegKey, int Index, out string ValueName, out int ValueType, out byte[] Data)
        {
            ValueName = null;
            ValueType = 0;
            Data = null;

            if (!TryGetRegistryValues(RegKey, out List<ValueNode> Values) || Index < 0 || Index >= Values.Count)
                return false;

            ValueNode Value = Values[Index];
            ValueName = Value.Name ?? string.Empty;
            ValueType = Value.Type;
            Data = Value.Data == null ? Array.Empty<byte>() : (byte[])Value.Data.Clone();
            return true;
        }

        public bool CreateRegistryKeyPath(string NtPath, out bool CreatedNew)
        {
            CreatedNew = false;

            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            string ParentPath = GetRegistryParentPath(NtPath);
            if (string.IsNullOrEmpty(ParentPath))
                return false;

            if (!RegistryKeyExists(ParentPath, out Hive ParentHive, out _, out _))
                return false;

            if (RegistryKeyExists(NtPath, out _, out _, out _))
                return true;

            TempRegistryKeys.Add(NtPath);
            DeletedRegistryKeys.Remove(NtPath);
            TempRegistryKeyHives[NtPath] = ParentHive;
            CreatedNew = true;
            CompleteRegistryNotifications(ParentPath, 0x00000001);
            return true;
        }

        public bool DeleteRegistryKeyPath(string NtPath)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            if (!RegistryKeyExists(NtPath, out _, out _, out _))
                return false;

            DeletedRegistryKeys.Add(NtPath);
            TempRegistryKeys.Remove(NtPath);
            TempRegistryValues.Remove(NtPath);
            DeletedRegistryValues.Remove(NtPath);
            TempRegistryKeyHives.Remove(NtPath);

            List<string> TempChildren = TempRegistryKeys.Where(x => x.StartsWith(NtPath + "\\", StringComparison.OrdinalIgnoreCase)).ToList();
            foreach (string Child in TempChildren)
            {
                TempRegistryKeys.Remove(Child);
                TempRegistryValues.Remove(Child);
                DeletedRegistryValues.Remove(Child);
                TempRegistryKeyHives.Remove(Child);
                DeletedRegistryKeys.Add(Child);
            }

            string ParentPath = GetRegistryParentPath(NtPath);
            CompleteRegistryNotifications(!string.IsNullOrEmpty(ParentPath) ? ParentPath : NtPath, 0x00000001);
            return true;
        }

        public bool SetRegistryValue(string NtPath, string ValueName, int Type, byte[] Data)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            if (!RegistryKeyExists(NtPath, out _, out _, out _))
                return false;

            if (ValueName == null)
                ValueName = string.Empty;

            if (!TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values))
            {
                Values = new Dictionary<string, ValueNode>(StringComparer.OrdinalIgnoreCase);
                TempRegistryValues[NtPath] = Values;
            }

            Values[ValueName] = new ValueNode { Name = ValueName, Type = Type, Data = Data ?? Array.Empty<byte>() };

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
                DeletedValues.Remove(ValueName);

            CompleteRegistryNotifications(NtPath, 0x00000004);
            return true;
        }

        public bool DeleteRegistryValue(string NtPath, string ValueName)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            if (!RegistryKeyExists(NtPath, out Hive Hive, out RegistryHiveReader.HiveKey Key, out bool TempOnly))
                return false;

            if (ValueName == null)
                ValueName = string.Empty;

            bool Exists = false;

            if (TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values) && Values.ContainsKey(ValueName))
                Exists = true;

            if (!Exists && Hive != null && Hive.Reader != null && !TempOnly)
                Exists = Hive.Reader.TryGetValue(Key, ValueName, out _);

            if (!Exists)
                return false;

            if (TempRegistryValues.TryGetValue(NtPath, out Values))
                Values.Remove(ValueName);

            if (!DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
            {
                DeletedValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                DeletedRegistryValues[NtPath] = DeletedValues;
            }

            DeletedValues.Add(ValueName);
            CompleteRegistryNotifications(NtPath, 0x00000004);
            return true;
        }

        public void RegisterRegistryNotification(WinRegistryNotification Notification)
        {
            if (Notification == null || string.IsNullOrEmpty(Notification.KeyPath))
                return;

            Notification.KeyPath = NormalizeNtRegistryPath(Notification.KeyPath);
            RegistryNotifications.Add(Notification);
        }

        private bool RegistryNotificationMatches(WinRegistryNotification Notification, string ChangedPath, uint ChangeFilter)
        {
            if (Notification == null || string.IsNullOrEmpty(Notification.KeyPath) || string.IsNullOrEmpty(ChangedPath))
                return false;

            if ((Notification.CompletionFilter & ChangeFilter) == 0)
                return false;

            string NotifyPath = NormalizeNtRegistryPath(Notification.KeyPath);
            ChangedPath = NormalizeNtRegistryPath(ChangedPath);

            if (ChangedPath.Equals(NotifyPath, StringComparison.OrdinalIgnoreCase))
                return true;

            return Notification.WatchTree && ChangedPath.StartsWith(NotifyPath + "\\", StringComparison.OrdinalIgnoreCase);
        }

        public void CompleteRegistryNotifications(string ChangedPath, uint ChangeFilter)
        {
            if (RegistryNotifications.Count == 0)
                return;

            List<WinRegistryNotification> Completed = RegistryNotifications
                .Where(Notification => RegistryNotificationMatches(Notification, ChangedPath, ChangeFilter))
                .ToList();

            foreach (WinRegistryNotification Notification in Completed)
            {
                if (Notification.IoStatusBlock != 0 && Emulator.IsRegionMapped(Notification.IoStatusBlock, 0x10))
                    WriteIoStatusBlock(Emulator, Notification.IoStatusBlock, NTSTATUS.STATUS_SUCCESS, 0);

                if (Notification.EventHandle != 0)
                {
                    WinEvent Event = GetEventByHandle(Notification.EventHandle, AccessMask.GiveTemp);
                    if (Event != null)
                        Event.Signaled = true;
                }
                else if (Notification.KeyHandle != 0)
                {
                    WinRegKey Key = HandleManager.GetObjectByHandle<WinRegKey>(Notification.KeyHandle);
                    if (Key != null)
                        Key.NotifySignaled = true;
                }

                RegistryNotifications.Remove(Notification);
            }
        }

        public WinHandle OpenRegistryKey(string NtPath, AccessMask Permissions)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return null;

            if (!RegistryKeyExists(NtPath, out Hive Hive, out RegistryHiveReader.HiveKey Key, out bool TempOnly))
                return null;

            WinRegKey RegKey = new WinRegKey
            {
                FullPath = NtPath,
                Hive = Hive,
                Key = null,
                ParsedKey = Key,
                HasParsedKey = !TempOnly && Hive != null && Hive.Reader != null
            };

            WinHandle Handle = HandleManager.AddHandle(RegKey, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinHandle CreateEventHandle(string Name, uint EventType, bool InitialState, AccessMask Permissions)
        {
            if (string.IsNullOrEmpty(Name))
                Name = "Event_" + GenerateRandomPID().ToString();

            WinEvent Ev = WinEvents.FirstOrDefault(e => e.Name.Equals(Name, StringComparison.OrdinalIgnoreCase));
            if (Ev == null)
            {
                Ev = new WinEvent { Name = Name, Signaled = InitialState, EventType = EventType };
                WinEvents.Add(Ev);
            }

            WinHandle Handle = HandleManager.AddHandle(Ev, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinHandle CreateTimerHandle(string Name, TIMER_TYPE TimerType, AccessMask Permissions)
        {
            if (string.IsNullOrEmpty(Name))
                Name = "Timer_" + GenerateRandomPID().ToString();

            WinTimer Timer = null;
            List<ulong> ExistingHandles = HandleManager.GetHandlesByObjectId(Name);
            for (int i = 0; i < ExistingHandles.Count; i++)
            {
                Timer = HandleManager.GetObjectByHandle<WinTimer>(ExistingHandles[i]);
                if (Timer != null)
                    break;
            }

            if (Timer == null)
            {
                Timer = new WinTimer
                {
                    Name = Name,
                    TimerType = TimerType,
                    Signaled = false,
                    Active = false
                };
            }

            WinHandle Handle = HandleManager.AddHandle(Timer, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinTimer? GetTimerByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.TimerHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinTimer>(Handle);
        }

        public WinEvent? GetEventByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.EventHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinEvent>(Handle);
        }

        public WinHandle CreateJobHandle(string Name, AccessMask Permissions)
        {
            if (string.IsNullOrEmpty(Name))
                Name = "Job_" + GenerateRandomPID().ToString();

            WinJob Job = WinJobs.FirstOrDefault(j => j.Name.Equals(Name, StringComparison.OrdinalIgnoreCase));
            if (Job == null)
            {
                Job = new WinJob { Name = Name };
                WinJobs.Add(Job);
            }

            WinHandle Handle = HandleManager.AddHandle(Job, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinJob? GetJobByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.JobHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinJob>(Handle);
        }

        public bool IsProcessInJob(ulong ProcessHandle, ulong JobHandle)
        {
            WinProcess Process = null;

            if (HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle) || ProcessHandle == uint.MaxValue)
                Process = WinProcesses.FirstOrDefault(p => p.PID == PID);
            else
                Process = GetProcessByHandle(ProcessHandle, AccessMask.GiveTemp);

            if (Process == null)
                return false;

            if (JobHandle == 0)
                return Process.JobObjectHandle != 0;

            WinJob Job = GetJobByHandle(JobHandle, AccessMask.GiveTemp);
            if (Job == null)
                return false;

            return Process.JobObjectHandle == JobHandle || Job.ProcessIds.Contains(Process.PID);
        }

        public NTSTATUS AssignProcessToJobHandle(ulong JobHandle, ulong ProcessHandle)
        {
            WinJob Job = GetJobByHandle(JobHandle, AccessMask.GiveTemp);
            if (Job == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinProcess Process;

            if (HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle) || ProcessHandle == uint.MaxValue)
                Process = WinProcesses.FirstOrDefault(p => p.PID == PID);
            else
                Process = GetProcessByHandle(ProcessHandle, AccessMask.GiveTemp);

            if (Process == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Process.JobObjectHandle != 0 && Process.JobObjectHandle != JobHandle)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Process.JobObjectHandle = JobHandle;

            if (!Job.ProcessIds.Contains(Process.PID))
                Job.ProcessIds.Add(Process.PID);

            return NTSTATUS.STATUS_SUCCESS;
        }

        public WinHandle CreateSemaphoreHandle(string Name, int InitialCount, int MaximumCount, AccessMask Permissions)
        {
            if (string.IsNullOrEmpty(Name))
                Name = "Semaphore_" + GenerateRandomPID().ToString();

            WinSemaphore Semaphore = WinSemaphores.FirstOrDefault(s => s.Name.Equals(Name, StringComparison.OrdinalIgnoreCase));
            if (Semaphore == null)
            {
                Semaphore = new WinSemaphore { Name = Name, CurrentCount = InitialCount, MaximumCount = MaximumCount };
                WinSemaphores.Add(Semaphore);
            }

            WinHandle Handle = HandleManager.AddHandle(Semaphore, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinSemaphore? GetSemaphoreByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.SemaphoreHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinSemaphore>(Handle);
        }

        public WinHandle CreateSectionHandle(string Name, ulong Size, uint Protection, uint Attributes, string Path, ulong BackingAddress, AccessMask Permissions)
        {
            if (string.IsNullOrEmpty(Name))
                Name = "Section_" + GenerateRandomPID().ToString();

            WinSection Sec = new WinSection
            {
                Name = Name,
                Size = Size,
                Protection = Protection,
                Attributes = Attributes,
                Path = Path,
                FileStream = string.IsNullOrEmpty(Path) ? null : WindowsFileStream.FromGuestPath(Path),
                BackingAddress = BackingAddress
            };

            if (Sec.IsImage && !string.IsNullOrEmpty(Path))
                AttachImageSectionIdentity(Sec, Path);

            WinSections.Add(Sec);

            WinHandle Handle = HandleManager.AddHandle(Sec, Permissions);
            AddWinHandle(Handle);
            return Handle;
        }

        public WinSection? GetSectionByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.SectionHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinSection>(Handle);
        }

        public void CloseHandle(ulong Handle)
        {
            if (HandleManager.TryGetHandle(Handle, out HandleEntry Entry))
            {
                if (Entry.Object != null && Entry.Object.ObjectType == HandleType.FileHandle)
                {
                    WinFile Closing = Entry.Object as WinFile;
                    if (Closing != null && Closing.DeletePending && !Closing.Device && !string.IsNullOrEmpty(Closing.Path))
                    {
                        List<ulong> HandlesForObject = HandleManager.GetHandlesByObjectId(Closing.ObjectId);
                        HandlesForObject.Remove(Handle);
                        if (HandlesForObject.Count == 0)
                            ApplyDeleteOnClose(Closing);
                    }
                }
            }

            if (HandleManager.TryRemoveHandle(Handle, out _))
            {
                RemoveWinHandle(Handle);
            }
        }

        private void ApplyDeleteOnClose(WinFile Target)
        {
            try
            {
                Target.FileStream = null;
                string VirtualPath = GeneralHelper.IO.ResolveVirtualHostPath(Target.Path, BinaryFormat.PE);
                if (string.IsNullOrEmpty(VirtualPath))
                    return;

                if (Target.Directory)
                {
                    if (Directory.Exists(VirtualPath))
                        Directory.Delete(VirtualPath, false);
                }
                else if (File.Exists(VirtualPath))
                {
                    File.Delete(VirtualPath);
                }

                WindowsFileStream.InvalidateGuestPathCache();
                if ((Emulator.Settings.Flags & LogFlags.Syscall) != 0)
                    Emulator.TriggerEventMessage($"[+] delete-on-close removed \"{Target.Path}\".", LogFlags.Syscall);
            }
            catch (Exception Ex)
            {
                if ((Emulator.Settings.Flags & LogFlags.Syscall) != 0)
                    Emulator.TriggerEventMessage($"[!] delete-on-close failed for \"{Target.Path}\": {Ex.Message}", LogFlags.Syscall);
            }
        }
    }
}
