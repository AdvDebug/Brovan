using System;
using System.Buffers.Binary;
using Brovan;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryAttributesFile : IWinSyscall
    {

        // FILE_BASIC_INFORMATION is 0x28 on x64 (40 bytes).
        private const uint FileBasicInformationSize = 0x28;

        // FILE_NETWORK_OPEN_INFORMATION is 0x38 on both x64 and x86.
        private const uint FileNetworkOpenInformationSize = 0x38;

        public NTSTATUS Handle(BinaryEmulator Instance) => Query(Instance, NetworkOpen: false);

        internal static NTSTATUS Query(BinaryEmulator Instance, bool NetworkOpen)
        {
            string SyscallName = NetworkOpen ? nameof(NtQueryFullAttributesFile) : nameof(NtQueryAttributesFile);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(0);
            ulong FileInformationPtr = Instance.WinHelper.GetArg(1);

            if (ObjectAttributesPtr == 0 || FileInformationPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(FileInformationPtr, NetworkOpen ? FileNetworkOpenInformationSize : FileBasicInformationSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out ulong AttributesRoot, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            string EmulatedPath = Instance.WinHelper.ResolveWindowsFilePath(FullName, AttributesRoot);
            if (string.IsNullOrEmpty(EmulatedPath))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            using WindowsFileStream Stream = WindowsFileStream.FromGuestPath(EmulatedPath);
            string HostPath = Stream.WriteHostPath;
            bool Found = TryGetLayerAttributes(HostPath, out FileInfo Info, out FileAttributes Attributes);
            if (!Found)
            {
                if (string.IsNullOrEmpty(Stream.ReadHostPath))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                if (!string.Equals(Stream.ReadHostPath, HostPath, StringComparison.Ordinal))
                {
                    HostPath = Stream.ReadHostPath;
                    Found = TryGetLayerAttributes(HostPath, out Info, out Attributes);
                }
            }

            if (!Found)
            {

                if (!Instance.WinHelper.IsSyntheticDirectory(EmulatedPath))
                {
                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[!] {SyscallName}: file not found: Name=\"{Name}\", FullName=\"{FullName}\", SyntheticDir=\"{EmulatedPath}\".", LogFlags.Syscall);
                    return NtCreateFile.ParentDirectoryExists(EmulatedPath)
                        ? NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND
                        : NTSTATUS.STATUS_OBJECT_PATH_NOT_FOUND;
                }

                long Now = DateTime.UtcNow.ToFileTimeUtc();
                if (!WriteInformation(Instance, FileInformationPtr, NetworkOpen, Now, Now, Now, 0, FileAttributes.Directory))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] {SyscallName}: Name=\"{Name}\", FullName=\"{FullName}\", SyntheticDir=\"{EmulatedPath}\".", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong EndOfFile = 0;
            if (NetworkOpen)
            {
                if ((Attributes & FileAttributes.Directory) == 0)
                    EndOfFile = (ulong)Math.Max(Info.Length, 0);

                if (Attributes == 0)
                    Attributes = FileAttributes.Normal;
            }

            if (!WriteInformation(Instance, FileInformationPtr, NetworkOpen, Info.CreationTimeUtc.ToFileTimeUtc(), Info.LastAccessTimeUtc.ToFileTimeUtc(),
                Info.LastWriteTimeUtc.ToFileTimeUtc(), EndOfFile, Attributes))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] {SyscallName}: Name=\"{Name}\", FullName=\"{FullName}\", HostPath=\"{HostPath}\".", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryGetLayerAttributes(string HostPath, out FileInfo Info, out FileAttributes Attributes)
        {
            Info = null;
            Attributes = 0;
            if (string.IsNullOrEmpty(HostPath))
                return false;

            Info = new FileInfo(HostPath);
            return GeneralHelper.IO.TryGetHostAttributes(Info, out Attributes);
        }

        private static bool WriteInformation(BinaryEmulator Instance, ulong FileInformationPtr, bool NetworkOpen, long CreationTime, long LastAccessTime,
            long LastWriteTime, ulong EndOfFile, FileAttributes Attributes)
        {
            Span<byte> Buffer = stackalloc byte[(int)FileNetworkOpenInformationSize];
            BinaryPrimitives.WriteInt64LittleEndian(Buffer, CreationTime);
            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x08), LastAccessTime);
            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x10), LastWriteTime);
            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x18), LastWriteTime);

            if (!NetworkOpen)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x20), (uint)Attributes);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x24), 0);
                return Instance.WriteMemory(FileInformationPtr, Buffer.Slice(0, (int)FileBasicInformationSize));
            }

            ulong AllocationSize = EndOfFile == 0 ? 0UL : (EndOfFile + 0xFFF) & ~0xFFFUL;
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x20), AllocationSize);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x28), EndOfFile);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x30), (uint)Attributes);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x34), 0);
            return Instance.WriteMemory(FileInformationPtr, Buffer);
        }

    }
}
