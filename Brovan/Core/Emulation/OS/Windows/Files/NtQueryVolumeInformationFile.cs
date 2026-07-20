using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryVolumeInformationFile : IWinSyscall
    {
        // FS_INFORMATION_CLASS
        private const uint FileFsVolumeInformation = 1;
        private const uint FileFsSizeInformation = 3;
        private const uint FileFsDeviceInformation = 4;
        private const uint FileFsAttributeInformation = 5;

        private const uint FileFsVolumeInformationFixedSize = 0x18;
        private const uint FileFsVolumeInformationLabelOffset = 0x12;

        private const uint FILE_DEVICE_DISK = 0x00000007;
        private const uint FILE_DEVICE_CONSOLE = 0x00000050;
        private const uint FILE_CASE_SENSITIVE_SEARCH = 0x00000001;
        private const uint FILE_CASE_PRESERVED_NAMES = 0x00000002;
        private const uint FILE_UNICODE_ON_DISK = 0x00000004;
        private const uint FILE_PERSISTENT_ACLS = 0x00000008;
        private const uint SyntheticVolumeSerial = (uint)WindowsStorageDeviceSupport.VolumeSerialNumber;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return Handle64(Instance);

            return Handle32(Instance);
        }

        private static NTSTATUS Handle64(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(1);
            ulong FsInfoBuffer = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);
            uint FsInfoClass = (uint)Instance.WinHelper.GetArg64(4);

            return QueryVolumeInformation(Instance, FileHandle, IoStatusBlockPtr, FsInfoBuffer, Length, FsInfoClass, true);
        }

        private static NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint FileHandle = Instance.WinHelper.GetArg32(0);
            uint IoStatusBlockPtr = Instance.WinHelper.GetArg32(1);
            uint FsInfoBuffer = Instance.WinHelper.GetArg32(2);
            uint Length = Instance.WinHelper.GetArg32(3);
            uint FsInfoClass = Instance.WinHelper.GetArg32(4);

            return QueryVolumeInformation(Instance, FileHandle, IoStatusBlockPtr, FsInfoBuffer, Length, FsInfoClass, false);
        }

        private static NTSTATUS QueryVolumeInformation(BinaryEmulator Instance, ulong FileHandle, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length, uint FsInfoClass, bool Is64Bit)
        {
            if (IoStatusBlockPtr == 0 || FsInfoBuffer == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, Is64Bit ? 0x10UL : 0x08UL))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(FsInfoBuffer, Math.Max(Length, 1u)))
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0, Is64Bit);

            WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (FileObj == null)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0, Is64Bit);
            }


            return FsInfoClass switch
            {
                FileFsVolumeInformation => QueryVolumeLabelInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length, Is64Bit),
                FileFsSizeInformation => QuerySizeInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length, Is64Bit),
                FileFsDeviceInformation => QueryDeviceInformation(Instance, FileHandle, FileObj, IoStatusBlockPtr, FsInfoBuffer, Length, Is64Bit),
                FileFsAttributeInformation => QueryAttributeInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length, Is64Bit),
                _ => WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_INFO_CLASS, 0, Is64Bit)
            };
        }

        private static NTSTATUS QueryVolumeLabelInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length, bool Is64Bit)
        {
            const string VolumeLabel = "Brovan";
            int LabelBytes = System.Text.Encoding.Unicode.GetByteCount(VolumeLabel);

            if (Length < FileFsVolumeInformationFixedSize)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0, Is64Bit);
            }

            Span<byte> LabelBuffer = LabelBytes == 0 ? Span<byte>.Empty : Instance.WinHelper.Shared.GetSpan((uint)LabelBytes);
            if (LabelBytes != 0)
                System.Text.Encoding.Unicode.GetBytes(VolumeLabel.AsSpan(), LabelBuffer);

            Instance._emulator.WriteMemory(FsInfoBuffer + 0x00, 0UL, 8);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x08, SyntheticVolumeSerial, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x0C, (uint)LabelBytes, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x10, (byte)0, 1);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x11, (byte)0, 1);

            uint WritableLabelBytes = Length > FileFsVolumeInformationLabelOffset ? Length - FileFsVolumeInformationLabelOffset : 0;
            uint LabelBytesToWrite = Math.Min((uint)LabelBytes, WritableLabelBytes);
            if (LabelBytesToWrite != 0)
                Instance._emulator.WriteMemory(FsInfoBuffer + FileFsVolumeInformationLabelOffset, LabelBuffer, LabelBytesToWrite);

            ulong BytesWritten = FileFsVolumeInformationLabelOffset + LabelBytesToWrite;
            if (LabelBytesToWrite < (uint)LabelBytes)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_OVERFLOW, BytesWritten, Is64Bit);
            }

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, BytesWritten, Is64Bit);
        }

        private static NTSTATUS QuerySizeInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length, bool Is64Bit)
        {
            const uint RequiredSize = 24;
            if (Length < RequiredSize)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_TOO_SMALL, 0, Is64Bit);
            }

            Instance._emulator.WriteMemory(FsInfoBuffer + 0x00, WindowsStorageDeviceSupport.TotalClusters, 8);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x08, WindowsStorageDeviceSupport.FreeClusters, 8);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x10, (uint)WindowsStorageDeviceSupport.SectorsPerCluster, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x14, (uint)WindowsStorageDeviceSupport.BytesPerSector, 4);

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize, Is64Bit);
        }

        private static NTSTATUS QueryDeviceInformation(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length, bool Is64Bit)
        {
            const uint RequiredSize = 8;
            if (Length < RequiredSize)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_TOO_SMALL, 0, Is64Bit);
            }

            uint DeviceType = IsConsoleHandle(Instance, FileHandle, FileObj) ? FILE_DEVICE_CONSOLE : FILE_DEVICE_DISK;

            Instance._emulator.WriteMemory(FsInfoBuffer + 0x0, DeviceType);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x4, 0u);

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize, Is64Bit);
        }

        private static NTSTATUS QueryAttributeInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length, bool Is64Bit)
        {
            const string FileSystemName = "NTFS";
            int NameBytes = System.Text.Encoding.Unicode.GetByteCount(FileSystemName);
            ulong RequiredSize = 0x0CUL + (ulong)NameBytes;

            if (Length < RequiredSize)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredSize, Is64Bit);
            }

            uint Attributes = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS;
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x00, Attributes, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x04, 255u, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x08, (uint)NameBytes, 4);

            if (NameBytes != 0)
            {
                Span<byte> NameBuffer = Instance.WinHelper.Shared.GetSpan((uint)NameBytes);
                System.Text.Encoding.Unicode.GetBytes(FileSystemName.AsSpan(), NameBuffer);
                Instance._emulator.WriteMemory(FsInfoBuffer + 0x0C, NameBuffer, (uint)NameBytes);
            }

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize, Is64Bit);
        }

        private static NTSTATUS WriteStatusBlock(BinaryEmulator Instance, ulong IoStatusBlockPtr, NTSTATUS Status, ulong Information, bool Is64Bit)
        {
            if (Is64Bit)
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, Information);
            else
                Instance.WinHelper.WriteIoStatusBlock(Instance, (uint)IoStatusBlockPtr, Status, (uint)Information);

            return Status;
        }

        private static bool IsConsoleHandle(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj)
        {
            if (Instance.WinHelper.STD_OUT != null && FileHandle == Instance.WinHelper.STD_OUT.Handle)
                return true;

            if (Instance.WinHelper.STD_IN != null && FileHandle == Instance.WinHelper.STD_IN.Handle)
                return true;

            if (Instance.WinHelper.ConsoleHandle != null && FileHandle == Instance.WinHelper.ConsoleHandle.Handle)
                return true;

            return FileObj.Device && string.Equals(FileObj.Path, "\\Device\\ConDrv", System.StringComparison.OrdinalIgnoreCase);
        }
    }
}
