using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryVolumeInformationFile : IWinSyscall
    {
        // FS_INFORMATION_CLASS
        private const uint FileFsVolumeInformation = 1;
        private const uint FileFsSizeInformation = 3;
        internal const uint FileFsDeviceInformation = 4;
        private const uint FileFsAttributeInformation = 5;
        private const uint FileFsFullSizeInformation = 7;
        private const uint FileFsObjectIdInformation = 8;
        private const uint FileFsSectorSizeInformation = 11;

        private const uint FileFsVolumeInformationFixedSize = 0x18;
        private const uint FileFsVolumeInformationLabelOffset = 0x12;

        private const uint FILE_DEVICE_DISK = 0x00000007;
        private const uint FILE_DEVICE_CONSOLE = 0x00000050;
        private const uint FILE_DEVICE_NAMED_PIPE = 0x00000011;
        internal const uint FILE_DEVICE_NULL = 0x00000015;
        private const uint FILE_DEVICE_SECURE_OPEN = 0x00000100;
        private const uint FILE_CASE_SENSITIVE_SEARCH = 0x00000001;
        private const uint FILE_CASE_PRESERVED_NAMES = 0x00000002;
        private const uint FILE_UNICODE_ON_DISK = 0x00000004;
        private const uint FILE_PERSISTENT_ACLS = 0x00000008;
        private const uint SyntheticVolumeSerial = (uint)WindowsStorageDeviceSupport.VolumeSerialNumber;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(1);
            ulong FsInfoBuffer = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);
            uint FsInfoClass = (uint)Instance.WinHelper.GetArg(4);

            if (IoStatusBlockPtr == 0 || FsInfoBuffer == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.ProbeIoStatusBlock(IoStatusBlockPtr))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(FsInfoBuffer, Math.Max(Length, 1u)))
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);

            NTSTATUS Reference = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out WinFile FileObj);
            if (Reference != NTSTATUS.STATUS_SUCCESS)
                return Reference;

            return FsInfoClass switch
            {
                FileFsVolumeInformation => QueryVolumeLabelInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length),
                FileFsSizeInformation => QuerySizeInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length),
                FileFsDeviceInformation => QueryDeviceInformation(Instance, FileObj, IoStatusBlockPtr, FsInfoBuffer, Length),
                FileFsAttributeInformation => QueryAttributeInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length),
                FileFsFullSizeInformation => QueryFullSizeInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length),
                FileFsObjectIdInformation => QueryObjectIdInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length),
                FileFsSectorSizeInformation => QuerySectorSizeInformation(Instance, IoStatusBlockPtr, FsInfoBuffer, Length),
                _ => WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_INFO_CLASS, 0)
            };
        }

        private static NTSTATUS QueryVolumeLabelInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length)
        {
            const string VolumeLabel = "Brovan";
            int LabelBytes = System.Text.Encoding.Unicode.GetByteCount(VolumeLabel);

            if (Length < FileFsVolumeInformationFixedSize)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
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
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_OVERFLOW, BytesWritten);
            }

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, BytesWritten);
        }

        private static NTSTATUS QuerySizeInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length)
        {
            const uint RequiredSize = 24;
            if (Length < RequiredSize)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_TOO_SMALL, 0);
            }

            Instance._emulator.WriteMemory(FsInfoBuffer + 0x00, WindowsStorageDeviceSupport.TotalClusters, 8);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x08, WindowsStorageDeviceSupport.FreeClusters, 8);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x10, (uint)WindowsStorageDeviceSupport.SectorsPerCluster, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x14, (uint)WindowsStorageDeviceSupport.BytesPerSector, 4);

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize);
        }

        // No quota, so the caller available count is the free count.
        private static NTSTATUS QueryFullSizeInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length)
        {
            const uint RequiredSize = 32;
            if (Length < RequiredSize)
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_TOO_SMALL, 0);

            Instance._emulator.WriteMemory(FsInfoBuffer + 0x00, WindowsStorageDeviceSupport.TotalClusters, 8);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x08, WindowsStorageDeviceSupport.FreeClusters, 8);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x10, WindowsStorageDeviceSupport.FreeClusters, 8);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x18, (uint)WindowsStorageDeviceSupport.SectorsPerCluster, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x1C, (uint)WindowsStorageDeviceSupport.BytesPerSector, 4);

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize);
        }

        private static NTSTATUS QueryObjectIdInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length)
        {
            const uint RequiredSize = 64;
            if (Length < RequiredSize)
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_TOO_SMALL, 0);

            Span<byte> ObjectId = stackalloc byte[16];
            if (!Guid.TryParse(Instance.WinHelper.SyntheticVolumeGuid, out Guid VolumeId))
                VolumeId = Guid.Empty;
            VolumeId.TryWriteBytes(ObjectId);

            Instance._emulator.WriteMemory(FsInfoBuffer, ObjectId);
            Instance.WinHelper.WriteZeroMemory(FsInfoBuffer + 0x10, 48);

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize);
        }

        private static NTSTATUS QuerySectorSizeInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length)
        {
            const uint RequiredSize = 28;
            const uint AlignedDeviceAndPartition = 0x00000003;
            if (Length < RequiredSize)
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_TOO_SMALL, 0);

            uint SectorSize = (uint)WindowsStorageDeviceSupport.BytesPerSector;

            Instance._emulator.WriteMemory(FsInfoBuffer + 0x00, SectorSize, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x04, SectorSize, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x08, SectorSize, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x0C, SectorSize, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x10, AlignedDeviceAndPartition, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x14, 0u, 4);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x18, 0u, 4);

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize);
        }

        private static NTSTATUS QueryDeviceInformation(BinaryEmulator Instance, WinFile FileObj, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length)
        {
            const uint RequiredSize = 8;
            if (Length < RequiredSize)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_TOO_SMALL, 0);
            }

            uint DeviceType = FILE_DEVICE_DISK;
            uint Characteristics = 0;
            if (IsConsoleHandle(FileObj))
                DeviceType = FILE_DEVICE_CONSOLE;
            else if (FileObj.Device && FileObj.Path != null && FileObj.Path.StartsWith("\\Device\\NamedPipe", System.StringComparison.OrdinalIgnoreCase))
                DeviceType = FILE_DEVICE_NAMED_PIPE;
            else if (FileObj.IsNullDevice)
            {
                DeviceType = FILE_DEVICE_NULL;
                Characteristics = FILE_DEVICE_SECURE_OPEN;
            }

            Instance._emulator.WriteMemory(FsInfoBuffer + 0x0, DeviceType);
            Instance._emulator.WriteMemory(FsInfoBuffer + 0x4, Characteristics);

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize);
        }

        private static NTSTATUS QueryAttributeInformation(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong FsInfoBuffer, uint Length)
        {
            const string FileSystemName = "NTFS";
            int NameBytes = System.Text.Encoding.Unicode.GetByteCount(FileSystemName);
            ulong RequiredSize = 0x0CUL + (ulong)NameBytes;

            if (Length < RequiredSize)
            {
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredSize);
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

            return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, RequiredSize);
        }

        private static NTSTATUS WriteStatusBlock(BinaryEmulator Instance, ulong IoStatusBlockPtr, NTSTATUS Status, ulong Information)
        {
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, Information);
            return Status;
        }

        private static bool IsConsoleHandle(WinFile FileObj)
        {
            if (FileObj.ConsoleKind != ConsoleObjectKind.None)
                return true;

            return FileObj.Device && FileObj.Path != null && FileObj.Path.StartsWith("\\Device\\ConDrv", System.StringComparison.OrdinalIgnoreCase);
        }
    }
}
