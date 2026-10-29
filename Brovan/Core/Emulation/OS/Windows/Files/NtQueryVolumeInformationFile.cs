using System.Buffers.Binary;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryVolumeInformationFile : IWinSyscall
    {
        private const uint FileFsVolumeInformation = 1;
        private const uint FileFsSizeInformation = 3;
        internal const uint FileFsDeviceInformation = 4;
        private const uint FileFsAttributeInformation = 5;
        private const uint FileFsFullSizeInformation = 7;
        private const uint FileFsObjectIdInformation = 8;
        private const uint FileFsSectorSizeInformation = 11;

        internal const int MaximumInformationClass = (int)FileFsSectorSizeInformation;
        internal const int MaximumInformationBytes = 64;

        private const uint FILE_DEVICE_DISK = 0x00000007;
        private const uint FILE_DEVICE_CONSOLE = 0x00000050;
        private const uint FILE_DEVICE_NAMED_PIPE = 0x00000011;
        internal const uint FILE_DEVICE_NULL = 0x00000015;
        private const uint FILE_DEVICE_SECURE_OPEN = 0x00000100;
        private const uint FILE_CASE_SENSITIVE_SEARCH = 0x00000001;
        private const uint FILE_CASE_PRESERVED_NAMES = 0x00000002;
        private const uint FILE_UNICODE_ON_DISK = 0x00000004;
        private const uint FILE_PERSISTENT_ACLS = 0x00000008;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(1);
            ulong FsInfoBuffer = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);
            uint FsInfoClass = (uint)Instance.WinHelper.GetArg(4);

            if (IoStatusBlockPtr == 0 || FsInfoBuffer == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryProbeIoStatusBlock(IoStatusBlockPtr, out NTSTATUS ProbeStatus))
                return ProbeStatus;

            NTSTATUS BufferStatus = Instance.WinHelper.ProbeForWrite(FsInfoBuffer, Math.Max(Length, 1u));
            if (BufferStatus != NTSTATUS.STATUS_SUCCESS)
                return BufferStatus;

            NTSTATUS Reference = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out WinFile FileObj);
            if (Reference != NTSTATUS.STATUS_SUCCESS)
                return Reference;

            Span<byte> Data = stackalloc byte[MaximumInformationBytes];
            int Required = BuildInformation(Instance, FileObj, FsInfoClass, Data);
            if (Required == 0)
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_INFO_CLASS, 0);

            uint Minimum = FsInfoClass == FileFsVolumeInformation ? 0x18u : (uint)Required;
            if (Length < Minimum)
            {
                NTSTATUS Status = FsInfoClass == FileFsVolumeInformation ? NTSTATUS.STATUS_INFO_LENGTH_MISMATCH
                    : FsInfoClass == FileFsAttributeInformation ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                return WriteStatusBlock(Instance, IoStatusBlockPtr, Status, FsInfoClass == FileFsAttributeInformation ? (ulong)Required : 0);
            }

            uint Written = Math.Min(Length, (uint)Required);
            if (!Instance.WriteMemory(FsInfoBuffer, Data.Slice(0, (int)Written)))
                return WriteStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);

            NTSTATUS Result = Written < Required ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_SUCCESS;
            Result = WriteStatusBlock(Instance, IoStatusBlockPtr, Result, Written);
            if (Result == NTSTATUS.STATUS_SUCCESS)
                Instance.WinHelper.KernelFileVolumeInformation?.NoteQuery(FileHandle, FileObj);
            return Result;
        }

        internal static int BuildInformation(BinaryEmulator Instance, WinFile? FileObj, uint InformationClass, Span<byte> Data)
        {
            Data.Clear();
            switch (InformationClass)
            {
                case FileFsVolumeInformation:
                    const string VolumeLabel = "Brovan";
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(8), (uint)WindowsStorageDeviceSupport.VolumeSerialNumber);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(12), (uint)Encoding.Unicode.GetByteCount(VolumeLabel));
                    return 0x12 + Encoding.Unicode.GetBytes(VolumeLabel.AsSpan(), Data.Slice(0x12));

                case FileFsSizeInformation:
                    BinaryPrimitives.WriteUInt64LittleEndian(Data, WindowsStorageDeviceSupport.TotalClusters);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(8), WindowsStorageDeviceSupport.FreeClusters);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(16), (uint)WindowsStorageDeviceSupport.SectorsPerCluster);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(20), (uint)WindowsStorageDeviceSupport.BytesPerSector);
                    return 24;

                case FileFsDeviceInformation:
                    uint DeviceType = FILE_DEVICE_DISK;
                    uint Characteristics = 0;
                    if (FileObj != null)
                    {
                        if (IsConsoleHandle(FileObj))
                            DeviceType = FILE_DEVICE_CONSOLE;
                        else if (FileObj.Device && FileObj.Path != null && FileObj.Path.StartsWith("\\Device\\NamedPipe", StringComparison.OrdinalIgnoreCase))
                            DeviceType = FILE_DEVICE_NAMED_PIPE;
                        else if (FileObj.IsNullDevice)
                        {
                            DeviceType = FILE_DEVICE_NULL;
                            Characteristics = FILE_DEVICE_SECURE_OPEN;
                        }
                    }
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, DeviceType);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(4), Characteristics);
                    return 8;

                case FileFsAttributeInformation:
                    const string FileSystemName = "NTFS";
                    uint Attributes = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS;
                    BinaryPrimitives.WriteUInt32LittleEndian(Data, Attributes);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(4), 255);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(8), (uint)Encoding.Unicode.GetByteCount(FileSystemName));
                    return 12 + Encoding.Unicode.GetBytes(FileSystemName.AsSpan(), Data.Slice(12));

                case FileFsFullSizeInformation:
                    BinaryPrimitives.WriteUInt64LittleEndian(Data, WindowsStorageDeviceSupport.TotalClusters);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(8), WindowsStorageDeviceSupport.FreeClusters);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(16), WindowsStorageDeviceSupport.FreeClusters);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(24), (uint)WindowsStorageDeviceSupport.SectorsPerCluster);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(28), (uint)WindowsStorageDeviceSupport.BytesPerSector);
                    return 32;

                case FileFsObjectIdInformation:
                    if (!Guid.TryParse(Instance.WinHelper.SyntheticVolumeGuid, out Guid VolumeId))
                        VolumeId = Guid.Empty;
                    VolumeId.TryWriteBytes(Data);
                    return 64;

                case FileFsSectorSizeInformation:
                    uint SectorSize = (uint)WindowsStorageDeviceSupport.BytesPerSector;
                    for (int Offset = 0; Offset < 16; Offset += 4)
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(Offset), SectorSize);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(16), 3);
                    return 28;

                default:
                    return 0;
            }
        }

        private static NTSTATUS WriteStatusBlock(BinaryEmulator Instance, ulong IoStatusBlockPtr, NTSTATUS Status, ulong Information)
        {
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, Information);
            return Status;
        }

        private static bool IsConsoleHandle(WinFile FileObj)
            => FileObj.ConsoleKind != ConsoleObjectKind.None
               || (FileObj.Device && FileObj.Path != null && FileObj.Path.StartsWith("\\Device\\ConDrv", StringComparison.OrdinalIgnoreCase));
    }
}
