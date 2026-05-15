using System;
using System.Buffers.Binary;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class WindowsStorageDeviceSupport
    {
        internal const string VolumeDeviceName = "\\Device\\HarddiskVolume1";
        internal const string PhysicalDiskDeviceName = "\\Device\\Harddisk0\\DR0";
        private const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
        private const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080;
        private const uint IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0;
        private const uint IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000;
        private const uint IOCTL_MOUNTDEV_QUERY_UNIQUE_ID = 0x004D0000;
        private const uint IOCTL_MOUNTDEV_QUERY_DEVICE_NAME = 0x004D0008;

        internal const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;
        internal const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;
        internal const uint FSCTL_ENUM_USN_DATA = 0x000900B3;
        internal const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
        internal const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;

        internal const uint FILE_DEVICE_DISK = 0x00000007;
        private const uint FixedMedia = 12;
        private const uint BusTypeVirtual = 14;

        internal const ulong BytesPerSector = 512;
        internal const ulong SectorsPerCluster = 8;
        internal const ulong BytesPerCluster = BytesPerSector * SectorsPerCluster;
        internal const ulong TotalClusters = 0x01000000UL;
        internal const ulong FreeClusters = 0x00800000UL;
        internal const ulong TotalSectors = TotalClusters * SectorsPerCluster;
        internal const ulong DiskSize = TotalSectors * BytesPerSector;
        internal const ulong VolumeSerialNumber = 0xB10A0001UL;
        private const ulong UsnJournalId = 0xB10A000100000001UL;
        private const ulong NextUsn = 0x1000UL;
        private const ulong RootFileReferenceNumber = 0x0005000000000005UL;
        private static readonly byte[] MountDevDeviceName = Encoding.Unicode.GetBytes(VolumeDeviceName);

        internal static bool IsStorageDevicePath(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Value = NormalizeStoragePath(Path, null);
            return Value.Equals(VolumeDeviceName, StringComparison.OrdinalIgnoreCase) ||
                Value.Equals(PhysicalDiskDeviceName, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool IsVolumeDevicePath(string Path)
        {
            return IsVolumeDevicePath(Path, null);
        }

        internal static bool IsVolumeDevicePath(string Path, string VolumeGuid)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Value = NormalizeStoragePath(Path, VolumeGuid);
            return Value.Equals(VolumeDeviceName, StringComparison.OrdinalIgnoreCase) ||
                Value.Equals("C:", StringComparison.OrdinalIgnoreCase) ||
                Value.Equals("C:\\", StringComparison.OrdinalIgnoreCase) ||
                Value.Equals("\\DosDevices\\C:", StringComparison.OrdinalIgnoreCase);
        }

        internal static string NormalizeStoragePath(string Path, string VolumeGuid = null)
        {
            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\');

            if (Value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
            {
                Value = Value.Substring(4);
            }

            if (Value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);

            while (Value.Length > 3 && Value.EndsWith("\\", StringComparison.Ordinal))
                Value = Value.Substring(0, Value.Length - 1);

            if (Value.Equals("PhysicalDrive0", StringComparison.OrdinalIgnoreCase))
                return PhysicalDiskDeviceName;

            if (Value.Equals("C:", StringComparison.OrdinalIgnoreCase))
                return VolumeDeviceName;

            string Trimmed = Value.TrimStart('\\');
            if (!string.IsNullOrEmpty(VolumeGuid) && Trimmed.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase))
            {
                int CloseBrace = Trimmed.IndexOf('}');
                if (CloseBrace >= "Volume{".Length &&
                    Trimmed.Substring(CloseBrace + 1).Trim('\\').Length == 0 &&
                    Trimmed.Substring("Volume{".Length, CloseBrace - "Volume{".Length).Equals(VolumeGuid, StringComparison.OrdinalIgnoreCase))
                {
                    return VolumeDeviceName;
                }
            }

            if (Value.Equals("\\DosDevices\\C:", StringComparison.OrdinalIgnoreCase))
                return VolumeDeviceName;

            return Value;
        }

        internal static NTSTATUS HandleDeviceControl(BinaryEmulator Instance, uint Ioctl, ref DeviceData Data, bool IsVolume)
        {
            return Ioctl switch
            {
                IOCTL_MOUNTDEV_QUERY_DEVICE_NAME => IsVolume ? QueryMountDevDeviceName(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                IOCTL_MOUNTDEV_QUERY_UNIQUE_ID => IsVolume ? QueryMountDevUniqueId(ref Data, Instance) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                IOCTL_STORAGE_QUERY_PROPERTY => QueryStorageProperty(ref Data, IsVolume),
                IOCTL_STORAGE_GET_DEVICE_NUMBER => QueryStorageDeviceNumber(ref Data, IsVolume),
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX => QueryDriveGeometry(ref Data),
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS => IsVolume ? QueryVolumeDiskExtents(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_GET_NTFS_VOLUME_DATA => IsVolume ? QueryNtfsVolumeData(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_QUERY_USN_JOURNAL => IsVolume ? QueryUsnJournal(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_ENUM_USN_DATA => IsVolume ? EnumUsnData(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_READ_USN_JOURNAL => IsVolume ? ReadUsnJournal(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_GET_REPARSE_POINT => NTSTATUS.STATUS_NOT_A_REPARSE_POINT,
                _ => NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
            };
        }

        internal static NTSTATUS HandleFsControl(uint FsControlCode, ref DeviceData Data, WinFile File)
        {
            bool IsVolume = File != null && (IsVolumeDevicePath(File.Path) || (File.Device && IsStorageDevicePath(File.Path)));

            return FsControlCode switch
            {
                FSCTL_GET_NTFS_VOLUME_DATA => IsVolume ? QueryNtfsVolumeData(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_QUERY_USN_JOURNAL => IsVolume ? QueryUsnJournal(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_ENUM_USN_DATA => IsVolume ? EnumUsnData(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_READ_USN_JOURNAL => IsVolume ? ReadUsnJournal(ref Data) : NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
                FSCTL_GET_REPARSE_POINT => NTSTATUS.STATUS_NOT_A_REPARSE_POINT,
                _ => NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
            };
        }


        private static NTSTATUS QueryMountDevDeviceName(ref DeviceData Data)
        {
            return WriteMountDevVariableBuffer(ref Data, MountDevDeviceName);
        }

        private static NTSTATUS QueryMountDevUniqueId(ref DeviceData Data, BinaryEmulator Instance)
        {
            return WriteMountDevVariableBuffer(ref Data, Instance.WinHelper.SyntheticMountDevUniqueId);
        }

        private static NTSTATUS WriteMountDevVariableBuffer(ref DeviceData Data, byte[] Payload)
        {
            if (Data.OutputBuffer == null || Data.OutputLength < 2)
            {
                Data.Information = 0;
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            ushort PayloadLength = checked((ushort)Payload.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Data.OutputBuffer.AsSpan(0, 2), PayloadLength);

            uint RequiredSize = checked((uint)(2 + Payload.Length));
            if (Data.OutputLength < RequiredSize)
            {
                Data.Information = 2;
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            Payload.CopyTo(Data.OutputBuffer.AsSpan(2));
            Data.Information = RequiredSize;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS QueryStorageProperty(ref DeviceData Data, bool IsVolume)
        {
            if (Data.InputBuffer == null || Data.InputLength < 8)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint PropertyId = BinaryPrimitives.ReadUInt32LittleEndian(Data.InputBuffer.AsSpan(0, 4));
            uint QueryType = BinaryPrimitives.ReadUInt32LittleEndian(Data.InputBuffer.AsSpan(4, 4));
            if (QueryType > 1)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            byte[] Output = PropertyId switch
            {
                0 => BuildStorageDeviceDescriptor(IsVolume),
                1 => BuildStorageAdapterDescriptor(),
                _ => BuildStorageDescriptorHeader(8),
            };

            return WriteOutput(ref Data, Output, AllowOverflow: true);
        }

        private static NTSTATUS QueryStorageDeviceNumber(ref DeviceData Data, bool IsVolume)
        {
            byte[] Output = new byte[12];
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(0, 4), FILE_DEVICE_DISK);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(4, 4), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Output.AsSpan(8, 4), IsVolume ? 1 : -1);
            return WriteOutput(ref Data, Output, AllowOverflow: false);
        }

        private static NTSTATUS QueryDriveGeometry(ref DeviceData Data)
        {
            byte[] Output = new byte[32];
            ulong Cylinders = Math.Max(1, TotalSectors / (255 * 63));
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(0, 8), Cylinders);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(8, 4), FixedMedia);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(12, 4), 255);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(16, 4), 63);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(20, 4), (uint)BytesPerSector);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(24, 8), DiskSize);
            return WriteOutput(ref Data, Output, AllowOverflow: false);
        }

        private static NTSTATUS QueryVolumeDiskExtents(ref DeviceData Data)
        {
            byte[] Output = new byte[32];
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(0, 4), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(8, 4), 0);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(16, 8), 0);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(24, 8), DiskSize);
            return WriteOutput(ref Data, Output, AllowOverflow: true);
        }

        private static NTSTATUS QueryNtfsVolumeData(ref DeviceData Data)
        {
            byte[] Output = new byte[96];
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(0, 8), VolumeSerialNumber);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(8, 8), TotalSectors);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(16, 8), TotalClusters);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(24, 8), FreeClusters);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(32, 8), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(40, 4), (uint)BytesPerSector);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(44, 4), (uint)BytesPerCluster);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(48, 4), 1024);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(52, 4), 0xFFFFFFFF);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(56, 8), 0x100000UL);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(64, 8), 0x00000004UL);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(72, 8), TotalClusters / 2);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(80, 8), TotalClusters / 4);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(88, 8), TotalClusters / 4 + 0x10000UL);
            return WriteOutput(ref Data, Output, AllowOverflow: false);
        }

        private static NTSTATUS QueryUsnJournal(ref DeviceData Data)
        {
            byte[] Output = new byte[56];
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(0, 8), UsnJournalId);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(8, 8), 0);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(16, 8), NextUsn);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(24, 8), 0);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(32, 8), ulong.MaxValue);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(40, 8), 0x02000000UL);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(48, 8), 0x00100000UL);
            return WriteOutput(ref Data, Output, AllowOverflow: false);
        }

        private static NTSTATUS EnumUsnData(ref DeviceData Data)
        {
            if (Data.InputBuffer == null || Data.InputLength < 24)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong StartFileReferenceNumber = BinaryPrimitives.ReadUInt64LittleEndian(Data.InputBuffer.AsSpan(0, 8));
            ulong HighUsn = BinaryPrimitives.ReadUInt64LittleEndian(Data.InputBuffer.AsSpan(16, 8));
            if (StartFileReferenceNumber > RootFileReferenceNumber || HighUsn == 0)
            {
                Data.Information = 0;
                return NTSTATUS.STATUS_NO_MORE_FILES;
            }

            byte[] Record = BuildUsnRecord(".", RootFileReferenceNumber, RootFileReferenceNumber, 1, 0x00000100);
            byte[] Output = new byte[8 + Record.Length];
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(0, 8), RootFileReferenceNumber + 1);
            Record.CopyTo(Output.AsSpan(8));
            return WriteOutput(ref Data, Output, AllowOverflow: false);
        }

        private static NTSTATUS ReadUsnJournal(ref DeviceData Data)
        {
            if (Data.InputBuffer == null || Data.InputLength < 8)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            byte[] Output = new byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(0, 8), NextUsn);
            return WriteOutput(ref Data, Output, AllowOverflow: false);
        }

        private static byte[] BuildStorageDescriptorHeader(uint Size)
        {
            byte[] Output = new byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(0, 4), 8);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(4, 4), Size);
            return Output;
        }

        private static byte[] BuildStorageDeviceDescriptor(bool IsVolume)
        {
            const int HeaderSize = 36;
            byte[] Vendor = Encoding.ASCII.GetBytes("BROVAN\0");
            byte[] Product = Encoding.ASCII.GetBytes(IsVolume ? "Virtual Volume\0" : "Virtual Disk\0");
            byte[] Revision = Encoding.ASCII.GetBytes("1.0\0");
            byte[] Serial = Encoding.ASCII.GetBytes("BROVAN0001\0");
            byte[] Output = new byte[HeaderSize + Vendor.Length + Product.Length + Revision.Length + Serial.Length];

            int Offset = HeaderSize;
            int VendorOffset = Offset;
            Vendor.CopyTo(Output.AsSpan(Offset));
            Offset += Vendor.Length;
            int ProductOffset = Offset;
            Product.CopyTo(Output.AsSpan(Offset));
            Offset += Product.Length;
            int RevisionOffset = Offset;
            Revision.CopyTo(Output.AsSpan(Offset));
            Offset += Revision.Length;
            int SerialOffset = Offset;
            Serial.CopyTo(Output.AsSpan(Offset));

            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(0, 4), HeaderSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(4, 4), (uint)Output.Length);
            Output[8] = 0;
            Output[9] = 0;
            Output[10] = 0;
            Output[11] = 1;
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(12, 4), (uint)VendorOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(16, 4), (uint)ProductOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(20, 4), (uint)RevisionOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(24, 4), (uint)SerialOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(28, 4), BusTypeVirtual);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(32, 4), 0);
            return Output;
        }

        private static byte[] BuildStorageAdapterDescriptor()
        {
            byte[] Output = new byte[36];
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(0, 4), 36);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(4, 4), 36);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(8, 4), 0x00100000);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(12, 4), 0xFF);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(16, 4), 0x1FF);
            Output[20] = 0;
            Output[21] = 0;
            Output[22] = 1;
            Output[23] = 1;
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(24, 4), BusTypeVirtual);
            BinaryPrimitives.WriteUInt16LittleEndian(Output.AsSpan(28, 2), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(Output.AsSpan(30, 2), 0);
            Output[32] = 0;
            Output[33] = 0;
            return Output;
        }

        private static byte[] BuildUsnRecord(string FileName, ulong FileReferenceNumber, ulong ParentFileReferenceNumber, ulong Usn, uint FileAttributes)
        {
            byte[] FileNameBytes = Encoding.Unicode.GetBytes(FileName);
            int RecordLength = AlignUp(60 + FileNameBytes.Length, 8);
            byte[] Output = new byte[RecordLength];
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(0, 4), (uint)RecordLength);
            BinaryPrimitives.WriteUInt16LittleEndian(Output.AsSpan(4, 2), 2);
            BinaryPrimitives.WriteUInt16LittleEndian(Output.AsSpan(6, 2), 0);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(8, 8), FileReferenceNumber);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(16, 8), ParentFileReferenceNumber);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(24, 8), Usn);
            BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(32, 8), unchecked((ulong)DateTime.UtcNow.ToFileTimeUtc()));
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(40, 4), 0x00000100);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(44, 4), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(48, 4), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(52, 4), FileAttributes);
            BinaryPrimitives.WriteUInt16LittleEndian(Output.AsSpan(56, 2), (ushort)FileNameBytes.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Output.AsSpan(58, 2), 60);
            FileNameBytes.CopyTo(Output.AsSpan(60));
            return Output;
        }

        private static int AlignUp(int Value, int Alignment)
        {
            return (Value + Alignment - 1) & ~(Alignment - 1);
        }

        private static NTSTATUS WriteOutput(ref DeviceData Data, byte[] Output, bool AllowOverflow)
        {
            if (Data.OutputBuffer == null || Data.OutputLength == 0)
            {
                Data.Information = 0;
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            uint RequiredSize = checked((uint)Output.Length);
            uint ToWrite = Math.Min(Data.OutputLength, RequiredSize);
            Data.OutputBuffer = Output;
            Data.Information = ToWrite;
            if (Data.OutputLength < RequiredSize)
                return AllowOverflow && Data.OutputLength != 0 ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Data.Information = RequiredSize;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
