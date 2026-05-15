using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class MountPointManagerDevice : IWinDevice
    {
        private const uint IOCTL_MOUNTMGR_QUERY_POINTS = 0x006D0008;
        private const uint IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER = 0x006D4010;
        private const uint IOCTL_MOUNTMGR_CHANGE_NOTIFY = 0x006D4020;
        private const uint IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH = 0x006D0030;
        private const uint IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS = 0x006D0034;
        private const uint IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT = 0x006D003C;

        private const int MountPointSize = 24;
        private const string DeviceNameValue = "\\Device\\HarddiskVolume1";
        private const string DriveSymbolicLink = "\\DosDevices\\C:";

        public string DeviceName => "\\Device\\MountPointManager";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DeviceName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            return IOCTL switch
            {
                IOCTL_MOUNTMGR_QUERY_POINTS => QueryPoints(ref Data, Instance),
                IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH => QueryDosVolumePaths(ref Data, Instance, false),
                IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS => QueryDosVolumePaths(ref Data, Instance, true),
                IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER => QueryNextDriveLetter(ref Data),
                IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT => QueryAutoMount(ref Data),
                IOCTL_MOUNTMGR_CHANGE_NOTIFY => QueryChangeNotify(ref Data),
                _ => NTSTATUS.STATUS_INVALID_DEVICE_REQUEST,
            };
        }

        private static NTSTATUS QueryPoints(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.InputBuffer == null || Data.InputLength < MountPointSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Data.OutputBuffer == null || Data.OutputLength < 8)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            MountPointFilter Filter = ParseFilter(Data.InputBuffer, Data.InputLength);
            if (!Filter.Valid)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            List<MountPointEntry> Entries = SelectEntries(Filter, Instance);
            if (Entries.Count == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            byte[] Output = BuildMountPoints(Entries, out uint RequiredSize);
            WriteRequiredHeader(Data.OutputBuffer, RequiredSize, Entries.Count);

            if (Data.OutputLength < RequiredSize)
            {
                Data.Information = Math.Min(Data.OutputLength, 8u);
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            Output.AsSpan().CopyTo(Data.OutputBuffer);
            Data.Information = RequiredSize;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS QueryDosVolumePaths(ref DeviceData Data, BinaryEmulator Instance, bool IncludeAll)
        {
            if (Data.InputBuffer == null || Data.InputLength < 2)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Data.OutputBuffer == null || Data.OutputLength < 4)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            string DeviceName = ReadTargetDeviceName(Data.InputBuffer, Data.InputLength);
            if (!IsKnownDeviceName(DeviceName, Instance))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            string MultiSz = IncludeAll ? string.Concat("C:\\", '\0', Instance.WinHelper.SyntheticVolumeWin32GuidPath, '\0', '\0') : string.Concat("C:\\", '\0', '\0');
            byte[] MultiSzBytes = Encoding.Unicode.GetBytes(MultiSz);
            uint RequiredSize = checked((uint)(4 + MultiSzBytes.Length));

            BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(0, 4), (uint)MultiSzBytes.Length);
            if (Data.OutputLength < RequiredSize)
            {
                Data.Information = 4;
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            MultiSzBytes.CopyTo(Data.OutputBuffer.AsSpan(4));
            Data.Information = RequiredSize;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS QueryNextDriveLetter(ref DeviceData Data)
        {
            if (Data.OutputBuffer == null || Data.OutputLength < 2)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Data.OutputBuffer[0] = 1;
            Data.OutputBuffer[1] = (byte)'C';
            Data.Information = 2;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS QueryAutoMount(ref DeviceData Data)
        {
            if (Data.OutputBuffer == null || Data.OutputLength < 4)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(0, 4), 0);
            Data.Information = 4;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS QueryChangeNotify(ref DeviceData Data)
        {
            if (Data.OutputBuffer == null || Data.OutputLength < 4)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(0, 4), 1);
            Data.Information = 4;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static MountPointFilter ParseFilter(byte[] Buffer, uint Length)
        {
            uint SymbolicLinkOffset = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.AsSpan(0, 4));
            ushort SymbolicLinkLength = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.AsSpan(4, 2));
            uint UniqueIdOffset = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.AsSpan(8, 4));
            ushort UniqueIdLength = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.AsSpan(12, 2));
            uint DeviceNameOffset = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.AsSpan(16, 4));
            ushort DeviceNameLength = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.AsSpan(20, 2));

            if (!RangeValid(SymbolicLinkOffset, SymbolicLinkLength, Length) ||
                !RangeValid(UniqueIdOffset, UniqueIdLength, Length) ||
                !RangeValid(DeviceNameOffset, DeviceNameLength, Length))
            {
                return new MountPointFilter { Valid = false };
            }

            return new MountPointFilter
            {
                Valid = true,
                SymbolicLinkName = ReadUnicodeString(Buffer, SymbolicLinkOffset, SymbolicLinkLength),
                UniqueId = ReadBytes(Buffer, UniqueIdOffset, UniqueIdLength),
                DeviceName = ReadUnicodeString(Buffer, DeviceNameOffset, DeviceNameLength),
            };
        }

        private static List<MountPointEntry> SelectEntries(MountPointFilter Filter, BinaryEmulator Instance)
        {
            List<MountPointEntry> Entries = new List<MountPointEntry>(2);
            byte[] UniqueId = Instance.WinHelper.SyntheticMountDevUniqueId;
            MountPointEntry Drive = new MountPointEntry(DriveSymbolicLink, UniqueId, DeviceNameValue);
            MountPointEntry Volume = new MountPointEntry(Instance.WinHelper.SyntheticVolumeGuidSymbolicLink, UniqueId, DeviceNameValue);

            bool Empty = string.IsNullOrEmpty(Filter.SymbolicLinkName) &&
                string.IsNullOrEmpty(Filter.DeviceName) &&
                (Filter.UniqueId == null || Filter.UniqueId.Length == 0);

            if (Empty || Matches(Filter, Drive, UniqueId, Instance))
                Entries.Add(Drive);

            if (Empty || Matches(Filter, Volume, UniqueId, Instance))
                Entries.Add(Volume);

            return Entries;
        }

        private static bool Matches(MountPointFilter Filter, MountPointEntry Entry, byte[] UniqueId, BinaryEmulator Instance)
        {
            if (!string.IsNullOrEmpty(Filter.SymbolicLinkName) && !NamesEqual(Filter.SymbolicLinkName, Entry.SymbolicLinkName))
                return false;

            if (!string.IsNullOrEmpty(Filter.DeviceName) && !IsKnownDeviceName(Filter.DeviceName, Instance))
                return false;

            if (Filter.UniqueId != null && Filter.UniqueId.Length != 0 && !Filter.UniqueId.AsSpan().SequenceEqual(UniqueId))
                return false;

            return true;
        }

        private static byte[] BuildMountPoints(List<MountPointEntry> Entries, out uint RequiredSize)
        {
            int HeaderSize = 8 + Entries.Count * MountPointSize;
            int StringOffset = HeaderSize;
            List<byte[]> SymbolicLinks = new List<byte[]>(Entries.Count);
            List<byte[]> DeviceNames = new List<byte[]>(Entries.Count);

            foreach (MountPointEntry Entry in Entries)
            {
                byte[] SymbolicLink = Encoding.Unicode.GetBytes(Entry.SymbolicLinkName);
                byte[] DeviceName = Encoding.Unicode.GetBytes(Entry.DeviceName);
                SymbolicLinks.Add(SymbolicLink);
                DeviceNames.Add(DeviceName);
                StringOffset += SymbolicLink.Length + Entry.UniqueId.Length + DeviceName.Length;
            }

            RequiredSize = checked((uint)StringOffset);
            byte[] Output = new byte[checked((int)RequiredSize)];
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(0, 4), RequiredSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(4, 4), (uint)Entries.Count);

            int CurrentStringOffset = HeaderSize;
            for (int i = 0; i < Entries.Count; i++)
            {
                MountPointEntry Entry = Entries[i];
                byte[] SymbolicLink = SymbolicLinks[i];
                byte[] DeviceName = DeviceNames[i];
                int EntryOffset = 8 + i * MountPointSize;

                WriteMountPoint(Output, EntryOffset, CurrentStringOffset, SymbolicLink.Length, CurrentStringOffset + SymbolicLink.Length, Entry.UniqueId.Length, CurrentStringOffset + SymbolicLink.Length + Entry.UniqueId.Length, DeviceName.Length);

                SymbolicLink.CopyTo(Output.AsSpan(CurrentStringOffset));
                CurrentStringOffset += SymbolicLink.Length;
                Entry.UniqueId.CopyTo(Output.AsSpan(CurrentStringOffset));
                CurrentStringOffset += Entry.UniqueId.Length;
                DeviceName.CopyTo(Output.AsSpan(CurrentStringOffset));
                CurrentStringOffset += DeviceName.Length;
            }

            return Output;
        }

        private static void WriteMountPoint(byte[] Buffer, int Offset, int SymbolicLinkOffset, int SymbolicLinkLength, int UniqueIdOffset, int UniqueIdLength, int DeviceNameOffset, int DeviceNameLength)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.AsSpan(Offset + 0, 4), (uint)SymbolicLinkOffset);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.AsSpan(Offset + 4, 2), (ushort)SymbolicLinkLength);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.AsSpan(Offset + 8, 4), (uint)UniqueIdOffset);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.AsSpan(Offset + 12, 2), (ushort)UniqueIdLength);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.AsSpan(Offset + 16, 4), (uint)DeviceNameOffset);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.AsSpan(Offset + 20, 2), (ushort)DeviceNameLength);
        }

        private static void WriteRequiredHeader(byte[] Buffer, uint RequiredSize, int Count)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.AsSpan(0, 4), RequiredSize);
            if (Buffer.Length >= 8)
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.AsSpan(4, 4), (uint)Count);
        }

        private static string ReadTargetDeviceName(byte[] Buffer, uint Length)
        {
            ushort DeviceNameLength = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.AsSpan(0, 2));
            if (DeviceNameLength == 0 || (uint)DeviceNameLength + 2u > Length)
                return string.Empty;

            return Encoding.Unicode.GetString(Buffer, 2, DeviceNameLength).TrimEnd('\0');
        }

        private static string ReadUnicodeString(byte[] Buffer, uint Offset, ushort Length)
        {
            if (Length == 0)
                return string.Empty;

            return Encoding.Unicode.GetString(Buffer, checked((int)Offset), Length).TrimEnd('\0');
        }

        private static byte[] ReadBytes(byte[] Buffer, uint Offset, ushort Length)
        {
            if (Length == 0)
                return Array.Empty<byte>();

            byte[] Value = new byte[Length];
            Buffer.AsSpan(checked((int)Offset), Length).CopyTo(Value);
            return Value;
        }

        private static bool RangeValid(uint Offset, ushort Length, uint BufferLength)
        {
            if (Length == 0)
                return Offset == 0 || Offset <= BufferLength;

            return Offset <= BufferLength && Length <= BufferLength - Offset;
        }

        private static bool NamesEqual(string Left, string Right)
        {
            return string.Equals(NormalizeMountName(Left), NormalizeMountName(Right), StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsKnownDeviceName(string Name, BinaryEmulator Instance)
        {
            return NamesEqual(Name, DeviceNameValue) ||
                NamesEqual(Name, "C:") ||
                NamesEqual(Name, "C:\\") ||
                NamesEqual(Name, DriveSymbolicLink) ||
                NamesEqual(Name, Instance.WinHelper.SyntheticVolumeGuidSymbolicLink) ||
                NamesEqual(Name, Instance.WinHelper.SyntheticVolumeWin32GuidPath);
        }

        private static string NormalizeMountName(string Name)
        {
            if (string.IsNullOrEmpty(Name))
                return string.Empty;

            string Value = Name.Trim().TrimEnd('\0').Replace('/', '\\');
            if (Value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) || Value.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
                Value = "\\??\\" + Value.Substring(4);

            if (Value.Length == 2 && char.IsLetter(Value[0]) && Value[1] == ':')
                Value = "\\DosDevices\\" + char.ToUpperInvariant(Value[0]) + ":";
            else if (Value.Length == 6 && Value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase) && char.IsLetter(Value[4]) && Value[5] == ':')
                Value = "\\DosDevices\\" + char.ToUpperInvariant(Value[4]) + ":";

            while (Value.EndsWith("\\", StringComparison.Ordinal) && Value.Length > 3 && !Value.EndsWith(":\\", StringComparison.Ordinal))
                Value = Value.Substring(0, Value.Length - 1);

            return Value;
        }

        private readonly struct MountPointEntry
        {
            public MountPointEntry(string SymbolicLinkName, byte[] UniqueId, string DeviceName)
            {
                this.SymbolicLinkName = SymbolicLinkName;
                this.UniqueId = UniqueId;
                this.DeviceName = DeviceName;
            }

            public readonly string SymbolicLinkName;
            public readonly byte[] UniqueId;
            public readonly string DeviceName;
        }

        private struct MountPointFilter
        {
            public bool Valid;
            public string SymbolicLinkName;
            public byte[] UniqueId;
            public string DeviceName;
        }
    }
}
