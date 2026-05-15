using Brovan.Core.Helpers;
using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryLicenseValue : IWinSyscall
    {
        private const uint MaxLicenseQuerySize = 0x00800000;
        private const string ProductPolicyKeyPath = @"\CurrentControlSet\Control\ProductOptions";
        private const string ProductPolicyValueName = "ProductPolicy";

        private static bool TryFindSystemHive(BinaryEmulator Instance, out Hive SystemHive)
        {
            SystemHive = null;

            if (Instance?.WinHelper?.RegHives == null)
                return false;

            foreach (Hive Hive in Instance.WinHelper.RegHives)
            {
                if (Hive == null || Hive.Reader == null || string.IsNullOrEmpty(Hive.NtMountPoint))
                    continue;

                if (Hive.NtMountPoint.Equals(@"\Registry\Machine\SYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    SystemHive = Hive;
                    return true;
                }
            }

            return false;
        }

        private static bool TryReadProductPolicy(BinaryEmulator Instance, out byte[] ProductPolicy)
        {
            ProductPolicy = null;

            if (!TryFindSystemHive(Instance, out Hive SystemHive))
                return false;

            if (!SystemHive.Reader.TryOpenPath(ProductPolicyKeyPath, out RegistryHiveReader.HiveKey ProductOptionsKey))
                return false;

            return SystemHive.Reader.TryReadValueData(ProductOptionsKey, ProductPolicyValueName, out ProductPolicy);
        }

        private static bool TryReadPolicyEntry(byte[] ProductPolicy, string ValueName, out ushort Type, out byte[] Data)
        {
            Type = 0;
            Data = null;

            if (ProductPolicy == null || ProductPolicy.Length < 0x14)
                return false;

            uint TotalSize = BitConverter.ToUInt32(ProductPolicy, 0x00);
            uint ValuesSize = BitConverter.ToUInt32(ProductPolicy, 0x04);

            if (TotalSize == 0 || TotalSize > ProductPolicy.Length)
                TotalSize = (uint)ProductPolicy.Length;

            ulong ValuesStart = 0x14;
            ulong ValuesEnd = ValuesStart + ValuesSize;

            if (ValuesEnd > TotalSize)
                ValuesEnd = TotalSize;

            if (ValuesEnd < ValuesStart)
                return false;

            for (ulong EntryOffset = ValuesStart; EntryOffset + 0x10 <= ValuesEnd;)
            {
                ushort EntrySize = BitConverter.ToUInt16(ProductPolicy, (int)EntryOffset + 0x00);
                ushort NameSize = BitConverter.ToUInt16(ProductPolicy, (int)EntryOffset + 0x02);
                ushort EntryType = BitConverter.ToUInt16(ProductPolicy, (int)EntryOffset + 0x04);
                ushort DataSize = BitConverter.ToUInt16(ProductPolicy, (int)EntryOffset + 0x06);

                if (EntrySize < 0x10)
                    break;

                ulong EntryEnd = EntryOffset + EntrySize;
                if (EntryEnd > ValuesEnd)
                    break;

                ulong NameOffset = EntryOffset + 0x10;
                ulong DataOffset = NameOffset + NameSize;

                if (DataOffset > EntryEnd)
                    break;

                ulong DataEnd = DataOffset + DataSize;
                if (DataEnd > EntryEnd)
                    break;

                string EntryName = NameSize == 0
                    ? string.Empty
                    : Encoding.Unicode.GetString(ProductPolicy, (int)NameOffset, NameSize).TrimEnd('\0');

                if (EntryName.Equals(ValueName, StringComparison.OrdinalIgnoreCase))
                {
                    Type = EntryType;
                    Data = new byte[DataSize];
                    if (DataSize != 0)
                        Buffer.BlockCopy(ProductPolicy, (int)DataOffset, Data, 0, DataSize);
                    return true;
                }

                EntryOffset = EntryEnd;
            }

            return false;
        }

        private static NTSTATUS QueryLicenseValue(BinaryEmulator Instance, string ValueName, ulong TypePtr, ulong DataPtr, uint DataSize, ulong ResultDataSizePtr)
        {
            if (string.IsNullOrEmpty(ValueName) || ResultDataSizePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(ResultDataSizePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (TypePtr != 0 && !Instance.IsRegionMapped(TypePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (DataPtr == 0)
            {
                if (DataSize != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }
            else
            {
                if (DataSize > MaxLicenseQuerySize)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (!Instance.IsRegionMapped(DataPtr, DataSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (!TryReadProductPolicy(Instance, out byte[] ProductPolicy))
            {
                Instance._emulator.WriteMemory(ResultDataSizePtr, 0u);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            if (!TryReadPolicyEntry(ProductPolicy, ValueName, out ushort EntryType, out byte[] EntryData))
            {
                Instance._emulator.WriteMemory(ResultDataSizePtr, 0u);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            uint RequiredSize = (uint)(EntryData?.Length ?? 0);
            Instance._emulator.WriteMemory(ResultDataSizePtr, RequiredSize);

            if (TypePtr != 0)
                Instance._emulator.WriteMemory(TypePtr, (uint)EntryType);

            if (DataPtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (DataSize < RequiredSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (RequiredSize != 0 && EntryData != null && !Instance._emulator.WriteMemory(DataPtr, EntryData))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ValueNamePtr = Instance.WinHelper.GetArg64(0);
                ulong TypePtr = Instance.WinHelper.GetArg64(1);
                ulong DataPtr = Instance.WinHelper.GetArg64(2);
                uint DataSize = (uint)Instance.WinHelper.GetArg64(3, true);
                ulong ResultDataSizePtr = Instance.WinHelper.GetArg64(4);

                if (!Instance.WinHelper.TryReadUnicodeString64(ValueNamePtr, out string ValueName, out NTSTATUS Status))
                    return Status;

                NTSTATUS QueryStatus = QueryLicenseValue(Instance, ValueName, TypePtr, DataPtr, DataSize, ResultDataSizePtr);
                if (QueryStatus == NTSTATUS.STATUS_SUCCESS || QueryStatus == NTSTATUS.STATUS_BUFFER_TOO_SMALL)
                    Instance.TriggerEventMessage($"[+] NtQueryLicenseValue: \"{ValueName}\"", LogFlags.Syscall);
                return QueryStatus;
            }

            if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                uint ValueNamePtr = Instance.WinHelper.GetArg32(0);
                uint TypePtr = Instance.WinHelper.GetArg32(1);
                uint DataPtr = Instance.WinHelper.GetArg32(2);
                uint DataSize = Instance.WinHelper.GetArg32(3);
                uint ResultDataSizePtr = Instance.WinHelper.GetArg32(4);

                if (!Instance.WinHelper.TryReadUnicodeString32(ValueNamePtr, out string ValueName, out NTSTATUS Status))
                    return Status;

                NTSTATUS QueryStatus = QueryLicenseValue(Instance, ValueName, TypePtr, DataPtr, DataSize, ResultDataSizePtr);
                if (QueryStatus == NTSTATUS.STATUS_SUCCESS || QueryStatus == NTSTATUS.STATUS_BUFFER_TOO_SMALL)
                    Instance.TriggerEventMessage($"[+] NtQueryLicenseValue (x86): \"{ValueName}\"", LogFlags.Syscall);
                return QueryStatus;
            }

            return Instance.WinUnimplemented;
        }
    }
}