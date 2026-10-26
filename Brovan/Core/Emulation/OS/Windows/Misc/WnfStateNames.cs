using System;
using System.Buffers.Binary;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // NT keeps permanent WNF names in the SOFTWARE hive, a record per name and the sequence mark under one key.
    internal static class WnfStateNames
    {
        internal enum NameLifetime : uint
        {
            WellKnown = 0,
            Permanent = 1,
            Persistent = 2,
            Temporary = 3
        }

        internal enum DataScope : uint
        {
            System = 0,
            Session = 1,
            User = 2,
            Process = 3,
            Machine = 4,
            PhysicalMachine = 5
        }

        private const ulong NameXorKey = 0x41C64E6DA3BC0074;
        private const ulong NameVersion = 1;
        private const int LifetimeShift = 4;
        private const int ScopeShift = 6;
        private const int SequenceShift = 11;
        private const ulong SequenceLimit = 1UL << 53;

        private const string SoftwareHive = "\\Registry\\Machine\\SOFTWARE";
        private const string StoreKey = "\\Microsoft\\Windows NT\\CurrentVersion\\Notifications";
        private const string SequenceValue = "SequenceNumber";
        private const ulong SequenceReserve = 100;

        // The generic mapping NT gives WNF state names (ExpWnfNotificationMapping).
        private static readonly GENERIC_MAPPING Mapping = new GENERIC_MAPPING
        {
            GenericRead = 0x00120001,
            GenericWrite = 0x00000002,
            GenericExecute = 0x001F0000,
            GenericAll = 0x001F0013,
        };

        internal static ulong Encode(ulong Sequence, NameLifetime Lifetime, DataScope Scope)
        {
            ulong Raw = Sequence << SequenceShift | (ulong)Scope << ScopeShift | (ulong)Lifetime << LifetimeShift | NameVersion;
            return Raw ^ NameXorKey;
        }

        internal static Hive GetStoreHive(WinSysHelper Helper) => Helper.RegManager.GetHiveByNtPath(SoftwareHive);

        internal static bool HasPermanent(Hive Store, ulong StateName)
        {
            if (Store?.Reader == null)
                return false;

            Store.SyncFromDisk();
            return Store.TryGetValue(StoreKey, RecordName(StateName), out _);
        }

        internal static bool HasPermanent(HiveUpdate Update, ulong StateName) => Update.TryGetValue(StoreKey, RecordName(StateName), out _);

        // NT stores the sequence mark before it hands out the name, so no sequence is used twice
        // (ExpWnfAllocateNextPersistentNameSequence, ExpWnfRegisterPermanentName).
        internal static bool TryCreatePermanent(HiveUpdate Update, DataScope Scope, byte[] Descriptor, out ulong StateName)
        {
            StateName = 0;

            // The record is the descriptor and a maximum state size of 0.
            byte[] Record = new byte[Descriptor.Length + sizeof(uint)];
            Descriptor.CopyTo(Record, 0);
            if (!NtAccessCheck.MapGenericRights(Record.AsSpan(0, Descriptor.Length), Mapping))
                return false;

            ulong Mark = 0;
            if (Update.TryGetValue(StoreKey, SequenceValue, out ValueNode Stored) && !Stored.TryGetUInt64(out Mark))
                return false;

            if (Mark >= SequenceLimit - 1)
                return false;

            byte[] NextMark = new byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(NextMark, Mark + SequenceReserve);
            if (!Update.TryCreateKey(StoreKey) || !Update.TrySetValue(StoreKey, SequenceValue, WinSysHelper.RegBinary, NextMark))
                return false;

            ulong Name = Encode(Mark + 1, NameLifetime.Permanent, Scope);
            if (!Update.TrySetValue(StoreKey, RecordName(Name), WinSysHelper.RegBinary, Record))
                return false;

            StateName = Name;
            return true;
        }

        private static string RecordName(ulong StateName) => StateName.ToString("X16");
    }
}
