using Brovan.Core.Emulation.OS.Windows.RPC.Ports;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static unsafe class RpcssSessionTable
    {
        private const string FileName = "rpcss.bin";

        private const int OxidCapacity = 32;
        private const int RegistrationCapacity = 64;

        private const int HolderField = 0x00;
        private const int RegionHeaderBytes = 64;

        private const int EndpointChars = 64;
        private const int SecurityBindingChars = 160;
        private const int PackageNameChars = 128;
        private const int SidChars = 192;
        private const int StringCount = 5;

        private const int GenerationField = 0x00;
        private const int OxidField = 0x08;
        private const int InfoField = 0x10;
        private const int LengthsField = InfoField + RpcssPortHandler.OxidInfoSize;
        private const int StringsField = LengthsField + StringCount * sizeof(ushort) + 6;
        private const int OxidEntryBytes = StringsField + (EndpointChars + SecurityBindingChars + PackageNameChars + 2 * SidChars) * sizeof(char);
        private const int OxidEntryStride = (OxidEntryBytes + 63) & ~63;

        private const int KeyField = 0x04;
        private const int ClassField = 0x08;
        private const int RegistrationOxidField = 0x18;
        private const int IpidField = 0x20;
        private const int FlagsField = 0x30;
        private const int ProcessIdField = 0x38;
        private const int SidLengthField = 0x3C;
        private const int SidField = 0x40;
        private const int PackageLengthField = SidField + NtQueryInformationToken.MaxSidLength;
        private const int PackageField = (PackageLengthField + sizeof(ushort) + 7) & ~7;
        private const int RegistrationEntryBytes = PackageField + PackageNameChars * sizeof(char);
        private const int RegistrationEntryStride = (RegistrationEntryBytes + 63) & ~63;

        // Each session slot has one region, and only the process that owns the slot writes it.
        private const int RegistrationsOffset = RegionHeaderBytes + OxidCapacity * OxidEntryStride;
        private const int RegionBytes = RegistrationsOffset + RegistrationCapacity * RegistrationEntryStride;

        // Launch cells follow the regions. Only a holder of the session lock writes a cell.
        internal const int LaunchCellCapacity = 16;
        private const int CellStateField = 0x00;
        private const int CellPerAppField = 0x08;
        private const int CellClassField = 0x10;
        private const int CellDeadlineField = 0x20;
        private const int CellHostProcessField = 0x28;
        private const int CellHolderField = 0x30;
        private const int CellSidLengthField = 0x38;
        private const int CellPackageLengthField = 0x3C;
        private const int CellSidField = 0x40;
        private const int CellPackageField = (CellSidField + NtQueryInformationToken.MaxSidLength + 7) & ~7;
        private const int CellBytes = CellPackageField + PackageNameChars * sizeof(char);
        private const int CellStride = (CellBytes + 63) & ~63;
        private const long CellsOffset = (long)GuestSession.SlotCount * RegionBytes;
        private const long TableBytes = CellsOffset + (long)LaunchCellCapacity * CellStride;

        // The state word of a cell: the status in the high half, then the generation and the state.
        internal const uint CellFree = 0;
        internal const uint CellStarting = 1;
        internal const uint CellFailed = 2;
        private const uint GenerationMask = 0x3FFFFFFF;

        private static readonly int[] StringChars = { EndpointChars, SecurityBindingChars, PackageNameChars, SidChars, SidChars };
        private static readonly int[] StringOffsets = StringOffsetsOf(StringChars);

        // A leaf lock. Every region write holds it, and nothing else is taken while it is held.
        private static readonly object Sync = new();
        private static SessionMapping _table;
        private static bool _unavailable;
        private static bool _ended;

        internal static bool PublishOxid(ulong Oxid, in RpcssPortHandler.ServerOxid Server)
        {
            if (!Fits(Server))
            {
                Utils.LogError($"[-] RPCSS: OXID 0x{Oxid:X} has a string longer than the session table holds; other processes do not see it.");
                return false;
            }

            string Location = PendingLocation();
            lock (Sync)
            {
                byte* Region = OwnRegion(Location);
                if (Region == null)
                    return true;

                byte* Entry = FindOxidEntry(Region, Oxid);
                if (Entry == null)
                    Entry = FindOxidEntry(Region, 0);

                if (Entry == null)
                {
                    Utils.LogError($"[-] RPCSS: the session table has no room for OXID 0x{Oxid:X}; other processes do not see it.");
                    return false;
                }

                WriteOxidEntry(Entry, Oxid, Server);
                return true;
            }
        }

        internal static void WithdrawOxid(ulong Oxid)
        {
            lock (Sync)
            {
                byte* Region = OwnRegion(null);
                byte* Entry = Region == null ? null : FindOxidEntry(Region, Oxid);
                if (Entry != null)
                    FreeOxidEntry(Entry);
            }
        }

        internal static bool TryFindOxid(ulong Oxid, out RpcssPortHandler.ServerOxid Server)
        {
            Server = default;
            if (Oxid == 0)
                return false;

            ulong Holder = 0;
            string Location = PendingLocation();
            lock (Sync)
            {
                if (!TryOpenLocked(Location))
                    return false;

                for (int Slot = 0; Slot < GuestSession.SlotCount && Holder == 0; Slot++)
                {
                    byte* Region = OtherRegion(Slot, out ulong RegionHolder);
                    if (Region == null)
                        continue;

                    for (int Index = 0; Index < OxidCapacity; Index++)
                    {
                        byte* Entry = OxidEntryAt(Region, Index);
                        if (Volatile.Read(ref *(ulong*)(Entry + OxidField)) != Oxid)
                            continue;

                        uint Generation = BeginRead(Entry);
                        if (TryCopyOxidEntry(Entry, out ulong Copied, out Server) && EndRead(Region, Entry, Generation, RegionHolder) && Copied == Oxid)
                            Holder = RegionHolder;
                        break;
                    }
                }
            }

            if (Holder != 0 && GuestSession.IsHolderAliveCached(Holder))
                return true;

            Server = default;
            return false;
        }

        internal static bool PublishRegistration(in RpcssPortHandler.ClassRegistration Registration)
        {
            if (Registration.PackageFullName.Length > PackageNameChars)
            {
                Utils.LogError($"[-] RPCSS: the package name of the registration of {Registration.Class} is longer than the session table holds.");
                return false;
            }

            string Location = PendingLocation();
            lock (Sync)
            {
                byte* Region = OwnRegion(Location);
                if (Region == null)
                    return true;

                byte* Entry = FindRegistrationEntry(Region, 0);
                if (Entry == null)
                {
                    Utils.LogError($"[-] RPCSS: the session table has no room for the registration of {Registration.Class}.");
                    return false;
                }

                WriteRegistrationEntry(Entry, Registration);
                return true;
            }
        }

        internal static void WithdrawRegistration(uint Key)
        {
            lock (Sync)
            {
                byte* Region = OwnRegion(null);
                byte* Entry = Region == null || Key == 0 ? null : FindRegistrationEntry(Region, Key);
                if (Entry != null)
                    FreeRegistrationEntry(Entry);
            }
        }

        internal static void FindRegistrations(Guid Class, List<RpcssPortHandler.ClassRegistration> Found)
        {
            List<ulong> Holders = null;
            int First = Found.Count;
            string Location = PendingLocation();
            lock (Sync)
            {
                if (!TryOpenLocked(Location))
                    return;

                for (int Slot = 0; Slot < GuestSession.SlotCount; Slot++)
                {
                    byte* Region = OtherRegion(Slot, out ulong RegionHolder);
                    if (Region == null)
                        continue;

                    for (int Index = 0; Index < RegistrationCapacity; Index++)
                    {
                        byte* Entry = RegistrationEntryAt(Region, Index);
                        if (Volatile.Read(ref *(uint*)(Entry + KeyField)) == 0 || *(Guid*)(Entry + ClassField) != Class)
                            continue;

                        uint Generation = BeginRead(Entry);
                        if (TryCopyRegistrationEntry(Entry, out RpcssPortHandler.ClassRegistration Registration) && EndRead(Region, Entry, Generation, RegionHolder)
                            && Registration.Key != 0 && Registration.Class == Class)
                        {
                            Found.Add(Registration);
                            (Holders ??= new List<ulong>()).Add(RegionHolder);
                        }
                    }
                }
            }

            for (int Index = Found.Count - 1; Index >= First; Index--)
            {
                if (!GuestSession.IsHolderAliveCached(Holders[Index - First]))
                    Found.RemoveAt(Index);
            }
        }

        internal readonly record struct LaunchCell(int Index, uint Generation);

        internal readonly record struct LaunchCellRecord(LaunchCell Cell, uint State, RpcssPortHandler.LaunchKey Key, long Deadline, uint HostProcessId, ulong Holder);

        // A launch opens the table before it takes the session lock, so no member waits on a file it creates.
        internal static bool TryOpen(string Location)
        {
            lock (Sync)
                return TryOpenLocked(Location);
        }

        // The caller holds the session lock, so no cell changes while it reads them.
        internal static bool TryReadLaunchCells(List<LaunchCellRecord> Cells)
        {
            lock (Sync)
            {
                if (_table == null)
                    return false;

                for (int Index = 0; Index < LaunchCellCapacity; Index++)
                {
                    byte* Entry = CellAt(Index);
                    ulong Word = Volatile.Read(ref *(ulong*)(Entry + CellStateField));
                    LaunchCell Cell = new LaunchCell(Index, GenerationOf(Word));
                    uint SidLength = *(uint*)(Entry + CellSidLengthField);
                    int PackageLength = *(ushort*)(Entry + CellPackageLengthField);
                    if (StateOf(Word) == CellFree || SidLength > NtQueryInformationToken.MaxSidLength || PackageLength > PackageNameChars)
                    {
                        Cells.Add(new LaunchCellRecord(Cell, CellFree, default, 0, 0, 0));
                        continue;
                    }

                    RpcssPortHandler.LaunchKey Key = new RpcssPortHandler.LaunchKey(*(Guid*)(Entry + CellClassField), *(uint*)(Entry + CellPerAppField) != 0,
                        new string(new ReadOnlySpan<char>(Entry + CellPackageField, PackageLength)), new ReadOnlySpan<byte>(Entry + CellSidField, (int)SidLength).ToArray());
                    Cells.Add(new LaunchCellRecord(Cell, StateOf(Word), Key, *(long*)(Entry + CellDeadlineField), *(uint*)(Entry + CellHostProcessField),
                        *(ulong*)(Entry + CellHolderField)));
                }

                return true;
            }
        }

        // The caller holds the session lock.
        internal static bool TryClaimLaunchCell(LaunchCell Cell, in RpcssPortHandler.LaunchKey Key, long Deadline, out LaunchCell Claimed)
        {
            Claimed = default;
            if (Key.UserSid.Length > NtQueryInformationToken.MaxSidLength || Key.PackageFullName.Length > PackageNameChars)
                return false;

            lock (Sync)
            {
                byte* Entry = CellEntry(Cell);
                if (Entry == null)
                    return false;

                *(uint*)(Entry + CellPerAppField) = Key.PerPackage ? 1u : 0u;
                *(Guid*)(Entry + CellClassField) = Key.Class;
                *(long*)(Entry + CellDeadlineField) = Deadline;
                *(uint*)(Entry + CellHostProcessField) = 0;
                *(ulong*)(Entry + CellHolderField) = 0;
                *(uint*)(Entry + CellSidLengthField) = (uint)Key.UserSid.Length;
                Key.UserSid.CopyTo(new Span<byte>(Entry + CellSidField, NtQueryInformationToken.MaxSidLength));
                *(ushort*)(Entry + CellPackageLengthField) = (ushort)Key.PackageFullName.Length;
                Key.PackageFullName.AsSpan().CopyTo(new Span<char>(Entry + CellPackageField, PackageNameChars));

                uint Next = (Cell.Generation + 1) & GenerationMask;
                Volatile.Write(ref *(ulong*)(Entry + CellStateField), StateWord(Next, CellStarting, 0));
                Claimed = new LaunchCell(Cell.Index, Next);
                return true;
            }
        }

        // The caller holds the session lock.
        internal static void SetLaunchServer(LaunchCell Cell, uint HostProcessId, ulong Holder)
        {
            lock (Sync)
            {
                byte* Entry = CellEntry(Cell);
                if (Entry == null)
                    return;

                if (HostProcessId != 0)
                    *(uint*)(Entry + CellHostProcessField) = HostProcessId;
                if (Holder != 0)
                    *(ulong*)(Entry + CellHolderField) = Holder;
            }
        }

        // The caller holds the session lock. A failed cell keeps its generation so that a waiter can read the status.
        internal static void EndLaunchCell(LaunchCell Cell, uint FailedStatus)
        {
            lock (Sync)
            {
                byte* Entry = CellEntry(Cell);
                if (Entry != null)
                {
                    Volatile.Write(ref *(ulong*)(Entry + CellStateField), FailedStatus == 0
                        ? StateWord((Cell.Generation + 1) & GenerationMask, CellFree, 0)
                        : StateWord(Cell.Generation, CellFailed, FailedStatus));
                }
            }
        }

        internal static uint ReadLaunchState(LaunchCell Cell, out uint Status)
        {
            Status = 0;
            lock (Sync)
            {
                if (_table == null || (uint)Cell.Index >= LaunchCellCapacity)
                    return CellFree;

                ulong Word = Volatile.Read(ref *(ulong*)(CellAt(Cell.Index) + CellStateField));
                if (GenerationOf(Word) != Cell.Generation)
                    return CellFree;

                Status = StatusOf(Word);
                return StateOf(Word);
            }
        }

        internal static ulong FindHolder(uint HostProcessId)
        {
            lock (Sync)
            {
                if (_table == null || HostProcessId == 0)
                    return 0;

                for (int Slot = 0; Slot < GuestSession.SlotCount; Slot++)
                {
                    ulong Holder = Volatile.Read(ref *(ulong*)(RegionAt(Slot) + HolderField));
                    if (Holder != 0 && (uint)Holder == HostProcessId)
                        return Holder;
                }

                return 0;
            }
        }

        // Messages between guest ports are x64 only, so an x86 process keeps its RPCSS state to itself.
        internal static void KeepLocal()
        {
            lock (Sync)
                _ended = true;
        }

        internal static void End()
        {
            lock (Sync)
            {
                if (_ended)
                    return;

                _ended = true;
                int Slot = GuestSession.OwnSlot;
                if (_table == null || Slot < 0)
                    return;

                ref ulong Holder = ref *(ulong*)(RegionAt(Slot) + HolderField);
                if (Volatile.Read(ref Holder) == GuestSession.OwnHolder)
                    Volatile.Write(ref Holder, 0);
            }
        }

        internal static void Close()
        {
            End();

            lock (Sync)
            {
                _table?.Dispose();
                _table = null;
            }
        }

        // GuestSession.Directory can take GuestSession's lock, so the path is read before this class or the session lock
        // is taken.
        internal static string PendingLocation()
        {
            if (Volatile.Read(ref _table) != null || Volatile.Read(ref _ended) || GuestSession.OwnSlot < 0)
                return null;

            return Path.Combine(GuestSession.Directory, FileName);
        }

        private static bool TryOpenLocked(string Location)
        {
            if (_table != null)
                return true;

            if (_unavailable || _ended || Location == null || GuestSession.OwnSlot < 0)
                return false;

            _table = SessionMapping.OpenFile(Location, FileMode.OpenOrCreate, TableBytes);
            _unavailable = _table == null;
            return _table != null;
        }

        // A slot that a member left keeps its entries until the next owner clears them, so the new holder goes in last.
        private static byte* OwnRegion(string Location)
        {
            if (_ended || !TryOpenLocked(Location))
                return null;

            byte* Region = RegionAt(GuestSession.OwnSlot);
            ref ulong Holder = ref *(ulong*)(Region + HolderField);
            if (Volatile.Read(ref Holder) != GuestSession.OwnHolder)
            {
                ClearOxidEntries(Region);
                ClearRegistrationEntries(Region);
                Volatile.Write(ref Holder, GuestSession.OwnHolder);
            }

            return Region;
        }

        // The caller tests the holder for life after it releases the lock.
        private static byte* OtherRegion(int Slot, out ulong Holder)
        {
            Holder = 0;
            if (Slot == GuestSession.OwnSlot)
                return null;

            byte* Region = RegionAt(Slot);
            Holder = Volatile.Read(ref *(ulong*)(Region + HolderField));
            return Holder == 0 ? null : Region;
        }

        private static byte* RegionAt(int Slot) => _table.Base + (long)Slot * RegionBytes;

        private static byte* OxidEntryAt(byte* Region, int Index) => Region + RegionHeaderBytes + (long)Index * OxidEntryStride;

        private static byte* FindOxidEntry(byte* Region, ulong Oxid)
        {
            for (int Index = 0; Index < OxidCapacity; Index++)
            {
                byte* Entry = OxidEntryAt(Region, Index);
                if (*(ulong*)(Entry + OxidField) == Oxid)
                    return Entry;
            }

            return null;
        }

        private static void ClearOxidEntries(byte* Region)
        {
            for (int Index = 0; Index < OxidCapacity; Index++)
            {
                byte* Entry = OxidEntryAt(Region, Index);
                if (*(ulong*)(Entry + OxidField) != 0)
                    FreeOxidEntry(Entry);
            }
        }

        private static byte* CellAt(int Index) => _table.Base + CellsOffset + (long)Index * CellStride;

        private static byte* CellEntry(LaunchCell Cell)
        {
            if (_table == null || (uint)Cell.Index >= LaunchCellCapacity)
                return null;

            byte* Entry = CellAt(Cell.Index);
            return GenerationOf(Volatile.Read(ref *(ulong*)(Entry + CellStateField))) == Cell.Generation ? Entry : null;
        }

        private static ulong StateWord(uint Generation, uint State, uint Status) => ((ulong)Status << 32) | (Generation << 2) | State;

        private static uint StateOf(ulong Word) => (uint)Word & 3;

        private static uint GenerationOf(ulong Word) => ((uint)Word >> 2) & GenerationMask;

        private static uint StatusOf(ulong Word) => (uint)(Word >> 32);

        private static byte* RegistrationEntryAt(byte* Region, int Index) => Region + RegistrationsOffset + (long)Index * RegistrationEntryStride;

        private static byte* FindRegistrationEntry(byte* Region, uint Key)
        {
            for (int Index = 0; Index < RegistrationCapacity; Index++)
            {
                byte* Entry = RegistrationEntryAt(Region, Index);
                if (*(uint*)(Entry + KeyField) == Key)
                    return Entry;
            }

            return null;
        }

        private static void ClearRegistrationEntries(byte* Region)
        {
            for (int Index = 0; Index < RegistrationCapacity; Index++)
            {
                byte* Entry = RegistrationEntryAt(Region, Index);
                if (*(uint*)(Entry + KeyField) != 0)
                    FreeRegistrationEntry(Entry);
            }
        }

        private static void WriteRegistrationEntry(byte* Entry, in RpcssPortHandler.ClassRegistration Registration)
        {
            uint Writing = BeginWrite(Entry);
            *(uint*)(Entry + KeyField) = Registration.Key;
            *(Guid*)(Entry + ClassField) = Registration.Class;
            *(ulong*)(Entry + RegistrationOxidField) = Registration.Oxid;
            *(Guid*)(Entry + IpidField) = Registration.Ipid;
            *(uint*)(Entry + FlagsField) = Registration.Flags;
            *(uint*)(Entry + ProcessIdField) = Registration.ProcessId;
            *(uint*)(Entry + SidLengthField) = (uint)Registration.UserSid.Length;
            Registration.UserSid.CopyTo(new Span<byte>(Entry + SidField, NtQueryInformationToken.MaxSidLength));
            *(ushort*)(Entry + PackageLengthField) = (ushort)Registration.PackageFullName.Length;
            Registration.PackageFullName.AsSpan().CopyTo(new Span<char>(Entry + PackageField, PackageNameChars));
            EndWrite(Entry, Writing);
        }

        private static void FreeRegistrationEntry(byte* Entry)
        {
            uint Writing = BeginWrite(Entry);
            *(uint*)(Entry + KeyField) = 0;
            EndWrite(Entry, Writing);
        }

        private static bool TryCopyRegistrationEntry(byte* Entry, out RpcssPortHandler.ClassRegistration Registration)
        {
            Registration = default;
            uint SidLength = *(uint*)(Entry + SidLengthField);
            int PackageLength = *(ushort*)(Entry + PackageLengthField);
            if (SidLength > NtQueryInformationToken.MaxSidLength || PackageLength > PackageNameChars)
                return false;

            Registration = new RpcssPortHandler.ClassRegistration(*(uint*)(Entry + KeyField), *(Guid*)(Entry + ClassField), *(ulong*)(Entry + RegistrationOxidField),
                *(Guid*)(Entry + IpidField), *(uint*)(Entry + FlagsField), *(uint*)(Entry + ProcessIdField),
                new ReadOnlySpan<byte>(Entry + SidField, (int)SidLength).ToArray(), new string(new ReadOnlySpan<char>(Entry + PackageField, PackageLength)));
            return true;
        }

        private static bool Fits(in RpcssPortHandler.ServerOxid Server)
        {
            for (int Index = 0; Index < StringCount; Index++)
            {
                if (StringOf(Server, Index).Length > StringChars[Index])
                    return false;
            }

            return true;
        }

        private static string StringOf(in RpcssPortHandler.ServerOxid Server, int Index) => (Index switch
        {
            0 => Server.Endpoint,
            1 => Server.SecurityBindings,
            2 => Server.PackageFullName,
            3 => Server.UserSid,
            _ => Server.AppContainerSid,
        }) ?? string.Empty;

        // The odd generation marks a write in progress. A reader keeps its copy only when the generation it read
        // before the copy is even and unchanged after it, and the region's holder did not change.
        private static uint BeginWrite(byte* Entry)
        {
            ref uint Generation = ref *(uint*)(Entry + GenerationField);
            uint Writing = Generation | 1;
            Volatile.Write(ref Generation, Writing);
            Interlocked.MemoryBarrier();
            return Writing;
        }

        private static void EndWrite(byte* Entry, uint Writing) => Volatile.Write(ref *(uint*)(Entry + GenerationField), Writing + 1);

        private static uint BeginRead(byte* Entry) => Volatile.Read(ref *(uint*)(Entry + GenerationField));

        private static bool EndRead(byte* Region, byte* Entry, uint Generation, ulong Holder)
        {
            Interlocked.MemoryBarrier();
            return (Generation & 1) == 0 && Volatile.Read(ref *(uint*)(Entry + GenerationField)) == Generation
                && Volatile.Read(ref *(ulong*)(Region + HolderField)) == Holder;
        }

        private static void WriteOxidEntry(byte* Entry, ulong Oxid, in RpcssPortHandler.ServerOxid Server)
        {
            uint Writing = BeginWrite(Entry);

            *(ulong*)(Entry + OxidField) = Oxid;
            Server.Info.AsSpan(0, RpcssPortHandler.OxidInfoSize).CopyTo(new Span<byte>(Entry + InfoField, RpcssPortHandler.OxidInfoSize));

            for (int Index = 0; Index < StringCount; Index++)
            {
                string Value = StringOf(Server, Index);
                *(ushort*)(Entry + LengthsField + Index * sizeof(ushort)) = (ushort)Value.Length;
                Value.AsSpan().CopyTo(new Span<char>(Entry + StringOffsets[Index], StringChars[Index]));
            }

            EndWrite(Entry, Writing);
        }

        private static int[] StringOffsetsOf(int[] Chars)
        {
            int[] Offsets = new int[Chars.Length];
            int Offset = StringsField;
            for (int Index = 0; Index < Chars.Length; Index++)
            {
                Offsets[Index] = Offset;
                Offset += Chars[Index] * sizeof(char);
            }

            return Offsets;
        }

        private static void FreeOxidEntry(byte* Entry)
        {
            uint Writing = BeginWrite(Entry);
            *(ulong*)(Entry + OxidField) = 0;
            EndWrite(Entry, Writing);
        }

        private static bool TryCopyOxidEntry(byte* Entry, out ulong Oxid, out RpcssPortHandler.ServerOxid Server)
        {
            Server = default;
            Oxid = *(ulong*)(Entry + OxidField);
            if (!TryCopyString(Entry, 0, out string Endpoint) || !TryCopyString(Entry, 1, out string SecurityBindings) || !TryCopyString(Entry, 2, out string Package)
                || !TryCopyString(Entry, 3, out string UserSid) || !TryCopyString(Entry, 4, out string AppContainerSid))
                return false;

            byte[] Info = new ReadOnlySpan<byte>(Entry + InfoField, RpcssPortHandler.OxidInfoSize).ToArray();
            Server = new RpcssPortHandler.ServerOxid(Info, Endpoint, SecurityBindings, Package, UserSid, AppContainerSid);
            return true;
        }

        private static bool TryCopyString(byte* Entry, int Index, out string Value)
        {
            int Length = *(ushort*)(Entry + LengthsField + Index * sizeof(ushort));
            Value = Length <= StringChars[Index] ? new string(new ReadOnlySpan<char>(Entry + StringOffsets[Index], Length)) : null;
            return Value != null;
        }
    }
}
