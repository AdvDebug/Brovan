using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    // System V returns a by value struct of nine to sixteen bytes in RAX and RDX.
    [StructLayout(LayoutKind.Sequential)]
    internal struct SteamRetPair
    {
        public ulong Low;
        public ulong High;
    }

    internal sealed unsafe class BrovSteamState
    {
        private const uint MaxBlobBytes = 1u << 20;
        private const uint MaxStringBytes = 1u << 16;
        // The guest returns strings out of a fixed ring slot.
        private const uint MaxReturnedStringBytes = 8191;
        private const uint MaxStringArray = 1024;

        private readonly Dictionary<uint, (IntPtr Ptr, int Version)> Objects = new Dictionary<uint, (IntPtr, int)>();
        private readonly Dictionary<(IntPtr Ptr, int Version), uint> Ids = new Dictionary<(IntPtr, int), uint>();
        private readonly GenArena Arena = new GenArena();
        private uint Next = 1;

        public uint Register(IntPtr Pointer, int Version)
        {
            if (Pointer == IntPtr.Zero)
                return 0;

            if (Ids.TryGetValue((Pointer, Version), out uint Existing))
                return Existing;

            uint Id = Next++;
            Objects[Id] = (Pointer, Version);
            Ids[(Pointer, Version)] = Id;
            return Id;
        }

        public uint Register(IntPtr Pointer, byte* Version)
        {
            return Register(Pointer, BrovSteamGenDispatch.VersionIndex(Marshal.PtrToStringAnsi((IntPtr)Version)));
        }

        public IntPtr Lookup(uint Id, int Version)
        {
            if (Objects.TryGetValue(Id, out (IntPtr Ptr, int Version) Entry) && Entry.Version == Version)
                return Entry.Ptr;

            throw new InvalidOperationException($"BrovSteam: bad interface id {Id} for version index {Version}.");
        }

        public IntPtr Alloc(int Size) => Arena.Alloc(Size);

        public void FreeCallAllocs() => Arena.FreeCallAllocs();

        public byte* ReadString(GenReader R)
        {
            uint Length = R.ReadU32();
            if (Length == 0)
                return null;

            uint Count = Length - 1;
            if (Count > MaxStringBytes)
                throw new InvalidOperationException($"BrovSteam: string of {Count} bytes exceeds the cap.");

            IntPtr Buffer = Arena.Alloc((int)Count + 1);
            if (Count != 0)
                R.CopyInto(Buffer, Count);
            ((byte*)Buffer)[Count] = 0;
            return (byte*)Buffer;
        }

        public IntPtr ReadBlob(GenReader R)
        {
            if (R.ReadU32() == 0)
                return IntPtr.Zero;

            uint Length = R.ReadU32();
            if (Length > MaxBlobBytes)
                throw new InvalidOperationException($"BrovSteam: buffer of {Length} bytes exceeds the cap.");

            if (Length == 0)
                return Arena.Alloc(1);

            IntPtr Buffer = Arena.Alloc((int)Length);
            R.CopyInto(Buffer, Length);
            return Buffer;
        }

        public IntPtr ReadStruct(GenReader R, int Size)
        {
            if (R.ReadU32() == 0)
                return IntPtr.Zero;

            uint Length = R.ReadU32();
            if (Length != (uint)Size)
                throw new InvalidOperationException($"BrovSteam: struct of {Length} bytes where {Size} were expected.");

            IntPtr Buffer = Arena.Alloc(Size);
            R.CopyInto(Buffer, (uint)Size);
            return Buffer;
        }

        public IntPtr ReadStringArray(GenReader R)
        {
            if (R.ReadU32() == 0)
                return IntPtr.Zero;

            uint Count = R.ReadU32();
            if (Count > MaxStringArray)
                throw new InvalidOperationException($"BrovSteam: string array of {Count} entries exceeds the cap.");

            IntPtr Pointers = Arena.Alloc((int)(Count == 0 ? 1 : Count) * IntPtr.Size);
            for (uint i = 0; i < Count; i++)
                ((IntPtr*)Pointers)[i] = (IntPtr)ReadString(R);

            // SteamParamStringArray_t is { const char **m_ppStrings; int32 m_nNumStrings; }
            IntPtr Array = Arena.Alloc(16);
            *(IntPtr*)Array = Pointers;
            *(int*)((byte*)Array + 8) = (int)Count;
            return Array;
        }

        public IntPtr ReadOutSlot(GenReader R, int Size)
        {
            return R.ReadU32() == 0 ? IntPtr.Zero : Arena.Alloc(Size);
        }

        public IntPtr ReadOutBuffer(GenReader R, out uint Capacity)
        {
            Capacity = 0;
            if (R.ReadU32() == 0)
                return IntPtr.Zero;

            Capacity = R.ReadU32();
            if (Capacity > MaxBlobBytes)
                throw new InvalidOperationException($"BrovSteam: output buffer of {Capacity} bytes exceeds the cap.");

            return Arena.Alloc((int)(Capacity == 0 ? 1 : Capacity));
        }

        // The client writes Count bytes into a block the guest sized separately, so the two have to agree.
        public static void CheckOutCapacity(IntPtr Buffer, uint Capacity, long Count)
        {
            if (Buffer == IntPtr.Zero)
                return;

            if (Count < 0 || (ulong)Count > Capacity)
                throw new InvalidOperationException($"BrovSteam: byte count {Count} does not fit the {Capacity} byte output buffer.");
        }

        public void WriteString(GenBuf W, IntPtr Text)
        {
            if (Text == IntPtr.Zero)
            {
                W.WriteU32(0);
                return;
            }

            uint Length = 0;
            byte* P = (byte*)Text;
            while (Length < MaxReturnedStringBytes && P[Length] != 0)
                Length++;

            W.WriteU32(Length + 1);
            if (Length != 0)
                W.WriteBytesFrom(Text, Length);
        }

        public void WriteOutSlot(GenBuf W, IntPtr Slot, int Size)
        {
            if (Slot != IntPtr.Zero)
                W.WriteBytesFrom(Slot, (uint)Size);
        }

        public void WriteOutString(GenBuf W, IntPtr Slot)
        {
            if (Slot != IntPtr.Zero)
                WriteString(W, *(IntPtr*)Slot);
        }

        public void WriteOutBuffer(GenBuf W, IntPtr Buffer, uint Capacity)
        {
            if (Buffer == IntPtr.Zero)
                return;

            W.WriteU32(Capacity);
            W.WriteBytesFrom(Buffer, Capacity);
        }
    }
}
