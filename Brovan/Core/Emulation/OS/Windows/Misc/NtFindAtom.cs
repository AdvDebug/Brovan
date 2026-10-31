using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtFindAtom : IWinSyscall
    {
        private const int MaxAtomChars = 255;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong NamePtr = Instance.WinHelper.GetArg(0);
            uint Length = Instance.WinHelper.GetArg32(1);
            ulong AtomPtr = Instance.WinHelper.GetArg(2);

            if (Length > MaxAtomChars * 2)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (AtomPtr != 0 && !Instance.IsRegionMapped(AtomPtr, 2))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (NamePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Length != 0 && (NamePtr & 1) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Length).Slice(0, (int)Length);
            if (Length != 0 && !Instance.ReadMemory(NamePtr, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string Name = Encoding.Unicode.GetString(Buffer);
            int End = Name.IndexOf('\0');
            if (End >= 0)
                Name = Name.Substring(0, End);

            if (Name.Length == 0)
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            if (!Instance.WinHelper.TryFindGlobalAtom(Name, out ushort Atom))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            if (AtomPtr != 0 && !Instance._emulator.WriteMemory(AtomPtr, Atom, 2))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
