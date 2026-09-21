using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAddAtomEx : IWinSyscall
    {
        private const int MaxAtomChars = 255;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong NamePtr = Instance.WinHelper.GetArg(0);
            uint Length = Instance.WinHelper.GetArg32(1);
            ulong AtomPtr = Instance.WinHelper.GetArg(2);

            if (NamePtr == 0 || Length == 0 || Length > MaxAtomChars * 2 || (Length & 1) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(NamePtr, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Length).Slice(0, (int)Length);
            if (!Instance.ReadMemory(NamePtr, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string Name = Encoding.Unicode.GetString(Buffer).TrimEnd('\0');
            if (Name.Length == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // A registered window message and a global atom come out of the same table on NT.
            ushort Atom = Instance.WinHelper.RegisterWindowMessageAtom(Name);
            if (Atom == 0)
                return NTSTATUS.STATUS_NO_MEMORY;

            if (AtomPtr != 0 && !Instance._emulator.WriteMemory(AtomPtr, Atom, 2))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
