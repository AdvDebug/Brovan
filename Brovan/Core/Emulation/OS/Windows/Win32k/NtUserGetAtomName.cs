using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetAtomName : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ushort Atom = (ushort)Instance.WinHelper.GetArg(0);
            ulong StringPtr = Instance.WinHelper.GetArg(1);

            uint BufferOffset = (uint)Instance.WinHelper.PointerSize;
            uint StructSize = BufferOffset * 2;

            if (StringPtr == 0 || !Instance.IsRegionMapped(StringPtr, StructSize) ||
                !Instance.WinHelper.TryGetAtomName(Atom, out string Name))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ushort MaximumLength = (ushort)(Instance.ReadMemoryUInt(StringPtr) >> 16);
            ulong Buffer = Instance.WinHelper.ReadPointer(StringPtr + BufferOffset);

            int MaxChars = MaximumLength / sizeof(char);
            if (Buffer == 0 || MaxChars <= 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Name.Length >= MaxChars)
                Name = Name.Substring(0, MaxChars - 1);

            uint NameBytes = (uint)((Name.Length + 1) * sizeof(char));
            if (!Instance.IsRegionMapped(Buffer, NameBytes))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Bytes = Instance.WinHelper.Shared.GetSpan(NameBytes);
            Bytes.Clear();
            Encoding.Unicode.GetBytes(Name, Bytes);

            if (!Instance.WriteMemory(Buffer, Bytes))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn((uint)Name.Length);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
