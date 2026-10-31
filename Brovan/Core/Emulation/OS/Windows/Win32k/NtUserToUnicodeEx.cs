using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserToUnicodeEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint VirtualKey = Instance.WinHelper.GetArg32(0);
            uint ScanCode = Instance.WinHelper.GetArg32(1);
            ulong KeyStatePtr = Instance.WinHelper.GetArg(2);
            ulong BufferPtr = Instance.WinHelper.GetArg(3);
            int BufferCharacters = unchecked((int)Instance.WinHelper.GetArg32(4));

            if (BufferCharacters <= 0)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Span<byte> KeyState = stackalloc byte[Win32kHelper.KeyStateSize];
            if (!Instance.ReadMemory(KeyStatePtr, KeyState))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<char> Characters = stackalloc char[Win32kHelper.MaxKeyCharacters];
            int Count = Win32kHelper.TranslateKey(Instance, VirtualKey, ScanCode, KeyState, Characters.Slice(0, Math.Min(BufferCharacters, Win32kHelper.MaxKeyCharacters)));

            // NT zero-fills the unused output.
            ReadOnlySpan<byte> Produced = MemoryMarshal.AsBytes(Characters.Slice(0, Math.Abs(Count)));
            if (!Instance.WinHelper.WritePadded(BufferPtr, (ulong)BufferCharacters * sizeof(char), Produced))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(unchecked((uint)Count));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
