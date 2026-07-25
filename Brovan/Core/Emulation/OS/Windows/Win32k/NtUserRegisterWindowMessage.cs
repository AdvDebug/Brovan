using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRegisterWindowMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong NamePtr = Instance.WinHelper.GetArg(0);

            bool Read = Instance.WinHelper.TryReadUnicodeString(NamePtr, out string Name, out _);

            Instance.SetRawSyscallReturn(Read ? Instance.WinHelper.RegisterWindowMessageAtom(Name) : (ushort)0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
