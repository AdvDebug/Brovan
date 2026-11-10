using System;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDManipHookInitFunction : IWinSyscall
    {
        private const int BufferBytes = 0x208;

        // NT: RegisterDManipHook stores this path in the session state.
        private const string HookModule = WindowsVersionInfo.SystemRoot + @"\System32\directmanipulation.dll";
        private const string HookFunction = "InitializeDManipHook";

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ModulePtr = Instance.WinHelper.GetArg(0);
            ulong FunctionPtr = Instance.WinHelper.GetArg(1);

            if (!CanProbeForWrite(Instance, ModulePtr) || !CanProbeForWrite(Instance, FunctionPtr) ||
                !TryWriteString(Instance, ModulePtr, HookModule) || !TryWriteString(Instance, FunctionPtr, HookFunction))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool CanProbeForWrite(BinaryEmulator Instance, ulong Address)
            => (Address & 1) == 0 && NtWow64GetNativeSystemInformation.IsUserRange(Address, BufferBytes) &&
               Instance.IsAccessible(Address, BufferBytes, Write: true);

        private static bool TryWriteString(BinaryEmulator Instance, ulong Address, string Text)
        {
            Span<byte> Data = stackalloc byte[(Text.Length + 1) * sizeof(char)];
            Encoding.Unicode.GetBytes(Text, Data);
            Data[^2] = 0;
            Data[^1] = 0;
            return Instance.WriteMemory(Address, Data);
        }
    }
}
