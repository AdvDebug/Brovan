using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetTextFaceW : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int MaxChars = unchecked((int)Instance.WinHelper.GetArg(1));
            ulong BufferPtr = Instance.WinHelper.GetArg(2);

            string Face = Win32kHelper.GetDcFaceName(Instance, Hdc) ?? string.Empty;

            if (BufferPtr == 0)
            {
                Instance.SetRawSyscallReturn((uint)(Face.Length + 1));
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (MaxChars <= 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Face.Length >= MaxChars)
                Face = Face.Substring(0, MaxChars - 1);

            uint Bytes = (uint)((Face.Length + 1) * sizeof(char));
            if (!Instance.IsRegionMapped(BufferPtr, Bytes))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(Bytes).Slice(0, (int)Bytes);
            Data.Clear();
            Encoding.Unicode.GetBytes(Face, Data);

            if (!Instance.WriteMemory(BufferPtr, Data))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Instance.SetRawSyscallReturn((uint)(Face.Length + 1));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
