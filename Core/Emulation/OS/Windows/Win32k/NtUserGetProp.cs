using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetProp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong PropertyName = Instance.WinHelper.GetArg64(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Result = 0;

            if (PropertyName <= 0xFFFF)
            {
                Window.AtomProperties.TryGetValue((ushort)PropertyName, out Result);
            }
            else
            {
                string Name = ReadNullTerminatedUnicodeString(Instance, PropertyName);
                if (Name == null)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Window.StringProperties.TryGetValue(Name, out Result);
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string ReadNullTerminatedUnicodeString(BinaryEmulator Instance, ulong Address)
        {
            if (Address == 0)
                return null;

            if (!Instance.IsRegionMapped(Address, 2))
                return null;

            StringBuilder Builder = new StringBuilder();
            ulong Current = Address;

            for (int i = 0; i < 32767; i++)
            {
                if (!Instance.IsRegionMapped(Current, 2))
                    return null;

                byte[] Bytes = Instance._emulator.ReadMemory(Current, 2);
                ushort Character = BitConverter.ToUInt16(Bytes, 0);
                if (Character == 0)
                    return Builder.ToString();

                Builder.Append((char)Character);
                Current += 2;
            }

            return Builder.ToString();
        }
    }
}
