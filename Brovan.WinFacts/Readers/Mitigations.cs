using System.Runtime.InteropServices;
using System.Text;

namespace Brovan.WinFacts.Readers
{
    // Unicorn jumps into the code it translates through indirect calls, which Control Flow Guard refuses. On Windows the
    // tool runs itself again with CFG turned off for the child, as Brovan does.
    internal static class Mitigations
    {
        private const string ChildVariable = "BROVAN_WINFACTS_CFG_OFF";
        private const int ProcessControlFlowGuardPolicy = 7;
        private const int ProcThreadAttributeMitigationPolicy = 0x00020007;
        private const ulong ControlFlowGuardAlwaysOff = 0x2UL << 40;
        private const ulong UserShadowStacksAlwaysOff = 0x2UL << 8;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint StartfUseStdHandles = 0x00000100;
        private const uint Infinite = 0xFFFFFFFF;

        // Null when this process can run Unicorn itself.
        internal static int? RunWithoutControlFlowGuard()
        {
            if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable(ChildVariable) != null || !ControlFlowGuardEnabled())
                return null;

            IntPtr Size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref Size);
            IntPtr List = Marshal.AllocHGlobal(Size);
            IntPtr Policy = Marshal.AllocHGlobal(2 * sizeof(ulong));
            try
            {
                if (!InitializeProcThreadAttributeList(List, 1, 0, ref Size))
                    throw new InvalidOperationException("InitializeProcThreadAttributeList failed");

                // The second policy word turns user shadow stacks off too, where the host knows it.
                Marshal.WriteInt64(Policy, unchecked((long)ControlFlowGuardAlwaysOff));
                Marshal.WriteInt64(Policy + sizeof(ulong), unchecked((long)UserShadowStacksAlwaysOff));
                if (!UpdateProcThreadAttribute(List, 0, ProcThreadAttributeMitigationPolicy, Policy, 2 * sizeof(ulong), IntPtr.Zero, IntPtr.Zero) &&
                    !UpdateProcThreadAttribute(List, 0, ProcThreadAttributeMitigationPolicy, Policy, sizeof(ulong), IntPtr.Zero, IntPtr.Zero))
                    throw new InvalidOperationException("UpdateProcThreadAttribute failed");

                StartupInfoEx Startup = new();
                Startup.StartupInfo.cb = Marshal.SizeOf<StartupInfoEx>();
                Startup.StartupInfo.dwFlags = StartfUseStdHandles;
                Startup.StartupInfo.hStdInput = GetStdHandle(-10);
                Startup.StartupInfo.hStdOutput = GetStdHandle(-11);
                Startup.StartupInfo.hStdError = GetStdHandle(-12);
                Startup.lpAttributeList = List;

                // Under "dotnet Brovan.WinFacts.dll" the command line starts at the assembly, so the host goes in front of it.
                StringBuilder CommandLine = new(Environment.CommandLine);
                if (!string.Equals(Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0]), Path.GetFileNameWithoutExtension(Environment.ProcessPath),
                        StringComparison.OrdinalIgnoreCase))
                    CommandLine.Insert(0, $"\"{Environment.ProcessPath}\" ");

                Environment.SetEnvironmentVariable(ChildVariable, "1");
                if (!CreateProcessW(Environment.ProcessPath, CommandLine, IntPtr.Zero, IntPtr.Zero, true, ExtendedStartupInfoPresent, IntPtr.Zero,
                        Environment.CurrentDirectory, ref Startup, out ProcessInformation Process))
                    throw new InvalidOperationException($"CreateProcessW failed: {Marshal.GetLastPInvokeError()}");

                WaitForSingleObject(Process.hProcess, Infinite);
                GetExitCodeProcess(Process.hProcess, out uint ExitCode);
                CloseHandle(Process.hThread);
                CloseHandle(Process.hProcess);
                return unchecked((int)ExitCode);
            }
            finally
            {
                DeleteProcThreadAttributeList(List);
                Marshal.FreeHGlobal(List);
                Marshal.FreeHGlobal(Policy);
            }
        }

        private static bool ControlFlowGuardEnabled()
        {
            uint Flags = 0;
            return GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, ref Flags, sizeof(uint)) && (Flags & 1) != 0;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int cb;
            public string lpReserved, lpDesktop, lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr List, int Count, int Flags, ref IntPtr Size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr List, uint Flags, IntPtr Attribute, IntPtr Value, IntPtr Size, IntPtr Previous, IntPtr ReturnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr List);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string Application, StringBuilder CommandLine, IntPtr ProcessAttributes, IntPtr ThreadAttributes,
            bool InheritHandles, uint CreationFlags, IntPtr Environment, string CurrentDirectory, ref StartupInfoEx Startup, out ProcessInformation Process);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr Handle, uint Milliseconds);

        [DllImport("kernel32.dll")]
        private static extern bool GetExitCodeProcess(IntPtr Process, out uint ExitCode);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr Handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(int Which);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern bool GetProcessMitigationPolicy(IntPtr Process, int Policy, ref uint Buffer, int Size);
    }
}
