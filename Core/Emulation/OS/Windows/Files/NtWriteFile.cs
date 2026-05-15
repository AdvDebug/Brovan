using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtWriteFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong FileHandle = Instance.WinHelper.GetArg64(0);
            ulong EventHandle = Instance.WinHelper.GetArg64(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg64(2);
            ulong ApcContext = Instance.WinHelper.GetArg64(3);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(4);
            ulong BufferPtr = Instance.WinHelper.GetArg64(5);
            uint Length = (uint)Instance.WinHelper.GetArg64(6, true);
            ulong ByteOffsetPtr = Instance.WinHelper.GetArg64(7);
            ulong KeyPtr = Instance.WinHelper.GetArg64(8);

            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, 0x10))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Length != 0)
            {
                if (BufferPtr == 0 || !Instance.IsRegionMapped(BufferPtr, Length))
                {
                    Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
            }

            ulong StdOut = Instance.WinHelper.STD_OUT.Handle;
            if (FileHandle == StdOut)
                return HandleStdOut(Instance, IoStatusBlockPtr, BufferPtr, Length);

            WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (FileObj == null)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (FileObj.Device)
            {
                if (NullDevice.IsNullDevicePath(FileObj.Path))
                {
                    if (!HasWriteAccess(Instance, FileHandle))
                    {
                        Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                        return NTSTATUS.STATUS_ACCESS_DENIED;
                    }

                    Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Length);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (FileObj.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_IS_A_DIRECTORY, 0);
                return NTSTATUS.STATUS_FILE_IS_A_DIRECTORY;
            }

            if (!HasWriteAccess(Instance, FileHandle))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if (WarnWrite(FileObj.Path, out string WarnData))
            {
                Instance.TriggerEventMessage($"[!] The emulated program tried to write to {WarnData}", LogFlags.Suspicious);
            }

            Span<byte> Incoming = Length == 0 ? Span<byte>.Empty : Instance.WinHelper.ReadMemorySpan(BufferPtr, Length);
            if (Length != 0 && Incoming.Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            WindowsFileStream Stream = FileObj.GetFileStream(true);
            if (Stream == null)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            bool AppendOnly = IsAppendOnlyHandle(Instance, FileHandle);
            long Offset = AppendOnly ? Stream.Length : Instance.WinHelper.GetEffectiveFileOffset(ByteOffsetPtr, FileObj.Position);
            if (Offset < 0)
                Offset = 0;

            if (Incoming.Length != 0 && FileObj.HasConflictingIoLock((ulong)Offset, (ulong)Incoming.Length, true))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_LOCK_CONFLICT, 0);
                return NTSTATUS.STATUS_FILE_LOCK_CONFLICT;
            }

            try
            {
                if (Incoming.Length != 0)
                    Stream.WriteAt(Offset, Incoming);
            }
            catch
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            FileObj.Real = true;
            FileObj.Position = Offset + Incoming.Length;

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Incoming.Length);

            Instance.TriggerEventMessage($"[+] NtWriteFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Wrote=0x{Incoming.Length:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleStdOut(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length)
        {
            if (Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Data = Instance.WinHelper.ReadMemorySpan(BufferPtr, Length);
            if (Data.Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            GeneralHelper.ConsoleWrite(Data, Instance.Settings.ConsoleOutputMode);
            Console.Out.Flush();

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Data.Length);
            return NTSTATUS.STATUS_SUCCESS;
        }


        private static bool HasWriteAccess(BinaryEmulator Instance, ulong FileHandle)
        {
            AccessMask Granted = Instance.WinHelper.HandleManager.GetPermissionsByHandle(FileHandle);

            if ((Granted & AccessMask.GenericAll) == AccessMask.GenericAll)
                return true;

            if ((Granted & AccessMask.GenericWrite) == AccessMask.GenericWrite)
                return true;

            if ((Granted & AccessMask.FileAllAccess) == AccessMask.FileAllAccess)
                return true;

            if ((Granted & AccessMask.FileWriteData) == AccessMask.FileWriteData)
                return true;

            if ((Granted & AccessMask.FileAppendData) == AccessMask.FileAppendData)
                return true;

            return false;
        }

        private static bool IsAppendOnlyHandle(BinaryEmulator Instance, ulong FileHandle)
        {
            AccessMask Granted = Instance.WinHelper.HandleManager.GetPermissionsByHandle(FileHandle);

            if ((Granted & AccessMask.FileAppendData) == AccessMask.FileAppendData &&
                (Granted & AccessMask.FileWriteData) != AccessMask.FileWriteData &&
                (Granted & AccessMask.GenericWrite) != AccessMask.GenericWrite &&
                (Granted & AccessMask.GenericAll) != AccessMask.GenericAll)
            {
                return true;
            }

            return false;
        }

        private static bool WarnWrite(string Path, out string Data)
        {
            Data = string.Empty;

            if (string.IsNullOrWhiteSpace(Path))
                return false;

            Path = Path.Replace('/', '\\').TrimEnd('\\');

            if (Path.Equals(@"\\.\PhysicalDrive0", StringComparison.OrdinalIgnoreCase))
            {
                Data = "PhysicalDrive0 (raw disk / possible MBR)";
                return true;
            }

            if (Path.Equals(@"\\.\PhysicalDrive1", StringComparison.OrdinalIgnoreCase))
            {
                Data = "PhysicalDrive1 (raw disk)";
                return true;
            }

            if (Path.Equals(@"\\.\PhysicalDrive2", StringComparison.OrdinalIgnoreCase))
            {
                Data = "PhysicalDrive2 (raw disk)";
                return true;
            }

            if (Path.Equals(@"\\.\PhysicalDrive3", StringComparison.OrdinalIgnoreCase))
            {
                Data = "PhysicalDrive3 (raw disk)";
                return true;
            }

            if (Path.Equals(@"\\.\C:", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A raw volume device";
                return true;
            }

            if (Path.Equals(@"C:\Boot\BCD", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The Boot Configuration Data";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\SAM", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The SAM database";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\SECURITY", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The SECURITY hive";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\SYSTEM", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The SYSTEM hive";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\SOFTWARE", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The SOFTWARE hive";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\DEFAULT", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The DEFAULT hive";
                return true;
            }

            if (Path.StartsWith(@"\\.\HarddiskVolume", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A raw volume device";
                return true;
            }

            if (Path.StartsWith(@"\\?\GLOBALROOT\Device\Harddisk", StringComparison.OrdinalIgnoreCase) ||
                Path.StartsWith(@"\Device\Harddisk", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A low-level disk device";
                return true;
            }

            if (Path.StartsWith(@"C:\Windows\System32\drivers\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The drivers folder";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\Tasks", StringComparison.OrdinalIgnoreCase) ||
                Path.StartsWith(@"C:\Windows\System32\Tasks\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The tasks folder directly";
                return true;
            }

            if (Path.StartsWith(@"C:\EFI\", StringComparison.OrdinalIgnoreCase) ||
                Path.StartsWith(@"C:\Windows\Boot\EFI\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "EFI boot files";
                return true;
            }

            if (Path.StartsWith(@"C:\Windows\System32\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A core Windows system32 directory";
                return true;
            }

            if (Path.StartsWith(@"C:\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A core Windows WOW64 system directory";
                return true;
            }

            if (Path.StartsWith(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The all-users Startup folder";
                return true;
            }

            return false;
        }
    }
}