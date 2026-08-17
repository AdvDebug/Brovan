using System;
using Brovan;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryFullAttributesFile : IWinSyscall
    {

        // FILE_NETWORK_OPEN_INFORMATION is 0x38 on both x64 and x86.
        private const uint FileNetworkOpenInformationSize = 0x38;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(0);
            ulong FileInformationPtr = Instance.WinHelper.GetArg(1);

            if (ObjectAttributesPtr == 0 || FileInformationPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(FileInformationPtr, FileNetworkOpenInformationSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out ulong AttributesRoot, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            string EmulatedPath = Instance.WinHelper.ResolveWindowsFilePath(FullName, AttributesRoot);
            if (string.IsNullOrEmpty(EmulatedPath))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            string HostPath = GeneralHelper.IO.ResolveHostPath(EmulatedPath, BinaryFormat.PE);
            if (string.IsNullOrEmpty(HostPath))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            bool Exists = File.Exists(HostPath) || Directory.Exists(HostPath);
            if (!Exists)
            {

                if (!Instance.WinHelper.IsSyntheticDirectory(EmulatedPath))
                {
                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[!] NtQueryFullAttributesFile: file not found: Name=\"{Name}\", FullName=\"{FullName}\", SyntheticDir=\"{EmulatedPath}\".", LogFlags.Syscall);
                    return NtCreateFile.ParentDirectoryExists(EmulatedPath)
                        ? NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND
                        : NTSTATUS.STATUS_OBJECT_PATH_NOT_FOUND;
                }

                FillSyntheticDirectoryInformation(Instance, FileInformationPtr);
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtQueryFullAttributesFile: Name=\"{Name}\", FullName=\"{FullName}\", SyntheticDir=\"{EmulatedPath}\".", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }

            FillNetworkOpenInformation(Instance, FileInformationPtr, HostPath);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtQueryFullAttributesFile: Name=\"{Name}\", FullName=\"{FullName}\", HostPath=\"{HostPath}\".", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void FillSyntheticDirectoryInformation(BinaryEmulator Instance, ulong FileInformationPtr)
        {
            long Now = DateTime.UtcNow.ToFileTimeUtc();
            Instance._emulator.WriteMemory(FileInformationPtr + 0x00, (ulong)Now, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x08, (ulong)Now, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x10, (ulong)Now, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x18, (ulong)Now, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x20, 0UL, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x28, 0UL, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x30, (uint)FileAttributes.Directory, 4);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x34, 0u, 4);
        }

        private static void FillNetworkOpenInformation(BinaryEmulator Instance, ulong FileInformationPtr, string HostPath)
        {
            FileAttributes Attr;
            DateTime CreationUtc;
            DateTime LastAccessUtc;
            DateTime LastWriteUtc;
            ulong EndOfFile = 0;

            if (Directory.Exists(HostPath))
            {
                DirectoryInfo di = new DirectoryInfo(HostPath);
                Attr = di.Attributes;
                CreationUtc = di.CreationTimeUtc;
                LastAccessUtc = di.LastAccessTimeUtc;
                LastWriteUtc = di.LastWriteTimeUtc;
                if ((Attr & FileAttributes.Directory) == 0)
                    Attr |= FileAttributes.Directory;
            }
            else
            {
                FileInfo fi = new FileInfo(HostPath);
                Attr = fi.Attributes;
                CreationUtc = fi.CreationTimeUtc;
                LastAccessUtc = fi.LastAccessTimeUtc;
                LastWriteUtc = fi.LastWriteTimeUtc;
                EndOfFile = (ulong)Math.Max(fi.Length, 0);
            }

            if (Attr == 0)
                Attr = FileAttributes.Normal;

            long CreationTime = CreationUtc.ToFileTimeUtc();
            long LastAccessTime = LastAccessUtc.ToFileTimeUtc();
            long LastWriteTime = LastWriteUtc.ToFileTimeUtc();
            long ChangeTime = LastWriteTime;

            ulong AllocationSize = EndOfFile == 0 ? 0UL : (EndOfFile + 0xFFF) & ~0xFFFUL;

            Instance._emulator.WriteMemory(FileInformationPtr + 0x00, (ulong)CreationTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x08, (ulong)LastAccessTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x10, (ulong)LastWriteTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x18, (ulong)ChangeTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x20, AllocationSize, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x28, EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x30, (uint)Attr, 4);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x34, 0u, 4);
        }

    }
}
