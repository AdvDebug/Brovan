using System;
using Brovan;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryAttributesFile : IWinSyscall
    {

        // FILE_BASIC_INFORMATION is 0x28 on x64 (40 bytes).
        private const uint FileBasicInformationSize = 0x28;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(0);
            ulong FileInformationPtr = Instance.WinHelper.GetArg64(1);

            if (ObjectAttributesPtr == 0 || FileInformationPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(FileInformationPtr, FileBasicInformationSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            string EmulatedPath = Instance.WinHelper.ResolveWindowsFilePath(FullName, Attributes.RootDirectory);
            if (string.IsNullOrEmpty(EmulatedPath))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            string HostPath = GeneralHelper.IO.ResolveHostPath(EmulatedPath, BinaryFormat.PE);
            if (string.IsNullOrEmpty(HostPath))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            bool Exists = File.Exists(HostPath) || Directory.Exists(HostPath);
            if (!Exists)
            {
                if (!Instance.WinHelper.IsSyntheticDirectory(EmulatedPath))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                FillSyntheticDirectoryInformation(Instance, FileInformationPtr);
                Instance.TriggerEventMessage($"[+] NtQueryAttributesFile: Name=\"{Name}\", FullName=\"{FullName}\", SyntheticDir=\"{EmulatedPath}\".", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }

            FillFileBasicInformation(Instance, FileInformationPtr, HostPath);

            Instance.TriggerEventMessage($"[+] NtQueryAttributesFile: Name=\"{Name}\", FullName=\"{FullName}\", HostPath=\"{HostPath}\".", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void FillSyntheticDirectoryInformation(BinaryEmulator Instance, ulong FileInformationPtr)
        {
            long Now = DateTime.UtcNow.ToFileTimeUtc();
            Instance._emulator.WriteMemory(FileInformationPtr + 0x00, (ulong)Now, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x08, (ulong)Now, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x10, (ulong)Now, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x18, (ulong)Now, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x20, (uint)FileAttributes.Directory, 4);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x24, 0u, 4);
        }

        private static void FillFileBasicInformation(BinaryEmulator Instance, ulong FileInformationPtr, string HostPath)
        {
            FileAttributes Attr;
            DateTime CreationUtc;
            DateTime LastAccessUtc;
            DateTime LastWriteUtc;

            if (Directory.Exists(HostPath))
            {
                DirectoryInfo di = new DirectoryInfo(HostPath);
                Attr = di.Attributes;
                CreationUtc = di.CreationTimeUtc;
                LastAccessUtc = di.LastAccessTimeUtc;
                LastWriteUtc = di.LastWriteTimeUtc;
            }
            else
            {
                FileInfo fi = new FileInfo(HostPath);
                Attr = fi.Attributes;
                CreationUtc = fi.CreationTimeUtc;
                LastAccessUtc = fi.LastAccessTimeUtc;
                LastWriteUtc = fi.LastWriteTimeUtc;
            }

            long CreationTime = CreationUtc.ToFileTimeUtc();
            long LastAccessTime = LastAccessUtc.ToFileTimeUtc();
            long LastWriteTime = LastWriteUtc.ToFileTimeUtc();
            long ChangeTime = LastWriteTime;

            Instance._emulator.WriteMemory(FileInformationPtr + 0x00, (ulong)CreationTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x08, (ulong)LastAccessTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x10, (ulong)LastWriteTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x18, (ulong)ChangeTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x20, (uint)Attr, 4);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x24, 0u, 4);
        }

    }
}
