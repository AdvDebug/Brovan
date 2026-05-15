using System;
using System.IO;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenSection : IWinSyscall
    {
        private const uint SEC_IMAGE = 0x01000000;
        private const uint PAGE_EXECUTE_READ = 0x20;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong SectionHandlePtr = Instance.WinHelper.GetArg64(0);
            AccessMask DesiredAccess = (AccessMask)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

            if (SectionHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SectionHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            // Normalize \Sessions\X\Windows\SharedSection into a single object.
            if (IsWindowsSharedSection(FullName))
            {
                FullName = "\\Windows\\SharedSection";
                Name = "SharedSection";
            }

            uint AllocationAttributes = 0;
            uint SectionPageProtection = 0;

            string ResolvedKnownDllBackingPath = null;

            if (IsKnownDllPath(Instance, Attributes.RootDirectory, FullName))
            {
                ResolvedKnownDllBackingPath = ResolveKnownDllBackingPath(Instance, Attributes.RootDirectory, FullName, Name);
                AllocationAttributes = SEC_IMAGE;
                SectionPageProtection = PAGE_EXECUTE_READ;
            }

            WinSection Existing = FindSectionByName(Instance, FullName, Name);
            if (Existing != null)
            {
                if (Existing.IsImage && Existing.ImageSectionId == 0 && !string.IsNullOrEmpty(ResolvedKnownDllBackingPath))
                {
                    Existing.Path = ResolvedKnownDllBackingPath;
                    Existing.FileStream = WindowsFileStream.FromGuestPath(ResolvedKnownDllBackingPath);
                    Instance.WinHelper.AttachImageSectionIdentity(Existing, ResolvedKnownDllBackingPath);
                }

                WinHandle ExistingHandle = Instance.WinHelper.HandleManager.AddHandle(Existing, DesiredAccess);
                Instance.WinHelper.WinHandles.Add(ExistingHandle);

                if (!Instance._emulator.WriteMemory(SectionHandlePtr, (ulong)ExistingHandle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance.TriggerEventMessage($"[+] NtOpenSection: Name=\"{Name}\", FullName=\"{FullName}\", Handle=0x{ExistingHandle.Handle:X} (reused).", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

            if (IsWindowsSharedSection(FullName))
            {
                ulong SharedSectionSize = 0x10000;

                ulong SharedSectionAddress = Instance.MapUniqueAddress((uint)SharedSectionSize, MemoryProtection.ReadWrite);

                if (SharedSectionAddress == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                WinHandle SharedSectionHandle = Instance.WinHelper.CreateSectionHandle(FullName, SharedSectionSize, (uint)Instance.WinHelper.ConvertInternalToWinProtect(MemoryProtection.ReadWrite), 0, null, SharedSectionAddress, DesiredAccess);

                if (!Instance._emulator.WriteMemory(SectionHandlePtr, (ulong)SharedSectionHandle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance.TriggerEventMessage($"[+] NtOpenSection: Name=\"{Name}\", FullName=\"{FullName}\", Handle=0x{SharedSectionHandle.Handle:X}, SharedSection.", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

            string ResolvedBackingPath = ResolvedKnownDllBackingPath ?? ResolveKnownDllBackingPath(Instance, Attributes.RootDirectory, FullName, Name);
            if (ResolvedBackingPath == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            WindowsFileStream Stream = WindowsFileStream.FromGuestPath(ResolvedBackingPath);
            if (!Stream.ExistsAsFile)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            ulong Size = (ulong)Stream.Length;
            if (Size == 0 || Size > uint.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool IsImage = (AllocationAttributes & SEC_IMAGE) != 0;
            ulong BackingAddress = 0;
            if (!IsImage)
            {
                BackingAddress = Instance.MapUniqueAddress((uint)Size, MemoryProtection.ReadWrite);
                if (BackingAddress == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (!Stream.TryReadAllBytes(out byte[] Data))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                if (Data.Length != 0 && !Instance.WriteMemory(BackingAddress, Data))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            WinHandle Handle = Instance.WinHelper.CreateSectionHandle(FullName, Size, SectionPageProtection, AllocationAttributes, ResolvedBackingPath, BackingAddress, DesiredAccess);

            if (!Instance._emulator.WriteMemory(SectionHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.TriggerEventMessage($"[+] NtOpenSection: Name=\"{Name}\", FullName=\"{FullName}\", File=\"{ResolvedBackingPath}\", Handle=0x{Handle.Handle:X}, Attributes=0x{AllocationAttributes:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsWindowsSharedSection(string FullName)
        {
            if (string.IsNullOrEmpty(FullName))
                return false;

            if (string.Equals(FullName, "\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase))
                return true;

            return FullName.EndsWith("\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsKnownDllPath(BinaryEmulator Instance, ulong RootDirectory, string FullName)
        {
            if (RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY || RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY)
                return true;

            if (!string.IsNullOrEmpty(FullName))
            {
                if (FullName.StartsWith("\\KnownDlls\\", StringComparison.OrdinalIgnoreCase))
                    return true;

                if (FullName.StartsWith("\\KnownDlls32\\", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static WinSection FindSectionByName(BinaryEmulator Instance, string FullName, string ShortName)
        {
            foreach (WinSection s in Instance.WinHelper.WinSections)
            {
                if (s == null || string.IsNullOrEmpty(s.Name))
                    continue;

                if (string.Equals(s.Name, FullName, StringComparison.OrdinalIgnoreCase))
                    return s;

                if (string.Equals(s.Name, ShortName, StringComparison.OrdinalIgnoreCase))
                    return s;
            }

            return null;
        }

        private static string ResolveKnownDllBackingPath(BinaryEmulator Instance, ulong RootDirectory, string FullName, string Name)
        {
            bool IsKnownDlls =
                RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY ||
                FullName.StartsWith("\\KnownDlls\\", StringComparison.OrdinalIgnoreCase);

            bool IsKnownDlls32 =
                RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY ||
                FullName.StartsWith("\\KnownDlls32\\", StringComparison.OrdinalIgnoreCase);

            if (!IsKnownDlls && !IsKnownDlls32)
                return null;

            string Leaf = Name;

            int Slash = FullName.LastIndexOf('\\');
            if (Slash >= 0 && Slash + 1 < FullName.Length)
                Leaf = FullName.Substring(Slash + 1);

            if (string.IsNullOrEmpty(Leaf))
                return null;

            string BaseDir = IsKnownDlls32 ? @"C:\Windows\SysWOW64" : @"C:\Windows\System32";
            return Path.Combine(BaseDir, Leaf);
        }
    }
}
