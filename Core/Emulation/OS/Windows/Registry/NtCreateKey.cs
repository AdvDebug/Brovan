using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong HandlePtr = Instance.WinHelper.GetArg64(0);
                AccessMask DesiredAccess = (AccessMask)Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
                uint TitleIndex = (uint)Instance.WinHelper.GetArg64(3, true);
                ulong ClassPtr = Instance.WinHelper.GetArg64(4);
                uint CreateOptions = (uint)Instance.WinHelper.GetArg64(5, true);
                ulong DispositionPtr = Instance.WinHelper.GetArg64(6);

                if (HandlePtr == 0 || ObjectAttributesPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(HandlePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (DispositionPtr != 0 && !Instance.IsRegionMapped(DispositionPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (ClassPtr != 0)
                {
                    uint UnicodeStringSize = (uint)Marshal.SizeOf<UNICODE_STRING64>();
                    if (!Instance.IsRegionMapped(ClassPtr, UnicodeStringSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (!Instance.WinHelper.TryResolveRegistryObjectPath64(ObjectAttributesPtr, NTSTATUS.STATUS_INVALID_PARAMETER, NTSTATUS.STATUS_INVALID_PARAMETER, NTSTATUS.STATUS_INVALID_PARAMETER, out string KeyPath, out NTSTATUS Status))
                {
                    return Status;
                }

                Instance.TriggerEventMessage($"[+] NtCreateKey Running with the KeyPath: {KeyPath}", LogFlags.Syscall);

                KeyPath = Instance.WinHelper.NormalizeNtRegistryPath(KeyPath);
                if (string.IsNullOrEmpty(KeyPath))
                    return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

                bool CreatedNew = false;
                if (!Instance.WinHelper.RegistryKeyExists(KeyPath, out _, out _, out _) && !Instance.WinHelper.CreateRegistryKeyPath(KeyPath, out CreatedNew))
                {
                    return NTSTATUS.STATUS_OBJECT_PATH_NOT_FOUND;
                }

                WinHandle Handle = Instance.WinHelper.OpenRegistryKey(KeyPath, DesiredAccess);
                if (Handle == null || Handle.Handle == 0)
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                if (!Instance._emulator.WriteMemory(HandlePtr, Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (DispositionPtr != 0)
                {
                    uint Disposition = CreatedNew ? 1u : 2u;
                    if (!Instance._emulator.WriteMemory(DispositionPtr, Disposition))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                _ = TitleIndex;
                _ = CreateOptions;
                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }
    }
}
