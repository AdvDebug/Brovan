using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateJobObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong JobHandlePtr = Instance.WinHelper.GetArg(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

                if (JobHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(JobHandlePtr, (uint)Instance.WinHelper.PointerSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                string Name = string.Empty;
                if (ObjectAttributesPtr != 0)
                {
                    if (!Instance.IsRegionMapped(ObjectAttributesPtr, 0x30))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!StructSerializer.ParseStruct(Instance, ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 ObjectAttrs))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (ObjectAttrs.ObjectName != 0 && !Instance.WinHelper.TryReadUnicodeString(ObjectAttrs.ObjectName, out Name, out NTSTATUS NameStatus))
                        return NameStatus;
                }

                WinHandle Handle = Instance.WinHelper.CreateJobHandle(Name, (AccessMask)(uint)DesiredAccess);
                if (!Instance.WinHelper.WritePointer(JobHandlePtr, Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            uint JobHandlePtr32 = (uint)Instance.WinHelper.GetArg(0);
            uint DesiredAccess32 = (uint)Instance.WinHelper.GetArg(1);
            uint ObjectAttributesPtr32 = (uint)Instance.WinHelper.GetArg(2);

            if (JobHandlePtr32 == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(JobHandlePtr32, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string Name32 = string.Empty;
            if (ObjectAttributesPtr32 != 0)
            {
                if (!Instance.IsRegionMapped(ObjectAttributesPtr32, 0x18))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint ObjectNamePtr32 = Instance.ReadMemoryUInt(ObjectAttributesPtr32 + 0x08);
                if (ObjectNamePtr32 != 0 && !Instance.WinHelper.TryReadUnicodeString32(ObjectNamePtr32, out Name32, out NTSTATUS NameStatus32))
                    return NameStatus32;
            }

            WinHandle Handle32 = Instance.WinHelper.CreateJobHandle(Name32, (AccessMask)DesiredAccess32);
            if (!Instance._emulator.WriteMemory(JobHandlePtr32, (uint)Handle32.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
