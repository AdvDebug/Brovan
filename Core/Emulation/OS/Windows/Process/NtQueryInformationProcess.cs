using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryInformationProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                PROCESSINFOCLASS InfoClass = (PROCESSINFOCLASS)Instance.WinHelper.GetArg64(1);
                ulong OutBufferPtr = Instance.WinHelper.GetArg64(2);
                uint OutBufferLength = (uint)Instance.WinHelper.GetArg64(3);
                ulong ReturnLengthPtr = Instance.WinHelper.GetArg64(4);
                void SetReturnLength(uint Len)
                {
                    if (ReturnLengthPtr == 0)
                        return;
                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                        return;
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Len);
                }
                bool CurrentProcess = ProcessHandle == ulong.MaxValue;
                switch (InfoClass)
                {
                    case PROCESSINFOCLASS.ProcessBasicInformation:
                        if (OutBufferLength < 48)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        if (CurrentProcess)
                        {
                            Span<byte> PBIBuffer = GetSharedWriteBuffer(Instance, 48);
                            WriteUInt32(PBIBuffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                            WriteUInt64(PBIBuffer, 8, Instance.PEB);
                            WriteUInt64(PBIBuffer, 16, (ulong)Environment.ProcessorCount);
                            WriteUInt64(PBIBuffer, 24, (ulong)Instance.WinHelper.CurrentPriority);
                            WriteUInt64(PBIBuffer, 32, Instance.WinHelper.PID);
                            WriteUInt64(PBIBuffer, 40, Instance.WinHelper.PPID);

                            if (!Instance.WriteMemory(OutBufferPtr, PBIBuffer))
                            {
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            SetReturnLength(48);
                            Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own PROCESS_BASIC_INFORMATION (PEB = 0x{Instance.PEB:X}).", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                        else
                        {
                            if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                            {
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryInformation | AccessMask.ProcessQueryLimitedInformation);

                                if (Process == null)
                                {
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                }

                                Span<byte> PBIBuffer = GetSharedWriteBuffer(Instance, 48);
                                WriteUInt32(PBIBuffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                                WriteUInt64(PBIBuffer, 8, Instance.PEB);
                                WriteUInt64(PBIBuffer, 16, (ulong)Environment.ProcessorCount);
                                WriteUInt64(PBIBuffer, 24, 0x8UL);
                                WriteUInt64(PBIBuffer, 32, Process.PID);
                                WriteUInt64(PBIBuffer, 40, Process.PPID);

                                if (!Instance.WriteMemory(OutBufferPtr, PBIBuffer))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                SetReturnLength(48);
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried PROCESS_BASIC_INFORMATION of process \"{Process.Name}\" (PID={Process.PID}).", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                return NTSTATUS.STATUS_INVALID_HANDLE;
                            }
                        }
                    case PROCESSINFOCLASS.ProcessTimes:
                        {
                            NTSTATUS Status = QueryProcessTimes(Instance, ProcessHandle, OutBufferPtr, OutBufferLength, SetReturnLength);
                            if (Status == NTSTATUS.STATUS_SUCCESS)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessTimes.", LogFlags.Syscall);
                            return Status;
                        }
                    case PROCESSINFOCLASS.ProcessBreakOnTermination:
                        if (OutBufferLength < 1)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteByte(OutBufferPtr, 0))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                SetReturnLength(1);
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own ProcessBreakOnTermination.", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance.WinHelper.WriteByte(OutBufferPtr, Process.Critical ? (byte)1 : (byte)0))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    SetReturnLength(1);
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessBreakOnTermination for \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    case PROCESSINFOCLASS.ProcessDebugPort:
                        if (OutBufferLength >= 8)
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried own debug port.", LogFlags.Syscall);
                                SetReturnLength(8);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    SetReturnLength(8);
                                    Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried debug port for process \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                        else
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                    case PROCESSINFOCLASS.ProcessDebugObjectHandle:
                        if (CurrentProcess)
                        {
                            if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                            {
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried own debug object handle.", LogFlags.Syscall);
                            SetReturnLength(8);
                            return NTSTATUS.STATUS_PORT_NOT_SET;
                        }
                        else
                        {
                            if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                            {
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryInformation);
                                if (Process == null)
                                {
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                }

                                if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                SetReturnLength(8);
                                Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried debug object handle for process \"{Process.Name}\".", LogFlags.Syscall);
                                return NTSTATUS.STATUS_PORT_NOT_SET;
                            }
                            else
                            {
                                return NTSTATUS.STATUS_INVALID_HANDLE;
                            }
                        }
                        break;
                    case PROCESSINFOCLASS.ProcessWow64Information:
                        if (OutBufferLength < 8)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance._emulator.WriteMemory(OutBufferPtr, (ulong)(Instance._binary.Architecture == BinaryArchitecture.x64 ? 0 : 1), 8))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own Wow64 status.", LogFlags.Syscall);
                                SetReturnLength(8);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance._emulator.WriteMemory(OutBufferPtr, Process.Arch == BinaryArchitecture.x64 ? 0u : 1u, 4))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    SetReturnLength(8);
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried Wow64 status of process \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    case PROCESSINFOCLASS.ProcessImageFileName:
                        if (OutBufferLength < 16)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        if (CurrentProcess)
                        {
                            string Path = Instance._binary.Location;
                            int PathByteCount = Encoding.Unicode.GetByteCount(Path);
                            Span<byte> PathBytes = Instance.WinHelper.Shared.GetSpan((uint)PathByteCount);
                            Encoding.Unicode.GetBytes(Path.AsSpan(), PathBytes);
                            ulong AllocatedImageMem = Instance.MapUniqueAddress((uint)PathByteCount, MemoryProtection.ReadWrite);
                            if (AllocatedImageMem == 0)
                                return NTSTATUS.STATUS_NO_MEMORY;
                            if (!Instance.WriteMemory(AllocatedImageMem, PathBytes.Slice(0, PathByteCount)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            UNICODE_STRING64 Unicode = new UNICODE_STRING64
                            {
                                Length = (ushort)PathByteCount,
                                MaximumLength = (ushort)PathByteCount,
                                Buffer = AllocatedImageMem
                            };

                            if (StructSerializer.WriteStruct(Instance, OutBufferPtr, Unicode) != WriteStructResult.Ok)
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(16);
                            Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own ProcessImageFileName = \"{Path}\".", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                        else
                        {
                            if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                            {
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                if (Process == null)
                                {
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                }
                                string Path = Process.Path;
                                int PathByteCount = Encoding.Unicode.GetByteCount(Path);
                                Span<byte> PathBytes = Instance.WinHelper.Shared.GetSpan((uint)PathByteCount);
                                Encoding.Unicode.GetBytes(Path.AsSpan(), PathBytes);
                                ulong AllocatedImageMem = Instance.MapUniqueAddress((uint)PathByteCount, MemoryProtection.ReadWrite);

                                if (AllocatedImageMem == 0)
                                    return NTSTATUS.STATUS_NO_MEMORY;

                                if (!Instance.WriteMemory(AllocatedImageMem, PathBytes.Slice(0, PathByteCount)))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                UNICODE_STRING64 Unicode = new UNICODE_STRING64
                                {
                                    Length = (ushort)PathByteCount,
                                    MaximumLength = (ushort)PathByteCount,
                                    Buffer = AllocatedImageMem
                                };

                                if (StructSerializer.WriteStruct(Instance, OutBufferPtr, Unicode) != WriteStructResult.Ok)
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                SetReturnLength(16);
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried the process \"{Process.Name}\" ProcessImageFileName = \"{Path}\".", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                        }
                        break;
                    case PROCESSINFOCLASS.ProcessCookie:
                        {
                            if (OutBufferLength < 4)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (Instance.ProcessCookie == 0)
                            {
                                Instance.ProcessCookie = (uint)Random.Shared.NextInt64();
                                if (Instance.ProcessCookie == 0)
                                    Instance.ProcessCookie = 1;
                            }

                            if (!Instance._emulator.WriteMemory(OutBufferPtr, Instance.ProcessCookie, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(4);
                            Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessCookie = 0x{Instance.ProcessCookie:X}.", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case PROCESSINFOCLASS.ProcessImageInformation:
                        {
                            uint StructSize = 0x40;

                            if (OutBufferLength < StructSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            ulong EntryPoint = Instance.WinHelper.WinModules[0].MappedBase + (ulong)Instance._binary.PE.OptionalHeader64.AddressOfEntryPoint;

                            ulong TransferAddress = EntryPoint;
                            uint ZeroBits = 0;

                            ulong MaximumStackSize = Instance.StackSize;
                            ulong CommittedStackSize = Instance.StackSize;

                            uint SubSystemType = (uint)Instance._binary.PE.OptionalHeader64.Subsystem;

                            uint SubSystemVersion = ((uint)Instance._binary.PE.OptionalHeader64.MinorSubsystemVersion << 16) |
                                                    (uint)Instance._binary.PE.OptionalHeader64.MajorSubsystemVersion;

                            uint GpValue = 0;

                            ushort ImageCharacteristics = (ushort)Instance._binary.PE.FileHeader.Characteristics;
                            ushort DllCharacteristics = (ushort)Instance._binary.PE.OptionalHeader64.DllCharacteristics;

                            ushort Machine = (ushort)Instance._binary.PE.FileHeader.Machine;

                            byte ImageContainsCode = 1;
                            byte ImageFlags = 0;

                            uint LoaderFlags = 0;
                            uint ImageFileSize = 0;
                            uint CheckSum = 0;

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);

                            WriteUInt64(Buffer, 0x00, TransferAddress);
                            WriteUInt64(Buffer, 0x08, ZeroBits);
                            WriteUInt64(Buffer, 0x10, MaximumStackSize);
                            WriteUInt64(Buffer, 0x18, CommittedStackSize);
                            WriteUInt32(Buffer, 0x20, SubSystemType);
                            WriteUInt32(Buffer, 0x24, SubSystemVersion);
                            WriteUInt32(Buffer, 0x28, GpValue);
                            WriteUInt16(Buffer, 0x2C, ImageCharacteristics);
                            WriteUInt16(Buffer, 0x2E, DllCharacteristics);
                            WriteUInt16(Buffer, 0x30, Machine);
                            Buffer[0x32] = ImageContainsCode;
                            Buffer[0x33] = ImageFlags;
                            WriteUInt32(Buffer, 0x34, LoaderFlags);
                            WriteUInt32(Buffer, 0x38, ImageFileSize);
                            WriteUInt32(Buffer, 0x3C, CheckSum);

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(0x40);
                            Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessImageInformation (TransferAddress=0x{TransferAddress:X}).", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessImageFileNameWin32:
                        return QueryProcessImageFileNameWin32(Instance, ProcessHandle, OutBufferPtr, OutBufferLength, SetReturnLength);
                    case (PROCESSINFOCLASS)52:
                        {
                            uint StructSize = 0x20;

                            if (OutBufferLength < StructSize)
                            {
                                SetReturnLength(StructSize);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            uint Policy = (uint)(Instance.ReadMemoryULong(OutBufferPtr) & 0xFFFFFFFF);

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
                            WriteUInt32(Buffer, 0, Policy);

                            uint UnionFlags = 0;
                            uint UnionExtra = 0;

                            if (Policy == 0)
                            {
                                UnionFlags = 1;
                                UnionExtra = 0;
                            }
                            else if (Policy == 2)
                            {
                                UnionFlags = 0;
                                UnionExtra = 0;
                            }

                            WriteUInt32(Buffer, 4, UnionFlags);
                            WriteUInt32(Buffer, 8, UnionExtra);

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(StructSize);
                            Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: ProcessMitigationPolicy ({Policy})", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    default:
                        Helpers.Utils.PrintHighlight($"[!] NtQueryInformationProcess: InfoClass 0x{InfoClass:X} is not implemented");
                        return Instance.WinUnimplemented;
                }
                Helpers.Utils.PrintHighlight($"[!] NtQueryInformationProcess: InfoClass 0x{InfoClass:X} is not implemented");
                return Instance.WinUnimplemented;
            }
            else
            {
                uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
                uint ProcessHandle = Instance.ReadMemoryUInt(ESP + 4);
                PROCESSINFOCLASS InfoClass = (PROCESSINFOCLASS)Instance.ReadMemoryUInt(ESP + 8);
                uint OutBufferPtr = Instance.ReadMemoryUInt(ESP + 12);
                uint OutBufferLength = Instance.ReadMemoryUInt(ESP + 16);
                uint ReturnLengthPtr = Instance.ReadMemoryUInt(ESP + 20);
                void SetReturnLength(uint Len)
                {
                    if (ReturnLengthPtr == 0)
                        return;
                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                        return;
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Len);
                }
                bool CurrentProcess = ProcessHandle == uint.MaxValue;
                switch (InfoClass)
                {
                    case PROCESSINFOCLASS.ProcessBasicInformation:
                        if (OutBufferLength < 24)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        if (CurrentProcess)
                        {
                            Span<byte> PBIBuffer = GetSharedWriteBuffer(Instance, 24);
                            WriteUInt32(PBIBuffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                            WriteUInt32(PBIBuffer, 4, (uint)Instance.PEB);
                            WriteUInt32(PBIBuffer, 8, (uint)Environment.ProcessorCount);
                            WriteUInt32(PBIBuffer, 12, Instance.WinHelper.CurrentPriority);
                            WriteUInt32(PBIBuffer, 16, Instance.WinHelper.PID);
                            WriteUInt32(PBIBuffer, 20, Instance.WinHelper.PPID);

                            if (!Instance.WriteMemory(OutBufferPtr, PBIBuffer))
                            {
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried own PROCESS_BASIC_INFORMATION.", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                        else
                        {
                            if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                            {
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryInformation | AccessMask.ProcessQueryLimitedInformation);

                                if (Process == null)
                                {
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                }

                                Span<byte> PBIBuffer = GetSharedWriteBuffer(Instance, 24);
                                WriteUInt32(PBIBuffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                                WriteUInt32(PBIBuffer, 4, (uint)Instance.PEB);
                                WriteUInt32(PBIBuffer, 8, (uint)Environment.ProcessorCount);
                                WriteUInt32(PBIBuffer, 12, 0x8u);
                                WriteUInt32(PBIBuffer, 16, Process.PID);
                                WriteUInt32(PBIBuffer, 20, Process.PPID);

                                if (!Instance.WriteMemory(OutBufferPtr, PBIBuffer))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried PROCESS_BASIC_INFORMATION of process \"{Process.Name}\".", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                return NTSTATUS.STATUS_INVALID_HANDLE;
                            }
                        }
                    case PROCESSINFOCLASS.ProcessTimes:
                        {
                            NTSTATUS Status = QueryProcessTimes(Instance, ProcessHandle, OutBufferPtr, OutBufferLength, SetReturnLength);
                            if (Status == NTSTATUS.STATUS_SUCCESS)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried ProcessTimes.", LogFlags.Syscall);
                            return Status;
                        }
                    case PROCESSINFOCLASS.ProcessBreakOnTermination:
                        if (OutBufferLength < 1)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteByte(OutBufferPtr, 0))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried own ProcessBreakOnTermination.", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance.WinHelper.WriteByte(OutBufferPtr, Process.Critical ? (byte)1 : (byte)0))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried ProcessBreakOnTermination for \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    case PROCESSINFOCLASS.ProcessDebugPort:
                        if (OutBufferLength >= 4)
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 4))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                Instance.TriggerEventMessage($"[!] NtQueryInformationProcess (x86): Queried own debug port.", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    Instance.TriggerEventMessage($"[!] NtQueryInformationProcess (x86): Queried debug port of \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                        else
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                    case PROCESSINFOCLASS.ProcessWow64Information:
                        if (OutBufferLength < 4)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance._emulator.WriteMemory(OutBufferPtr, Instance._binary.Architecture == BinaryArchitecture.x64 ? 0u : 1u, 4))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried own Wow64 info.", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance._emulator.WriteMemory(OutBufferPtr, Process.Arch == BinaryArchitecture.x64 ? 0u : 1u, 4))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried Wow64 info for \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    default:
                        return Instance.WinUnimplemented;
                }
            }
        }


        private static NTSTATUS QueryProcessImageFileNameWin32(BinaryEmulator Instance, ulong ProcessHandle, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            NTSTATUS Status = ResolveProcessForQuery(Instance, ProcessHandle, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            bool CurrentProcess = ProcessHandle == HandleManager.CurrentProcess || ProcessHandle == uint.MaxValue;
            string FullPath = CurrentProcess ? Instance.WinHelper.WinModules[0].Path : Process.Path;
            if (string.IsNullOrEmpty(FullPath))
                FullPath = Process.Path ?? string.Empty;

            uint StructSize = StructSerializer.GetStructSize<UNICODE_STRING64>(Instance);
            int PathByteCount = Encoding.Unicode.GetByteCount(FullPath) + 2;
            Span<byte> PathBytes = Instance.WinHelper.Shared.GetSpan((uint)PathByteCount);
            Encoding.Unicode.GetBytes(FullPath.AsSpan(), PathBytes);
            PathBytes[PathByteCount - 2] = 0;
            PathBytes[PathByteCount - 1] = 0;

            ushort Length = checked((ushort)(PathByteCount - 2));
            ushort MaximumLength = checked((ushort)PathByteCount);

            uint RequiredSize = StructSize + (uint)PathByteCount;
            SetReturnLength(RequiredSize);


            if (OutBufferLength < RequiredSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(OutBufferPtr, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong BufferPtr = OutBufferPtr + StructSize;

            if (!Instance._emulator.WriteMemory(BufferPtr, PathBytes.Slice(0, PathByteCount)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            UNICODE_STRING64 Unicode = new UNICODE_STRING64()
            {
                Length = Length,
                MaximumLength = MaximumLength,
                Buffer = BufferPtr
            };

            if (!StructSerializer.WriteStruct(Instance, OutBufferPtr, Unicode).Success)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static Span<byte> GetSharedWriteBuffer(BinaryEmulator Instance, uint Size)
        {
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Size);
            Buffer.Clear();
            return Buffer;
        }

        private static void WriteUInt16(Span<byte> Buffer, int Offset, ushort Value)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(Offset, 2), Value);
        }

        private static void WriteUInt32(Span<byte> Buffer, int Offset, uint Value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        private static void WriteUInt64(Span<byte> Buffer, int Offset, ulong Value)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
        }

        private static void WriteInt64(Span<byte> Buffer, int Offset, long Value)
        {
            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
        }

        private static NTSTATUS QueryProcessTimes(BinaryEmulator Instance, ulong ProcessHandle, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            const uint StructSize = 0x20;

            SetReturnLength(StructSize);

            if (OutBufferLength < StructSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = ResolveProcessForQuery(Instance, ProcessHandle, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Instance.WinHelper.UpdateProcessTimes(Process);

            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
            WriteInt64(Buffer, 0x00, Process.CreationTime);
            WriteInt64(Buffer, 0x08, Process.ExitTime);
            WriteInt64(Buffer, 0x10, Process.KernelTime);
            WriteInt64(Buffer, 0x18, Process.UserTime);

            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ResolveProcessForQuery(BinaryEmulator Instance, ulong ProcessHandle, out WinProcess Process)
        {
            Process = null;

            if (ProcessHandle == HandleManager.CurrentProcess || ProcessHandle == uint.MaxValue)
            {
                Process = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == Instance.WinHelper.PID);
                return Process != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            AccessMask GrantedAccess = Instance.WinHelper.HandleManager.GetPermissionsByHandle(ProcessHandle);
            bool CanQuery = GrantedAccess == AccessMask.GiveTemp ||
                            (GrantedAccess & AccessMask.GenericAll) != 0 ||
                            (GrantedAccess & AccessMask.ProcessAllAccess) == AccessMask.ProcessAllAccess ||
                            (GrantedAccess & AccessMask.ProcessQueryInformation) != 0 ||
                            (GrantedAccess & AccessMask.ProcessQueryLimitedInformation) != 0;

            if (!CanQuery)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Process = Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle);
            return Process != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
        }

    }
}
