using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryInformationProcess : IWinSyscall
    {
        private const uint MemExecuteOptionEnable = 0x2;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg(0);
                PROCESSINFOCLASS InfoClass = (PROCESSINFOCLASS)Instance.WinHelper.GetArg(1);
                ulong OutBufferPtr = Instance.WinHelper.GetArg(2);
                uint OutBufferLength = (uint)Instance.WinHelper.GetArg(3);
                ulong ReturnLengthPtr = Instance.WinHelper.GetArg(4);
                void SetReturnLength(uint Len)
                {
                    if (ReturnLengthPtr == 0)
                        return;
                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                        return;
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Len);
                }
                bool CurrentProcess = HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle);
                switch (InfoClass)
                {
                    case PROCESSINFOCLASS.ProcessBasicInformation:
                    {
                        uint PbiSize = (uint)(Instance.WinHelper.PointerSize == 8 ? 48 : 24);
                        if (OutBufferLength < PbiSize)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        if (CurrentProcess)
                        {
                            if (!WriteProcessBasicInformation(Instance, OutBufferPtr, Instance.PEB, (ulong)Instance.WinHelper.CurrentPriority, Instance.WinHelper.PID, Instance.WinHelper.PPID))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(PbiSize);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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

                                if (!WriteProcessBasicInformation(Instance, OutBufferPtr, Instance.PEB, 0x8UL, Process.PID, Process.PPID))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                SetReturnLength(PbiSize);
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried PROCESS_BASIC_INFORMATION of process \"{Process.Name}\" (PID={Process.PID}).", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                return NTSTATUS.STATUS_INVALID_HANDLE;
                            }
                        }
                    }
                    case PROCESSINFOCLASS.ProcessTimes:
                        {
                            NTSTATUS Status = QueryProcessTimes(Instance, ProcessHandle, OutBufferPtr, OutBufferLength, SetReturnLength);
                            if (Status == NTSTATUS.STATUS_SUCCESS)
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                        Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessBreakOnTermination for \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    case PROCESSINFOCLASS.ProcessExecuteFlags:
                        {
                            if (OutBufferLength < sizeof(uint))
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, sizeof(uint)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (!Instance.WinHelper.WriteUInt32(OutBufferPtr, MemExecuteOptionEnable))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(sizeof(uint));
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessDebugPort:
                        if (OutBufferLength >= (ulong)Instance.WinHelper.PointerSize)
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, (uint)Instance.WinHelper.PointerSize))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried own debug port.", LogFlags.Syscall);
                                SetReturnLength((uint)Instance.WinHelper.PointerSize);
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

                                    if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, (uint)Instance.WinHelper.PointerSize))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    SetReturnLength((uint)Instance.WinHelper.PointerSize);
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
                            if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, (uint)Instance.WinHelper.PointerSize))
                            {
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried own debug object handle.", LogFlags.Syscall);
                            SetReturnLength((uint)Instance.WinHelper.PointerSize);
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

                                if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, (uint)Instance.WinHelper.PointerSize))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                SetReturnLength((uint)Instance.WinHelper.PointerSize);
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
                        if (OutBufferLength < (ulong)Instance.WinHelper.PointerSize)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WritePointer(OutBufferPtr, Instance._binary.Architecture == BinaryArchitecture.x64 ? 0UL : Instance.PEB))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own Wow64 status.", LogFlags.Syscall);
                                SetReturnLength((uint)Instance.WinHelper.PointerSize);
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

                                    if (!Instance.WinHelper.WritePointer(OutBufferPtr, Process.Arch == BinaryArchitecture.x64 ? 0UL : Instance.PEB))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    SetReturnLength((uint)Instance.WinHelper.PointerSize);
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessCookie = 0x{Instance.ProcessCookie:X}.", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case PROCESSINFOCLASS.ProcessImageInformation:
                        {
                            bool Is64Image = Instance.WinHelper.PointerSize == 8;
                            uint StructSize = Is64Image ? 0x40u : 0x30u;

                            if (OutBufferLength < StructSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            uint AddressOfEntryPoint = Is64Image
                                ? Instance._binary.PE.OptionalHeader64.AddressOfEntryPoint
                                : Instance._binary.PE.OptionalHeader32.AddressOfEntryPoint;

                            ulong TransferAddress = Instance.WinHelper.WinModules[0].MappedBase + AddressOfEntryPoint;
                            uint ZeroBits = 0;

                            ulong MaximumStackSize = Instance.StackSize;
                            ulong CommittedStackSize = Instance.StackSize;

                            uint SubSystemType = Is64Image
                                ? (uint)Instance._binary.PE.OptionalHeader64.Subsystem
                                : (uint)Instance._binary.PE.OptionalHeader32.Subsystem;

                            uint SubSystemVersion = Is64Image
                                ? (((uint)Instance._binary.PE.OptionalHeader64.MinorSubsystemVersion << 16) | (uint)Instance._binary.PE.OptionalHeader64.MajorSubsystemVersion)
                                : (((uint)Instance._binary.PE.OptionalHeader32.MinorSubsystemVersion << 16) | (uint)Instance._binary.PE.OptionalHeader32.MajorSubsystemVersion);

                            uint GpValue = 0;

                            ushort ImageCharacteristics = (ushort)Instance._binary.PE.FileHeader.Characteristics;
                            ushort DllCharacteristics = Is64Image
                                ? (ushort)Instance._binary.PE.OptionalHeader64.DllCharacteristics
                                : (ushort)Instance._binary.PE.OptionalHeader32.DllCharacteristics;

                            ushort Machine = (ushort)Instance._binary.PE.FileHeader.Machine;

                            byte ImageContainsCode = 1;
                            byte ImageFlags = 0;

                            uint LoaderFlags = 0;
                            uint ImageFileSize = 0;
                            uint CheckSum = 0;

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);

                            int Cursor;
                            if (Is64Image)
                            {
                                WriteUInt64(Buffer, 0x00, TransferAddress);
                                WriteUInt64(Buffer, 0x08, ZeroBits);
                                WriteUInt64(Buffer, 0x10, MaximumStackSize);
                                WriteUInt64(Buffer, 0x18, CommittedStackSize);
                                Cursor = 0x20;
                            }
                            else
                            {
                                WriteUInt32(Buffer, 0x00, (uint)TransferAddress);
                                WriteUInt32(Buffer, 0x04, ZeroBits);
                                WriteUInt32(Buffer, 0x08, (uint)MaximumStackSize);
                                WriteUInt32(Buffer, 0x0C, (uint)CommittedStackSize);
                                Cursor = 0x10;
                            }

                            WriteUInt32(Buffer, Cursor + 0x00, SubSystemType);
                            WriteUInt32(Buffer, Cursor + 0x04, SubSystemVersion);
                            WriteUInt32(Buffer, Cursor + 0x08, GpValue);
                            WriteUInt16(Buffer, Cursor + 0x0C, ImageCharacteristics);
                            WriteUInt16(Buffer, Cursor + 0x0E, DllCharacteristics);
                            WriteUInt16(Buffer, Cursor + 0x10, Machine);
                            Buffer[Cursor + 0x12] = ImageContainsCode;
                            Buffer[Cursor + 0x13] = ImageFlags;
                            WriteUInt32(Buffer, Cursor + 0x14, LoaderFlags);
                            WriteUInt32(Buffer, Cursor + 0x18, ImageFileSize);
                            WriteUInt32(Buffer, Cursor + 0x1C, CheckSum);

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(StructSize);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
        }


        private static NTSTATUS QueryProcessImageFileNameWin32(BinaryEmulator Instance, ulong ProcessHandle, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            NTSTATUS Status = ResolveProcessForQuery(Instance, ProcessHandle, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            bool CurrentProcess = HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle) || ProcessHandle == uint.MaxValue;
            string FullPath = CurrentProcess ? Instance.WinHelper.WinModules[0].Path : Process.Path;
            if (string.IsNullOrEmpty(FullPath))
                FullPath = Process.Path ?? string.Empty;

            uint StructSize = (uint)(Instance.WinHelper.PointerSize == 8 ? 0x10 : 0x08);
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

            if (!WriteUnicodeStringHeader(Instance, OutBufferPtr, Length, MaximumLength, BufferPtr))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool WriteProcessBasicInformation(BinaryEmulator Instance, ulong OutBufferPtr, ulong Peb, ulong AffinityMask, ulong Pid, ulong ParentPid)
        {
            if (Instance.WinHelper.PointerSize == 8)
            {
                Span<byte> Buffer = GetSharedWriteBuffer(Instance, 48);
                WriteUInt32(Buffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                WriteUInt64(Buffer, 8, Peb);
                WriteUInt64(Buffer, 16, AffinityMask);
                WriteUInt64(Buffer, 24, (ulong)Instance.WinHelper.CurrentPriority);
                WriteUInt64(Buffer, 32, Pid);
                WriteUInt64(Buffer, 40, ParentPid);
                return Instance.WriteMemory(OutBufferPtr, Buffer);
            }

            Span<byte> Buffer32 = GetSharedWriteBuffer(Instance, 24);
            WriteUInt32(Buffer32, 0x00, (uint)NTSTATUS.STATUS_PENDING);
            WriteUInt32(Buffer32, 0x04, (uint)Peb);
            WriteUInt32(Buffer32, 0x08, (uint)AffinityMask);
            WriteUInt32(Buffer32, 0x0C, (uint)Instance.WinHelper.CurrentPriority);
            WriteUInt32(Buffer32, 0x10, (uint)Pid);
            WriteUInt32(Buffer32, 0x14, (uint)ParentPid);
            return Instance.WriteMemory(OutBufferPtr, Buffer32);
        }

        private static bool WriteUnicodeStringHeader(BinaryEmulator Instance, ulong Address, ushort Length, ushort MaximumLength, ulong Buffer)
        {
            if (!Instance._emulator.WriteMemory(Address + 0x0, Length, 2))
                return false;
            if (!Instance._emulator.WriteMemory(Address + 0x2, MaximumLength, 2))
                return false;

            if (Instance.WinHelper.PointerSize == 8)
                return Instance._emulator.WriteMemory(Address + 0x4, 0u, 4) && Instance.WinHelper.WritePointer(Address + 0x8, Buffer);

            return Instance.WinHelper.WritePointer(Address + 0x4, Buffer);
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

            if (HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle) || ProcessHandle == uint.MaxValue)
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
