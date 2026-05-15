using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryObject : IWinSyscall
    {
        private const uint ObjProtectClose = 0x1;
        private const uint ObjInherit = 0x2;
        private const int UnicodeTailStackallocLimit = 512;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong Handle = Instance.WinHelper.GetArg64(0);
                OBJECT_INFORMATION_CLASS ObjectInformationClass = (OBJECT_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg64(1, true);
                ulong ObjectInformation = Instance.WinHelper.GetArg64(2);
                uint ObjectInformationLength = (uint)Instance.WinHelper.GetArg64(3, true);
                ulong ReturnLength = Instance.WinHelper.GetArg64(4);
                return HandleQueryObject(Instance, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength, true);
            }
            else
            {
                ulong Handle = Instance.WinHelper.GetArg32(0);
                OBJECT_INFORMATION_CLASS ObjectInformationClass = (OBJECT_INFORMATION_CLASS)Instance.WinHelper.GetArg32(1);
                ulong ObjectInformation = Instance.WinHelper.GetArg32(2);
                uint ObjectInformationLength = Instance.WinHelper.GetArg32(3);
                ulong ReturnLength = Instance.WinHelper.GetArg32(4);
                return HandleQueryObject(Instance, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength, false);
            }
        }

        private NTSTATUS HandleQueryObject(BinaryEmulator Instance, ulong Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, ulong ObjectInformation, uint ObjectInformationLength, ulong ReturnLength, bool Is64)
        {
            if (ReturnLength != 0 && !Instance.IsRegionMapped(ReturnLength, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            switch (ObjectInformationClass)
            {
                case OBJECT_INFORMATION_CLASS.ObjectBasicInformation:
                    return QueryBasicInformation(Instance, Handle, ObjectInformation, ObjectInformationLength, ReturnLength);
                case OBJECT_INFORMATION_CLASS.ObjectNameInformation:
                    return QueryNameInformation(Instance, Handle, ObjectInformation, ObjectInformationLength, ReturnLength, Is64);
                case OBJECT_INFORMATION_CLASS.ObjectTypeInformation:
                    return QueryTypeInformation(Instance, Handle, ObjectInformation, ObjectInformationLength, ReturnLength, Is64);
                case OBJECT_INFORMATION_CLASS.ObjectHandleFlagInformation:
                    return QueryHandleFlagInformation(Instance, Handle, ObjectInformation, ObjectInformationLength, ReturnLength);
                default:
                    Instance.TriggerEventMessage($"[!] NtQueryObject: {ObjectInformationClass} (0x{(uint)ObjectInformationClass:X}) not implemented.", LogFlags.Syscall);
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }

        private NTSTATUS QueryBasicInformation(BinaryEmulator Instance, ulong Handle, ulong ObjectInformation, uint ObjectInformationLength, ulong ReturnLength)
        {
            if (!TryGetHandleContext(Instance, Handle, out IHandleObject HandleObject, out string _, out string _))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            uint Size = (uint)StructSerializer.GetStructSize<OBJECT_BASIC_INFORMATION_DATA>(Instance._binary.Architecture == BinaryArchitecture.x64);
            WriteReturnLength(Instance, ReturnLength, Size);

            if (ObjectInformationLength < Size)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (ObjectInformation == 0 || !Instance.IsRegionMapped(ObjectInformation, Size))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Attributes = 0;
            uint GrantedAccess = (uint)AccessMask.None;

            if (Instance.WinHelper.HandleManager.HandleExists(Handle))
            {
                ObjectHandleFlags Flags = Instance.WinHelper.HandleManager.GetHandleFlags(Handle);
                if ((Flags & ObjectHandleFlags.ProtectFromClose) != 0)
                    Attributes |= ObjProtectClose;
                if ((Flags & ObjectHandleFlags.Inherit) != 0)
                    Attributes |= ObjInherit;
                GrantedAccess = (uint)Instance.WinHelper.HandleManager.GetPermissionsByHandle(Handle);
            }
            else if (Handle == HandleManager.CurrentProcess)
                GrantedAccess = (uint)AccessMask.ProcessAllAccess;
            else if (Handle == HandleManager.CurrentThread)
                GrantedAccess = (uint)AccessMask.StandardRightsAll;

            OBJECT_BASIC_INFORMATION_DATA Data = new OBJECT_BASIC_INFORMATION_DATA
            {
                Attributes = Attributes,
                GrantedAccess = GrantedAccess,
                HandleCount = 1,
                PointerCount = 1,
                NameInfoSize = GetNameInformationSize(GetObjectName(Instance, Handle, HandleObject), Instance._binary.Architecture == BinaryArchitecture.x64),
                TypeInfoSize = GetTypeInformationSize(GetObjectTypeName(Instance, Handle, HandleObject), Instance._binary.Architecture == BinaryArchitecture.x64),
                SecurityDescriptorSize = 0,
                CreationTime = 0
            };

            if (!StructSerializer.WriteStruct(Instance, ObjectInformation, Data).Success)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS QueryNameInformation(BinaryEmulator Instance, ulong Handle, ulong ObjectInformation, uint ObjectInformationLength, ulong ReturnLength, bool Is64)
        {
            if (!TryGetHandleContext(Instance, Handle, out IHandleObject HandleObject, out string _, out string _))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            string Name = GetObjectName(Instance, Handle, HandleObject);
            uint RequiredSize = GetNameInformationSize(Name, Is64);
            WriteReturnLength(Instance, ReturnLength, RequiredSize);

            if (ObjectInformationLength < RequiredSize || ObjectInformation == 0)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (!Instance.IsRegionMapped(ObjectInformation, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return WriteUnicodeInformation(Instance, ObjectInformation, Name, Is64);
        }

        private NTSTATUS QueryTypeInformation(BinaryEmulator Instance, ulong Handle, ulong ObjectInformation, uint ObjectInformationLength, ulong ReturnLength, bool Is64)
        {
            if (!TryGetHandleContext(Instance, Handle, out IHandleObject HandleObject, out string TypeName, out string _))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            uint RequiredSize = GetTypeInformationSize(TypeName, Is64);
            WriteReturnLength(Instance, ReturnLength, RequiredSize);

            if (ObjectInformationLength < RequiredSize || ObjectInformation == 0)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (!Instance.IsRegionMapped(ObjectInformation, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return WriteTypeInformation(Instance, ObjectInformation, TypeName, Is64);
        }

        private NTSTATUS QueryHandleFlagInformation(BinaryEmulator Instance, ulong Handle, ulong ObjectInformation, uint ObjectInformationLength, ulong ReturnLength)
        {
            if (!TryGetHandleContext(Instance, Handle, out IHandleObject _, out string _, out string _))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WriteReturnLength(Instance, ReturnLength, 2);

            if (ObjectInformationLength < 2)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (ObjectInformation == 0 || !Instance.IsRegionMapped(ObjectInformation, 2))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            byte Inherit = 0;
            byte ProtectFromClose = 0;

            if (Instance.WinHelper.HandleManager.HandleExists(Handle))
            {
                ObjectHandleFlags Flags = Instance.WinHelper.HandleManager.GetHandleFlags(Handle);
                Inherit = (byte)(((Flags & ObjectHandleFlags.Inherit) != 0) ? 1 : 0);
                ProtectFromClose = (byte)(((Flags & ObjectHandleFlags.ProtectFromClose) != 0) ? 1 : 0);
            }

            Span<byte> FlagsBuffer = stackalloc byte[2];
            FlagsBuffer[0] = Inherit;
            FlagsBuffer[1] = ProtectFromClose;

            if (!Instance.WriteMemory(ObjectInformation, FlagsBuffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private bool TryGetHandleContext(BinaryEmulator Instance, ulong Handle, out IHandleObject HandleObject, out string TypeName, out string Name)
        {
            HandleObject = null;
            TypeName = string.Empty;
            Name = string.Empty;

            if (Handle == HandleManager.CurrentProcess)
            {
                TypeName = "Process";
                return true;
            }

            if (Handle == HandleManager.CurrentThread)
            {
                TypeName = "Thread";
                return true;
            }

            if (Handle == HandleManager.KNOWN_DLLS_DIRECTORY)
            {
                TypeName = "Directory";
                Name = "\\KnownDlls";
                return true;
            }

            if (Handle == HandleManager.KNOWN_DLLS32_DIRECTORY)
            {
                TypeName = "Directory";
                Name = "\\KnownDlls32";
                return true;
            }

            if (Handle == HandleManager.BASE_NAMED_OBJECTS_DIRECTORY)
            {
                TypeName = "Directory";
                Name = "\\Sessions\\1\\BaseNamedObjects";
                return true;
            }

            if (Handle == HandleManager.RPC_CONTROL_DIRECTORY)
            {
                TypeName = "Directory";
                Name = "\\RPC Control";
                return true;
            }

            HandleObject = Instance.WinHelper.HandleManager.GetObjectByHandle(Handle);
            if (HandleObject == null)
                return false;

            TypeName = GetObjectTypeName(Instance, Handle, HandleObject);
            Name = GetObjectName(Instance, Handle, HandleObject);
            return true;
        }

        private string GetObjectTypeName(BinaryEmulator Instance, ulong Handle, IHandleObject HandleObject)
        {
            if (Handle == HandleManager.CurrentProcess)
                return "Process";
            if (Handle == HandleManager.CurrentThread)
                return "Thread";
            if (Handle == HandleManager.KNOWN_DLLS_DIRECTORY || Handle == HandleManager.KNOWN_DLLS32_DIRECTORY || Handle == HandleManager.BASE_NAMED_OBJECTS_DIRECTORY || Handle == HandleManager.RPC_CONTROL_DIRECTORY)
                return "Directory";

            if (HandleObject is WinSymbolicLink)
                return "SymbolicLink";
            if (HandleObject is WinProcess)
                return "Process";
            if (HandleObject is WinFile File)
                return File.Device ? "Device" : "File";
            if (HandleObject is WinMutex)
                return "Mutant";
            if (HandleObject is WinRegKey)
                return "Key";
            if (HandleObject is WinEvent)
                return "Event";
            if (HandleObject is WinSemaphore)
                return "Semaphore";
            if (HandleObject is WinSection)
                return "Section";
            if (HandleObject is EmulatedThread)
                return "Thread";
            if (HandleObject is WinTimer)
                return "Timer";
            if (HandleObject is WinToken)
                return "Token";
            if (HandleObject is WinPort)
                return "Port";
            if (HandleObject is WinIoCompletion)
                return "IoCompletion";
            if (HandleObject is WinWorkerFactory)
                return "TpWorkerFactory";
            if (HandleObject is WinWaitCompletionPacket)
                return "WaitCompletionPacket";
            return HandleObject.ObjectType.ToString();
        }

        private string GetObjectName(BinaryEmulator Instance, ulong Handle, IHandleObject HandleObject)
        {
            if (Handle == HandleManager.KNOWN_DLLS_DIRECTORY)
                return "\\KnownDlls";
            if (Handle == HandleManager.KNOWN_DLLS32_DIRECTORY)
                return "\\KnownDlls32";
            if (Handle == HandleManager.BASE_NAMED_OBJECTS_DIRECTORY)
                return "\\Sessions\\1\\BaseNamedObjects";
            if (Handle == HandleManager.RPC_CONTROL_DIRECTORY)
                return "\\RPC Control";

            if (HandleObject is WinSymbolicLink Link)
                return Link.FullName ?? string.Empty;
            if (HandleObject is WinFile File)
                return BuildFileObjectName(File);
            if (HandleObject is WinSection Section)
                return !string.IsNullOrEmpty(Section.Name) ? Section.Name : (Section.Path ?? string.Empty);
            if (HandleObject is WinMutex Mutex)
                return Mutex.Name ?? string.Empty;
            if (HandleObject is WinRegKey RegKey)
                return GetRegistryObjectName(RegKey.FullPath);
            if (HandleObject is WinEvent Event)
                return Event.Name ?? string.Empty;
            if (HandleObject is WinSemaphore Semaphore)
                return Semaphore.Name ?? string.Empty;
            if (HandleObject is WinTimer Timer)
                return Timer.Name ?? string.Empty;
            if (HandleObject is WinPort Port)
                return Port.Name ?? string.Empty;
            if (HandleObject is WinIoCompletion IoCompletion)
                return IoCompletion.Name ?? string.Empty;
            if (HandleObject is WinWorkerFactory WorkerFactory)
                return WorkerFactory.Name ?? string.Empty;
            if (HandleObject is WinWaitCompletionPacket Packet)
                return Packet.Name ?? string.Empty;
            return string.Empty;
        }

        private string GetRegistryObjectName(string Path)
        {
            if (string.IsNullOrEmpty(Path))
                return string.Empty;

            Path = Path.TrimEnd('\\', '\0');

            if (Path.Equals("\\Registry\\User", StringComparison.OrdinalIgnoreCase))
                return "\\REGISTRY\\USER";
            if (Path.StartsWith("\\Registry\\User\\", StringComparison.OrdinalIgnoreCase))
                return "\\REGISTRY\\USER" + Path.Substring("\\Registry\\User".Length);

            if (Path.Equals("\\Registry\\Machine", StringComparison.OrdinalIgnoreCase))
                return "\\REGISTRY\\MACHINE";
            if (Path.StartsWith("\\Registry\\Machine\\", StringComparison.OrdinalIgnoreCase))
                return "\\REGISTRY\\MACHINE" + Path.Substring("\\Registry\\Machine".Length);

            return Path;
        }

        private string BuildFileObjectName(WinFile File)
        {
            string Path = File?.Path ?? string.Empty;
            if (string.IsNullOrWhiteSpace(Path))
                return string.Empty;

            Path = Path.Trim().TrimEnd('\0').Replace('/', '\\');

            if (File.Device || Path.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
                return Path;

            while (Path.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Path = Path.Substring(4);

            if (Path.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) ||
                Path.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
                Path = Path.Substring(4);

            if (Path.Length >= 3 && char.IsLetter(Path[0]) && Path[1] == ':' && Path[2] == '\\')
                return "\\Device\\HarddiskVolume1" + Path.Substring(2);

            if (Path.StartsWith("\\\\", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\Mup" + Path.Substring(1);

            return Path;
        }

        private uint GetNameInformationSize(string Name, bool Is64)
        {
            uint StructSize = (uint)(Is64 ? StructSerializer.GetStructSize<UNICODE_STRING64>(true) : StructSerializer.GetStructSize<UNICODE_STRING>(false));
            if (string.IsNullOrEmpty(Name))
                return StructSize;
            return StructSize + GetUnicodeTailSize(Name);
        }

        private uint GetTypeInformationSize(string TypeName, bool Is64)
        {
            uint StructSize = (uint)(Is64 ? StructSerializer.GetStructSize<OBJECT_TYPE_INFORMATION64>(true) : StructSerializer.GetStructSize<OBJECT_TYPE_INFORMATION32>(false));
            if (string.IsNullOrEmpty(TypeName))
                return StructSize;
            return StructSize + GetUnicodeTailSize(TypeName);
        }

        private NTSTATUS WriteUnicodeInformation(BinaryEmulator Instance, ulong ObjectInformation, string Value, bool Is64)
        {
            uint TextSize = GetUnicodeTailSize(Value);

            if (Is64)
            {
                uint StructSize = (uint)StructSerializer.GetStructSize<UNICODE_STRING64>(true);
                UNICODE_STRING64 Info = new UNICODE_STRING64
                {
                    Length = (ushort)(TextSize == 0 ? 0 : TextSize - 2),
                    MaximumLength = (ushort)TextSize,
                    Buffer = TextSize == 0 ? 0UL : ObjectInformation + StructSize
                };

                if (!StructSerializer.WriteStruct(Instance, ObjectInformation, Info).Success)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return WriteUnicodeTail(Instance, ObjectInformation + StructSize, Value);
            }
            else
            {
                uint StructSize = (uint)StructSerializer.GetStructSize<UNICODE_STRING>(false);
                UNICODE_STRING Info = new UNICODE_STRING
                {
                    Length = (ushort)(TextSize == 0 ? 0 : TextSize - 2),
                    MaximumLength = (ushort)TextSize,
                    Buffer = TextSize == 0 ? 0U : (uint)(ObjectInformation + StructSize)
                };

                if (!StructSerializer.WriteStruct(Instance, ObjectInformation, Info).Success)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return WriteUnicodeTail(Instance, ObjectInformation + StructSize, Value);
            }
        }

        private NTSTATUS WriteTypeInformation(BinaryEmulator Instance, ulong ObjectInformation, string TypeName, bool Is64)
        {
            uint NameSize = GetUnicodeTailSize(TypeName);

            if (Is64)
            {
                uint StructSize = (uint)StructSerializer.GetStructSize<OBJECT_TYPE_INFORMATION64>(true);
                OBJECT_TYPE_INFORMATION64 Info = new OBJECT_TYPE_INFORMATION64
                {
                    TypeName = new UNICODE_STRING64
                    {
                        Length = (ushort)(NameSize == 0 ? 0 : NameSize - 2),
                        MaximumLength = (ushort)NameSize,
                        Buffer = NameSize == 0 ? 0UL : ObjectInformation + StructSize
                    },
                    TotalNumberOfObjects = 1,
                    TotalNumberOfHandles = 1,
                    GenericMapping = new GENERIC_MAPPING
                    {
                        GenericRead = (uint)AccessMask.GenericRead,
                        GenericWrite = (uint)AccessMask.GenericWrite,
                        GenericExecute = (uint)AccessMask.GenericExecute,
                        GenericAll = (uint)AccessMask.GenericAll
                    },
                    ValidAccessMask = uint.MaxValue,
                    MaintainHandleCount = 1
                };

                if (!StructSerializer.WriteStruct(Instance, ObjectInformation, Info).Success)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return WriteUnicodeTail(Instance, ObjectInformation + StructSize, TypeName);
            }
            else
            {
                uint StructSize = (uint)StructSerializer.GetStructSize<OBJECT_TYPE_INFORMATION32>(false);
                OBJECT_TYPE_INFORMATION32 Info = new OBJECT_TYPE_INFORMATION32
                {
                    TypeName = new UNICODE_STRING
                    {
                        Length = (ushort)(NameSize == 0 ? 0 : NameSize - 2),
                        MaximumLength = (ushort)NameSize,
                        Buffer = NameSize == 0 ? 0U : (uint)(ObjectInformation + StructSize)
                    },
                    TotalNumberOfObjects = 1,
                    TotalNumberOfHandles = 1,
                    GenericMapping = new GENERIC_MAPPING
                    {
                        GenericRead = (uint)AccessMask.GenericRead,
                        GenericWrite = (uint)AccessMask.GenericWrite,
                        GenericExecute = (uint)AccessMask.GenericExecute,
                        GenericAll = (uint)AccessMask.GenericAll
                    },
                    ValidAccessMask = uint.MaxValue,
                    MaintainHandleCount = 1
                };

                if (!StructSerializer.WriteStruct(Instance, ObjectInformation, Info).Success)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return WriteUnicodeTail(Instance, ObjectInformation + StructSize, TypeName);
            }
        }

        private static uint GetUnicodeTailSize(string Value)
        {
            if (string.IsNullOrEmpty(Value))
                return 0;

            return checked((uint)((Value.Length + 1) * sizeof(char)));
        }

        private static NTSTATUS WriteUnicodeTail(BinaryEmulator Instance, ulong Address, string Value)
        {
            uint Size = GetUnicodeTailSize(Value);
            if (Size == 0)
                return NTSTATUS.STATUS_SUCCESS;

            Span<byte> Buffer = Size <= UnicodeTailStackallocLimit ? stackalloc byte[(int)Size] : new byte[(int)Size];
            Encoding.Unicode.GetBytes(Value.AsSpan(), Buffer.Slice(0, (int)Size - sizeof(char)));
            Buffer[(int)Size - 2] = 0;
            Buffer[(int)Size - 1] = 0;

            if (!Instance.WriteMemory(Address, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private void WriteReturnLength(BinaryEmulator Instance, ulong ReturnLength, uint Value)
        {
            if (ReturnLength != 0)
                Instance._emulator.WriteMemory(ReturnLength, Value);
        }
    }
}