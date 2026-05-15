using System;
using System.Linq;
using System.Text;
using Brovan;
using Brovan.Core;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtMapViewOfSection : IWinSyscall
    {
        private const ulong PageSize = 0x1000;

        private static ulong AlignDown(ulong v, ulong a) => v & ~(a - 1);

        private static void InitializeWindowsSharedSection(BinaryEmulator Instance, ulong Base)
        {
            Instance._emulator.WriteMemory(Base + 0x8, 0x10UL, 8);

            ulong Descriptor = Base + 0x10;
            ulong BaseStaticServerData = Base + 0x1000;

            Instance._emulator.WriteMemory(Descriptor + 0x0, 0UL, 8);
            Instance._emulator.WriteMemory(Descriptor + 0x8, BaseStaticServerData, 8);

            // Zero a reasonable chunk so uninitialized padding doesn't leak random values.
            Instance.WinHelper.WriteZeroMemory(BaseStaticServerData, 0xC00);

            // Shared string heap inside the shared section.
            ulong HeapCursor = Base + 0x2000;

            ulong WriteSharedString(string Value)
            {
                if (Value == null)
                    Value = string.Empty;

                int ByteCount = Encoding.Unicode.GetByteCount(Value) + 2;
                Span<byte> Data = Instance.WinHelper.Shared.GetSpan((uint)ByteCount);
                Encoding.Unicode.GetBytes(Value.AsSpan(), Data);
                Data[ByteCount - 2] = 0;
                Data[ByteCount - 1] = 0;

                ulong Address = HeapCursor;
                Instance._emulator.WriteMemory(Address, Data.Slice(0, ByteCount));
                HeapCursor = BinaryEmulator.AlignUp(Address + (ulong)ByteCount, 0x10);
                return Address;
            }

            void WriteUnicodeStringAbsolute(ulong UnicodeStringAddress, string Value)
            {
                ulong Buffer = WriteSharedString(Value);
                ushort Length = (ushort)Encoding.Unicode.GetByteCount(Value);
                ushort MaximumLength = (ushort)(Length + 2);

                Instance._emulator.WriteMemory(UnicodeStringAddress + 0x0, Length, 2);
                Instance._emulator.WriteMemory(UnicodeStringAddress + 0x2, MaximumLength, 2);
                Instance._emulator.WriteMemory(UnicodeStringAddress + 0x4, 0u, 4);
                Instance._emulator.WriteMemory(UnicodeStringAddress + 0x8, Buffer, 8);
            }

            // Fill BASE_STATIC_SERVER_DATA fields referenced during early init.
            WriteUnicodeStringAbsolute(BaseStaticServerData + 0x000, "C:\\Windows");
            WriteUnicodeStringAbsolute(BaseStaticServerData + 0x010, "C:\\Windows\\System32");
            WriteUnicodeStringAbsolute(BaseStaticServerData + 0x020, "\\Sessions\\1\\BaseNamedObjects");

            ulong ReadOnlyStaticServerData = Base + 0x3000;
            Instance.WinHelper.WriteZeroMemory(ReadOnlyStaticServerData, 0x400);
            WindowsVersionInfo.WriteSharedDataVersionInformation(Instance, ReadOnlyStaticServerData);
            const string WindowsDirectory = "C:\\Windows";
            int WindowsDirectoryByteCount = Encoding.Unicode.GetByteCount(WindowsDirectory) + 2;
            Span<byte> WindowsDirectoryBytes = Instance.WinHelper.Shared.GetSpan((uint)WindowsDirectoryByteCount);
            Encoding.Unicode.GetBytes(WindowsDirectory.AsSpan(), WindowsDirectoryBytes);
            WindowsDirectoryBytes[WindowsDirectoryByteCount - 2] = 0;
            WindowsDirectoryBytes[WindowsDirectoryByteCount - 1] = 0;
            Instance._emulator.WriteMemory(ReadOnlyStaticServerData + 0x1E, WindowsDirectoryBytes.Slice(0, WindowsDirectoryByteCount));

            // CSDNumber / RCNumber.
            Instance._emulator.WriteMemory(BaseStaticServerData + 0x036, (ushort)0, 2);
            Instance._emulator.WriteMemory(BaseStaticServerData + 0x038, (ushort)0, 2);

            // DefaultSeparateVDM / IsWowTaskReady.
            Instance._emulator.WriteMemory(BaseStaticServerData + 0x958, (byte)0, 1);
            Instance._emulator.WriteMemory(BaseStaticServerData + 0x959, (byte)1, 1);

            // SysWOW64 directory
            WriteUnicodeStringAbsolute(BaseStaticServerData + 0x960, "C:\\Windows\\SysWOW64");

            // AppContainer and user objects directories
            WriteUnicodeStringAbsolute(BaseStaticServerData + 0xB40, "\\AppContainerNamedObjects");
            WriteUnicodeStringAbsolute(BaseStaticServerData + 0xB58, "\\Sessions\\1\\Windows\\WindowStations");
            Instance._emulator.WriteMemory(BaseStaticServerData + 0x9E8, BaseStaticServerData, 8);
            Instance._emulator.WriteMemory(BaseStaticServerData + 0xB50, BaseStaticServerData, 8);
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong SectionHandle = Instance.WinHelper.GetArg64(0);
            ulong ProcessHandle = Instance.WinHelper.GetArg64(1);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg64(2);
            ulong ZeroBits = Instance.WinHelper.GetArg64(3);
            ulong CommitSizePtr = Instance.WinHelper.GetArg64(4);
            ulong SectionOffsetPtr = Instance.WinHelper.GetArg64(5);
            ulong ViewSizePtr = Instance.WinHelper.GetArg64(6);
            uint InheritDisposition = (uint)Instance.WinHelper.GetArg64(7);
            uint AllocationType = (uint)Instance.WinHelper.GetArg64(8);
            uint Win32Protect = (uint)Instance.WinHelper.GetArg64(9);

            if (ProcessHandle != ulong.MaxValue)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (BaseAddressPtr == 0 || ViewSizePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, 8) || !Instance.IsRegionMapped(ViewSizePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinSection Section = Instance.WinHelper.GetSectionByHandle(SectionHandle, AccessMask.GiveTemp);
            if (Section == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            bool IsSharedSection = !string.IsNullOrEmpty(Section.Name) && (string.Equals(Section.Name, "\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase) || Section.Name.EndsWith("\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase));

            if (IsSharedSection)
            {
                //Instance.StopReturn = true;
                ulong Base = Section.BackingAddress;
                ulong Size = Section.Size;

                if (!Section.Initialized)
                {
                    InitializeWindowsSharedSection(Instance, Base);
                    Section.Initialized = true;
                }

                Instance._emulator.WriteMemory(Instance.PEB + 0x88, Base, 8);
                Instance._emulator.WriteMemory(Instance.PEB + 0x98, Base + 0x10, 8);
                Instance._emulator.WriteMemory(Instance.PEB + 0x380, Base, 8);
                Instance._emulator.WriteMemory(Instance.PEB + 0x90, Base + 0x3000, 8);

                Instance._emulator.WriteMemory(BaseAddressPtr, Base, 8);
                Instance._emulator.WriteMemory(ViewSizePtr, Size, 8);

                Instance.TriggerEventMessage($"[+] NtMapViewOfSection: SharedSection Base=0x{Base:X}, Size=0x{Size:X}", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong RequestedBase = Instance._emulator.ReadMemoryULong(BaseAddressPtr);
            ulong RequestedSize = Instance._emulator.ReadMemoryULong(ViewSizePtr);

            ulong SectionOffset = 0;
            if (SectionOffsetPtr != 0)
            {
                if (!Instance.IsRegionMapped(SectionOffsetPtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                SectionOffset = Instance._emulator.ReadMemoryULong(SectionOffsetPtr);
            }

            if (SectionOffset > Section.Size)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong ReturnedBase = 0;
            ulong ReturnedSize = 0;

            if (Section.IsImage)
            {
                WindowsFileStream Stream = Section.GetFileStream();
                if (Stream == null || !Stream.ExistsAsFile)
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                string SectionHostPath = Stream.EffectiveReadHostPath;
                if (string.IsNullOrEmpty(SectionHostPath))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                string IdentityPath = !string.IsNullOrEmpty(Section.Path) ? Section.Path : SectionHostPath;
                Instance.WinHelper.AttachImageSectionIdentity(Section, IdentityPath);

                BinaryFile Image = null;
                try
                {
                    Image = Instance.LoadBinary(SectionHostPath);
                    if (Image.FileFormat != BinaryFormat.PE || Image.Architecture != Instance._binary.Architecture)
                        return NTSTATUS.STATUS_INVALID_IMAGE_FORMAT;

                    ulong ImageSize = Instance.AlignToPageSize(Image.PE.SizeOfImage != 0 ? Image.PE.SizeOfImage : (uint)Image.BinarySize);
                    Section.Size = ImageSize;
                    if (RequestedBase != 0 && Instance.IsRegionInUse(RequestedBase, ImageSize))
                        return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

                    WinModule Module = Instance.LoadWinLibrary(Image, false, false, RequestedBase);
                    Image = null;

                    if (Module == null)
                        return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

                    if (Section.ImageSectionId != 0)
                    {
                        Module.ImageSectionId = Section.ImageSectionId;
                        Module.CanonicalImagePath = Section.MappedImageCanonicalPath;
                    }

                    Section.MappedImageCanonicalPath = Module.CanonicalImagePath;

                    ReturnedBase = Module.MappedBase;
                    ReturnedSize = Module.SizeOfImage;

                    if (RequestedSize != 0 && RequestedSize < ReturnedSize)
                        ReturnedSize = BinaryEmulator.AlignUp(RequestedSize, PageSize);

                    if (!Instance._emulator.WriteMemory(BaseAddressPtr, ReturnedBase, 8))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(ViewSizePtr, ReturnedSize, 8))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    NTSTATUS Status = NTSTATUS.STATUS_SUCCESS;

                    Instance.TriggerEventMessage(
                        $"[+] NtMapViewOfSection: Section=0x{SectionHandle:X}, Base=0x{ReturnedBase:X}, Size=0x{ReturnedSize:X}, Image=1, ImageSectionId=0x{Module.ImageSectionId:X}, Prot=0x{Win32Protect:X}, MapOrdinal={Module.ImageMapOrdinal}, Status={Status}.",
                        LogFlags.Syscall);

                    return Status;
                }
                finally
                {
                    Image?.Dispose();
                }
            }

            ulong Available = Section.Size - SectionOffset;
            ReturnedSize = BinaryEmulator.AlignUp(Available, PageSize);

            if (RequestedSize != 0 && RequestedSize < ReturnedSize)
                ReturnedSize = BinaryEmulator.AlignUp(RequestedSize, PageSize);

            if (ReturnedSize == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ReturnedBase = Section.BackingAddress + SectionOffset;

            if (RequestedBase != 0 && RequestedBase != ReturnedBase)
                return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

            MemoryProtection Protection = Instance.WinHelper.ConvertWinProtectToInternal(Win32Protect);
            Instance._emulator.SetMemoryProtection(ReturnedBase, ReturnedSize, Protection);

            if (!Instance._emulator.WriteMemory(BaseAddressPtr, ReturnedBase, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(ViewSizePtr, ReturnedSize, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.TriggerEventMessage($"[+] NtMapViewOfSection: Section=0x{SectionHandle:X}, Base=0x{ReturnedBase:X}, Size=0x{ReturnedSize:X}, Image={Section.IsImage}, Prot=0x{Win32Protect:X}", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}