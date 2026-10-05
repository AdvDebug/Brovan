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

        // NT: MmMakeSectionAccess.
        private static ReadOnlySpan<byte> SectionAccessByMask => new byte[] { 0x04, 0x04, 0x08, 0x0C, 0x02, 0x04, 0x0A, 0x0C };

        // NT: MmCompatibleProtectionMask.
        private static ReadOnlySpan<byte> CompatibleViewProtection => new byte[] { 0x01, 0x0B, 0x11, 0xBB, 0x0F, 0x0B, 0xFF, 0xBB };

        // NT: MiSectionMapping. Handle access still holds generic rights.
        private static AccessMask MapSectionAccess(AccessMask Granted)
        {
            if ((Granted & (AccessMask.GenericAll | AccessMask.MaximumAllowed)) != 0)
                return AccessMask.SectionAllAccess;

            if ((Granted & AccessMask.GenericRead) != 0)
                Granted |= AccessMask.SectionMapRead | AccessMask.SectionQuery;

            if ((Granted & AccessMask.GenericWrite) != 0)
                Granted |= AccessMask.SectionMapWrite;

            if ((Granted & AccessMask.GenericExecute) != 0)
                Granted |= AccessMask.SectionMapExecute;

            return Granted;
        }

        private static NTSTATUS CheckDataViewProtection(uint SectionProtect, uint Win32Protect)
        {
            if ((Win32Protect & WinSysHelper.PageTargetsInvalid) != 0 && (Win32Protect & 0xF0) == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // KnownDlls sections that Brovan builds have no page protection.
            int SectionMask = WinSysHelper.MakeProtectionMask(SectionProtect & 0xFFF);
            if (SectionMask < 0)
                return NTSTATUS.STATUS_SUCCESS;

            uint Allowed = CompatibleViewProtection[SectionMask & 7] | 0x700u;
            return ((Win32Protect & ~WinSysHelper.PageTargetsInvalid) & ~Allowed) == 0
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_SECTION_PROTECTION;
        }

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

            // kernel32 dereferences IniFileMapping without a null check.
            ulong IniFileMapping = BaseStaticServerData + 0xC00;
            Instance.WinHelper.WriteZeroMemory(IniFileMapping, 0x20);
            Instance._emulator.WriteMemory(BaseStaticServerData + 0x170, IniFileMapping, 8);

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

        private static void ApplySharedSectionToPeb(BinaryEmulator Instance, ulong Base)
        {
            if (Instance.WinHelper.PointerSize == 8)
            {
                Instance._emulator.WriteMemory(Instance.PEB + 0x88, Base, 8);
                Instance._emulator.WriteMemory(Instance.PEB + 0x90, Base + 0x3000, 8);
                Instance._emulator.WriteMemory(Instance.PEB + 0x98, Base + 0x10, 8);
                Instance._emulator.WriteMemory(Instance.PEB + 0x380, Base, 8);
                return;
            }

            Instance._emulator.WriteMemory(Instance.PEB + 0x4C, (uint)Base);
            Instance._emulator.WriteMemory(Instance.PEB + 0x50, (uint)(Base + 0x3000));
            Instance._emulator.WriteMemory(Instance.PEB + 0x54, (uint)(Base + 0x10));
            Instance._emulator.WriteMemory(Instance.PEB + 0x248, Base, 8);
        }

        internal static bool EnsureWindowsSharedSection(BinaryEmulator Instance)
        {
            const ulong SharedSectionSize = 0x10000;

            WinSection Section = Instance.WinHelper.WinSections.FirstOrDefault(s => s != null && !string.IsNullOrEmpty(s.Name) && s.Name.EndsWith("\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase));

            if (Section == null)
            {
                ulong Allocated = Instance.MapUniqueAddress((uint)SharedSectionSize, MemoryProtection.ReadWrite);
                if (Allocated == 0)
                    return false;

                Section = Instance.WinHelper.GetSectionByHandle((ulong)Instance.WinHelper.CreateSectionHandle("\\Windows\\SharedSection", SharedSectionSize, (uint)Instance.WinHelper.ConvertInternalToWinProtect(MemoryProtection.ReadWrite), 0, null, Allocated, AccessMask.SectionAllAccess).Handle, AccessMask.GiveTemp);
                if (Section == null)
                    return false;
            }

            if (!Section.Initialized)
            {
                InitializeWindowsSharedSection(Instance, Section.BackingAddress);
                Section.Initialized = true;
            }

            ApplySharedSectionToPeb(Instance, Section.BackingAddress);

            // The PEB keeps pointers into the shared section for the lifetime of the process, so it counts
            // as a view of its own. a guest that opens and closes the section handle must not free it.
            Section.MappedViewCount++;
            return true;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            using GeneralHelper.IO.ProbeScope Scope = GeneralHelper.IO.BeginProbeScope();
            ulong SectionHandle = Instance.WinHelper.GetArg(0);
            ulong ProcessHandle = Instance.WinHelper.GetArg(1);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(2);
            ulong ZeroBits = Instance.WinHelper.GetArg(3);
            ulong CommitSizePtr = Instance.WinHelper.GetArg(4);
            ulong SectionOffsetPtr = Instance.WinHelper.GetArg(5);
            ulong ViewSizePtr = Instance.WinHelper.GetArg(6);
            uint InheritDisposition = (uint)Instance.WinHelper.GetArg(7);
            uint AllocationType = (uint)Instance.WinHelper.GetArg(8);
            uint Win32Protect = (uint)Instance.WinHelper.GetArg(9);

            // NT checks the protection before either handle.
            int ProtectionMask = WinSysHelper.MakeProtectionMask(Win32Protect & ~WinSysHelper.PageTargetsInvalid);
            if (ProtectionMask < 0)
                return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

            NTSTATUS ProcessStatus = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation, out WinProcess TargetProcess);
            if (ProcessStatus != NTSTATUS.STATUS_SUCCESS)
                return ProcessStatus;

            if (TargetProcess.PID != Instance.WinHelper.PID)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (BaseAddressPtr == 0 || ViewSizePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, (uint)Instance.WinHelper.PointerSize) || !Instance.IsRegionMapped(ViewSizePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinSection Section = Instance.WinHelper.GetSectionByHandle(SectionHandle, AccessMask.GiveTemp);
            if (Section == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            AccessMask RequiredAccess = (AccessMask)SectionAccessByMask[ProtectionMask & 7];
            if ((MapSectionAccess(Instance.WinHelper.HandleManager.GetPermissionsByHandle(SectionHandle)) & RequiredAccess) != RequiredAccess)
                return NTSTATUS.STATUS_ACCESS_DENIED;

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

                ApplySharedSectionToPeb(Instance, Base);

                Instance.WinHelper.WritePointer(BaseAddressPtr, Base);
                Instance.WinHelper.WritePointer(ViewSizePtr, Size);
                Section.MappedViewCount++;
                Section.BackingViewCount++;

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtMapViewOfSection: SharedSection Base=0x{Base:X}, Size=0x{Size:X}", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong RequestedBase = Instance.WinHelper.ReadPointer(BaseAddressPtr);
            ulong RequestedSize = Instance.WinHelper.ReadPointer(ViewSizePtr);

            ulong SectionOffset = 0;
            if (SectionOffsetPtr != 0)
            {
                if (!Instance.IsRegionMapped(SectionOffsetPtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                SectionOffset = Instance._emulator.ReadMemoryULong(SectionOffsetPtr);
            }

            ulong ReturnedBase = 0;
            ulong ReturnedSize = 0;

            if (Section.IsImage)
            {
                if ((Win32Protect & WinSysHelper.PageTargetsInvalid) != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (SectionOffset > Section.Size)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

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
                    if (Image.FileFormat != BinaryFormat.PE)
                        return NTSTATUS.STATUS_INVALID_IMAGE_FORMAT;

                    // NT maps an image built for another machine and reports it in the status. Only the
                    // loader refuses the mismatch.
                    bool MachineMismatch = Image.Architecture != Instance._binary.Architecture;

                    ulong ImageSize = Instance.AlignToPageSize(Image.PE.SizeOfImage != 0 ? Image.PE.SizeOfImage : (uint)Image.BinarySize);
                    Section.Size = ImageSize;
                    if (RequestedBase != 0 && Instance.IsRegionInUse(RequestedBase, ImageSize))
                        return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

                    // NT relocates an ASLR image once per section, and all views share it. Other images keep their preferred base.
                    bool Relocatable = !Image.PE.ILOnly && (Image.PE.DllCharacteristics & DllCharacteristics.DynamicBase) != 0 && BinaryEmulator.HasBaseRelocations(Image);
                    ulong SectionBase = Section.ImageBase != 0 ? Section.ImageBase : Relocatable ? 0 : Image.PE.ImageBase;

                    WinModule Module = Instance.LoadWinLibrary(Image, false, false, RequestedBase, ImageBase: SectionBase);
                    Image = null;

                    if (Module == null)
                        return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

                    if (Section.ImageBase == 0)
                        Section.ImageBase = SectionBase != 0 ? SectionBase : Module.MappedBase;

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

                    if (!Instance.WinHelper.WritePointer(BaseAddressPtr, ReturnedBase))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.WinHelper.WritePointer(ViewSizePtr, ReturnedSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    NTSTATUS Status = MachineMismatch ? NTSTATUS.STATUS_IMAGE_MACHINE_TYPE_MISMATCH
                        : ReturnedBase != Section.ImageBase ? NTSTATUS.STATUS_IMAGE_NOT_AT_BASE
                        : NTSTATUS.STATUS_SUCCESS;

                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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

            if ((SectionOffset & (WinSysHelper.AllocationGranularity - 1)) != 0 || (RequestedBase & (WinSysHelper.AllocationGranularity - 1)) != 0)
                return NTSTATUS.STATUS_MAPPED_ALIGNMENT;

            NTSTATUS ProtectStatus = CheckDataViewProtection(Section.Protection, Win32Protect);
            if (ProtectStatus != NTSTATUS.STATUS_SUCCESS)
                return ProtectStatus;

            Win32Protect &= ~WinSysHelper.PageTargetsInvalid;

            ulong SectionEnd = BinaryEmulator.AlignUp(Section.Size, PageSize);
            if (SectionOffset >= Section.Size || RequestedSize > SectionEnd - SectionOffset)
                return NTSTATUS.STATUS_INVALID_VIEW_SIZE;

            ReturnedSize = RequestedSize != 0 ? BinaryEmulator.AlignUp(RequestedSize, PageSize) : SectionEnd - SectionOffset;

            ulong UserEnd = Instance.UserAddressEnd;
            if (RequestedBase != 0 && RequestedBase >= UserEnd)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (RequestedBase != 0 && ReturnedSize > UserEnd - RequestedBase)
                return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

            NTSTATUS MapStatus = MapDataView(Instance, Section, SectionOffset, ReturnedSize, RequestedBase, Win32Protect, out ReturnedBase);
            if (MapStatus != NTSTATUS.STATUS_SUCCESS)
                return MapStatus;

            if (!Instance.WinHelper.WritePointer(BaseAddressPtr, ReturnedBase))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.WritePointer(ViewSizePtr, ReturnedSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtMapViewOfSection: Section=0x{SectionHandle:X}, Base=0x{ReturnedBase:X}, Size=0x{ReturnedSize:X}, Image={Section.IsImage}, Prot=0x{Win32Protect:X}", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // A view congruent to its section offset modulo 2 MiB can use 2 MiB host pages.
        private static bool TryFindViewBase(BinaryEmulator Instance, ulong SectionOffset, ulong ViewSize, out ulong ViewBase)
        {
            const ulong LargePage = 0x200000;

            if (ViewSize >= LargePage)
            {
                ulong Skew = SectionOffset & (LargePage - 1);
                if (Instance.TryFindFreeBaseAddress(ViewSize + Skew, LargePage, Instance.BaseAddress, Instance.MaxAddress, out ulong LargeBase))
                {
                    ViewBase = LargeBase + Skew;
                    return true;
                }
            }

            return Instance.TryFindFreeBaseAddress(ViewSize, WinSysHelper.AllocationGranularity, Instance.BaseAddress, Instance.MaxAddress, out ViewBase);
        }

        // The caller aligns and bounds SectionOffset and ViewSize.
        internal static NTSTATUS MapDataView(BinaryEmulator Instance, WinSection Section, ulong SectionOffset, ulong ViewSize, ulong RequestedBase, uint Win32Protect, out ulong ViewBase)
        {
            ViewBase = RequestedBase;
            if (ViewBase == 0 && !TryFindViewBase(Instance, SectionOffset, ViewSize, out ViewBase))
                return NTSTATUS.STATUS_NO_MEMORY;

            uint AllocationProtect = Win32Protect != 0 ? Win32Protect : Section.Protection;
            ulong ExistingStorage = Section.Storage == IntPtr.Zero ? Section.FindViewStorage(SectionOffset, ViewSize, out _) : 0;

            if (Section.Storage == IntPtr.Zero && ExistingStorage == 0)
            {
                // SEC_RESERVE: the view is a reservation that NtAllocateVirtualMemory commits into.
                if (!Instance.ReserveMemory(ViewBase, ViewSize, AllocationProtect))
                    return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

                // Only a view that spans the whole section may stand in as the section's backing range.
                // latching a partial one makes every address above it look like part of this section.
                if (Section.BackingAddress == 0 && SectionOffset == 0 && ViewSize >= Section.Size)
                    Section.BackingAddress = ViewBase;

                Section.AddView(SectionOffset, ViewBase, ViewSize, false, Instance.WinHelper.ConvertWinProtectToInternal(Section.Protection));
            }
            else
            {
                if (Instance.IsRegionMapped(ViewBase, ViewSize))
                    return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

                MemoryProtection ViewProtection = Instance.WinHelper.ConvertWinProtectToInternal(Win32Protect);
                bool Mapped = Section.Storage != IntPtr.Zero
                    ? Instance.MapSharedMemoryRegion(ViewBase, ViewSize, ViewProtection, (nint)Section.Storage + (nint)SectionOffset, AllocationProtect, ViewBase)
                    : Instance.MapSharedMemoryRange(ViewBase, ExistingStorage, ViewSize, ViewProtection, AllocationProtect);
                if (!Mapped)
                    return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

                Section.AddView(SectionOffset, ViewBase, ViewSize, true, ViewProtection);
            }

            Instance.WinHelper.TrackSectionRange(ViewBase, ViewSize);
            Section.MappedViewCount++;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}