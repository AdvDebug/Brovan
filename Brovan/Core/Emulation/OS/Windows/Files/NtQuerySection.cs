using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtQuerySection : IWinSyscall
    {
        private const uint SectionBasicInformation = 0;
        private const uint SectionImageInformation = 1;
        private const uint SectionRelocationInformation = 2;
        private const uint SectionOriginalBaseInformation = 3;

        private const uint SecFile = 0x00800000;
        private const uint SecImage = 0x01000000;
        private const uint SecReserve = 0x04000000;
        private const uint SecCommit = 0x08000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SectionHandle = Instance.WinHelper.GetArg(0);
            uint InformationClass = (uint)Instance.WinHelper.GetArg(1);
            ulong Information = Instance.WinHelper.GetArg(2);
            ulong Length = Instance.WinHelper.GetArg(3);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(4);

            bool Wide = Instance.WinHelper.PointerSize == 8;
            uint Required;
            switch (InformationClass)
            {
                case SectionBasicInformation:
                    Required = Wide ? 24u : 16u;
                    break;
                case SectionImageInformation:
                    Required = SECTION_IMAGE_INFORMATION.SizeOf(Wide);
                    break;
                case SectionRelocationInformation:
                    Required = (uint)Instance.WinHelper.PointerSize;
                    break;
                // NT refuses this class to WOW64 callers.
                case SectionOriginalBaseInformation when Wide:
                    Required = 8;
                    break;
                default:
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }

            if (Length < Required)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsMemoryRangeMapped(Information, Required))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.HandleManager.TryGetHandle(SectionHandle, out HandleEntry Entry))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Entry.Object is not WinSection Section)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if ((NtMapViewOfSection.MapSectionAccess(Entry.Permissions) & AccessMask.SectionQuery) == 0)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (InformationClass != SectionBasicInformation)
            {
                if (!Section.IsImage)
                    return NTSTATUS.STATUS_SECTION_NOT_IMAGE;

                // NT reports the relocated base from the create, but Brovan picks it at the first view.
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[!] NtQuerySection: class {InformationClass} of an image section is not implemented.", LogFlags.Issues);
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            ulong MaximumSize;
            uint Attributes;
            if (Section.IsImage)
            {
                NTSTATUS ImageStatus = TryGetImageSize(Instance, Section, out MaximumSize);
                if (ImageStatus != NTSTATUS.STATUS_SUCCESS)
                    return ImageStatus;

                Attributes = SecImage | SecFile;
            }
            else if (Section.Path != null)
            {
                MaximumSize = Section.Size;
                Attributes = SecFile;
            }
            else
            {
                MaximumSize = Instance.AlignToPageSize(Section.Size);
                Attributes = Section.Attributes & (SecCommit | SecReserve);
            }

            // NT leaves the x64 padding after AllocationAttributes unwritten.
            int AttributesEnd = Wide ? 12 : 8;
            int SizeOffset = Wide ? 16 : 8;
            Span<byte> Basic = stackalloc byte[24];
            BinaryPrimitives.WriteUInt32LittleEndian(Basic.Slice(AttributesEnd - 4), Attributes);
            BinaryPrimitives.WriteUInt64LittleEndian(Basic.Slice(SizeOffset), MaximumSize);
            if (!Instance.WriteMemory(Information, Basic.Slice(0, AttributesEnd)) ||
                !Instance.WriteMemory(Information + (ulong)SizeOffset, Basic.Slice(SizeOffset, 8)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReturnLengthPtr != 0 && !Instance.WinHelper.WritePointer(ReturnLengthPtr, Required))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS TryGetImageSize(BinaryEmulator Instance, WinSection Section, out ulong Size)
        {
            Size = 0;
            WindowsFileStream Stream = Section.GetFileStream();
            string? HostPath = Stream != null && Stream.ExistsAsFile ? Stream.EffectiveReadHostPath : null;
            if (string.IsNullOrEmpty(HostPath))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            BinaryFile Image = Instance.LoadBinary(HostPath);
            try
            {
                if (Image.FileFormat != BinaryFormat.PE)
                    return NTSTATUS.STATUS_INVALID_IMAGE_FORMAT;

                Size = BinaryEmulator.GetPeImageSize(Image);
                return NTSTATUS.STATUS_SUCCESS;
            }
            finally
            {
                Image.Dispose();
            }
        }
    }
}
