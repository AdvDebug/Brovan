using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.Guests
{
    internal static class GuestFactory
    {
        public static IGuestEnvironment Create(BinaryFile binary)
        {
            return binary.FileFormat switch
            {
                BinaryFormat.PE => new WindowsGuest(),
                BinaryFormat.ELF => new LinuxGuest(),
                _ => throw new BadImageFormatException($"Unsupported guest format: {binary.FileFormat}. use the generic guest.")
            };
        }
    }
}