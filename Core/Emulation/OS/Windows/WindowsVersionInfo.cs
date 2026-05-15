using System.Text;
using Brovan.Core.Emulation;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class WindowsVersionInfo
    {
        public const uint MajorVersion = 10;
        public const uint MinorVersion = 0;
        public const uint BuildNumber = 26200;
        public const ushort BuildNumberShort = 26200;
        public const uint UpdateBuildRevision = 8246;
        public const uint ProductTypeWinNt = 1;
        public const uint SuiteMask = 0;
        public const uint PlatformIdWin32Nt = 2;
        public const uint BuildVersionInformationLength = 0x244;

        public const string DisplayVersion = "25H2";
        public const string ProductName = "Windows 11 Pro";
        public const string EditionId = "Professional";
        public const string InstallationType = "Client";
        public const string RegistryProductType = "WinNT";
        public const string CurrentVersion = "10.0";
        public const string BuildBranch = "ge_release";
        public const string BuildLab = "26200.ge_release.260414-0000";
        public const string BuildLabEx = "26200.8246.amd64fre.ge_release.260414-0000";

        public static void WriteSharedDataVersionInformation(BinaryEmulator Instance, ulong Address)
        {
            Instance._emulator.WriteMemory(Address + 0x00, 1u);
            Instance._emulator.WriteMemory(Address + 0x10, ProductTypeWinNt);
            Instance._emulator.WriteMemory(Address + 0x14, SuiteMask);
        }

        public static void WriteBuildVersionInformation(BinaryEmulator Instance, ulong Address)
        {
            Instance.WinHelper.WriteZeroMemory(Address, BuildVersionInformationLength);
            Instance._emulator.WriteMemory(Address + 0x04, MajorVersion);
            Instance._emulator.WriteMemory(Address + 0x08, MinorVersion);
            Instance._emulator.WriteMemory(Address + 0x0C, BuildNumber);
            Instance._emulator.WriteMemory(Address + 0x10, PlatformIdWin32Nt);
            WriteFixedAnsiString(Instance, Address + 0x014, 0x80, string.Empty);
            WriteFixedAnsiString(Instance, Address + 0x094, 0x80, ProductName);
            WriteFixedAnsiString(Instance, Address + 0x114, 0x80, DisplayVersion);
            WriteFixedAnsiString(Instance, Address + 0x194, 0x80, BuildLabEx);
            WriteFixedAnsiString(Instance, Address + 0x214, 0x1A, DisplayVersion);
            WriteFixedAnsiString(Instance, Address + 0x22E, 0x12, $"{BuildNumber}.{UpdateBuildRevision}");
            Instance._emulator.WriteMemory(Address + 0x240, UpdateBuildRevision);
        }

        private static void WriteFixedAnsiString(BinaryEmulator Instance, ulong Address, int Capacity, string Value)
        {
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((uint)Capacity);
            Buffer.Slice(0, Capacity).Clear();

            if (!string.IsNullOrEmpty(Value) && Capacity > 1)
            {
                int Written = Encoding.ASCII.GetBytes(Value.AsSpan(), Buffer.Slice(0, Capacity - 1));
                Buffer[Written] = 0;
            }

            Instance._emulator.WriteMemory(Address, Buffer.Slice(0, Capacity));
        }
    }
}
