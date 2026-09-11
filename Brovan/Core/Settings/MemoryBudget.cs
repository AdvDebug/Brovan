namespace Brovan.Core.Settings
{
    public enum MemoryProfile
    {
        Off,
        Minimal,
        Medium,
        High,
        Aggressive,
    }

    /// <summary>
    /// Sizes every cache, pool and retained buffer the emulator keeps, and the memory the guest is
    /// told the machine has. The Off column is what Brovan uses when nothing asks it to save memory.
    /// </summary>
    public static class MemoryBudget
    {
        private static MemoryProfile Current;

        public static MemoryProfile Profile
        {
            get => Current;
            set
            {
                Current = value;
                Resolve();
            }
        }

        public static ulong CodeBufferBytes { get; private set; }

        public static long CodeCacheDirectoryBytes { get; private set; }

        public static ulong PendingFreeBytes { get; private set; }

        public static uint PooledIoBytes { get; private set; }

        public static int SharedBufferBytes { get; private set; }

        public static int SharedBufferTrimAfter { get; private set; }

        public static int RegistryPathCacheEntries { get; private set; }

        public static ulong GuestPhysicalBytes { get; private set; }

        // NT memory reports count in 4 KiB pages.
        public static uint GuestPhysicalPages { get; private set; }

        static MemoryBudget() => Resolve();

        // These are read on syscall paths, so the ladder is walked once per profile change rather than
        // once per read.
        private static void Resolve()
        {
            CodeBufferBytes = Megabytes(Pick(Off: 2048, Minimal: 1024, Medium: 512, High: 256, Aggressive: 128));
            CodeCacheDirectoryBytes = (long)Megabytes(Pick(Off: 512, Minimal: 384, Medium: 256, High: 128, Aggressive: 96));
            PendingFreeBytes = Megabytes(Pick(Off: 64, Minimal: 48, Medium: 32, High: 16, Aggressive: 8));
            PooledIoBytes = (uint)Megabytes(Pick(Off: 64, Minimal: 32, Medium: 16, High: 8, Aggressive: 4));
            SharedBufferBytes = (int)Kilobytes(Pick(Off: 256, Minimal: 192, Medium: 128, High: 64, Aggressive: 32));
            SharedBufferTrimAfter = (int)Pick(Off: 256, Minimal: 192, Medium: 128, High: 64, Aggressive: 32);
            RegistryPathCacheEntries = (int)Pick(Off: 8192, Minimal: 6144, Medium: 4096, High: 2048, Aggressive: 1024);
            ulong PhysicalMegabytes = Pick(Off: 8192, Minimal: 6144, Medium: 4096, High: 3072, Aggressive: 2048);

            GuestPhysicalBytes = Megabytes(PhysicalMegabytes);
            GuestPhysicalPages = (uint)(PhysicalMegabytes * 256);
        }

        private static ulong Megabytes(ulong Value) => Value * 1024 * 1024;

        private static ulong Kilobytes(ulong Value) => Value * 1024;

        private static ulong Pick(ulong Off, ulong Minimal, ulong Medium, ulong High, ulong Aggressive)
        {
            return Current switch
            {
                MemoryProfile.Minimal => Minimal,
                MemoryProfile.Medium => Medium,
                MemoryProfile.High => High,
                MemoryProfile.Aggressive => Aggressive,
                _ => Off,
            };
        }
    }
}
