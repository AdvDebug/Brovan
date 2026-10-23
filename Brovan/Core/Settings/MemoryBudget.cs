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

        public static long ImageCacheDirectoryBytes { get; private set; }

        public static ulong PendingFreeBytes { get; private set; }

        public static uint PooledIoBytes { get; private set; }

        public static int SharedBufferBytes { get; private set; }

        public static int SharedBufferTrimAfter { get; private set; }

        public static int RegistryPathCacheEntries { get; private set; }

        public static int HostDirectoryIndexNames { get; private set; }

        public static int SandboxPathCacheEntries { get; private set; }

        public static int ConsoleInputRecords { get; private set; }

        public static int HostStreamInputBytes { get; private set; }

        public static int KernelReadFiles { get; private set; }

        public static long KernelReadViewBytes { get; private set; }

        // KernelReadFiles bounds the cells that hold a read view.
        public static int KernelFileCells { get; private set; }

        public static int VulkanWaitThreads { get; private set; }

        public static int CoreMessagingRegistrations { get; private set; }

        public static int DxgkHandles { get; private set; }

        public static int DxgkQueuedPackets { get; private set; }

        // Presents of one swapchain that the GUI thread has not drawn yet.
        public static int DxgkPendingPresents { get; private set; }

        // Fence references held by D3DKMT waits and queued signals, and the fence count of one call.
        public static int DxgkFenceReferences { get; private set; }

        // The guest Vulkan ICD sizes its descriptor pool raise budget from this figure.
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
            ImageCacheDirectoryBytes = (long)Megabytes(Pick(Off: 2048, Minimal: 1536, Medium: 1024, High: 768, Aggressive: 512));
            PendingFreeBytes = Megabytes(Pick(Off: 64, Minimal: 48, Medium: 32, High: 16, Aggressive: 8));
            PooledIoBytes = (uint)Megabytes(Pick(Off: 64, Minimal: 32, Medium: 16, High: 8, Aggressive: 4));
            SharedBufferBytes = (int)Kilobytes(Pick(Off: 256, Minimal: 192, Medium: 128, High: 64, Aggressive: 32));
            SharedBufferTrimAfter = (int)Pick(Off: 256, Minimal: 192, Medium: 128, High: 64, Aggressive: 32);
            RegistryPathCacheEntries = (int)Pick(Off: 8192, Minimal: 6144, Medium: 4096, High: 2048, Aggressive: 1024);
            HostDirectoryIndexNames = (int)Pick(Off: 32768, Minimal: 24576, Medium: 16384, High: 8192, Aggressive: 4096);
            SandboxPathCacheEntries = (int)Pick(Off: 32768, Minimal: 24576, Medium: 16384, High: 8192, Aggressive: 4096);
            ConsoleInputRecords = (int)Pick(Off: 262144, Minimal: 131072, Medium: 65536, High: 32768, Aggressive: 16384);
            HostStreamInputBytes = (int)Kilobytes(Pick(Off: 64, Minimal: 64, Medium: 32, High: 16, Aggressive: 8));
            KernelReadFiles = (int)Pick(Off: 64, Minimal: 48, Medium: 32, High: 16, Aggressive: 8);
            KernelReadViewBytes = (long)Megabytes(Pick(Off: 256, Minimal: 192, Medium: 128, High: 64, Aggressive: 32));
            KernelFileCells = (int)Pick(Off: 512, Minimal: 384, Medium: 256, High: 128, Aggressive: 64);
            VulkanWaitThreads = (int)Pick(Off: 8, Minimal: 8, Medium: 6, High: 4, Aggressive: 2);
            CoreMessagingRegistrations = (int)Pick(Off: 4096, Minimal: 4096, Medium: 2048, High: 1024, Aggressive: 512);
            DxgkHandles = (int)Pick(Off: 65536, Minimal: 49152, Medium: 32768, High: 16384, Aggressive: 8192);
            DxgkQueuedPackets = (int)Pick(Off: 16384, Minimal: 12288, Medium: 8192, High: 4096, Aggressive: 2048);
            DxgkPendingPresents = (int)Pick(Off: 64, Minimal: 64, Medium: 48, High: 32, Aggressive: 16);
            DxgkFenceReferences = (int)Pick(Off: 8192, Minimal: 6144, Medium: 4096, High: 3072, Aggressive: 2048);
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
