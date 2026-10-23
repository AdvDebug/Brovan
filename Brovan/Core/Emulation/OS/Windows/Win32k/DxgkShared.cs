namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal sealed class DxgkStorage
    {
        internal readonly IntPtr Memory;
        internal readonly ulong Size;
        internal uint Width;
        internal uint Height;
        internal uint Pitch;
        internal uint Format;
        private int References = 1;

        private DxgkStorage(IntPtr Memory, ulong Size)
        {
            this.Memory = Memory;
            this.Size = Size;
        }

        internal static bool TryCreate(BinaryEmulator Instance, DxgkProcess Process, ulong Size, out DxgkStorage Storage)
        {
            Storage = null;
            if (Size > Win32kDxgk.SharedSegmentSize - Process.AllocatedBytes)
                return false;

            IntPtr Memory = Instance._emulator.AllocateSharedStorage(Size);
            if (Memory == IntPtr.Zero)
                return false;

            Process.AllocatedBytes += Size;
            Storage = new DxgkStorage(Memory, Size);
            return true;
        }

        internal static void AddReferences(DxgkStorage[] Blocks)
        {
            foreach (DxgkStorage Block in Blocks)
                Block.References++;
        }

        internal static void Release(BinaryEmulator Instance, DxgkProcess Process, DxgkStorage[] Blocks)
        {
            foreach (DxgkStorage Block in Blocks)
                Block.Release(Instance, Process);
        }

        internal void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
            if (--References != 0)
                return;

            Instance._emulator.ReleaseSharedStorage(Memory);
            Process.AllocatedBytes -= Size;
        }
    }

    // NT: an object ShareObjects returns keeps what it names until its last handle closes.
    internal sealed class DxgkSharedResource : DxgkNtObject
    {
        internal DxgkStorage[] Storage;

        public override HandleType ObjectType => HandleType.DxgkSharedResourceHandle;

        internal override string TypeName => "DxgkSharedResource";

        internal override void Release(BinaryEmulator Instance, DxgkProcess Process) => DxgkStorage.Release(Instance, Process, Storage);
    }

    // A fence destroyed by its D3DKMT handle ignores later signals, so nothing needs to be released here.
    internal sealed class DxgkSharedSyncObject : DxgkNtObject
    {
        internal DxgkFence Fence;

        public override HandleType ObjectType => HandleType.DxgkSharedSyncObjectHandle;

        internal override string TypeName => "DxgkSharedSyncObject";

        internal override void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
        }
    }
}
