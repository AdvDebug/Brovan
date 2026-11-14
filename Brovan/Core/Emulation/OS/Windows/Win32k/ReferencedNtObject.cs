namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal abstract class ReferencedNtObject : IHandleObject
    {
        internal string Name;
        private int References;
        private bool HandlesClosed;
        private bool Released;

        public string ObjectId => Name;

        public abstract HandleType ObjectType { get; }

        internal abstract string TypeName { get; }

        internal NTSTATUS Insert(BinaryEmulator Instance, AccessMask Access, ulong HandlePtr)
        {
            Name = $"{TypeName}_{Instance.WinHelper.GenerateAnonymousObjectId()}";
            Register(Instance);
            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(this, Access);
            if (Instance.WinHelper.WritePointer(HandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_SUCCESS;

            Instance.WinHelper.CloseHandle(Handle.Handle);
            return NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        internal void Reference() => References++;

        internal static void Hold<T>(BinaryEmulator Instance, ref T Slot, T Value) where T : ReferencedNtObject
        {
            T Old = Slot;
            if (Old == Value)
                return;

            Value?.Reference();
            Slot = Value;
            Old?.Unreference(Instance);
        }

        internal void Unreference(BinaryEmulator Instance)
        {
            References--;
            ReleaseIfUnused(Instance);
        }

        internal void CloseLastHandle(BinaryEmulator Instance)
        {
            HandlesClosed = true;
            ReleaseIfUnused(Instance);
        }

        private void ReleaseIfUnused(BinaryEmulator Instance)
        {
            if (HandlesClosed && References == 0)
                Release(Instance);
        }

        internal void Release(BinaryEmulator Instance)
        {
            if (Released)
                return;

            Released = true;
            Forget(Instance);
            OnRelease(Instance);
        }

        protected abstract void Register(BinaryEmulator Instance);

        protected abstract void Forget(BinaryEmulator Instance);

        protected abstract void OnRelease(BinaryEmulator Instance);
    }
}
