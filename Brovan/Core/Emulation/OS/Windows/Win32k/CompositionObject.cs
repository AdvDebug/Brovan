namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal abstract class CompositionObject : ReferencedNtObject
    {
        public override HandleType ObjectType => HandleType.CompositionObjectHandle;

        internal override string TypeName => "Composition";

        protected override void Register(BinaryEmulator Instance) => Instance.WinHelper.Composition.AddObject(this);

        protected override void Forget(BinaryEmulator Instance) => Instance.WinHelper.Composition.ForgetObject(this);
    }

    internal sealed class CompositionSharedVisual : CompositionObject
    {
        internal readonly uint ResourceType;
        internal bool Opened;

        internal CompositorResource Committed;

        internal CompositionSharedVisual(uint ResourceType)
        {
            this.ResourceType = ResourceType;
        }

        protected override void OnRelease(BinaryEmulator Instance)
        {
        }
    }
}
