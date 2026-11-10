using System;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal sealed class CompositionBlurredWallpaperBackdropBrush : CompositionResource
    {
        internal CompositionBlurredWallpaperBackdropBrush(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Integer | CompositionSlots.Buffer | CompositionSlots.Reference | CompositionSlots.CallbackId;
    }

    internal sealed class CompositionColorBrush : CompositionResource
    {
        private const int ColorBytes = 16;

        internal CompositionColorBrush(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Integer | CompositionSlots.Reference | CompositionSlots.CallbackId;

        // Property 0 is the RGBA color as four floats (CColorBrushMarshaler::SetBufferProperty).
        internal override NTSTATUS SetBuffer(uint Property, ReadOnlySpan<byte> Data)
            => Property == 0 && Data.Length == ColorBytes ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
    }

    internal sealed class CompositionSurfaceBrush : CompositionResource
    {
        internal CompositionSurfaceBrush(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.CallbackId;

        internal override NTSTATUS SetInteger(uint Property, ulong Value) => Accept(CompositionSlots.Integer, Property);

        internal override NTSTATUS SetFloat(uint Property, float Value)
            => Channel.Tables.HasOwnProperties(CompositionClass.SurfaceBrush, CompositionSlots.Float) ? Accept(CompositionSlots.Float, Property) : Unserved;

        // NT: a buffer property that needs a surface is refused without one, and the surface here is always null.
        internal override NTSTATUS SetBuffer(uint Property, ReadOnlySpan<byte> Data)
            => Channel.Tables.TryGetBufferBytes(CompositionClass.SurfaceBrush, Property, out int Bytes) && Data.Length == Bytes
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_INVALID_PARAMETER;

        // NT: each listed reference property takes null. Which targets it takes is not modeled.
        internal override NTSTATUS SetReference(uint Property, CompositionResource Target)
        {
            NTSTATUS Status = Accept(CompositionSlots.Reference, Property);
            return Status == NTSTATUS.STATUS_SUCCESS && Target != null ? Unserved : Status;
        }

        private NTSTATUS Accept(CompositionSlots Setter, uint Property)
            => Channel.Tables.IsOwnProperty(CompositionClass.SurfaceBrush, Setter, Property) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
    }

    internal sealed class CompositionComponentTransform3D : CompositionPropertyChangeResource
    {
        internal CompositionComponentTransform3D(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Reference;
    }

    internal sealed class CompositionVisual : CompositionPropertyChangeResource
    {
        private CompositionResource Transform;

        internal CompositionVisual(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.None;

        internal override CompositionVisual AsVisual => this;

        // NT: CVisualMarshaler::SetIntegerProperty handles its own properties and passes every other one to its base.
        internal override NTSTATUS SetInteger(uint Property, ulong Value)
            => Channel.Tables.IsOwnProperty(CompositionClass.Visual, CompositionSlots.Integer, Property) ? Unserved : base.SetInteger(Property, Value);

        internal override NTSTATUS SetReference(uint Property, CompositionResource Target)
        {
            CompositionTableSet Tables = Channel.Tables;
            if (Property == Tables.Property(CompositionProperty.VisualTransform))
                return SetReferenceSlot(ref Transform, Target, Tables.RequiredBase(CompositionProperty.VisualTransform), Optional: true);

            return Tables.IsOwnProperty(CompositionClass.Visual, CompositionSlots.Reference, Property) ? Unserved : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        internal override void ReleaseReferences()
        {
            CompositionResource Held = Transform;
            Transform = null;
            Held?.Channel.ReleaseResource(Held);
        }
    }
}
