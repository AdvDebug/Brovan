using System;
using System.Collections.Generic;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal sealed class CompositionBlurredWallpaperBackdropBrush : CompositionResource
    {
        internal CompositionBlurredWallpaperBackdropBrush(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Integer | CompositionSlots.Buffer | CompositionSlots.Reference | CompositionSlots.CallbackId |
                                                          CompositionSlots.Handle;
    }

    internal sealed class CompositionColorBrush : CompositionResource
    {
        internal CompositionColorBrush(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Integer | CompositionSlots.Reference | CompositionSlots.CallbackId | CompositionSlots.Handle;

        protected override NTSTATUS BufferFallback(uint Property, ReadOnlySpan<byte> Data) => NTSTATUS.STATUS_INVALID_PARAMETER;
    }

    internal sealed class CompositionSurfaceBrush : CompositionResource
    {
        private CompositionResource Surface;

        internal CompositionSurfaceBrush(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.CallbackId | CompositionSlots.Handle;

        // NT: a buffer property that needs a surface is refused without one, and the surface here is always null.
        protected override NTSTATUS IntegerFallback(uint Property, ulong Value) => NTSTATUS.STATUS_INVALID_PARAMETER;

        protected override NTSTATUS BufferFallback(uint Property, ReadOnlySpan<byte> Data) => NTSTATUS.STATUS_INVALID_PARAMETER;

        protected override NTSTATUS FloatFallback(uint Property, float Value)
            => Channel.Tables.HasOwnProperties(CompositionClass.SurfaceBrush, CompositionSlots.Float) ? NTSTATUS.STATUS_INVALID_PARAMETER : Unserved;

        // NT: each listed reference property takes null. Which targets it takes is not modeled.
        internal override NTSTATUS SetReference(BinaryEmulator Instance, uint Property, CompositionResource Target)
        {
            CompositionTableSet Tables = Channel.Tables;
            if (Property == Tables.Property(CompositionProperty.SurfaceBrushSurface))
            {
                NTSTATUS Status = SetReferenceSlot(Instance, ref Surface, Target, Tables.RequiredBases(CompositionProperty.SurfaceBrushSurface), Optional: true);
                if (Status == NTSTATUS.STATUS_SUCCESS && Target == null)
                    ClearGate();

                return Status;
            }

            if (!Tables.IsOwnProperty(CompositionClass.SurfaceBrush, CompositionSlots.Reference, Property))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Target != null ? Unserved : NTSTATUS.STATUS_SUCCESS;
        }

        internal override CompositionResource HeldReference(CompositionProperty Property) => Property == CompositionProperty.SurfaceBrushSurface ? Surface : null;

        internal override void ReleaseReferences(BinaryEmulator Instance) => ReleaseSlot(Instance, ref Surface);
    }

    internal sealed class CompositionSurfaceBitmap : CompositionResource
    {
        private DxgkCompositionSurface Surface;

        internal CompositionSurfaceBitmap(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Buffer | CompositionSlots.Reference | CompositionSlots.CallbackId;

        // NT sets the surface's delegated ink cookie through one more property, which is not modeled.
        protected override NTSTATUS IntegerFallback(uint Property, ulong Value) => Surface != null ? Unserved : NTSTATUS.STATUS_INVALID_PARAMETER;

        internal override NTSTATUS SetHandle(BinaryEmulator Instance, uint Property, ulong Handle)
        {
            if (!Channel.Tables.TryGetHandle(Class, Property, out _, out uint Access, out uint Kind))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkCompositionSurface Next = null;
            if (Handle != 0)
            {
                if (Kind != DxgkCompositionSurface.ObjectKind)
                    return Unserved;

                NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(Handle, (AccessMask)Access, out Next);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            if (Next == Surface)
                return Unchanged;

            ReferencedNtObject.Hold(Instance, ref Surface, Next);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal override ReferencedNtObject HeldObject(CompositionProperty Property) => Property == CompositionProperty.SurfaceBitmapSurface ? Surface : null;

        internal override void ReleaseReferences(BinaryEmulator Instance) => ReferencedNtObject.Hold(Instance, ref Surface, null);
    }

    internal sealed class CompositionComponentTransform3D : CompositionPropertyChangeResource
    {
        internal CompositionComponentTransform3D(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Reference | CompositionSlots.Handle;
    }

    internal class CompositionVisual : CompositionPropertyChangeResource
    {
        private CompositionResource Transform;

        internal CompositionVisual Parent;

        // NT keeps the children bottom first (CVisualMarshaler::AddChild).
        internal readonly List<CompositionVisual> Children = new();

        internal CompositionVisual(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Handle;

        internal override CompositionVisual AsVisual => this;

        protected override NTSTATUS BufferFallback(uint Property, ReadOnlySpan<byte> Data) => NTSTATUS.STATUS_INVALID_PARAMETER;

        internal override NTSTATUS SetReference(BinaryEmulator Instance, uint Property, CompositionResource Target)
        {
            CompositionTableSet Tables = Channel.Tables;
            if (Property == Tables.Property(CompositionProperty.VisualTransform))
                return SetReferenceSlot(Instance, ref Transform, Target, Tables.RequiredBases(CompositionProperty.VisualTransform), Optional: true);

            return Tables.IsOwnProperty(CompositionClass.Visual, CompositionSlots.Reference, Property) ? Unserved : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        internal NTSTATUS AddChild(CompositionVisual Child, bool Above, CompositionVisual Reference)
        {
            if (Child.Parent != null || Reference != null && Reference.Parent != this)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int Index = Reference == null ? (Above ? 0 : Children.Count) : Children.IndexOf(Reference) + (Above ? 1 : 0);
            Children.Insert(Index, Child);
            Child.Parent = this;
            Child.References++;
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal NTSTATUS RemoveChild(BinaryEmulator Instance, CompositionVisual Child)
        {
            if (Child.Parent != this)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Children.Remove(Child);
            Child.Parent = null;
            Channel.ReleaseResource(Instance, Child);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal NTSTATUS RemoveAllChildren(BinaryEmulator Instance)
        {
            if (Children.Count == 0)
                return Unchanged;

            ReleaseChildren(Instance);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The last child goes first, so the committed tree drops each child from the end of its parent's list.
        private void ReleaseChildren(BinaryEmulator Instance)
        {
            CompositionVisual[] Held = Children.ToArray();
            Children.Clear();
            for (int Index = Held.Length - 1; Index >= 0; Index--)
            {
                Held[Index].Parent = null;
                Channel.ReleaseResource(Instance, Held[Index]);
            }
        }

        internal override void ReleaseReferences(BinaryEmulator Instance)
        {
            ReleaseSlot(Instance, ref Transform);
            ReleaseChildren(Instance);
        }
    }

    internal sealed class CompositionSpriteVisual : CompositionVisual
    {
        private CompositionResource Brush;

        internal CompositionSpriteVisual(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        internal override NTSTATUS SetReference(BinaryEmulator Instance, uint Property, CompositionResource Target)
        {
            CompositionTableSet Tables = Channel.Tables;
            if (Property == Tables.Property(CompositionProperty.SpriteVisualBrush))
                return SetReferenceSlot(Instance, ref Brush, Target, Tables.RequiredBases(CompositionProperty.SpriteVisualBrush), Optional: true);

            if (Tables.IsRefused(CompositionClass.SpriteVisual, CompositionSlots.Reference, Property))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Tables.IsOwnProperty(CompositionClass.SpriteVisual, CompositionSlots.Reference, Property) ? Unserved : base.SetReference(Instance, Property, Target);
        }

        internal override void ReleaseReferences(BinaryEmulator Instance)
        {
            ReleaseSlot(Instance, ref Brush);
            base.ReleaseReferences(Instance);
        }
    }

    internal sealed class CompositionVisualTarget : CompositionResource
    {
        internal readonly CompositionSharedVisual Shared;
        private CompositionResource Root;
        private bool Holding = true;

        internal CompositionVisualTarget(uint Type, CompositionChannel Channel, CompositionSharedVisual Shared) : base(Type, Channel)
        {
            this.Shared = Shared;
            Shared.Reference();
        }

        protected override CompositionSlots BaseSlots => CompositionSlots.Integer | CompositionSlots.Buffer | CompositionSlots.CallbackId | CompositionSlots.Handle;

        internal override NTSTATUS SetReference(BinaryEmulator Instance, uint Property, CompositionResource Target)
        {
            CompositionTableSet Tables = Channel.Tables;
            if (Property == Tables.Property(CompositionProperty.VisualTargetRoot))
                return SetReferenceSlot(Instance, ref Root, Target, Tables.RequiredBases(CompositionProperty.VisualTargetRoot), Optional: true);

            return Tables.IsOwnProperty(CompositionClass.VisualTarget, CompositionSlots.Reference, Property) ? Unserved : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        internal override void ReleaseReferences(BinaryEmulator Instance)
        {
            ReleaseSlot(Instance, ref Root);
            if (Holding)
            {
                Holding = false;
                Shared.Opened = false;
                Shared.Unreference(Instance);
            }
        }
    }
}
