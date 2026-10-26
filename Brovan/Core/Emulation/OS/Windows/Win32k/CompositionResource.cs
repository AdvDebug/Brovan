using System;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // Brovan.WinFacts writes these member names into CompositionTables.Generated.cs.
    [Flags]
    internal enum CompositionSlots
    {
        None = 0,
        Integer = 1,
        Buffer = 2,
        Reference = 4,
        CallbackId = 8,
    }

    // A slot in BaseSlots answers as NT's CResourceMarshaler stub does, and any other slot is the type's own code.
    // Brovan.WinFacts checks both against every table version.
    internal abstract class CompositionResource
    {
        internal const NTSTATUS Unserved = NTSTATUS.STATUS_NOT_IMPLEMENTED;

        internal readonly uint Type;
        internal readonly CompositionChannel Channel;
        internal int References = 1;

        protected CompositionResource(uint Type, CompositionChannel Channel)
        {
            this.Type = Type;
            this.Channel = Channel;
        }

        protected abstract CompositionSlots BaseSlots { get; }

        internal virtual NTSTATUS SetInteger(uint Property, ulong Value) => BaseAnswer(CompositionSlots.Integer, NTSTATUS.STATUS_INVALID_PARAMETER);

        internal virtual NTSTATUS SetBuffer(uint Property, ReadOnlySpan<byte> Data) => BaseAnswer(CompositionSlots.Buffer, NTSTATUS.STATUS_INVALID_PARAMETER);

        internal virtual NTSTATUS SetReference(uint Property, CompositionResource Target) => BaseAnswer(CompositionSlots.Reference, NTSTATUS.STATUS_INVALID_PARAMETER);

        internal virtual NTSTATUS SetCallbackId(uint Id) => BaseAnswer(CompositionSlots.CallbackId, NTSTATUS.STATUS_NOT_SUPPORTED);

        internal virtual CompositionVisual AsVisual => null;

        // Each held reference is released once and its slot cleared, as NT's ReleaseAllReferences does.
        internal virtual void ReleaseReferences()
        {
        }

        private NTSTATUS BaseAnswer(CompositionSlots Slot, NTSTATUS Answer) => (BaseSlots & Slot) != 0 ? Answer : Unserved;

        // The type checks follow CResourceMarshaler::SetReferencePropertyHelper.
        protected NTSTATUS SetReferenceSlot(ref CompositionResource Slot, CompositionResource Target, uint RequiredBase, bool Optional)
        {
            if (Target != null ? !IsDerived(Channel.Tables, Target.Type, RequiredBase) : !Optional)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Target == Slot)
                return NTSTATUS.STATUS_SUCCESS;

            if (Target != null)
                Target.References++;

            CompositionResource Old = Slot;
            Slot = Target;
            Old?.Channel.ReleaseResource(Old);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT walks parent types until it meets Base or leaves the table (IsDerivedResourceType).
        internal static bool IsDerived(CompositionTableSet Tables, uint Type, uint Base)
        {
            while (Type < Tables.Parents.Length)
            {
                if (Type == Base)
                    return true;

                Type = Tables.Parents[Type];
            }

            return false;
        }

        // Only the classes modeled here are created, and types can share a class (CApplicationChannel::CreatePrivateMarshaler).
        internal static CompositionResource Create(uint Type, CompositionChannel Channel) => Channel.Tables.TypeClasses[Type] switch
        {
            CompositionClass.BlurredWallpaperBackdropBrush => new CompositionBlurredWallpaperBackdropBrush(Type, Channel),
            CompositionClass.ColorBrush => new CompositionColorBrush(Type, Channel),
            CompositionClass.ComponentTransform3D => new CompositionComponentTransform3D(Type, Channel),
            CompositionClass.Visual => new CompositionVisual(Type, Channel),
            _ => null
        };
    }

    // Mirrors CNotificationResourceMarshaler, which takes any callback ID.
    internal abstract class CompositionNotificationResource : CompositionResource
    {
        protected CompositionNotificationResource(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        internal override NTSTATUS SetCallbackId(uint Id) => NTSTATUS.STATUS_SUCCESS;
    }

    // Mirrors CPropertyChangeResourceMarshaler, whose one integer property is the property-change mask.
    internal abstract class CompositionPropertyChangeResource : CompositionNotificationResource
    {
        protected CompositionPropertyChangeResource(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        internal override NTSTATUS SetInteger(uint Property, ulong Value)
            => Property == Channel.Tables.Property(CompositionProperty.PropertyChangeMask) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
    }
}
