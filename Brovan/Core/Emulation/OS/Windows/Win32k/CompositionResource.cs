using System;
using System.Collections.Generic;

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
        Float = 16,
        Handle = 32,
    }

    // Brovan.WinFacts writes these member names into CompositionTables.Generated.cs.
    internal enum CompositionCompare : byte
    {
        None,
        Value,
        NonZero,
        Never,
        AfterCommit,
    }

    // Initial is the start value where it is known: the integer, its truth for a NonZero compare, or the bits of a float.
    // The NonZero flag marks a buffer that takes only nonzero bytes.
    internal sealed record CompositionRule(CompositionClass Class, CompositionSlots Setter, uint Property, int Bytes, ulong[] Values,
        CompositionCompare Compare, ulong? Initial, bool NonZero = false, CompositionProperty? Requires = null, uint[] RequiredBases = null)
    {
        internal bool IsCompared => Compare is CompositionCompare.Value or CompositionCompare.NonZero;
    }

    // A slot in BaseSlots answers as NT's CResourceMarshaler stub does, and any other slot is the type's own code.
    // Brovan.WinFacts checks both against every table version.
    internal abstract class CompositionResource
    {
        internal const NTSTATUS Unserved = NTSTATUS.STATUS_NOT_IMPLEMENTED;

        // Brovan's own status, which the parser turns into success without marking the channel changed.
        internal const NTSTATUS Unchanged = (NTSTATUS)0x000000FF;

        // Brovan's own status, which the parser turns into success, keeping the value without making the batch due.
        internal const NTSTATUS Kept = (NTSTATUS)0x000000FE;

        internal readonly uint Type;
        internal readonly CompositionChannel Channel;
        internal int References = 1;

        // NT counts after-commit properties once a built batch emitted the resource with a gated property set.
        internal bool GateHeld;
        internal bool GateCommitted;
        internal uint DueOrdinal;

        // A property whose start value NT does not show counts as changed at its first set.
        private Dictionary<(CompositionSlots Setter, uint Property), ulong> HeldValues;
        private Dictionary<uint, byte[]> HeldBuffers;

        protected CompositionResource(uint Type, CompositionChannel Channel)
        {
            this.Type = Type;
            this.Channel = Channel;
        }

        protected abstract CompositionSlots BaseSlots { get; }

        internal CompositionClass Class => Channel.Tables.TypeClasses[Type];

        internal CompositionClass RuleClass => Channel.Tables.RuleOwner(Class);

        internal NTSTATUS SetInteger(uint Property, ulong Value)
            => TryGetRule(CompositionSlots.Integer, Property, out CompositionRule Rule, out bool Own) ? SetIntegerByRule(Rule, Value)
                : Own ? Unserved : IntegerFallback(Property, Value);

        internal NTSTATUS SetBuffer(uint Property, ReadOnlySpan<byte> Data)
            => TryGetRule(CompositionSlots.Buffer, Property, out CompositionRule Rule, out bool Own) ? SetBufferByRule(Rule, Data)
                : Own ? Unserved : BufferFallback(Property, Data);

        internal NTSTATUS SetFloat(uint Property, float Value)
            => TryGetRule(CompositionSlots.Float, Property, out CompositionRule Rule, out bool Own) ? SetFloatByRule(Rule, Value)
                : Own ? Unserved : FloatFallback(Property, Value);

        protected virtual NTSTATUS IntegerFallback(uint Property, ulong Value) => BaseAnswer(CompositionSlots.Integer, NTSTATUS.STATUS_INVALID_PARAMETER);

        protected virtual NTSTATUS BufferFallback(uint Property, ReadOnlySpan<byte> Data) => BaseAnswer(CompositionSlots.Buffer, NTSTATUS.STATUS_INVALID_PARAMETER);

        // NT's base SetFloatProperty answers from a per-type property table, so no type has Float in BaseSlots.
        protected virtual NTSTATUS FloatFallback(uint Property, float Value) => Unserved;

        private bool TryGetRule(CompositionSlots Setter, uint Property, out CompositionRule Rule, out bool Own)
        {
            CompositionTableSet Tables = Channel.Tables;
            CompositionClass Owner = RuleClass;
            if (Tables.TryGetRule(Owner, Setter, Property, out Rule))
            {
                Own = true;
                return true;
            }

            Own = Tables.IsOwnProperty(Owner, Setter, Property);
            return false;
        }

        internal virtual NTSTATUS SetReference(BinaryEmulator Instance, uint Property, CompositionResource Target)
            => BaseAnswer(CompositionSlots.Reference, NTSTATUS.STATUS_INVALID_PARAMETER);

        internal virtual NTSTATUS SetCallbackId(uint Id) => BaseAnswer(CompositionSlots.CallbackId, NTSTATUS.STATUS_NOT_SUPPORTED);

        internal virtual NTSTATUS SetHandle(BinaryEmulator Instance, uint Property, ulong Handle) => BaseAnswer(CompositionSlots.Handle, NTSTATUS.STATUS_INVALID_PARAMETER);

        internal virtual CompositionResource HeldReference(CompositionProperty Property) => null;

        internal virtual ReferencedNtObject HeldObject(CompositionProperty Property) => null;

        protected void ClearGate()
        {
            GateHeld = false;
            GateCommitted = false;
        }

        internal virtual CompositionVisual AsVisual => null;

        // Each held reference is released once and its slot cleared, as NT's ReleaseAllReferences does.
        internal virtual void ReleaseReferences(BinaryEmulator Instance)
        {
        }

        private NTSTATUS BaseAnswer(CompositionSlots Slot, NTSTATUS Answer) => (BaseSlots & Slot) != 0 ? Answer : Unserved;

        private NTSTATUS SetIntegerByRule(CompositionRule Rule, ulong Value)
        {
            if (Rule.Values != null && Array.IndexOf(Rule.Values, Value) < 0 || !IsGateOpen(Rule))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Rule.IsCompared)
                return Taken(Rule);

            return Hold(Rule, Rule.Compare == CompositionCompare.NonZero ? (Value != 0 ? 1UL : 0UL) : Value, IsFloat: false);
        }

        private NTSTATUS SetFloatByRule(CompositionRule Rule, float Value)
        {
            if (!IsGateOpen(Rule))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Rule.IsCompared ? Hold(Rule, (uint)BitConverter.SingleToInt32Bits(Value), IsFloat: true) : Taken(Rule);
        }

        private NTSTATUS SetBufferByRule(CompositionRule Rule, ReadOnlySpan<byte> Data)
        {
            if (Data.Length != Rule.Bytes || Rule.NonZero && !Data.ContainsAnyExcept((byte)0) || !IsGateOpen(Rule))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Rule.IsCompared)
                return Taken(Rule);

            HeldBuffers ??= new Dictionary<uint, byte[]>();
            HeldBuffers.TryGetValue(Rule.Property, out byte[] Held);
            if (Held != null ? Data.SequenceEqual(Held) : Rule.Initial == 0 && !Data.ContainsAnyExcept((byte)0))
                return Unchanged;

            if (Held == null)
                HeldBuffers[Rule.Property] = Data.ToArray();
            else
                Data.CopyTo(Held);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private bool IsGateOpen(CompositionRule Rule)
        {
            if (Rule.Requires is not CompositionProperty Gate)
                return true;

            CompositionResource Held = HeldReference(Gate);
            return Held != null && IsDerivedFromAny(Channel.Tables, Held.Type, Rule.RequiredBases);
        }

        private NTSTATUS Taken(CompositionRule Rule)
        {
            if (Rule.Requires != null)
            {
                GateHeld = true;
                Channel.WatchGate(this);
            }

            return Rule.Compare switch
            {
                CompositionCompare.Never => Kept,
                CompositionCompare.AfterCommit => GateCommitted ? NTSTATUS.STATUS_SUCCESS : Kept,
                _ => NTSTATUS.STATUS_SUCCESS,
            };
        }

        // NT compares floats as floats, so 0 equals -0 and a NaN equals nothing.
        private NTSTATUS Hold(CompositionRule Rule, ulong Value, bool IsFloat)
        {
            HeldValues ??= new Dictionary<(CompositionSlots, uint), ulong>();
            ulong? Held = HeldValues.TryGetValue((Rule.Setter, Rule.Property), out ulong Set) ? Set : Rule.Initial;
            if (Held is ulong Known && (IsFloat ? BitConverter.Int32BitsToSingle((int)Known) == BitConverter.Int32BitsToSingle((int)Value) : Known == Value))
                return Unchanged;

            HeldValues[(Rule.Setter, Rule.Property)] = Value;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The type checks follow CResourceMarshaler::SetReferencePropertyHelper.
        protected NTSTATUS SetReferenceSlot(BinaryEmulator Instance, ref CompositionResource Slot, CompositionResource Target, uint[] RequiredBases, bool Optional)
        {
            if (Target != null ? !IsDerivedFromAny(Channel.Tables, Target.Type, RequiredBases) : !Optional)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Target == Slot)
                return NTSTATUS.STATUS_SUCCESS;

            if (Target != null)
                Target.References++;

            CompositionResource Old = Slot;
            Slot = Target;
            Old?.Channel.ReleaseResource(Instance, Old);
            return NTSTATUS.STATUS_SUCCESS;
        }

        protected static void ReleaseSlot(BinaryEmulator Instance, ref CompositionResource Slot)
        {
            CompositionResource Held = Slot;
            Slot = null;
            Held?.Channel.ReleaseResource(Instance, Held);
        }

        internal static bool IsDerivedFromAny(CompositionTableSet Tables, uint Type, uint[] Bases)
        {
            foreach (uint Base in Bases)
            {
                if (IsDerived(Tables, Type, Base))
                    return true;
            }

            return false;
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
            CompositionClass.SpriteVisual => new CompositionSpriteVisual(Type, Channel),
            CompositionClass.SurfaceBrush => new CompositionSurfaceBrush(Type, Channel),
            CompositionClass.CompositionSurfaceBitmap => new CompositionSurfaceBitmap(Type, Channel),
            _ => null
        };
    }

    // Mirrors CNotificationResourceMarshaler, which takes any callback ID.
    internal abstract class CompositionNotificationResource : CompositionResource
    {
        private uint CallbackId;

        protected CompositionNotificationResource(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        internal override NTSTATUS SetCallbackId(uint Id)
        {
            if (Id == CallbackId)
                return Unchanged;

            CallbackId = Id;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    // Mirrors CPropertyChangeResourceMarshaler, whose one integer property is the property-change mask.
    internal abstract class CompositionPropertyChangeResource : CompositionNotificationResource
    {
        private uint PropertyChangeMask;

        protected CompositionPropertyChangeResource(uint Type, CompositionChannel Channel) : base(Type, Channel)
        {
        }

        protected override NTSTATUS IntegerFallback(uint Property, ulong Value)
        {
            if (Property != Channel.Tables.Property(CompositionProperty.PropertyChangeMask))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((uint)Value == PropertyChangeMask)
                return Unchanged;

            PropertyChangeMask = (uint)Value;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
