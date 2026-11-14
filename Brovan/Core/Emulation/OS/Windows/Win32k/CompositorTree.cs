using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal struct CompositorValue
    {
        private const int InlineBytes = 16;

        private ulong Low;
        private ulong High;
        private byte[] Large;

        internal static CompositorValue FromBytes(ReadOnlySpan<byte> Data)
        {
            if (Data.Length > InlineBytes)
                return new CompositorValue { Large = Data.ToArray() };

            Span<byte> Bytes = stackalloc byte[InlineBytes];
            Bytes.Clear();
            Data.CopyTo(Bytes);
            return new CompositorValue
            {
                Low = BinaryPrimitives.ReadUInt64LittleEndian(Bytes),
                High = BinaryPrimitives.ReadUInt64LittleEndian(Bytes.Slice(8)),
            };
        }

        internal static CompositorValue FromInteger(ulong Value) => new() { Low = Value };

        internal static CompositorValue FromFloat(float Value) => new() { Low = (uint)BitConverter.SingleToInt32Bits(Value) };

        internal ulong Integer => Low;

        internal int Int32(int Index)
        {
            if (Large != null)
                return Index * 4 + 4 <= Large.Length ? BinaryPrimitives.ReadInt32LittleEndian(Large.AsSpan(Index * 4)) : 0;

            if (Index >= InlineBytes / 4)
                return 0;

            ulong Word = Index < 2 ? Low : High;
            return (int)(Word >> (Index % 2 * 32));
        }

        internal float Float(int Index) => BitConverter.Int32BitsToSingle(Int32(Index));
    }

    internal enum CompositionChangeKind : byte
    {
        None,
        Create,
        Open,
        Release,
        Value,
        Reference,
        Object,
        InsertChild,
        RemoveChild,
        RemoveAllChildren,
    }

    internal struct CompositionChange
    {
        internal CompositionChangeKind Kind;
        internal CompositionResource Resource;
        internal CompositionResource Other;
        internal CompositionResource Sibling;
        internal bool Above;
        // A CompositionName for a value, or the CompositionProperty of a reference or a handle.
        internal byte Key;
        internal CompositorValue Value;
        // Held once until the committed tree takes it.
        internal ReferencedNtObject Object;
    }

    internal sealed class CompositorResource
    {
        internal readonly CompositionClass Class;

        internal ReferencedNtObject Held { get; private set; }

        internal CompositorResource Parent;

        // The walk that last drew this resource, so a tree that holds itself is drawn once.
        internal int WalkStamp;

        // Children are kept bottom first, as on the kernel side.
        internal readonly List<CompositorResource> Children = new();

        private List<(CompositionName Name, CompositorValue Value)> Values;
        private List<(CompositionProperty Property, CompositorResource Target)> References;

        internal CompositorResource(CompositionClass Class)
        {
            this.Class = Class;
        }

        // Takes over one hold of the object.
        internal void SetHeld(BinaryEmulator Instance, ReferencedNtObject Object)
        {
            ReferencedNtObject Old = Held;
            Held = Object;
            Old?.Unreference(Instance);
        }

        internal bool TryGet(CompositionName Name, out CompositorValue Value)
        {
            if (Values != null)
            {
                foreach ((CompositionName Held, CompositorValue Stored) in Values)
                {
                    if (Held == Name)
                    {
                        Value = Stored;
                        return true;
                    }
                }
            }

            Value = default;
            return false;
        }

        internal void Set(CompositionName Name, in CompositorValue Value)
        {
            Values ??= new List<(CompositionName, CompositorValue)>(4);
            for (int Index = 0; Index < Values.Count; Index++)
            {
                if (Values[Index].Name == Name)
                {
                    Values[Index] = (Name, Value);
                    return;
                }
            }

            Values.Add((Name, Value));
        }

        internal CompositorResource Reference(CompositionProperty Property)
        {
            if (References != null)
            {
                foreach ((CompositionProperty Held, CompositorResource Target) in References)
                {
                    if (Held == Property)
                        return Target;
                }
            }

            return null;
        }

        internal void SetReference(CompositionProperty Property, CompositorResource Target)
        {
            References ??= new List<(CompositionProperty, CompositorResource)>(2);
            for (int Index = 0; Index < References.Count; Index++)
            {
                if (References[Index].Property == Property)
                {
                    References[Index] = (Property, Target);
                    return;
                }
            }

            References.Add((Property, Target));
        }

        // The kernel side releases a parent's children last first, so a child leaves from the end of its parent's list.
        internal void Detach(BinaryEmulator Instance)
        {
            if (Parent != null)
            {
                int Index = Parent.Children.LastIndexOf(this);
                if (Index >= 0)
                    Parent.Children.RemoveAt(Index);
            }

            Parent = null;
            foreach (CompositorResource Child in Children)
                Child.Parent = null;

            Children.Clear();
            References?.Clear();
            if (Held is CompositionSharedVisual Shared && Shared.Committed == this)
                Shared.Committed = null;

            SetHeld(Instance, null);
        }
    }
}
