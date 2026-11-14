using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // Opcodes and record sizes come from the channel's tables. Field offsets are the same in every version they cover.
    internal static class CompositionBatchParser
    {
        internal static NTSTATUS Process(BinaryEmulator Instance, CompositionChannel Channel, ReadOnlySpan<byte> Batch, ref uint Count)
        {
            CompositionTableSet Tables = Channel.Tables;
            NTSTATUS Status = NTSTATUS.STATUS_SUCCESS;
            int Offset = 0;
            while (Status == NTSTATUS.STATUS_SUCCESS && Batch.Length - Offset >= 4)
            {
                // NT counts a record before it handles it, so a failing record is counted.
                Count++;
                ReadOnlySpan<byte> Record = Batch.Slice(Offset);
                uint Opcode = BinaryPrimitives.ReadUInt32LittleEndian(Record);
                if (Tables == null)
                {
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[!] DirectComposition: opcode {Opcode} not served, no tables for this win32kbase.sys", LogFlags.Issues);

                    return CompositionResource.Unserved;
                }

                if (Opcode >= Tables.RecordSizes.Length || Tables.RecordSizes[Opcode] == 0 || Record.Length < Tables.RecordSizes[Opcode])
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Channel.CanCapture)
                    return NTSTATUS.STATUS_NO_MEMORY;

                int Size = Tables.RecordSizes[Opcode];
                uint Id = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(4));
                CompositionResource Resource = Channel.Lookup(Id);
                uint Type = Resource?.Type ?? 0;
                uint Property = 0;
                CompositionChange Change = new() { Resource = Resource };
                switch (Tables.Commands[Opcode])
                {
                    case CompositionCommand.CreateResource:
                        Type = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        Status = CreateResource(Channel, Id, Type, BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(12)));
                        Change = new CompositionChange { Kind = CompositionChangeKind.Create, Resource = Channel.Lookup(Id) };
                        break;

                    case CompositionCommand.OpenResource:
                    {
                        Type = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(16));
                        if (Type == 0 || Type > Tables.MaxType)
                        {
                            Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                            break;
                        }

                        // NT: a nonzero mode opens a shared resource for writing, which is not modeled.
                        if (BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(20)) != 0)
                        {
                            Status = CompositionResource.Unserved;
                            break;
                        }

                        Status = Channel.OpenSharedResource(Instance, Id, BinaryPrimitives.ReadUInt64LittleEndian(Record.Slice(8)), Type, out CompositionResource Opened);
                        Change = new CompositionChange { Kind = CompositionChangeKind.Open, Resource = Opened };
                        break;
                    }

                    // NT builds no batch for the release of a resource that something still holds.
                    case CompositionCommand.ReleaseResource:
                        if (Resource == null)
                        {
                            Status = NTSTATUS.STATUS_ACCESS_DENIED;
                            break;
                        }

                        Status = Resource.References == 1 ? NTSTATUS.STATUS_SUCCESS : CompositionResource.Unchanged;
                        Channel.RemoveId(Id);
                        Channel.ReleaseResource(Instance, Resource);
                        break;

                    case CompositionCommand.SetCallbackId:
                        Status = Resource?.SetCallbackId(BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8))) ?? NTSTATUS.STATUS_ACCESS_DENIED;
                        break;

                    case CompositionCommand.SetInteger:
                    {
                        Property = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        ulong Value = BinaryPrimitives.ReadUInt64LittleEndian(Record.Slice(16));
                        Status = Resource?.SetInteger(Property, Value) ?? NTSTATUS.STATUS_ACCESS_DENIED;
                        if (Status is NTSTATUS.STATUS_SUCCESS or CompositionResource.Kept && TryNameValue(Channel, ref Change, CompositionSlots.Integer, Property))
                            Change.Value = CompositorValue.FromInteger(Value);
                        break;
                    }

                    case CompositionCommand.SetFloat:
                    {
                        Property = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        float Value = BinaryPrimitives.ReadSingleLittleEndian(Record.Slice(12));
                        Status = Resource?.SetFloat(Property, Value) ?? NTSTATUS.STATUS_ACCESS_DENIED;
                        if (Status is NTSTATUS.STATUS_SUCCESS or CompositionResource.Kept && TryNameValue(Channel, ref Change, CompositionSlots.Float, Property))
                            Change.Value = CompositorValue.FromFloat(Value);
                        break;
                    }

                    case CompositionCommand.SetBuffer:
                    {
                        Property = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        uint Bytes = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(12));
                        ulong Padded = ((ulong)Bytes + 3) & ~3UL;
                        if (Padded > (ulong)(Record.Length - Size))
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        ReadOnlySpan<byte> Data = Record.Slice(Size, (int)Bytes);
                        Status = Resource?.SetBuffer(Property, Data) ?? NTSTATUS.STATUS_ACCESS_DENIED;
                        if (Status is NTSTATUS.STATUS_SUCCESS or CompositionResource.Kept && TryNameValue(Channel, ref Change, CompositionSlots.Buffer, Property))
                            Change.Value = CompositorValue.FromBytes(Data);

                        Size += (int)Padded;
                        break;
                    }

                    case CompositionCommand.SetHandle:
                    {
                        Property = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        ulong Handle = BinaryPrimitives.ReadUInt64LittleEndian(Record.Slice(16));
                        Status = Resource?.SetHandle(Instance, Property, Handle) ?? NTSTATUS.STATUS_ACCESS_DENIED;
                        if (Status == NTSTATUS.STATUS_SUCCESS && Tables.TryGetHandle(Resource.Class, Property, out CompositionProperty Name, out _, out _))
                        {
                            ReferencedNtObject Held = Resource.HeldObject(Name);
                            Held?.Reference();
                            Change = new CompositionChange { Kind = CompositionChangeKind.Object, Resource = Resource, Key = (byte)Name, Object = Held };
                        }

                        break;
                    }

                    case CompositionCommand.SetReference:
                    {
                        if (Resource == null)
                        {
                            Status = NTSTATUS.STATUS_ACCESS_DENIED;
                            break;
                        }

                        Property = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        uint TargetId = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(12));
                        CompositionResource Target = Channel.Lookup(TargetId);
                        Status = TargetId != 0 && Target == null ? NTSTATUS.STATUS_INVALID_PARAMETER : Resource.SetReference(Instance, Property, Target);
                        if (Tables.TryGetReference(Resource.Class, Property, out CompositionProperty Name))
                            Change = new CompositionChange { Kind = CompositionChangeKind.Reference, Resource = Resource, Other = Target, Key = (byte)Name };

                        break;
                    }

                    case CompositionCommand.SetVisualInputSink:
                        if (Resource == null)
                            Status = NTSTATUS.STATUS_ACCESS_DENIED;
                        else if (Resource.AsVisual == null)
                            Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                        else if (BinaryPrimitives.ReadUInt64LittleEndian(Record.Slice(8)) != 0)
                            Status = CompositionResource.Unserved;
                        break;

                    case CompositionCommand.InsertChild:
                        Status = InsertChild(Channel, Resource, Record, ref Change);
                        break;

                    case CompositionCommand.RemoveChild:
                        Status = RemoveChild(Instance, Channel, Resource, Record, ref Change);
                        break;

                    default:
                        Status = CompositionResource.Unserved;
                        break;
                }

                if (Status == CompositionResource.Unserved && (Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[!] DirectComposition: opcode {Opcode} type 0x{Type:X} property {Property} not served", LogFlags.Issues);

                if (Status == CompositionResource.Unchanged)
                {
                    Status = NTSTATUS.STATUS_SUCCESS;
                }
                else if (Status == CompositionResource.Kept)
                {
                    Status = NTSTATUS.STATUS_SUCCESS;
                    Channel.MarkChanged(Instance, Change, Due: false);
                }
                else if (Status == NTSTATUS.STATUS_SUCCESS)
                {
                    Channel.MarkChanged(Instance, Change);
                }

                Offset += Size;
            }

            // NT fails an otherwise successful batch that leaves one to three bytes over.
            return Status == NTSTATUS.STATUS_SUCCESS && Offset != Batch.Length ? NTSTATUS.STATUS_INVALID_PARAMETER : Status;
        }

        private static NTSTATUS CreateResource(CompositionChannel Channel, uint Id, uint Type, uint Sharing)
        {
            if (Type == 0 || Type > Channel.Tables.MaxType)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Sharing != 0 ? CompositionResource.Unserved : Channel.TryCreateResource(Id, Type);
        }

        private static bool TryNameValue(CompositionChannel Channel, ref CompositionChange Change, CompositionSlots Setter, uint Property)
        {
            if (Change.Resource == null || !Channel.Process.TryGetName(Change.Resource.RuleClass, Setter, Property, out CompositionName Name))
                return false;

            Change = new CompositionChange { Kind = CompositionChangeKind.Value, Resource = Change.Resource, Key = (byte)Name };
            return true;
        }

        private static NTSTATUS InsertChild(CompositionChannel Channel, CompositionResource Resource, ReadOnlySpan<byte> Record, ref CompositionChange Change)
        {
            if (Resource == null)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            CompositionVisual Parent = Resource.AsVisual;
            CompositionVisual Child = Channel.Lookup(BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8)))?.AsVisual;
            uint ReferenceId = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(16));
            CompositionVisual Reference = ReferenceId != 0 ? Channel.Lookup(ReferenceId)?.AsVisual : null;
            if (Parent == null || Child == null || ReferenceId != 0 && Reference == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool Above = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(12)) != 0;
            Change = new CompositionChange { Kind = CompositionChangeKind.InsertChild, Resource = Parent, Other = Child, Sibling = Reference, Above = Above };
            return Parent.AddChild(Child, Above, Reference);
        }

        // NT removes every child when the child ID is 0.
        private static NTSTATUS RemoveChild(BinaryEmulator Instance, CompositionChannel Channel, CompositionResource Resource, ReadOnlySpan<byte> Record,
            ref CompositionChange Change)
        {
            if (Resource == null)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            CompositionVisual Parent = Resource.AsVisual;
            uint ChildId = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
            if (Parent == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (ChildId == 0)
            {
                Change = new CompositionChange { Kind = CompositionChangeKind.RemoveAllChildren, Resource = Parent };
                return Parent.RemoveAllChildren(Instance);
            }

            CompositionVisual Child = Channel.Lookup(ChildId)?.AsVisual;
            if (Child == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Change = new CompositionChange { Kind = CompositionChangeKind.RemoveChild, Resource = Parent, Other = Child };
            return Parent.RemoveChild(Instance, Child);
        }
    }
}
