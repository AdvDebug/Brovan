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

                int Size = Tables.RecordSizes[Opcode];
                uint Id = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(4));
                CompositionResource Resource = Channel.Lookup(Id);
                uint Type = Resource?.Type ?? 0;
                uint Property = 0;
                switch (Tables.Commands[Opcode])
                {
                    case CompositionCommand.CreateResource:
                        Type = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        Status = CreateResource(Channel, Id, Type, BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(12)));
                        break;

                    case CompositionCommand.ReleaseResource:
                        if (Resource == null)
                        {
                            Status = NTSTATUS.STATUS_ACCESS_DENIED;
                            break;
                        }

                        Channel.RemoveId(Id);
                        Channel.ReleaseResource(Resource);
                        break;

                    case CompositionCommand.SetCallbackId:
                        Status = Resource?.SetCallbackId(BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8))) ?? NTSTATUS.STATUS_ACCESS_DENIED;
                        break;

                    case CompositionCommand.SetInteger:
                        Property = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        Status = Resource?.SetInteger(Property, BinaryPrimitives.ReadUInt64LittleEndian(Record.Slice(16))) ?? NTSTATUS.STATUS_ACCESS_DENIED;
                        break;

                    case CompositionCommand.SetBuffer:
                    {
                        Property = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(8));
                        uint Bytes = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(12));
                        ulong Padded = ((ulong)Bytes + 3) & ~3UL;
                        if (Padded > (ulong)(Record.Length - Size))
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        Status = Resource?.SetBuffer(Property, Record.Slice(Size, (int)Bytes)) ?? NTSTATUS.STATUS_ACCESS_DENIED;
                        Size += (int)Padded;
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
                        Status = TargetId != 0 && Target == null ? NTSTATUS.STATUS_INVALID_PARAMETER : Resource.SetReference(Property, Target);
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

                    default:
                        Status = CompositionResource.Unserved;
                        break;
                }

                if (Status == CompositionResource.Unserved && (Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[!] DirectComposition: opcode {Opcode} type 0x{Type:X} property {Property} not served", LogFlags.Issues);

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
    }
}
