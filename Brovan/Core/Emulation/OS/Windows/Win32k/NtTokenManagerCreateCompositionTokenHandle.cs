using System.Buffers.Binary;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtTokenManagerCreateCompositionTokenHandle : IWinSyscall
    {
        // Each update is a 64-bit surface handle and a RECT on x86 and x64 (CompositionTokenObject::ObjectInit).
        private const int UpdateSize = 24;
        private const int OffsetRect = 8;

        private const AccessMask SurfaceAccess = (AccessMask)2;
        private const AccessMask TokenAccess = (AccessMask)3;

        // NT writes the handle last, so a bad output pointer fails after the token was made, and the release ends it.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong UpdatesPtr = Instance.WinHelper.GetArg(0);
            uint Count = Instance.WinHelper.GetArg32(1);
            uint Distinct = Instance.WinHelper.GetArg32(2);
            ulong PresentIdPtr = Instance.WinHelper.GetArg(3);
            ulong SynchronizationIdPtr = Instance.WinHelper.GetArg(4);
            ulong HandlePtr = Instance.WinHelper.GetArg(5);

            if (UpdatesPtr == 0 || Count == 0 || Distinct == 0 || PresentIdPtr == 0 || SynchronizationIdPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Count > uint.MaxValue / UpdateSize)
                return NTSTATUS.STATUS_INTEGER_OVERFLOW;

            CompositionProcess Composition = Instance.WinHelper.Composition;
            if (Count > MemoryBudget.CompositionTokenUpdates || !Composition.TryAddToken((int)Count))
                return NTSTATUS.STATUS_NO_MEMORY;

            Span<byte> Updates = Instance.WinHelper.Shared.GetSpan((ulong)Count * UpdateSize).Slice(0, (int)Count * UpdateSize);
            Span<byte> Ids = stackalloc byte[16];
            if (!Instance.ReadMemory(UpdatesPtr, Updates) || !Instance.ReadMemory(PresentIdPtr, Ids.Slice(0, 8)) ||
                !Instance.ReadMemory(SynchronizationIdPtr, Ids.Slice(8)))
            {
                Composition.RemoveToken((int)Count);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            DxgkCompositionToken Token = new()
            {
                SynchronizationId = BinaryPrimitives.ReadUInt64LittleEndian(Ids.Slice(8)),
                Rects = (int)Count,
            };

            NTSTATUS Status = Fill(Instance, Token, Updates, Distinct);
            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Token.Discard(Instance);
                Composition.RemoveToken(Token.Rects);
                return Status;
            }

            if (HandlePtr == 0)
            {
                Token.Release(Instance);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            Status = Token.Insert(Instance, TokenAccess, HandlePtr);
            if (Status == NTSTATUS.STATUS_SUCCESS)
            {
                Token.Notified = true;
                Composition.NotifyPendingPresent(Token.SynchronizationId);
            }

            return Status;
        }

        private static NTSTATUS Fill(BinaryEmulator Instance, DxgkCompositionToken Token, ReadOnlySpan<byte> Updates, uint Distinct)
        {
            Dictionary<DxgkCompositionSurface, DxgkCompositionUpdate> BySurface = new();
            for (int Offset = 0; Offset < Updates.Length; Offset += UpdateSize)
            {
                ReadOnlySpan<byte> Entry = Updates.Slice(Offset, UpdateSize);
                NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(BinaryPrimitives.ReadUInt64LittleEndian(Entry), SurfaceAccess,
                    out DxgkCompositionSurface Surface);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                if (Surface.ActiveBuffer == null)
                    return NTSTATUS.STATUS_NOT_FOUND;

                if (!BySurface.TryGetValue(Surface, out DxgkCompositionUpdate Update))
                {
                    if (Token.Updates.Count == Distinct)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    Surface.Reference();
                    Update = new DxgkCompositionUpdate(Surface);
                    Token.Updates.Add(Update);
                    BySurface.Add(Surface, Update);
                }

                ReadOnlySpan<byte> Rect = Entry.Slice(OffsetRect);
                Update.Rects.Add(new DxgkDirtyRect(BinaryPrimitives.ReadInt32LittleEndian(Rect), BinaryPrimitives.ReadInt32LittleEndian(Rect.Slice(4)),
                    BinaryPrimitives.ReadInt32LittleEndian(Rect.Slice(8)), BinaryPrimitives.ReadInt32LittleEndian(Rect.Slice(12))));
            }

            return Token.Updates.Count == Distinct ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
