using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.Intrinsics;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal sealed class DxgkCompositionSurface : DxgkNtObject
    {
        internal const int StatisticsSize = 0x50;

        // NT DxgkCompositionObjectType is 1 for a surface and 2 for a token.
        internal const uint ObjectKind = 1;

        internal readonly List<DxgkCompositionBuffer> Buffers = new();
        private ulong LastBindingId;

        public override HandleType ObjectType => HandleType.DxgkCompositionObjectHandle;

        internal override string TypeName => "DxgkCompositionObject";

        // NT: only the newest buffer can be active (CCompositionSurface::GetActiveBuffer).
        internal DxgkCompositionBuffer ActiveBuffer => Buffers.Count != 0 && Buffers[0].Active ? Buffers[0] : null;

        internal DxgkCompositionBuffer GetBoundBuffer(ulong BindingId)
        {
            DxgkCompositionBuffer Active = ActiveBuffer;
            return Active?.BindingId == BindingId ? Active : null;
        }

        internal ulong Bind(DxgkCompositionBuffer Buffer)
        {
            Buffer.BindingId = ++LastBindingId;
            Buffer.Active = true;
            Buffer.Surface = this;
            Buffers.Insert(0, Buffer);
            return Buffer.BindingId;
        }

        internal void ReleaseBuffers(BinaryEmulator Instance, DxgkProcess Process)
        {
            foreach (DxgkCompositionBuffer Buffer in Buffers)
                Buffer.Release(Instance, Process);

            Buffers.Clear();
        }

        protected override void OnRelease(BinaryEmulator Instance)
        {
            ReleaseBuffers(Instance, Instance.WinHelper.DxgkProcess);
            Instance.WinHelper.Composition.Compositor.ForgetSurface(this);
        }
    }

    internal readonly record struct DxgkDirtyRect(int Left, int Top, int Right, int Bottom);

    internal sealed class DxgkCompositionUpdate
    {
        internal readonly DxgkCompositionSurface Surface;
        internal readonly List<DxgkDirtyRect> Rects = new();

        internal DxgkCompositionUpdate(DxgkCompositionSurface Surface)
        {
            this.Surface = Surface;
        }
    }

    internal sealed class DxgkCompositionToken : DxgkNtObject
    {
        private enum TokenState
        {
            Pending,
            Completed,
            InFrame,
            Discarded,
        }

        internal readonly List<DxgkCompositionUpdate> Updates = new();
        internal ulong SynchronizationId;
        private TokenState State;

        internal int Rects;

        internal bool Notified;

        public override HandleType ObjectType => HandleType.DxgkCompositionObjectHandle;

        internal override string TypeName => "DxgkCompositionObject";

        internal void Complete(BinaryEmulator Instance)
        {
            if (State != TokenState.Pending)
                return;

            State = TokenState.Completed;
            CompositionProcess Composition = Instance.WinHelper.Composition;
            Composition.NotifyCompletedPresent(Instance, SynchronizationId);
            Composition.TokenCompleted(Instance, this);
        }

        internal void DropPresent(BinaryEmulator Instance)
        {
            if (State == TokenState.Pending)
                Discard(Instance);
        }

        internal void EnterFrame(BinaryEmulator Instance)
        {
            State = TokenState.InFrame;
            Discard(Instance);
        }

        // NT: a token discarded before it completed tells the batch side its present completed (CCompositionToken::Discard).
        internal void Discard(BinaryEmulator Instance)
        {
            if (State == TokenState.Discarded)
                return;

            if (State == TokenState.Pending && Notified)
                Instance.WinHelper.Composition.NotifyCompletedPresent(Instance, SynchronizationId);

            State = TokenState.Discarded;
            foreach (DxgkCompositionUpdate Update in Updates)
                Update.Surface.Unreference(Instance);

            Updates.Clear();
        }

        protected override void OnRelease(BinaryEmulator Instance)
        {
            Discard(Instance);
            Instance.WinHelper.Composition.RemoveToken(Rects);
        }
    }

    // A swapchain bound to a surface, CFlipExBuffer in dxgkrnl.
    internal sealed class DxgkCompositionBuffer
    {
        // CSM_BUFFER_STATISTICS as dxgi reads it into DXGI_FRAME_STATISTICS.
        private const int OffsetPresentCount = 24;
        private const int OffsetPresentRefreshCount = 28;
        private const int OffsetSyncRefreshCount = 32;
        private const int OffsetSyncQpcTime = 40;
        private const int OffsetCompositionFrame = 64;
        private const int OffsetCompositionPresentCount = 72;

        internal ulong BindingId;
        internal bool Active;
        internal DxgkCompositionSurface Surface;
        internal DxgkStorage[][] Realizations;

        internal uint Scaling;
        internal DxgkPresentPacket NewestPresent;
        internal ulong Window;
        internal WinSemaphore PresentLimit;
        internal DxgkFence FlipExFence;

        internal bool Ended;
        private ulong ShownFenceValue;
        internal readonly Queue<DxgkPresentPacket> Pending = new();

        internal readonly byte[] Statistics = new byte[DxgkCompositionSurface.StatisticsSize];
        internal bool HasStatistics;

        // Only the newest consumed present was drawn, because each frame replaces the undrawn one in its slot.
        internal void RetireConsumed(BinaryEmulator Instance)
        {
            DxgkPresentPacket Newest = null;
            int Released = 0;
            while (Pending.TryPeek(out DxgkPresentPacket Present) && Present.Slot != null && Present.Serial <= Present.Slot.Consumed)
            {
                Pending.Dequeue();
                Released += Present.PresentLimitReleases;
                Newest = Present;
            }

            if (Newest != null)
                Show(Instance, Newest, Released);
        }

        internal void Show(BinaryEmulator Instance, DxgkPresentPacket Present, int PresentLimitReleases)
        {
            ReleaseOlderBuffers(Instance, Present.FenceValue);
            ShownFenceValue = Math.Max(ShownFenceValue, Present.FenceValue);

            Instance.WinHelper.GetVerticalBlankClock(out _, out long Period, out long VerticalBlank);
            uint RefreshCount = (uint)(VerticalBlank / Period);
            Span<byte> Data = Statistics;
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(OffsetPresentCount), Present.PresentCount);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(OffsetPresentRefreshCount), RefreshCount);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(OffsetSyncRefreshCount), RefreshCount);
            BinaryPrimitives.WriteInt64LittleEndian(Data.Slice(OffsetSyncQpcTime), VerticalBlank);
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(OffsetCompositionFrame), RefreshCount);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(OffsetCompositionPresentCount), Present.PresentCount);
            HasStatistics = true;

            ReleasePresentLimit(PresentLimitReleases);
        }

        internal void Skip(BinaryEmulator Instance, ulong FenceValue, int PresentLimitReleases)
        {
            ReleaseOlderBuffers(Instance, FenceValue);
            ReleasePresentLimit(PresentLimitReleases);
        }

        internal void ReleasePresentLimit(int Count) => PresentLimit?.ReleaseUpToMaximum(Count);

        internal void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
            Ended = true;
            int Dropped = 0;
            while (Pending.TryDequeue(out DxgkPresentPacket Present))
                Dropped += Present.PresentLimitReleases;

            FlipExFence?.Signal(Instance, ShownFenceValue);
            ReleasePresentLimit(Dropped);
            Process.RemovePendingBuffer(this);
            foreach (DxgkStorage[] Realization in Realizations)
                DxgkStorage.Release(Instance, Process, Realization);
        }

        // NT: the present on screen keeps its buffer, and the FlipEx fence releases every older one.
        private void ReleaseOlderBuffers(BinaryEmulator Instance, ulong FenceValue)
        {
            if (FenceValue > 1)
                FlipExFence?.Signal(Instance, FenceValue - 1);
        }
    }

    // Brovan stands in for DWM, so a redirected flip is drawn straight into the window of its binding.
    internal static class DxgkComposition
    {
        internal const uint TokenModelRedirectedFlip = 2;
        internal const uint ScalingNone = 1;
        internal const uint TokenModelComposition = 7;
        internal const int OffsetTokenBindingId = 8;

        private const uint FormatR8G8B8A8 = 28;
        private const uint FormatR8G8B8A8Srgb = 29;
        private const uint FormatB8G8R8A8 = 87;
        private const uint FormatB8G8R8X8 = 88;
        private const uint FormatB8G8R8A8Srgb = 91;
        private const uint FormatB8G8R8X8Srgb = 93;

        internal static bool IsPresentableFormat(uint Format) => Format is FormatR8G8B8A8 or FormatR8G8B8A8Srgb or FormatB8G8R8A8
            or FormatB8G8R8X8 or FormatB8G8R8A8Srgb or FormatB8G8R8X8Srgb;

        internal static bool TryPresent(BinaryEmulator Instance, DxgkPresentPacket Present)
        {
            DxgkCompositionBuffer Buffer = Present.Buffer;
            if (Buffer.Ended || Present.Index >= Buffer.Realizations.Length)
            {
                Present.Drop();
                return true;
            }

            if (Buffer.Pending.Count >= MemoryBudget.DxgkPendingPresents)
                return false;

            // A present that is not drawn shows after the presents before it, which keeps the statistics in order.
            bool Undrawn = !Instance.WinHelper.Composition.Compositor.TryTakeBase(Instance, Present) &&
                           !TryHandToWindow(Instance, Buffer.Realizations[Present.Index], Present);
            if (Undrawn)
                MarkUndrawn(Present);

            Buffer.Pending.Enqueue(Present);
            Buffer.NewestPresent = Present;
            Instance.WinHelper.DxgkProcess.AddPendingBuffer(Buffer);
            if (Undrawn)
                Buffer.RetireConsumed(Instance);

            return true;
        }

        internal static void HandBack(BinaryEmulator Instance, DxgkPresentPacket Present)
        {
            if (Present.Buffer.Ended || !TryHandToWindow(Instance, Present.Buffer.Realizations[Present.Index], Present))
                MarkUndrawn(Present);
        }

        // NT: a present that passed the window check shows, even when its window went before it ran.
        internal static void MarkUndrawn(DxgkPresentPacket Present)
        {
            Present.Slot = UndrawnSlot;
            Present.Serial = 0;
        }

        private static readonly GuiThreadManager.FrameSlot UndrawnSlot = new();

        private static bool TryHandToWindow(BinaryEmulator Instance, DxgkStorage[] Realization, DxgkPresentPacket Present)
        {
            ulong Window = Present.Buffer.Window;
            return Realization.Length == 1 && Instance.WinHelper.GuiManager is GuiThreadManager Gui
                && TryCreateFrame(Instance, Window, Realization[0], Present.Buffer.Scaling, out GdiPrimitive Frame)
                && Gui.TrySubmitFrame(Window, Frame, out Present.Slot, out Present.Serial);
        }

        internal static bool IsReadable(DxgkStorage Block) => IsPresentableFormat(Block.Format) && HasRows(Block);

        private static bool HasRows(DxgkStorage Block)
        {
            int Width = (int)Block.Width;
            int Height = (int)Block.Height;
            return Win32kHelper.IsBlitExtentValid(Width, Height) && Block.Pitch >= (ulong)Width * 4
                   && (ulong)Block.Pitch * (ulong)(Height - 1) + (ulong)Width * 4 <= Block.Size;
        }

        internal static DxgkDirtyRect ClampRect(DxgkStorage Block, in DxgkDirtyRect Rect)
            => new(Math.Clamp(Rect.Left, 0, (int)Block.Width), Math.Clamp(Rect.Top, 0, (int)Block.Height), Math.Clamp(Rect.Right, 0, (int)Block.Width),
                Math.Clamp(Rect.Bottom, 0, (int)Block.Height));

        internal static void CopyRect(DxgkStorage Block, uint[] Target, in DxgkDirtyRect Rect)
        {
            DxgkDirtyRect Clamped = ClampRect(Block, Rect);
            if (Clamped.Left < Clamped.Right && Clamped.Top < Clamped.Bottom)
                CopyRows(Block, Target, (int)Block.Width, Clamped, Opaque: Block.Format is FormatB8G8R8X8 or FormatB8G8R8X8Srgb);
        }

        private static unsafe void CopyRows(DxgkStorage Block, uint[] Target, int TargetWidth, in DxgkDirtyRect Rect, bool Opaque)
        {
            int Columns = Rect.Right - Rect.Left;
            bool SwapRedBlue = Block.Format is FormatR8G8B8A8 or FormatR8G8B8A8Srgb;
            byte* Source = (byte*)Block.Memory;
            for (int Row = Rect.Top; Row < Rect.Bottom; Row++)
            {
                ReadOnlySpan<uint> Line = new(Source + (long)Row * Block.Pitch + Rect.Left * 4L, Columns);
                Span<uint> Into = Target.AsSpan(Row * TargetWidth + Rect.Left, Columns);
                if (SwapRedBlue)
                    CopySwappingRedBlue(Line, Into);
                else
                    Line.CopyTo(Into);

                if (Opaque)
                    SetOpaque(Into);
            }
        }

        private static void SetOpaque(Span<uint> Pixels)
        {
            int Index = 0;
            if (Vector128.IsHardwareAccelerated)
            {
                Vector128<uint> Alpha = Vector128.Create(0xFF000000u);
                for (; Index <= Pixels.Length - Vector128<uint>.Count; Index += Vector128<uint>.Count)
                    (Vector128.Create(Pixels.Slice(Index)) | Alpha).CopyTo(Pixels.Slice(Index));
            }

            for (; Index < Pixels.Length; Index++)
                Pixels[Index] |= 0xFF000000u;
        }

        private static bool TryCreateFrame(BinaryEmulator Instance, ulong Hwnd, DxgkStorage Block, uint Scaling, out GdiPrimitive Frame)
        {
            Frame = default;
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            int Width = (int)Block.Width;
            int Height = (int)Block.Height;
            if (Window == null || !HasRows(Block))
                return false;

            Win32kHelper.GetClientSize(Instance, Window, out int ClientWidth, out int ClientHeight);
            if (Scaling == ScalingNone && Win32kHelper.IsBlitExtentValid(ClientWidth, ClientHeight))
            {
                uint[] Client = Win32kHelper.RentGuiPixels(ClientWidth * ClientHeight, out bool ClientPooled);
                Client.AsSpan(0, ClientWidth * ClientHeight).Clear();
                CopyRows(Block, Client, ClientWidth, new DxgkDirtyRect(0, 0, Math.Min(Width, ClientWidth), Math.Min(Height, ClientHeight)), Opaque: false);
                Frame = Instance.WinHelper.CreateGdiBlit(Hwnd, Hdc: 0, Left: 0, Top: 0, ClientWidth, ClientHeight, Client, ClientPooled, ClientWidth,
                    ClientHeight, Win32kHelper.SrcCopyRop);
                return true;
            }

            uint[] Pixels = Win32kHelper.RentGuiPixels(Width * Height, out bool Pooled);
            CopyRows(Block, Pixels, Width, new DxgkDirtyRect(0, 0, Width, Height), Opaque: false);
            Frame = Instance.WinHelper.CreateGdiBlit(Hwnd, Hdc: 0, Left: 0, Top: 0, ClientWidth, ClientHeight, Pixels, Pooled, Width, Height,
                Win32kHelper.SrcCopyRop);
            return true;
        }

        private static void CopySwappingRedBlue(ReadOnlySpan<uint> Source, Span<uint> Target)
        {
            int Index = 0;
            if (Vector128.IsHardwareAccelerated)
            {
                Vector128<uint> GreenAlpha = Vector128.Create(0xFF00FF00u);
                Vector128<uint> LowByte = Vector128.Create(0xFFu);
                for (; Index <= Source.Length - Vector128<uint>.Count; Index += Vector128<uint>.Count)
                {
                    Vector128<uint> Pixel = Vector128.Create(Source.Slice(Index));
                    Vector128<uint> Swapped = (Pixel & GreenAlpha) | Vector128.ShiftLeft(Pixel & LowByte, 16)
                        | (Vector128.ShiftRightLogical(Pixel, 16) & LowByte);
                    Swapped.CopyTo(Target.Slice(Index));
                }
            }

            for (; Index < Source.Length; Index++)
            {
                uint Pixel = Source[Index];
                Target[Index] = (Pixel & 0xFF00FF00) | ((Pixel & 0xFF) << 16) | ((Pixel >> 16) & 0xFF);
            }
        }
    }
}
