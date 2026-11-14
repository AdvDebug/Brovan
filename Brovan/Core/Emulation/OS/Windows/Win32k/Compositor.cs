using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal sealed class Compositor
    {
        // NT gives a window three target slots, topmost FALSE in slot 0, TRUE in slot 1 and an internal kind in slot 2.
        internal const uint TargetSlots = 3;

        private const int MaxDepth = 256;
        private const int ShutdownWaitMilliseconds = 2000;

        private readonly CompositionProcess Process;
        private readonly Dictionary<ulong, WindowState> Windows = new();

        // Released surfaces stay until no raster reads their copies.
        private readonly Dictionary<DxgkCompositionSurface, CompositorSurfaceCopy> Surfaces = new();
        private readonly List<DxgkCompositionSurface> ForgottenSurfaces = new();
        private ulong SurfaceBytes;
        private readonly List<Task> Rasters = new();
        private readonly object RasterSync = new();
        private int Ended;
        private int WalkStamp;

        private int CommittedResources;

        private sealed class FlipInput
        {
            internal DxgkPresentPacket Uncopied;
            internal DxgkPresentPacket Newest;
            internal readonly List<DxgkPresentPacket> Waiting = new();
        }

        private readonly Dictionary<DxgkCompositionSurface, FlipInput> Inputs = new();
        private bool InputsToFill;

        private static readonly List<DxgkDirtyRect> WholeSurface = new() { new DxgkDirtyRect(0, 0, int.MaxValue, int.MaxValue) };

        internal bool HasWork { get; private set; }

        private sealed class WindowState
        {
            internal readonly CompositionSharedVisual[] Targets = new CompositionSharedVisual[TargetSlots];
            internal bool Dirty;

            internal DxgkCompositionSurface BaseSurface;
            internal uint BaseScaling;
            internal readonly List<DxgkPresentPacket> FramePresents = new();
            internal CompositorDisplayList List;
            internal Task<CompositorFrame> Raster;
            internal GuiThreadManager.FrameSlot Slot;
            internal long Serial;

            internal readonly List<(CompositionChannel Channel, uint Processed)> Batches = new();

            internal bool HasTargets => Targets[0] != null || Targets[1] != null || Targets[2] != null;

            internal bool InFlight => Raster != null || Slot != null;
        }

        internal Compositor(CompositionProcess Process)
        {
            this.Process = Process;
        }

        internal bool HasTarget(ulong Hwnd, uint Slot) => Windows.TryGetValue(Hwnd, out WindowState Window) && Window.Targets[Slot] != null;

        internal void AttachTarget(BinaryEmulator Instance, ulong Hwnd, uint Slot, CompositionSharedVisual Visual)
        {
            ref WindowState Window = ref CollectionsMarshal.GetValueRefOrAddDefault(Windows, Hwnd, out _);
            Window ??= new WindowState();
            bool First = !Window.HasTargets;
            Window.Targets[Slot] = Visual;
            Visual.Reference();
            if (First)
                SeedBase(Instance, Hwnd, Window);

            MarkDirty(Instance, Window);
        }

        // NT: a window that gets its first target already shows its flip content, which DWM draws under the targets.
        private void SeedBase(BinaryEmulator Instance, ulong Hwnd, WindowState Window)
        {
            if (GetComposedWindow(Instance, Hwnd)?.SwapChainSurface is not DxgkCompositionSurface Surface ||
                Surface.ActiveBuffer is not { Ended: false, NewestPresent: DxgkPresentPacket Present } Buffer || Buffer.Window != Hwnd)
                return;

            Window.BaseSurface = Surface;
            Window.BaseScaling = Buffer.Scaling;
            TakeNewest(Surface, Present);
        }

        private FlipInput TakeNewest(DxgkCompositionSurface Surface, DxgkPresentPacket Present)
        {
            ref FlipInput Input = ref CollectionsMarshal.GetValueRefOrAddDefault(Inputs, Surface, out bool Exists);
            if (!Exists)
                ForgottenSurfaces.Remove(Surface);

            Input ??= new FlipInput();
            Input.Uncopied = Present;
            Input.Newest = Present;
            InputsToFill = true;
            return Input;
        }

        internal bool DetachTarget(BinaryEmulator Instance, ulong Hwnd, uint Slot)
        {
            if (!Windows.TryGetValue(Hwnd, out WindowState Window) || Window.Targets[Slot] is not CompositionSharedVisual Visual)
                return false;

            Window.Targets[Slot] = null;
            MarkDirty(Instance, Window);
            Visual.Unreference(Instance);
            if (!Window.HasTargets)
                EndBase(Instance, Window);

            return true;
        }

        // DWM draws a window's own flip content under its DComp targets, so the present shows with the next frame.
        internal bool TryTakeBase(BinaryEmulator Instance, DxgkPresentPacket Present)
        {
            ulong Hwnd = Present.Buffer.Window;
            if (!Windows.TryGetValue(Hwnd, out WindowState Window) || !Window.HasTargets)
                return false;

            DxgkCompositionSurface Surface = Present.Buffer.Surface;
            bool Composed = GetComposedWindow(Instance, Hwnd) != null;
            if (Window.BaseSurface != Surface || !Composed)
            {
                EndInput(Instance, Window.BaseSurface, GiveBack: false);
                Window.BaseSurface = Composed ? Surface : null;
            }

            if (!Composed)
                return false;

            Window.BaseScaling = Present.Buffer.Scaling;
            TakeNewest(Surface, Present).Waiting.Add(Present);
            MarkDirty(Instance, Window);
            return true;
        }

        private void EndBase(BinaryEmulator Instance, WindowState Window)
        {
            EndInput(Instance, Window.BaseSurface, GiveBack: true);
            Window.BaseSurface = null;
        }

        // Given back, the window shows the newest present alone, as DWM shows the swapchain once the targets are gone.
        private void EndInput(BinaryEmulator Instance, DxgkCompositionSurface Surface, bool GiveBack)
        {
            if (Surface == null)
                return;

            if (Inputs.Remove(Surface, out FlipInput Input))
            {
                foreach (DxgkPresentPacket Present in Input.Waiting)
                    DxgkComposition.MarkUndrawn(Present);

                if (GiveBack && Input.Newest != null)
                    DxgkComposition.HandBack(Instance, Input.Newest);

                foreach (DxgkPresentPacket Present in Input.Waiting)
                    Present.Buffer.RetireConsumed(Instance);

                Instance.WakeSignal.Bump();
            }

            ForgetSurface(Surface);
        }

        private FlipInput GetInput(DxgkCompositionSurface Surface) => Surface != null && Inputs.TryGetValue(Surface, out FlipInput Input) ? Input : null;

        private static void MarkUndrawn(BinaryEmulator Instance, List<DxgkPresentPacket> Presents)
        {
            if (Presents == null || Presents.Count == 0)
                return;

            foreach (DxgkPresentPacket Present in Presents)
            {
                if (Present.Slot == null)
                    DxgkComposition.MarkUndrawn(Present);
            }

            foreach (DxgkPresentPacket Present in Presents)
                Present.Buffer.RetireConsumed(Instance);

            Presents.Clear();
            Instance.WakeSignal.Bump();
        }

        internal void WindowDestroyed(BinaryEmulator Instance, ulong Hwnd)
        {
            if (!Windows.Remove(Hwnd, out WindowState Window))
                return;

            EndInput(Instance, Window.BaseSurface, GiveBack: false);
            MarkUndrawn(Instance, Window.FramePresents);
            Discard(Window);
            ReleaseTargets(Instance, Window);
        }

        private static void ReleaseTargets(BinaryEmulator Instance, WindowState Window)
        {
            for (int Slot = 0; Slot < TargetSlots; Slot++)
            {
                CompositionSharedVisual Visual = Window.Targets[Slot];
                Window.Targets[Slot] = null;
                Visual?.Unreference(Instance);
            }
        }

        // DWM applies a batch when it processes it, and Brovan's compositor applies it inside the commit.
        internal bool TryApply(BinaryEmulator Instance, CompositionChannel Channel)
        {
            if (Channel.PendingCreates - Process.CapturedReleases > MemoryBudget.CompositionResources - CommittedResources)
                return false;

            if (Channel.PendingCount == 0)
                return true;

            Dictionary<CompositionResource, CompositorResource> Committed = Channel.CommittedResources;
            foreach (ref readonly CompositionChange Change in Channel.PendingChanges)
            {
                switch (Change.Kind)
                {
                    case CompositionChangeKind.Create:
                    case CompositionChangeKind.Open:
                    {
                        CompositorResource Made = new(Change.Resource.Class);
                        if (Change.Resource is CompositionVisualTarget Target)
                        {
                            Target.Shared.Reference();
                            Made.SetHeld(Instance, Target.Shared);
                            Target.Shared.Committed = Made;
                        }

                        Committed[Change.Resource] = Made;
                        CommittedResources++;
                        break;
                    }

                    case CompositionChangeKind.Release:
                        if (Committed.Remove(Change.Resource, out CompositorResource Released))
                        {
                            Released.Detach(Instance);
                            CommittedResources--;
                        }

                        break;

                    case CompositionChangeKind.Value:
                        if (Committed.TryGetValue(Change.Resource, out CompositorResource Holder))
                            Holder.Set((CompositionName)Change.Key, Change.Value);

                        break;

                    case CompositionChangeKind.Reference:
                        if (Committed.TryGetValue(Change.Resource, out CompositorResource Source))
                            Source.SetReference((CompositionProperty)Change.Key, Change.Other != null ? Committed.GetValueOrDefault(Change.Other) : null);

                        break;

                    case CompositionChangeKind.Object:
                        if (Committed.TryGetValue(Change.Resource, out CompositorResource Holding))
                            Holding.SetHeld(Instance, Change.Object);
                        else
                            Change.Object?.Unreference(Instance);

                        break;

                    case CompositionChangeKind.InsertChild:
                        ApplyInsert(Committed, Change);
                        break;

                    case CompositionChangeKind.RemoveChild:
                        if (Committed.TryGetValue(Change.Other, out CompositorResource Removed) && Removed.Parent != null &&
                            Committed.GetValueOrDefault(Change.Resource) == Removed.Parent)
                        {
                            Removed.Parent.Children.Remove(Removed);
                            Removed.Parent = null;
                        }

                        break;

                    case CompositionChangeKind.RemoveAllChildren:
                        if (Committed.TryGetValue(Change.Resource, out CompositorResource Emptied))
                        {
                            foreach (CompositorResource Child in Emptied.Children)
                                Child.Parent = null;

                            Emptied.Children.Clear();
                        }

                        break;
                }
            }

            Channel.ClearPending(Instance, Applied: true);
            RedrawAll(Instance);
            return true;
        }

        // The same order rules as the kernel side (CompositionVisual.AddChild).
        private static void ApplyInsert(Dictionary<CompositionResource, CompositorResource> Committed, in CompositionChange Change)
        {
            if (!Committed.TryGetValue(Change.Resource, out CompositorResource Parent) || !Committed.TryGetValue(Change.Other, out CompositorResource Child) ||
                Child.Parent != null)
                return;

            CompositorResource Reference = Change.Sibling != null ? Committed.GetValueOrDefault(Change.Sibling) : null;
            int Found = Reference != null ? Parent.Children.IndexOf(Reference) : -1;
            int Index = Found < 0 ? (Change.Above ? 0 : Parent.Children.Count) : Found + (Change.Above ? 1 : 0);
            Parent.Children.Insert(Index, Child);
            Child.Parent = Parent;
        }

        internal void ForgetChannel(BinaryEmulator Instance, CompositionChannel Channel)
        {
            foreach (CompositorResource Resource in Channel.CommittedResources.Values)
                Resource.Detach(Instance);

            CommittedResources -= Channel.CommittedResources.Count;
            Channel.CommittedResources.Clear();
            RedrawAll(Instance);
        }

        internal void RedrawAll(BinaryEmulator Instance)
        {
            foreach (WindowState Window in Windows.Values)
            {
                if (Window.HasTargets)
                    MarkDirty(Instance, Window);
            }
        }

        internal void Redraw(BinaryEmulator Instance, ulong TopLevel)
        {
            foreach ((ulong Hwnd, WindowState Window) in Windows)
            {
                if (Window.HasTargets && Win32kHelper.GetTopLevelWindow(Instance, Instance.WinHelper.GetWindow(Hwnd))?.Hwnd == TopLevel)
                    MarkDirty(Instance, Window);
            }
        }

        // The wake scan runs the compositor only while it has work, so work that starts bumps the wake epoch.
        private void MarkDirty(BinaryEmulator Instance, WindowState Window)
        {
            Window.Dirty = true;
            if (HasWork)
                return;

            HasWork = true;
            Instance.WakeSignal.Bump();
        }

        internal void Service(BinaryEmulator Instance)
        {
            if (!IsRastering)
            {
                DropForgottenSurfaces();
                TakeTokens(Instance);
            }

            FillInputs(Instance);

            bool InFlight = false;
            foreach ((ulong Hwnd, WindowState Window) in Windows)
            {
                if (Window.Raster is { IsCompleted: true })
                    Submit(Instance, Hwnd, Window);

                if (Window.Slot != null && Window.Slot.Consumed >= Window.Serial)
                    FrameDone(Instance, Window);

                if (!Window.InFlight && Window.Dirty)
                    Build(Instance, Hwnd, Window);

                InFlight |= Window.InFlight;
            }

            HasWork = InFlight;
            if (!InFlight)
                Process.ConfirmAll();
        }

        // Only windows without a redirection surface are drawn, because DWM's redirected content is not modeled.
        private void Build(BinaryEmulator Instance, ulong Hwnd, WindowState Window)
        {
            Window.Dirty = false;
            WinWindow Target = Window.HasTargets ? GetComposedWindow(Instance, Hwnd) : null;
            int Width = 0;
            int Height = 0;
            if (Target != null)
                Win32kHelper.GetClientSize(Instance, Target, out Width, out Height);

            FlipInput Input = GetInput(Window.BaseSurface);
            if (Target == null || !Win32kHelper.IsBlitExtentValid(Width, Height))
            {
                MarkUndrawn(Instance, Input?.Waiting);
                return;
            }

            CompositorDisplayList List = new(Width, Height);
            if (Window.BaseSurface != null && Surfaces.TryGetValue(Window.BaseSurface, out CompositorSurfaceCopy Base))
            {
                bool Unscaled = Window.BaseScaling == DxgkComposition.ScalingNone;
                List.Add(new CompositorTexture(0, 0, Unscaled ? Base.Width : Width, Unscaled ? Base.Height : Height, Base, 0, 0, Base.Width, Base.Height, 1f,
                    Opaque: true));
            }

            foreach (CompositionSharedVisual Shared in Window.Targets)
            {
                WalkStamp++;
                Walk(Shared?.Committed?.Reference(CompositionProperty.VisualTargetRoot), 0f, 0f, 1f, 0, List);
            }

            Task<CompositorFrame> Raster = StartRaster(Instance, List);
            if (Raster == null)
            {
                MarkUndrawn(Instance, Input?.Waiting);
                return;
            }

            if (Input is { Uncopied: null })
            {
                Window.FramePresents.AddRange(Input.Waiting);
                Input.Waiting.Clear();
            }

            Window.List = List;
            Process.SnapshotBatches(Window.Batches);
            Window.Raster = Raster;
        }

        private static WinWindow GetComposedWindow(BinaryEmulator Instance, ulong Hwnd)
        {
            WinWindow Target = Instance.WinHelper.GetWindow(Hwnd);
            return Target != null && !Target.Destroyed && Instance.WinHelper.GuiManager != null &&
                   Win32kHelper.GetTopLevelWindow(Instance, Target) is WinWindow TopLevel && (TopLevel.ExStyle & Win32kHelper.WindowExStyleNoRedirectionBitmap) != 0
                ? Target
                : null;
        }

        private void Walk(CompositorResource Visual, float X, float Y, float Opacity, int Depth, CompositorDisplayList List)
        {
            if (Visual == null || Depth > MaxDepth || Visual.WalkStamp == WalkStamp)
                return;

            Visual.WalkStamp = WalkStamp;
            if (Visual.TryGet(CompositionName.VisualIsVisible, out CompositorValue Visible) && Visible.Integer == 0)
                return;

            if (Visual.TryGet(CompositionName.VisualOffset, out CompositorValue Offset))
            {
                X += Offset.Float(0);
                Y += Offset.Float(1);
            }

            // NT clamps the opacity it stores, and a NaN to 0.
            if (Visual.TryGet(CompositionName.VisualOpacity, out CompositorValue Own))
                Opacity *= float.IsNaN(Own.Float(0)) ? 0f : Math.Clamp(Own.Float(0), 0f, 1f);

            if (Visual.Class == CompositionClass.SpriteVisual && Visual.TryGet(CompositionName.VisualSize, out CompositorValue Size))
            {
                CompositorResource Brush = Visual.Reference(CompositionProperty.SpriteVisualBrush);
                if (Brush?.Class == CompositionClass.ColorBrush && Brush.TryGet(CompositionName.ColorBrushColor, out CompositorValue Color))
                    List.Add(new CompositorRectangle(X, Y, X + Size.Float(0), Y + Size.Float(1), Color.Float(0), Color.Float(1), Color.Float(2),
                        Color.Float(3) * Opacity));
                else if (Brush?.Class == CompositionClass.SurfaceBrush && TryGetSurface(Brush, out CompositorSurfaceCopy Copy, out DxgkDirtyRect Source))
                    List.Add(new CompositorTexture(X, Y, X + Size.Float(0), Y + Size.Float(1), Copy, Source.Left, Source.Top, Source.Right, Source.Bottom, Opacity));
            }

            foreach (CompositorResource Child in Visual.Children)
                Walk(Child, X, Y, Opacity, Depth + 1, List);
        }

        private bool IsRastering
        {
            get
            {
                foreach (WindowState Window in Windows.Values)
                {
                    if (Window.Raster is { IsCompleted: false })
                        return true;
                }

                return false;
            }
        }

        // NT applies a token's dirty rectangles to its surfaces when it enters a frame (CCompositionToken::InFrame).
        private void TakeTokens(BinaryEmulator Instance)
        {
            if (!Process.TakeTokensChanged())
                return;

            List<DxgkCompositionToken> Tokens = Process.CompletedTokens;
            bool Filled = false;
            int Deferred = 0;
            for (int Index = 0; Index < Tokens.Count; Index++)
            {
                DxgkCompositionToken Token = Tokens[Index];
                if (Process.ShouldDeferToken(Token))
                {
                    Tokens[Deferred++] = Token;
                    continue;
                }

                foreach (DxgkCompositionUpdate Update in Token.Updates)
                {
                    DxgkCompositionBuffer Buffer = Update.Surface.ActiveBuffer;
                    if (Buffer != null)
                        Filled |= FillFromRealization(Instance, Update.Surface, Buffer.Realizations.Length == 1 ? Buffer.Realizations[0] : null, Update.Rects);
                }

                Token.EnterFrame(Instance);
                Token.Unreference(Instance);
            }

            Tokens.RemoveRange(Deferred, Tokens.Count - Deferred);
            if (Filled)
                RedrawAll(Instance);
        }

        // The buffer still holds the newest present, because it goes back to the application only after a newer one shows.
        private void FillInputs(BinaryEmulator Instance)
        {
            if (!InputsToFill)
                return;

            InputsToFill = false;
            foreach ((DxgkCompositionSurface Surface, FlipInput Input) in Inputs)
            {
                if (Input.Uncopied is not DxgkPresentPacket Present)
                    continue;

                if (IsDrawing(Surface))
                {
                    InputsToFill = true;
                    continue;
                }

                Input.Uncopied = null;
                if (!Present.Buffer.Ended)
                    FillFromRealization(Instance, Surface, Present.Buffer.Realizations[Present.Index], WholeSurface);

                foreach (WindowState Window in Windows.Values)
                {
                    if (Window.BaseSurface == Surface)
                        MarkDirty(Instance, Window);
                }
            }
        }

        private bool IsDrawing(DxgkCompositionSurface Surface)
        {
            if (!Surfaces.TryGetValue(Surface, out CompositorSurfaceCopy Copy))
                return false;

            foreach (WindowState Window in Windows.Values)
            {
                if (Window.Raster is not { IsCompleted: false } || Window.List == null)
                    continue;

                foreach (CompositorTexture Texture in Window.List.Textures)
                {
                    if (Texture.Surface == Copy)
                        return true;
                }
            }

            return false;
        }

        private bool FillFromRealization(BinaryEmulator Instance, DxgkCompositionSurface Surface, DxgkStorage[] Realization, List<DxgkDirtyRect> Rects)
        {
            if (Realization == null || Realization.Length != 1 || !DxgkComposition.IsReadable(Realization[0]))
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage("[!] DirectComposition: a surface buffer that is not one readable realization is not drawn", LogFlags.Issues);

                return false;
            }

            return Fill(Instance, Surface, Realization[0], Rects);
        }

        private bool Fill(BinaryEmulator Instance, DxgkCompositionSurface Surface, DxgkStorage Block, List<DxgkDirtyRect> Rects)
        {
            int Width = (int)Block.Width;
            int Height = (int)Block.Height;
            if (!Surfaces.TryGetValue(Surface, out CompositorSurfaceCopy Copy) || Copy.Width != Width || Copy.Height != Height)
            {
                if (Copy != null)
                    Forget(Surface, Copy);

                ulong Bytes = (ulong)Width * (ulong)Height * 4;
                if (Bytes > MemoryBudget.CompositorSurfaceBytes - SurfaceBytes)
                {
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[!] DirectComposition: a {Width} by {Height} surface does not fit the compositor's surface budget, it is not drawn", LogFlags.Issues);

                    return false;
                }

                Copy = new CompositorSurfaceCopy(Width, Height);
                SurfaceBytes += Bytes;
                Surfaces[Surface] = Copy;
            }

            long Area = 0;
            DxgkDirtyRect Bounds = new(Width, Height, 0, 0);
            foreach (DxgkDirtyRect Rect in Rects)
            {
                DxgkDirtyRect Clamped = DxgkComposition.ClampRect(Block, Rect);
                if (Clamped.Left >= Clamped.Right || Clamped.Top >= Clamped.Bottom)
                    continue;

                Area += (long)(Clamped.Right - Clamped.Left) * (Clamped.Bottom - Clamped.Top);
                Bounds = new DxgkDirtyRect(Math.Min(Bounds.Left, Clamped.Left), Math.Min(Bounds.Top, Clamped.Top), Math.Max(Bounds.Right, Clamped.Right),
                    Math.Max(Bounds.Bottom, Clamped.Bottom));
            }

            if (Area > (long)Width * Height)
            {
                DxgkComposition.CopyRect(Block, Copy.Pixels, Bounds);
                return true;
            }

            foreach (DxgkDirtyRect Rect in Rects)
                DxgkComposition.CopyRect(Block, Copy.Pixels, Rect);

            return true;
        }

        internal bool HasForgottenSurfaces => ForgottenSurfaces.Count != 0;

        internal void ForgetSurface(DxgkCompositionSurface Surface)
        {
            Inputs.Remove(Surface);
            if (Surfaces.ContainsKey(Surface))
                ForgottenSurfaces.Add(Surface);
        }

        private void DropForgottenSurfaces()
        {
            foreach (DxgkCompositionSurface Surface in ForgottenSurfaces)
            {
                if (Surfaces.TryGetValue(Surface, out CompositorSurfaceCopy Copy))
                    Forget(Surface, Copy);
            }

            ForgottenSurfaces.Clear();
        }

        private void Forget(DxgkCompositionSurface Surface, CompositorSurfaceCopy Copy)
        {
            Surfaces.Remove(Surface);
            SurfaceBytes -= Copy.Bytes;
        }

        // The brush's stretch, alignment and transform are not drawn.
        private bool TryGetSurface(CompositorResource Brush, out CompositorSurfaceCopy Copy, out DxgkDirtyRect Source)
        {
            Copy = null;
            Source = default;
            if (!Process.HasName(CompositionName.SurfaceBrushSourceRect) ||
                Brush.Reference(CompositionProperty.SurfaceBrushSurface) is not { Class: CompositionClass.CompositionSurfaceBitmap } Bitmap ||
                Bitmap.Held is not DxgkCompositionSurface Surface || !Surfaces.TryGetValue(Surface, out Copy))
                return false;

            Source = new DxgkDirtyRect(0, 0, Copy.Width, Copy.Height);
            if (Brush.TryGet(CompositionName.SurfaceBrushSourceRect, out CompositorValue Rect) && Rect.Int32(2) > Rect.Int32(0) && Rect.Int32(3) > Rect.Int32(1))
                Source = new DxgkDirtyRect(Rect.Int32(0), Rect.Int32(1), Rect.Int32(2), Rect.Int32(3));

            return true;
        }

        private Task<CompositorFrame> StartRaster(BinaryEmulator Instance, CompositorDisplayList List)
        {
            Task<CompositorFrame> Raster;
            lock (RasterSync)
            {
                if (Ended != 0)
                    return null;

                Raster = Task.Run(() => CompositorRenderer.Render(List));
                Rasters.Add(Raster);
            }

            Raster.ContinueWith(Done =>
            {
                lock (RasterSync)
                    Rasters.Remove(Done);

                if (Volatile.Read(ref Ended) == 0)
                    Instance.WakeSignal.Bump();
            }, TaskContinuationOptions.ExecuteSynchronously);
            return Raster;
        }

        // The GUI thread owns the pixels once the frame is submitted, whatever the submit answers.
        private void Submit(BinaryEmulator Instance, ulong Hwnd, WindowState Window)
        {
            Task<CompositorFrame> Raster = Window.Raster;
            Window.Raster = null;
            if (!Raster.IsCompletedSuccessfully)
            {
                Utils.LogError($"[Compositor] A frame of window 0x{Hwnd:X} failed: {Raster.Exception?.GetBaseException().Message}");
                FrameDone(Instance, Window);
                return;
            }

            CompositorFrame Rastered = Raster.Result;
            WinWindow Target = Instance.WinHelper.GetWindow(Hwnd);
            CompositorDisplayList List = Window.List;
            if (!Window.HasTargets || Target == null || Target.Destroyed || Instance.WinHelper.GuiManager is not GuiThreadManager Gui)
            {
                Rastered.Return();
                FrameDone(Instance, Window);
                return;
            }

            GdiPrimitive Frame = Instance.WinHelper.CreateGdiBlit(Hwnd, Hdc: 0, Left: 0, Top: 0, List.Width, List.Height, Rastered.Pixels, Rastered.Pooled,
                List.Width, List.Height, Win32kHelper.SrcCopyRop);
            if (!Gui.TrySubmitFrame(Hwnd, Frame, out Window.Slot, out Window.Serial))
            {
                FrameDone(Instance, Window);
                return;
            }

            foreach (DxgkPresentPacket Present in Window.FramePresents)
            {
                Present.Slot = Window.Slot;
                Present.Serial = Window.Serial;
            }

            Window.FramePresents.Clear();
        }

        private void FrameDone(BinaryEmulator Instance, WindowState Window)
        {
            Window.Slot = null;
            Window.List = null;
            Process.Confirm(Window.Batches);
            Window.Batches.Clear();
            MarkUndrawn(Instance, Window.FramePresents);
        }

        private static void Discard(WindowState Window)
        {
            Window.Raster?.ContinueWith(static Done =>
            {
                if (Done.IsCompletedSuccessfully)
                    Done.Result.Return();
            }, TaskContinuationOptions.ExecuteSynchronously);
            Window.Raster = null;
            Window.Slot = null;
            Window.Batches.Clear();
        }

        internal bool AwaitsHostWork
        {
            get
            {
                foreach (WindowState Window in Windows.Values)
                {
                    if (Window.InFlight)
                        return true;
                }

                return false;
            }
        }

        // Runs before shutdown takes KernelLock. A raster that does not end in time keeps its pixels.
        internal void End()
        {
            Task[] Running;
            lock (RasterSync)
            {
                Volatile.Write(ref Ended, 1);
                Running = Rasters.ToArray();
            }

            try
            {
                Task.WaitAll(Running, ShutdownWaitMilliseconds);
            }
            catch (AggregateException Error)
            {
                Utils.LogError($"[Compositor] A frame failed at shutdown: {Error.GetBaseException().Message}");
            }
        }

        internal void ReleaseAll(BinaryEmulator Instance)
        {
            foreach (WindowState Window in Windows.Values)
            {
                if (Window.Raster is { IsCompletedSuccessfully: true } Raster)
                    Raster.Result.Return();

                Window.Raster = null;
                Window.FramePresents.Clear();
                Window.BaseSurface = null;
                ReleaseTargets(Instance, Window);
            }

            Windows.Clear();
            Surfaces.Clear();
            ForgottenSurfaces.Clear();
            SurfaceBytes = 0;
            HasWork = false;
            Inputs.Clear();
            InputsToFill = false;
        }
    }
}
