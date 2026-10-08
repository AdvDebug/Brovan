using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal enum GuiCommandKind : byte
    {
        None,
        RenderText,
        GdiPrimitive,
        CreateWindow,
        WarpCursor,
        SetCursorClip,
        SetCursorVisible,
        EnsureTopLevel,
        HideTopLevels,
        Shutdown,
    }

    internal struct GuiCommand
    {
        public GuiCommandKind Kind;
        public uint TextOptions;
        public ulong Hwnd;
        public IntPtr Font;
        public int X;
        public int Y;
        public int RectLeft;
        public int RectTop;
        public int RectRight;
        public int RectBottom;
        public string Text;
        public GdiClipRect[] Clip;
        public object Request;
        public GdiPrimitive Primitive;
    }

    internal sealed class CreateWindowRequest
    {
        public readonly WindowOptions Options;
        public readonly TaskCompletionSource<IWindow> Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public CreateWindowRequest(WindowOptions options)
        {
            Options = options;
        }
    }

    // Pending, Applying, Applied and PendingLayered need the present lock. Host and ApplyingLayered are GUI thread only.
    internal sealed class TopLevelEntry
    {
        public readonly ulong Window;
        public TopLevelFrame? Pending;
        public TopLevelFrame? Applying;
        public TopLevelFrame? Applied;
        public List<LayeredUpdate> PendingLayered = new();
        public List<LayeredUpdate> ApplyingLayered = new();
        public bool Queued;
        public bool Destroyed;
        public ITopLevelWindow Host;

        public TopLevelEntry(ulong window)
        {
            Window = window;
        }
    }

    internal struct PresentState
    {
        public string Title;
        public int Width;
        public int Height;
        public bool Visible;
        public WindowState State;
        public bool HostGeometryStale;

        public bool Matches(in PresentState other)
        {
            return Width == other.Width
                && Height == other.Height
                && Visible == other.Visible
                && State == other.State
                && string.Equals(Title, other.Title, StringComparison.Ordinal);
        }
    }

    internal sealed class GuiThreadManager : IDisplayConnection
    {
        private const int InitializationTimeoutMilliseconds = 5000;
        private const int ShutdownTimeoutMilliseconds = 2000;
        private const int DrainBudget = 4096;

        /// <summary>
        /// The wait is armed on both the host event source and the wake object, so this only bounds how long a
        /// dropped wake can stall the loop; it is not the rate at which events are noticed.
        /// </summary>
        private const int WaitWatchdogMilliseconds = 250;

        private readonly Func<IDisplayConnection> _displayFactory;
        private readonly Thread _guiThread;
        private readonly ConcurrentQueue<GuiCommand> _commands = new();
        private readonly TaskCompletionSource<bool> _initCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object _presentSync = new();

        private IDisplayConnection _display;
        private IGdiRenderSupport _gdiRender;
        private ITextRenderSupport _textRender;
        private ITextMetricsSupport _textMetrics;
        private IKeyboardTranslateSupport _keyboardTranslate;
        private ITopLevelWindowHost _topLevelHost;

        private volatile IWindow _window;
        private volatile bool _disposed;
        private bool _running = true;

        private PresentState _pendingPresent;
        private PresentState _appliedPresent;
        private bool _hasPendingPresent;
        private bool _hasAppliedPresent;
        private int _parked;

        private const int MaxOwnerDepth = 16;

        private readonly Dictionary<ulong, TopLevelEntry> _topLevels = new();
        private List<TopLevelEntry> _dirtyTopLevels = new();
        private List<TopLevelEntry> _destroyedTopLevels = new();
        private ulong[] _pendingStacking;
        private ulong? _pendingActivation;

        // GUI thread only.
        private readonly Dictionary<ulong, ITopLevelWindow> _hostWindows = new();
        private readonly HashSet<ITopLevelWindow> _surfaceHosts = new();
        private List<TopLevelEntry> _applyingTopLevels = new();
        private List<TopLevelEntry> _applyingDestroyed = new();
        private ITopLevelWindow[] _stackScratch = Array.Empty<ITopLevelWindow>();

        public GuiThreadManager(Func<IDisplayConnection> displayFactory)
        {
            _displayFactory = displayFactory ?? throw new ArgumentNullException(nameof(displayFactory));
            _guiThread = new Thread(GuiThreadMain)
            {
                IsBackground = true,
                Name = "BrovanGuiThread",

                // Guest CPU threads run flat out on every core, and this is the only thread that takes host
                // input or pushes a frame to the screen. At Normal it gets scheduled behind them and the whole
                // presentation path inherits their quantum as latency.
                Priority = ThreadPriority.AboveNormal,
            };
            _guiThread.Start();
        }

        public bool IsConnected => !_disposed && _display != null && _display.IsConnected;

        public IntPtr NativeHandle => _display?.NativeHandle ?? IntPtr.Zero;

        public IWindow CreateWindow(WindowOptions options)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(GuiThreadManager));

            if (!WaitForInitialization())
                return null;

            CreateWindowRequest request = new(options ?? new WindowOptions());
            Submit(new GuiCommand { Kind = GuiCommandKind.CreateWindow, Request = request });
            return WaitForGuiThread(request.Completion.Task, nameof(CreateWindow));
        }

        private static T WaitForGuiThread<T>(Task<T> task, string name)
        {
            try
            {
                if (task.Wait(InitializationTimeoutMilliseconds))
                    return task.Result;

                Utils.LogError($"[GuiThreadManager] {name} timed out");
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] {name} failed: {ex.Message}");
            }

            return default;
        }

        /// <summary>
        /// Moves the host pointer to a point in the window's client area.
        /// </summary>
        public void EnqueueWarpCursor(ulong hwnd, int clientX, int clientY)
        {
            if (_disposed)
                return;

            Submit(new GuiCommand { Kind = GuiCommandKind.WarpCursor, Hwnd = hwnd, X = clientX, Y = clientY });
        }

        public void EnqueueSetCursorClip(ulong hwnd, bool enabled, int clientLeft, int clientTop, int clientRight, int clientBottom)
        {
            if (_disposed)
                return;

            Submit(new GuiCommand
            {
                Kind = GuiCommandKind.SetCursorClip,
                Hwnd = hwnd,
                X = enabled ? 1 : 0,
                RectLeft = clientLeft,
                RectTop = clientTop,
                RectRight = clientRight,
                RectBottom = clientBottom,
            });
        }

        /// <summary>
        /// Shows or hides the host pointer over the window.
        /// </summary>
        public void EnqueueSetCursorVisible(bool visible)
        {
            if (_disposed)
                return;

            Submit(new GuiCommand { Kind = GuiCommandKind.SetCursorVisible, X = visible ? 1 : 0 });
        }

        public void EnqueuePresent(string title, int width, int height, bool visible, WindowState state)
        {
            if (_disposed)
                return;

            PresentState present = new()
            {
                Title = title ?? string.Empty,
                Width = width,
                Height = height,
                Visible = visible,
                State = state,
                HostGeometryStale = HostEventQueue.GeometryPending,
            };

            lock (_presentSync)
            {
                if (!_hasPendingPresent && _hasAppliedPresent && _appliedPresent.Matches(present))
                    return;

                _pendingPresent = present;
                _hasPendingPresent = true;
            }

            WakeGuiThread();
        }

        public bool SupportsTopLevels => !_disposed && WaitForInitialization() && _topLevelHost != null;

        public void EnqueueTopLevel(in TopLevelFrame frame)
        {
            if (_disposed)
                return;

            TopLevelFrame present = frame;
            present.HostGeometryStale = HostEventQueue.IsGeometryPending(frame.Window);

            lock (_presentSync)
            {
                TopLevelEntry entry = GetOrAddTopLevel(frame.Window);

                if ((entry.Pending ?? entry.Applying) is TopLevelFrame pending)
                {
                    if (pending.Matches(present) && (!pending.HostGeometryStale || present.HostGeometryStale))
                        return;
                }
                else if (entry.Applied is TopLevelFrame applied && applied.Matches(present))
                {
                    return;
                }

                entry.Pending = present;
                MarkTopLevelDirty(entry);
            }

            WakeGuiThread();
        }

        public void EnqueueTopLevelDestroyed(ulong window)
        {
            if (_disposed)
                return;

            lock (_presentSync)
            {
                if (!_topLevels.Remove(window, out TopLevelEntry entry))
                    return;

                entry.Destroyed = true;
                ReturnLayered(entry.PendingLayered);
                _destroyedTopLevels.Add(entry);
            }

            WakeGuiThread();
        }

        public void EnqueueStacking(ulong[] topToBottom)
        {
            if (_disposed)
                return;

            lock (_presentSync)
                _pendingStacking = topToBottom;

            WakeGuiThread();
        }

        public void RequestActivation(ulong window)
        {
            if (_disposed)
                return;

            lock (_presentSync)
                _pendingActivation = window;

            WakeGuiThread();
        }

        // A partial update needs the queued ones before it. An update without pixels is repeated by the next one.
        public void EnqueueLayered(ulong window, LayeredUpdate update)
        {
            if (_disposed)
            {
                ReturnLayered(update);
                return;
            }

            lock (_presentSync)
            {
                // Only a presented top-level window drains its updates.
                if (!_topLevels.TryGetValue(window, out TopLevelEntry entry))
                {
                    ReturnLayered(update);
                    return;
                }

                List<LayeredUpdate> pending = entry.PendingLayered;
                bool wholeSurface = update.Pixels != null && update.DirtyLeft == 0 && update.DirtyTop == 0
                    && update.DirtyWidth >= update.Width && update.DirtyHeight >= update.Height;

                if (wholeSurface)
                {
                    ReturnLayered(pending);
                }
                else if (pending.Count > 0 && pending[^1].Pixels == null)
                {
                    pending.RemoveAt(pending.Count - 1);
                }

                pending.Add(update);
                MarkTopLevelDirty(entry);
            }

            WakeGuiThread();
        }

        /// <summary>
        /// Blocks until the GUI thread answers.
        /// </summary>
        public IntPtr EnsureTopLevelHandle(ulong window)
        {
            if (!SupportsTopLevels)
                return IntPtr.Zero;

            TaskCompletionSource<IntPtr> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Submit(new GuiCommand { Kind = GuiCommandKind.EnsureTopLevel, Hwnd = window, Request = completion });
            return WaitForGuiThread(completion.Task, nameof(EnsureTopLevelHandle));
        }

        public void HideTopLevels()
        {
            if (_disposed)
                return;

            Submit(new GuiCommand { Kind = GuiCommandKind.HideTopLevels });
        }

        private TopLevelEntry GetOrAddTopLevel(ulong window)
        {
            if (!_topLevels.TryGetValue(window, out TopLevelEntry entry))
            {
                entry = new TopLevelEntry(window);
                _topLevels.Add(window, entry);
            }

            return entry;
        }

        private void MarkTopLevelDirty(TopLevelEntry entry)
        {
            if (entry.Queued)
                return;

            entry.Queued = true;
            _dirtyTopLevels.Add(entry);
        }

        private static void ReturnLayered(List<LayeredUpdate> updates)
        {
            foreach (LayeredUpdate update in updates)
                ReturnLayered(update);

            updates.Clear();
        }

        private static void ReturnLayered(LayeredUpdate update)
        {
            if (update == null || update.Pixels == null)
                return;

            if (update.PixelsPooled)
                ArrayPool<uint>.Shared.Return(update.Pixels);

            update.Pixels = null;
        }

        public void EnqueueTextRender(ulong hwnd, IntPtr font, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options, GdiClipRect[] clip)
        {
            if (_disposed || string.IsNullOrEmpty(text))
                return;

            Submit(new GuiCommand
            {
                Kind = GuiCommandKind.RenderText,
                Hwnd = hwnd,
                Font = font,
                Text = text,
                X = x,
                Y = y,
                RectLeft = rectLeft,
                RectTop = rectTop,
                RectRight = rectRight,
                RectBottom = rectBottom,
                TextOptions = options,
                Clip = clip,
            });
        }

        public void EnqueueGdiPrimitive(GdiPrimitive primitive)
        {
            if (_disposed)
                return;

            Submit(new GuiCommand { Kind = GuiCommandKind.GdiPrimitive, Primitive = primitive });
        }

        public bool TranslateVirtualKey(uint virtualKey, uint scanCode, out char character)
        {
            character = '\0';

            if (_disposed || !WaitForInitialization())
                return false;

            IKeyboardTranslateSupport support = _keyboardTranslate;
            return support != null && support.TranslateVirtualKey(virtualKey, scanCode, out character);
        }

        public bool MeasureText(IntPtr font, string text, out int width, out int height)
        {
            width = 0;
            height = 0;

            if (_disposed || !WaitForInitialization())
                return false;

            ITextMetricsSupport support = _textMetrics;
            return support != null && support.MeasureText(font, text ?? string.Empty, out width, out height);
        }

        public bool GetTextMetrics(IntPtr font, out TextMetricsData metrics)
        {
            metrics = default;

            if (_disposed || !WaitForInitialization())
                return false;

            ITextMetricsSupport support = _textMetrics;
            return support != null && support.GetTextMetrics(font, out metrics);
        }

        public bool RasterizeText(IntPtr font, string text, Span<uint> pixels, int width, int height,
            int x, int y, uint textColor, uint backColor, bool opaque)
        {
            if (_disposed || !WaitForInitialization())
                return false;

            ITextMetricsSupport support = _textMetrics;
            return support != null && support.RasterizeText(font, text ?? string.Empty, pixels, width, height,
                x, y, textColor, backColor, opaque);
        }

        public IntPtr CreateFont(in FontDescription description)
        {
            if (_disposed || !WaitForInitialization())
                return IntPtr.Zero;

            ITextMetricsSupport support = _textMetrics;
            return support == null ? IntPtr.Zero : support.CreateFont(description);
        }

        public IReadOnlyList<FontFamilyData> EnumerateFontFamilies(string faceName, byte charSet)
        {
            if (_disposed || !WaitForInitialization())
                return Array.Empty<FontFamilyData>();

            ITextMetricsSupport support = _textMetrics;
            return support == null ? Array.Empty<FontFamilyData>() : support.EnumerateFontFamilies(faceName, charSet);
        }

        public void DeleteFont(IntPtr font)
        {
            if (_disposed || font == IntPtr.Zero)
                return;

            _textMetrics?.DeleteFont(font);
        }

        public void PumpEvents()
        {
        }

        public void WaitForEvents(int timeoutMilliseconds)
        {
        }

        public void Wake()
        {
            WakeGuiThread();
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            TaskCompletionSource<bool> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Submit(new GuiCommand { Kind = GuiCommandKind.Shutdown, Request = completion });

            try
            {
                completion.Task.Wait(ShutdownTimeoutMilliseconds);
            }
            catch
            {
            }

            try
            {
                _guiThread.Join(ShutdownTimeoutMilliseconds);
            }
            catch
            {
            }
        }

        private void Submit(in GuiCommand command)
        {
            _commands.Enqueue(command);
            WakeGuiThread();
        }

        /// <summary>
        /// Pairs with the park sequence in <see cref="GuiThreadMain"/>: the producer publishes work before it
        /// reads the park flag and the GUI thread publishes the flag before it rechecks for work, so whichever
        /// side loses the race still sees the other's store and the wake cannot be dropped.
        /// </summary>
        private void WakeGuiThread()
        {
            if (Interlocked.CompareExchange(ref _parked, 0, 1) == 1)
                _display?.Wake();
        }

        private bool WaitForInitialization()
        {
            Task<bool> initialization = _initCompletion.Task;
            if (!initialization.IsCompleted && !initialization.Wait(InitializationTimeoutMilliseconds))
            {
                Utils.LogError("[GuiThreadManager] Display initialization timed out");
                return false;
            }

            return _display != null;
        }

        private bool HasWork()
        {
            if (!_commands.IsEmpty)
                return true;

            lock (_presentSync)
                return _hasPendingPresent || HasPendingTopLevels();
        }

        private bool HasPendingTopLevels()
        {
            return _dirtyTopLevels.Count != 0 || _destroyedTopLevels.Count != 0 || _pendingStacking != null || _pendingActivation.HasValue;
        }

        private void GuiThreadMain()
        {
            try
            {
                _display = _displayFactory();
                _gdiRender = _display as IGdiRenderSupport;
                _textRender = _display as ITextRenderSupport;
                _textMetrics = _display as ITextMetricsSupport;
                _keyboardTranslate = _display as IKeyboardTranslateSupport;
                _topLevelHost = _display as ITopLevelWindowHost;
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] Failed to create display: {ex.Message}");
                _initCompletion.SetResult(false);
                return;
            }

            _initCompletion.SetResult(true);

            while (_running)
            {
                try
                {
                    bool worked = ApplyPendingPresent();
                    worked |= ApplyPendingTopLevels();
                    worked |= DrainCommands();

                    _display.PumpEvents();

                    if (worked || !_running)
                        continue;

                    Interlocked.Exchange(ref _parked, 1);
                    if (!HasWork())
                        _display.WaitForEvents(WaitWatchdogMilliseconds);

                    Interlocked.Exchange(ref _parked, 0);
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[GuiThreadManager] GUI thread error: {ex.Message}");
                }
            }
        }

        private bool DrainCommands()
        {
            bool executed = false;

            for (int i = 0; i < DrainBudget && _running && _commands.TryDequeue(out GuiCommand command); i++)
            {
                Execute(in command);
                executed = true;
            }

            return executed;
        }

        private void Execute(in GuiCommand command)
        {
            IWindow window;

            switch (command.Kind)
            {
                case GuiCommandKind.GdiPrimitive:
                    try
                    {
                        window = ResolveWindow(command.Primitive.Hwnd);
                        if (window != null && _gdiRender != null)
                            _gdiRender.ExecuteGdiPrimitive(window.NativeHandle, command.Primitive);
                    }
                    finally
                    {
                        if (command.Primitive.PixelsPooled)
                            ArrayPool<uint>.Shared.Return(command.Primitive.Pixels);
                    }

                    return;

                case GuiCommandKind.RenderText:
                    window = ResolveWindow(command.Hwnd);
                    if (window != null && _textRender != null)
                    {
                        _textRender.RenderText(
                            window.NativeHandle,
                            command.Hwnd,
                            command.Font,
                            command.Text,
                            command.X,
                            command.Y,
                            command.RectLeft,
                            command.RectTop,
                            command.RectRight,
                            command.RectBottom,
                            command.TextOptions,
                            command.Clip);
                    }

                    return;

                case GuiCommandKind.CreateWindow:
                    ExecuteCreateWindow((CreateWindowRequest)command.Request);
                    return;

                case GuiCommandKind.WarpCursor:
                    ResolveWindow(command.Hwnd)?.WarpCursor(command.X, command.Y);
                    return;

                case GuiCommandKind.SetCursorClip:
                {
                    // The host clip is global, so no other window may keep one to apply again.
                    IWindow target = ResolveWindow(command.Hwnd);
                    foreach (ITopLevelWindow TopLevel in _hostWindows.Values)
                    {
                        if (TopLevel != target)
                            TopLevel.SetCursorClip(false, 0, 0, 0, 0);
                    }

                    target?.SetCursorClip(command.X != 0, command.RectLeft, command.RectTop, command.RectRight, command.RectBottom);
                    return;
                }

                case GuiCommandKind.SetCursorVisible:
                    _window?.SetCursorVisible(command.X != 0);
                    foreach (ITopLevelWindow TopLevel in _hostWindows.Values)
                        TopLevel.SetCursorVisible(command.X != 0);
                    return;

                case GuiCommandKind.EnsureTopLevel:
                {
                    ApplyPendingTopLevels();
                    ITopLevelWindow host = EnsureHostWindow(command.Hwnd, 0);
                    if (host != null)
                        _surfaceHosts.Add(host);

                    ((TaskCompletionSource<IntPtr>)command.Request).SetResult(host?.NativeHandle ?? IntPtr.Zero);
                    return;
                }

                case GuiCommandKind.HideTopLevels:
                    foreach (ITopLevelWindow TopLevel in _hostWindows.Values)
                        TopLevel.SetShown(false);
                    return;

                case GuiCommandKind.Shutdown:
                    ExecuteShutdown((TaskCompletionSource<bool>)command.Request, _window);
                    return;
            }
        }

        private IWindow ResolveWindow(ulong hwnd)
        {
            if (_topLevelHost == null)
                return _window;

            if (_hostWindows.TryGetValue(hwnd, out ITopLevelWindow window))
                return window;

            if (ApplyPendingTopLevels() && _hostWindows.TryGetValue(hwnd, out window))
                return window;

            return null;
        }

        private bool ApplyPendingTopLevels()
        {
            ulong[] stacking;
            ulong? activation;

            lock (_presentSync)
            {
                if (!HasPendingTopLevels())
                    return false;

                (_dirtyTopLevels, _applyingTopLevels) = (_applyingTopLevels, _dirtyTopLevels);
                (_destroyedTopLevels, _applyingDestroyed) = (_applyingDestroyed, _destroyedTopLevels);
                stacking = _pendingStacking;
                _pendingStacking = null;
                activation = _pendingActivation;
                _pendingActivation = null;
            }

            // Owner changes first. DestroyWindow also destroys owned windows.
            for (int i = 0; i < _applyingTopLevels.Count; i++)
                ApplyTopLevel(_applyingTopLevels[i]);

            _applyingTopLevels.Clear();

            for (int i = 0; i < _applyingDestroyed.Count; i++)
                DestroyHostWindow(_applyingDestroyed[i]);

            _applyingDestroyed.Clear();

            if (stacking != null)
                Restack(stacking);

            if (activation is ulong target && _hostWindows.TryGetValue(target, out ITopLevelWindow active))
                RunHostCall(active, static window => window.Activate());

            return true;
        }

        private void ApplyTopLevel(TopLevelEntry entry)
        {
            TopLevelFrame frame;
            List<LayeredUpdate> layered;

            lock (_presentSync)
            {
                entry.Queued = false;
                if (entry.Destroyed)
                    return;

                TopLevelFrame? next = entry.Pending ?? entry.Applied;
                entry.Pending = null;

                if (next == null)
                    return;

                frame = next.Value;

                if (entry.Host == null && !frame.Visible)
                {
                    entry.Applied = frame;
                    return;
                }

                entry.Applying = frame;
                (entry.PendingLayered, entry.ApplyingLayered) = (entry.ApplyingLayered, entry.PendingLayered);
                layered = entry.ApplyingLayered;
            }

            if (entry.Host == null && CreateHostWindow(entry, frame, 0) == null)
            {
                ReturnLayered(layered);
                lock (_presentSync)
                    entry.Applying = null;

                return;
            }

            TopLevelFrame baseline;
            lock (_presentSync)
                baseline = entry.Applied.GetValueOrDefault();

            TopLevelFrame record = frame;
            ITopLevelWindow host = entry.Host;

            try
            {
                if (!string.Equals(baseline.Title, frame.Title, StringComparison.Ordinal))
                    host.Title = frame.Title;

                bool frameChanged = baseline.Style != frame.Style || baseline.ExStyle != frame.ExStyle;
                if (frameChanged)
                    host.SetFrame(frame.Style, frame.ExStyle);

                if (baseline.Enabled != frame.Enabled)
                    host.SetEnabled(frame.Enabled);

                if (baseline.Owner != frame.Owner)
                    host.SetOwner(frame.Owner != 0 ? EnsureHostWindow(frame.Owner, 1) : null);

                if (frame.LayeredByAttributes && (!baseline.LayeredByAttributes || frameChanged || baseline.LayeredFlags != frame.LayeredFlags
                    || baseline.LayeredColorKey != frame.LayeredColorKey || baseline.LayeredAlpha != frame.LayeredAlpha))
                {
                    host.SetLayeredAttributes(frame.LayeredColorKey, frame.LayeredAlpha, frame.LayeredFlags);
                }

                if (frame.HostGeometryStale)
                {
                    record.State = baseline.State;
                    record.ClientX = baseline.ClientX;
                    record.ClientY = baseline.ClientY;
                    record.ClientWidth = baseline.ClientWidth;
                    record.ClientHeight = baseline.ClientHeight;
                }
                else
                {
                    if (baseline.State != frame.State)
                        host.State = frame.State;

                    if (frameChanged || baseline.ClientX != frame.ClientX || baseline.ClientY != frame.ClientY
                        || baseline.ClientWidth != frame.ClientWidth || baseline.ClientHeight != frame.ClientHeight)
                    {
                        host.SetClientBounds(frame.ClientX, frame.ClientY, frame.ClientWidth, frame.ClientHeight);
                    }
                }

                if (baseline.Visible != frame.Visible)
                    host.SetShown(frame.Visible);

                foreach (LayeredUpdate update in layered)
                    host.UpdateLayered(update);
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] Top-level window {entry.Window:X} update failed: {ex.Message}");
            }
            finally
            {
                ReturnLayered(layered);
            }

            lock (_presentSync)
            {
                entry.Applied = record;
                entry.Applying = null;
            }
        }

        // An owned host window needs a host owner to stay above it.
        private ITopLevelWindow EnsureHostWindow(ulong window, int depth)
        {
            if (_hostWindows.TryGetValue(window, out ITopLevelWindow existing))
                return existing;

            if (depth > MaxOwnerDepth)
                return null;

            TopLevelEntry entry;
            TopLevelFrame frame;
            lock (_presentSync)
            {
                if (!_topLevels.TryGetValue(window, out entry) || (entry.Applied ?? entry.Pending) is not TopLevelFrame current)
                    return null;

                frame = current;
            }

            return entry.Host ?? CreateHostWindow(entry, frame, depth);
        }

        // CreateTopLevel makes the window hidden and normal. The rest of the frame is applied as a change.
        private ITopLevelWindow CreateHostWindow(TopLevelEntry entry, in TopLevelFrame frame, int depth)
        {
            ITopLevelWindow owner = frame.Owner != 0 ? EnsureHostWindow(frame.Owner, depth + 1) : null;

            ITopLevelWindow host;
            try
            {
                host = _topLevelHost.CreateTopLevel(frame, owner);
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] Top-level window {entry.Window:X} creation failed: {ex.Message}");
                return null;
            }

            TopLevelFrame created = frame;
            created.Visible = false;
            created.State = WindowState.Normal;
            created.LayeredByAttributes = false;
            created.LayeredFlags = 0;
            created.LayeredColorKey = 0;
            created.LayeredAlpha = 0;
            created.HostGeometryStale = false;

            entry.Host = host;
            _hostWindows[entry.Window] = host;

            lock (_presentSync)
                entry.Applied = created;

            return host;
        }

        private void DestroyHostWindow(TopLevelEntry entry)
        {
            ITopLevelWindow host = entry.Host;
            if (host == null)
                return;

            entry.Host = null;
            if (_hostWindows.TryGetValue(entry.Window, out ITopLevelWindow mapped) && mapped == host)
                _hostWindows.Remove(entry.Window);

            // The host destroys owned windows with their owner, so windows that still name it are released first.
            List<ITopLevelWindow> owned = null;
            lock (_presentSync)
            {
                foreach (TopLevelEntry candidate in _topLevels.Values)
                {
                    if (candidate.Host == null || candidate.Applied is not TopLevelFrame applied || applied.Owner != entry.Window)
                        continue;

                    applied.Owner = 0;
                    candidate.Applied = applied;
                    (owned ??= new List<ITopLevelWindow>()).Add(candidate.Host);
                }
            }

            if (owned != null)
            {
                foreach (ITopLevelWindow ownedWindow in owned)
                    RunHostCall(ownedWindow, static window => window.SetOwner(null));
            }

            // A guest swapchain may still present to this HWND, and destroying it faults the host driver.
            // The host destroys owned windows with their owner, so it keeps no owner either.
            if (_surfaceHosts.Contains(host))
            {
                RunHostCall(host, static window =>
                {
                    window.SetOwner(null);
                    window.SetShown(false);
                });
                return;
            }

            RunHostCall(host, static window => window.Dispose());
        }

        private void Restack(ulong[] topToBottom)
        {
            if (_stackScratch.Length < topToBottom.Length)
                _stackScratch = new ITopLevelWindow[topToBottom.Length];

            int count = 0;
            for (int i = 0; i < topToBottom.Length; i++)
            {
                if (_hostWindows.TryGetValue(topToBottom[i], out ITopLevelWindow window))
                    _stackScratch[count++] = window;
            }

            try
            {
                _topLevelHost.Restack(_stackScratch.AsSpan(0, count));
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] Restack failed: {ex.Message}");
            }

            Array.Clear(_stackScratch, 0, count);
        }

        private static void RunHostCall(ITopLevelWindow window, Action<ITopLevelWindow> call)
        {
            try
            {
                call(window);
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] Top-level window call failed: {ex.Message}");
            }
        }

        private void ExecuteCreateWindow(CreateWindowRequest request)
        {
            try
            {
                IWindow window = _display.CreateWindow(request.Options);
                if (window != null)
                    _window = window;

                request.Completion.SetResult(window);
            }
            catch (Exception ex)
            {
                request.Completion.SetException(ex);
            }
        }

        private void ExecuteShutdown(TaskCompletionSource<bool> completion, IWindow window)
        {
            _running = false;

            try
            {
                window?.Dispose();
                _display?.Dispose();
                completion.SetResult(true);
            }
            catch (Exception ex)
            {
                completion.SetException(ex);
            }
        }

        private bool ApplyPendingPresent()
        {
            PresentState present;
            PresentState applied;
            bool hasApplied;
            lock (_presentSync)
            {
                if (!_hasPendingPresent)
                    return false;

                present = _pendingPresent;
                applied = _appliedPresent;
                hasApplied = _hasAppliedPresent;
                _hasPendingPresent = false;
            }

            IWindow window = _window;
            if (window == null)
                return false;

            if (!hasApplied || !string.Equals(applied.Title, present.Title, StringComparison.Ordinal))
                window.Title = present.Title;

            if ((!hasApplied || applied.Visible != present.Visible) && window.Visible != present.Visible)
                window.Visible = present.Visible;

            // A present built before the guest read the queued host resize describes the previous frame.
            if (present.HostGeometryStale)
            {
                present.State = hasApplied ? applied.State : window.State;
                present.Width = hasApplied ? applied.Width : window.Width;
                present.Height = hasApplied ? applied.Height : window.Height;
            }
            else
            {
                if ((!hasApplied || applied.State != present.State) && window.State != present.State)
                    window.State = present.State;

                if (present.State == WindowState.Normal)
                {
                    if (present.Width > 0 && (!hasApplied || applied.Width != present.Width) && window.Width != present.Width)
                        window.Width = present.Width;

                    if (present.Height > 0 && (!hasApplied || applied.Height != present.Height) && window.Height != present.Height)
                        window.Height = present.Height;
                }
            }

            lock (_presentSync)
            {
                _appliedPresent = present;
                _hasAppliedPresent = true;
            }

            return true;
        }
    }
}
