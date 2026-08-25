using System;
using System.Collections.Concurrent;
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
        SetCursorVisible,
        Shutdown,
    }

    internal struct GuiCommand
    {
        public GuiCommandKind Kind;
        public uint TextOptions;
        public ulong Hwnd;
        public int X;
        public int Y;
        public int RectLeft;
        public int RectTop;
        public int RectRight;
        public int RectBottom;
        public string Text;
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

    internal struct PresentState
    {
        public string Title;
        public int Width;
        public int Height;
        public bool Visible;
        public WindowState State;

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

        private volatile IWindow _window;
        private volatile bool _disposed;
        private bool _running = true;

        private PresentState _pendingPresent;
        private PresentState _appliedPresent;
        private bool _hasPendingPresent;
        private bool _hasAppliedPresent;
        private int _parked;

        public GuiThreadManager(Func<IDisplayConnection> displayFactory)
        {
            _displayFactory = displayFactory ?? throw new ArgumentNullException(nameof(displayFactory));
            _guiThread = new Thread(GuiThreadMain)
            {
                IsBackground = true,
                Name = "BrovanGuiThread",

                // Guest CPU threads run flat out on every core, and this is the only thread that turns host
                // input into guest messages or pushes a frame to the screen. At Normal it gets scheduled
                // behind them and the whole presentation path inherits their quantum as latency.
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

            try
            {
                if (!request.Completion.Task.Wait(InitializationTimeoutMilliseconds))
                {
                    Utils.LogError("[GuiThreadManager] CreateWindow timed out");
                    return null;
                }

                return request.Completion.Task.Result;
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] CreateWindow failed: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Moves the host pointer to a point in the window's client area.
        /// </summary>
        public void EnqueueWarpCursor(int clientX, int clientY)
        {
            if (_disposed)
                return;

            Submit(new GuiCommand { Kind = GuiCommandKind.WarpCursor, X = clientX, Y = clientY });
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

        public void EnqueueTextRender(ulong hwnd, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options)
        {
            if (_disposed || string.IsNullOrEmpty(text))
                return;

            Submit(new GuiCommand
            {
                Kind = GuiCommandKind.RenderText,
                Hwnd = hwnd,
                Text = text,
                X = x,
                Y = y,
                RectLeft = rectLeft,
                RectTop = rectTop,
                RectRight = rectRight,
                RectBottom = rectBottom,
                TextOptions = options,
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

        public bool MeasureText(string text, out int width, out int height)
        {
            width = 0;
            height = 0;

            if (_disposed || !WaitForInitialization())
                return false;

            ITextMetricsSupport support = _textMetrics;
            return support != null && support.MeasureText(text ?? string.Empty, out width, out height);
        }

        public bool GetTextMetrics(out TextMetricsData metrics)
        {
            metrics = default;

            if (_disposed || !WaitForInitialization())
                return false;

            ITextMetricsSupport support = _textMetrics;
            return support != null && support.GetTextMetrics(out metrics);
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
                return _hasPendingPresent;
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
            IWindow window = _window;

            switch (command.Kind)
            {
                case GuiCommandKind.GdiPrimitive:
                    if (window != null && _gdiRender != null)
                        _gdiRender.ExecuteGdiPrimitive(window.NativeHandle, command.Primitive);
                    return;

                case GuiCommandKind.RenderText:
                    if (window != null && _textRender != null)
                    {
                        _textRender.RenderText(
                            window.NativeHandle,
                            command.Hwnd,
                            command.Text,
                            command.X,
                            command.Y,
                            command.RectLeft,
                            command.RectTop,
                            command.RectRight,
                            command.RectBottom,
                            command.TextOptions);
                    }

                    return;

                case GuiCommandKind.CreateWindow:
                    ExecuteCreateWindow((CreateWindowRequest)command.Request);
                    return;

                case GuiCommandKind.WarpCursor:
                    window?.WarpCursor(command.X, command.Y);
                    return;

                case GuiCommandKind.SetCursorVisible:
                    window?.SetCursorVisible(command.X != 0);
                    return;

                case GuiCommandKind.Shutdown:
                    ExecuteShutdown((TaskCompletionSource<bool>)command.Request, window);
                    return;
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

            if ((!hasApplied || applied.State != present.State) && window.State != present.State)
                window.State = present.State;

            if (present.State == WindowState.Normal)
            {
                if (present.Width > 0 && (!hasApplied || applied.Width != present.Width) && window.Width != present.Width)
                    window.Width = present.Width;

                if (present.Height > 0 && (!hasApplied || applied.Height != present.Height) && window.Height != present.Height)
                    window.Height = present.Height;
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
