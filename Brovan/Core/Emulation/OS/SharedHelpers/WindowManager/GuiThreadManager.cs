using System;
using System.Collections.Concurrent;
using System.Threading;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal abstract class GuiCommand
    {
        public abstract void Execute(IDisplayConnection display, IWindow window);
    }

    internal sealed class RenderTextCommand : GuiCommand
    {
        public readonly string Text;
        public readonly int X;
        public readonly int Y;
        public readonly int RectLeft;
        public readonly int RectTop;
        public readonly int RectRight;
        public readonly int RectBottom;
        public readonly uint Options;

        public RenderTextCommand(string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options)
        {
            Text = text;
            X = x;
            Y = y;
            RectLeft = rectLeft;
            RectTop = rectTop;
            RectRight = rectRight;
            RectBottom = rectBottom;
            Options = options;
        }

        public override void Execute(IDisplayConnection display, IWindow window)
        {
            if (window == null || string.IsNullOrEmpty(Text))
                return;

            if (display is ITextRenderSupport textRender)
                textRender.RenderText(window.NativeHandle, Text, X, Y, RectLeft, RectTop, RectRight, RectBottom, Options);
        }
    }

    internal sealed class GdiPrimitiveCommand : GuiCommand
    {
        public readonly GdiPrimitive Primitive;

        public GdiPrimitiveCommand(GdiPrimitive primitive)
        {
            Primitive = primitive;
        }

        public override void Execute(IDisplayConnection display, IWindow window)
        {
            if (window == null)
                return;

            if (display is IGdiRenderSupport gdiRender)
                gdiRender.ExecuteGdiPrimitive(window.NativeHandle, Primitive);
        }
    }

    internal sealed class CreateWindowCommand : GuiCommand
    {
        public readonly WindowOptions Options;
        public readonly TaskCompletionSource<IWindow> Completion;

        public CreateWindowCommand(WindowOptions options)
        {
            Options = options;
            Completion = new TaskCompletionSource<IWindow>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        public override void Execute(IDisplayConnection display, IWindow window)
        {
            try
            {
                IWindow result = display.CreateWindow(Options);
                Completion.SetResult(result);
            }
            catch (Exception ex)
            {
                Completion.SetException(ex);
            }
        }
    }

    internal sealed class PresentCommand : GuiCommand
    {
        public readonly string Title;
        public readonly int Width;
        public readonly int Height;
        public readonly bool Visible;
        public readonly WindowState State;

        public PresentCommand(string title, int width, int height, bool visible, WindowState state)
        {
            Title = title;
            Width = width;
            Height = height;
            Visible = visible;
            State = state;
        }

        public override void Execute(IDisplayConnection display, IWindow window)
        {
            if (window == null)
                return;

            if (window.Title != Title)
                window.Title = Title;

            if (Width > 0 && window.Width != Width)
                window.Width = Width;

            if (Height > 0 && window.Height != Height)
                window.Height = Height;

            if (window.Visible != Visible)
                window.Visible = Visible;

            if (window.State != State)
                window.State = State;
        }
    }

    internal sealed class DisposeCommand : GuiCommand
    {
        public readonly TaskCompletionSource<bool> Completion;

        public DisposeCommand()
        {
            Completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        public override void Execute(IDisplayConnection display, IWindow window)
        {
            try
            {
                window?.Dispose();
                display?.Dispose();
                Completion.SetResult(true);
            }
            catch (Exception ex)
            {
                Completion.SetException(ex);
            }
        }
    }

    internal sealed class GuiThreadManager : IDisplayConnection
    {
        private IDisplayConnection _display;
        private readonly Thread _guiThread;
        private readonly BlockingCollection<GuiCommand> _commandQueue;
        private IWindow _window;
        private volatile bool _disposed;
        private readonly object _windowLock = new();
        private readonly Func<IDisplayConnection> _displayFactory;
        private readonly TaskCompletionSource<bool> _initCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public GuiThreadManager(Func<IDisplayConnection> displayFactory)
        {
            _displayFactory = displayFactory ?? throw new ArgumentNullException(nameof(displayFactory));
            _commandQueue = new BlockingCollection<GuiCommand>();
            _guiThread = new Thread(GuiThreadMain)
            {
                IsBackground = true,
                Name = "BrovanGuiThread"
            };
            _guiThread.Start();
        }

        public bool IsConnected => !_disposed && _display != null && _display.IsConnected;

        public IntPtr NativeHandle => _display?.NativeHandle ?? IntPtr.Zero;

        public IWindow CreateWindow(WindowOptions options)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(GuiThreadManager));

            try
            {
                _initCompletion.Task.Wait(5000);
            }
            catch
            {
                Utils.LogError("[GuiThreadManager] Display initialization timed out");
                return null;
            }

            if (_display == null)
                return null;

            CreateWindowCommand cmd = new CreateWindowCommand(options);
            _commandQueue.Add(cmd);

            try
            {
                cmd.Completion.Task.Wait(5000);
                IWindow result = cmd.Completion.Task.Result;
                if (result != null)
                {
                    lock (_windowLock)
                        _window = result;
                }
                return result;
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] CreateWindow timed out or failed: {ex.Message}");
                return null;
            }
        }

        public void EnqueuePresent(string title, int width, int height, bool visible, WindowState state)
        {
            if (_disposed)
                return;

            _commandQueue.Add(new PresentCommand(title, width, height, visible, state));
        }

        public void EnqueueTextRender(ulong hwnd, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options)
        {
            if (_disposed)
                return;

            _commandQueue.Add(new RenderTextCommand(text, x, y, rectLeft, rectTop, rectRight, rectBottom, options));
        }

        public void EnqueueGdiPrimitive(GdiPrimitive primitive)
        {
            if (_disposed)
                return;

            _commandQueue.Add(new GdiPrimitiveCommand(primitive));
        }

        public bool TranslateVirtualKey(uint virtualKey, uint scanCode, out char character)
        {
            character = '\0';

            if (_disposed)
                return false;

            try
            {
                _initCompletion.Task.Wait(5000);
            }
            catch
            {
                return false;
            }

            if (_display is not IKeyboardTranslateSupport support)
                return false;

            return support.TranslateVirtualKey(virtualKey, scanCode, out character);
        }

        public bool MeasureText(string text, out int width, out int height)
        {
            width = 0;
            height = 0;

            if (_disposed)
                return false;

            try
            {
                _initCompletion.Task.Wait(5000);
            }
            catch
            {
                return false;
            }

            if (_display is not ITextMetricsSupport metrics)
                return false;

            return metrics.MeasureText(text ?? string.Empty, out width, out height);
        }

        public bool GetTextMetrics(out TextMetricsData metrics)
        {
            metrics = default;

            if (_disposed)
                return false;

            try
            {
                _initCompletion.Task.Wait(5000);
            }
            catch
            {
                return false;
            }

            if (_display is not ITextMetricsSupport support)
                return false;

            return support.GetTextMetrics(out metrics);
        }

        public void PumpEvents()
        {
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            DisposeCommand cmd = new DisposeCommand();
            _commandQueue.Add(cmd);

            try
            {
                cmd.Completion.Task.Wait(2000);
            }
            catch
            {
            }

            _commandQueue.CompleteAdding();

            try
            {
                _guiThread.Join(1000);
            }
            catch
            {
            }

            _commandQueue.Dispose();
        }

        private void GuiThreadMain()
        {
            try
            {
                _display = _displayFactory();
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuiThreadManager] Failed to create display: {ex.Message}");
                _initCompletion.SetResult(false);
                return;
            }

            _initCompletion.SetResult(true);

            while (!_disposed)
            {
                try
                {
                    if (_commandQueue.TryTake(out GuiCommand cmd, 16))
                    {
                        IWindow currentWindow;
                        lock (_windowLock)
                            currentWindow = _window;

                        cmd.Execute(_display, currentWindow);
                        _display.PumpEvents();
                    }
                    else
                    {
                        _display.PumpEvents();
                    }
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[GuiThreadManager] GUI thread error: {ex.Message}");
                }
            }
        }
    }
}
