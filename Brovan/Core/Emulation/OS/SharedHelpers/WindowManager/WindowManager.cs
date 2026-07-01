using System;
using System.Collections.Generic;
using System.Linq;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    public enum LinuxDisplayBackend
    {
        None,
        X11,
        Wayland
    }

    public enum WindowState
    {
        Normal,
        Minimized,
        Maximized,
        Fullscreen
    }

    public sealed record WindowOptions
    {
        public string Title { get; init; } = string.Empty;
        public string AppId { get; init; } = string.Empty;
        public int Width { get; init; } = 800;
        public int Height { get; init; } = 600;
        public int X { get; init; } = 0;
        public int Y { get; init; } = 0;
        public bool Visible { get; init; } = true;
        public bool Resizable { get; init; } = true;
        public bool Decorated { get; init; } = true;
        public bool Center { get; init; } = false;
        public WindowState State { get; init; } = WindowState.Normal;
    }

    public struct WindowData
    {
        public string Title;
        public string Class;
        public int Width;
        public int Height;
        public int X;
        public int Y;
        public bool Show;
        public bool Resizable;
        public bool Decorated;
        public bool Center;
        public WindowState State;

        public WindowOptions ToOptions()
        {
            return new WindowOptions
            {
                Title = Title ?? string.Empty,
                AppId = Class ?? string.Empty,
                Width = Width > 0 ? Width : 800,
                Height = Height > 0 ? Height : 600,
                X = X,
                Y = Y,
                Visible = Show,
                Resizable = Resizable,
                Decorated = Decorated,
                Center = Center,
                State = State,
            };
        }
    }

    public interface ITextRenderSupport
    {
        void RenderText(IntPtr windowHandle, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options);
    }

    public enum GdiPrimitiveKind
    {
        Line,
        FillRect,
        Rectangle,
        Ellipse,
        RoundRect,
        Polygon,
        Polyline
    }

    public struct GdiPenDescriptor
    {
        public uint ColorRef;
        public int Width;
    }

    public struct GdiBrushDescriptor
    {
        public uint ColorRef;
    }

    public struct GdiPoint
    {
        public int X;
        public int Y;
    }

    public struct GdiPrimitive
    {
        public GdiPrimitiveKind Kind;
        public int X1;
        public int Y1;
        public int X2;
        public int Y2;
        public uint Rop;
        public int RoundedWidth;
        public int RoundedHeight;
        public GdiPoint[] Points;
        public GdiPenDescriptor Pen;
        public GdiBrushDescriptor Brush;
        public bool HasPen;
        public bool HasBrush;
    }

    public interface IGdiRenderSupport
    {
        void ExecuteGdiPrimitive(IntPtr windowHandle, GdiPrimitive primitive);
    }

    public interface IKeyboardTranslateSupport
    {
        bool TranslateVirtualKey(uint virtualKey, uint scanCode, out char character);
    }

    public struct TextMetricsData
    {
        public int Height;
        public int Ascent;
        public int Descent;
        public int InternalLeading;
        public int ExternalLeading;
        public int AveCharWidth;
        public int MaxCharWidth;
        public int Weight;
        public int Overhang;
        public int DigitizedAspectX;
        public int DigitizedAspectY;
        public ushort FirstChar;
        public ushort LastChar;
        public ushort DefaultChar;
        public ushort BreakChar;
        public byte Italic;
        public byte Underlined;
        public byte StruckOut;
        public byte PitchAndFamily;
        public byte CharSet;
    }

    public interface ITextMetricsSupport
    {
        bool MeasureText(string text, out int width, out int height);

        bool GetTextMetrics(out TextMetricsData metrics);
    }

    public interface IDisplayConnection : IDisposable
    {
        IWindow CreateWindow(WindowOptions options);

        void PumpEvents();

        bool IsConnected { get; }

        IntPtr NativeHandle { get; }
    }

    public interface IWindow : IDisposable
    {
        string Title { get; set; }

        int Width { get; set; }

        int Height { get; set; }

        bool Visible { get; set; }

        WindowState State { get; set; }

        bool Resizable { get; }

        bool Decorated { get; set; }

        void Present();

        IntPtr NativeHandle { get; }

        void Show();

        void Hide();

        void Close();
    }

    public static class WindowManagerFactory
    {
        public static IDisplayConnection Create()
        {
            Func<IDisplayConnection> factory;

            if (OperatingSystem.IsWindows())
                factory = () => new WindowsWinManager();
            else if (OperatingSystem.IsLinux())
                factory = () => new LinuxWinManager();
            else
                throw new PlatformNotSupportedException("No supported window backend is available for this platform.");

            return new GuiThreadManager(factory);
        }
    }
}
