using System;
using System.Collections.Generic;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Android
{
    internal sealed class AndroidGdiSurface
    {
        private const int DefaultBackground = unchecked((int)0xFFFFFFFF);

        private const uint EtoClipped = 0x0004;

        private const int MaximumWindows = 32;

        private sealed class WindowBuffer
        {
            public int[] Pixels = Array.Empty<int>();
            public int Width;
            public int Height;
            public bool Dirty;
        }

        private readonly object _sync = new();
        private readonly Dictionary<ulong, WindowBuffer> _windows = new();

        private ulong _lastDrawn;

        public void Execute(in GdiPrimitive primitive)
        {
            lock (_sync)
            {
                WindowBuffer target = Resolve(primitive.Hwnd);
                if (target == null)
                    return;

                Draw(target, primitive);
                target.Dirty = true;
                _lastDrawn = primitive.Hwnd;
            }
        }

        public void DrawText(ulong hwnd, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options)
        {
            if (string.IsNullOrEmpty(text))
                return;

            lock (_sync)
            {
                WindowBuffer target = Resolve(hwnd);
                if (target == null)
                    return;

                if (!AndroidText.Rasterize(text, out AndroidTextBitmap bitmap))
                    return;

                int left = 0;
                int top = 0;
                int right = target.Width;
                int bottom = target.Height;

                if ((options & EtoClipped) != 0 && rectRight > rectLeft && rectBottom > rectTop)
                {
                    left = Math.Max(left, rectLeft);
                    top = Math.Max(top, rectTop);
                    right = Math.Min(right, rectRight);
                    bottom = Math.Min(bottom, rectBottom);
                }

                // TA_TOP: the reference point is the top of the cell, not the baseline.
                Blend(target, bitmap, x - bitmap.Padding, y - bitmap.Padding, left, top, right, bottom);
                target.Dirty = true;
                _lastDrawn = hwnd;
            }
        }

        public void Flush()
        {
            lock (_sync)
            {
                IntPtr window = AndroidHost.NativeWindow;
                if (window == IntPtr.Zero)
                    return;

                ulong selected = AndroidGuestWindows.Selected;
                if (selected == 0)
                    selected = _lastDrawn;

                if (!_windows.TryGetValue(selected, out WindowBuffer target) || !target.Dirty)
                    return;

                Post(window, target);
                target.Dirty = false;
            }
        }

        public void Invalidate()
        {
            lock (_sync)
            {
                foreach (WindowBuffer buffer in _windows.Values)
                    buffer.Dirty = true;
            }
        }

        private WindowBuffer Resolve(ulong hwnd)
        {
            if (!_windows.TryGetValue(hwnd, out WindowBuffer buffer))
            {
                // A guest that churns windows would otherwise grow this without bound; the emulator only
                // presents one at a time, so dropping the oldest costs nothing visible.
                if (_windows.Count >= MaximumWindows)
                    _windows.Clear();

                buffer = new WindowBuffer();
                _windows[hwnd] = buffer;
            }

            int width = AndroidHost.Width;
            int height = AndroidHost.Height;
            if (width <= 0 || height <= 0)
                return null;

            if (buffer.Width != width || buffer.Height != height || buffer.Pixels.Length == 0)
            {
                buffer.Pixels = new int[width * height];
                buffer.Width = width;
                buffer.Height = height;
                Array.Fill(buffer.Pixels, DefaultBackground);
            }

            return buffer;
        }

        private static void Draw(WindowBuffer target, in GdiPrimitive primitive)
        {
            int fill = ToPixel(primitive.Brush.ColorRef);
            int stroke = ToPixel(primitive.Pen.ColorRef);
            int thickness = Math.Max(1, primitive.Pen.Width);

            switch (primitive.Kind)
            {
                case GdiPrimitiveKind.Line:
                    if (primitive.HasPen)
                        DrawLine(target, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2, stroke, thickness);
                    break;

                case GdiPrimitiveKind.FillRect:
                    FillRectangle(target, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2, primitive.HasBrush ? fill : stroke);
                    break;

                case GdiPrimitiveKind.Rectangle:
                case GdiPrimitiveKind.RoundRect:
                    if (primitive.HasBrush)
                        FillRectangle(target, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2, fill);
                    if (primitive.HasPen)
                        StrokeRectangle(target, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2, stroke, thickness);
                    break;

                case GdiPrimitiveKind.Ellipse:
                    DrawEllipse(target, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2, primitive.HasBrush, fill, primitive.HasPen, stroke);
                    break;

                case GdiPrimitiveKind.Polygon:
                case GdiPrimitiveKind.Polyline:
                    DrawPolyline(target, primitive.Points, primitive.Kind == GdiPrimitiveKind.Polygon, primitive.HasPen ? stroke : fill, thickness);
                    break;
            }
        }

        private static unsafe void Post(IntPtr window, WindowBuffer source)
        {
            AndroidNative.NativeWindowSetBuffersGeometry(window, source.Width, source.Height, AndroidNative.WindowFormatRgba8888);

            AndroidNative.NativeWindowBuffer buffer;
            if (AndroidNative.NativeWindowLock(window, &buffer, IntPtr.Zero) != 0)
                return;

            try
            {
                int rows = Math.Min(buffer.Height, source.Height);
                int columns = Math.Min(buffer.Width, source.Width);
                int* destination = (int*)buffer.Bits;

                fixed (int* pixels = source.Pixels)
                {
                    for (int y = 0; y < rows; y++)
                    {
                        int* sourceRow = pixels + (y * source.Width);
                        int* destinationRow = destination + (y * buffer.Stride);
                        for (int x = 0; x < columns; x++)
                            destinationRow[x] = sourceRow[x];
                    }
                }
            }
            finally
            {
                AndroidNative.NativeWindowUnlockAndPost(window);
            }
        }

        private static void Blend(WindowBuffer target, in AndroidTextBitmap bitmap, int left, int top, int clipLeft, int clipTop, int clipRight, int clipBottom)
        {
            int firstRow = Math.Max(0, clipTop - top);
            int lastRow = Math.Min(bitmap.Height, clipBottom - top);
            int firstColumn = Math.Max(0, clipLeft - left);
            int lastColumn = Math.Min(bitmap.Width, clipRight - left);

            for (int row = firstRow; row < lastRow; row++)
            {
                int source = row * bitmap.Width;
                int destination = ((top + row) * target.Width) + left;

                for (int column = firstColumn; column < lastColumn; column++)
                {
                    int coverage = bitmap.Coverage[source + column];
                    if (coverage == 0)
                        continue;

                    if (coverage == 0xFF)
                    {
                        target.Pixels[destination + column] = unchecked((int)0xFF000000);
                        continue;
                    }

                    int pixel = target.Pixels[destination + column];
                    int remaining = 255 - coverage;
                    int red = ((pixel & 0xFF) * remaining) / 255;
                    int green = (((pixel >> 8) & 0xFF) * remaining) / 255;
                    int blue = (((pixel >> 16) & 0xFF) * remaining) / 255;

                    target.Pixels[destination + column] = unchecked((int)0xFF000000) | (blue << 16) | (green << 8) | red;
                }
            }
        }

        private static int ToPixel(uint colorRef)
        {
            return unchecked((int)(0xFF000000u | (colorRef & 0x00FFFFFFu)));
        }

        private static void SetPixel(WindowBuffer target, int x, int y, int color)
        {
            if ((uint)x >= (uint)target.Width || (uint)y >= (uint)target.Height)
                return;

            target.Pixels[(y * target.Width) + x] = color;
        }

        private static void FillRectangle(WindowBuffer target, int left, int top, int right, int bottom, int color)
        {
            Normalize(ref left, ref right);
            Normalize(ref top, ref bottom);

            left = Math.Max(left, 0);
            top = Math.Max(top, 0);
            right = Math.Min(right, target.Width);
            bottom = Math.Min(bottom, target.Height);

            for (int y = top; y < bottom; y++)
            {
                int row = y * target.Width;
                for (int x = left; x < right; x++)
                    target.Pixels[row + x] = color;
            }
        }

        private static void StrokeRectangle(WindowBuffer target, int left, int top, int right, int bottom, int color, int thickness)
        {
            Normalize(ref left, ref right);
            Normalize(ref top, ref bottom);

            for (int i = 0; i < thickness; i++)
            {
                DrawLine(target, left, top + i, right, top + i, color, 1);
                DrawLine(target, left, bottom - 1 - i, right, bottom - 1 - i, color, 1);
                DrawLine(target, left + i, top, left + i, bottom, color, 1);
                DrawLine(target, right - 1 - i, top, right - 1 - i, bottom, color, 1);
            }
        }

        private static void DrawLine(WindowBuffer target, int x0, int y0, int x1, int y1, int color, int thickness)
        {
            int dx = Math.Abs(x1 - x0);
            int dy = -Math.Abs(y1 - y0);
            int stepX = x0 < x1 ? 1 : -1;
            int stepY = y0 < y1 ? 1 : -1;
            int error = dx + dy;
            int radius = thickness / 2;

            while (true)
            {
                if (thickness <= 1)
                {
                    SetPixel(target, x0, y0, color);
                }
                else
                {
                    for (int oy = -radius; oy <= radius; oy++)
                        for (int ox = -radius; ox <= radius; ox++)
                            SetPixel(target, x0 + ox, y0 + oy, color);
                }

                if (x0 == x1 && y0 == y1)
                    return;

                int doubled = error * 2;
                if (doubled >= dy)
                {
                    if (x0 == x1)
                        return;
                    error += dy;
                    x0 += stepX;
                }

                if (doubled <= dx)
                {
                    if (y0 == y1)
                        return;
                    error += dx;
                    y0 += stepY;
                }
            }
        }

        private static void DrawEllipse(WindowBuffer target, int left, int top, int right, int bottom, bool hasBrush, int fill, bool hasPen, int stroke)
        {
            Normalize(ref left, ref right);
            Normalize(ref top, ref bottom);

            int radiusX = (right - left) / 2;
            int radiusY = (bottom - top) / 2;
            if (radiusX <= 0 || radiusY <= 0)
                return;

            int centerX = left + radiusX;
            int centerY = top + radiusY;
            long squaredX = (long)radiusX * radiusX;
            long squaredY = (long)radiusY * radiusY;

            for (int y = -radiusY; y <= radiusY; y++)
            {
                long span = squaredX - ((squaredX * y * y) / squaredY);
                if (span < 0)
                    continue;

                int half = (int)Math.Sqrt(span);

                if (hasBrush)
                {
                    for (int x = -half; x <= half; x++)
                        SetPixel(target, centerX + x, centerY + y, fill);
                }

                if (hasPen)
                {
                    SetPixel(target, centerX - half, centerY + y, stroke);
                    SetPixel(target, centerX + half, centerY + y, stroke);
                }
            }
        }

        private static void DrawPolyline(WindowBuffer target, GdiPoint[] points, bool close, int color, int thickness)
        {
            if (points == null || points.Length < 2)
                return;

            for (int i = 1; i < points.Length; i++)
                DrawLine(target, points[i - 1].X, points[i - 1].Y, points[i].X, points[i].Y, color, thickness);

            if (close)
                DrawLine(target, points[^1].X, points[^1].Y, points[0].X, points[0].Y, color, thickness);
        }

        private static void Normalize(ref int low, ref int high)
        {
            if (low > high)
                (low, high) = (high, low);
        }
    }
}
