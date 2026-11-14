using System;
using System.Buffers;
using System.Collections.Generic;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // Straight RGBA, with the opacity of its visuals applied to the alpha.
    internal readonly record struct CompositorRectangle(float Left, float Top, float Right, float Bottom, float Red, float Green, float Blue, float Alpha);

    // The pixels are premultiplied 0xAARRGGBB rows of Width.
    internal sealed class CompositorSurfaceCopy
    {
        internal readonly uint[] Pixels;
        internal readonly int Width;
        internal readonly int Height;

        internal CompositorSurfaceCopy(int Width, int Height)
        {
            this.Width = Width;
            this.Height = Height;
            Pixels = new uint[Width * Height];
        }

        internal ulong Bytes => (ulong)Pixels.Length * 4;
    }

    internal readonly record struct CompositorFrame(uint[] Pixels, bool Pooled)
    {
        internal void Return()
        {
            if (Pooled)
                ArrayPool<uint>.Shared.Return(Pixels);
        }
    }

    // An opaque texture ignores the surface's alpha, as DWM does for a window's own flip content.
    internal readonly record struct CompositorTexture(float Left, float Top, float Right, float Bottom, CompositorSurfaceCopy Surface, int SourceLeft,
        int SourceTop, int SourceRight, int SourceBottom, float Opacity, bool Opaque = false);

    // Holds plain values and surface copies only, so a raster needs nothing that a commit can change.
    internal sealed class CompositorDisplayList
    {
        internal readonly int Width;
        internal readonly int Height;
        internal readonly List<CompositorRectangle> Rectangles = new();
        internal readonly List<CompositorTexture> Textures = new();

        internal readonly List<(bool Texture, int Index)> Order = new();

        internal CompositorDisplayList(int Width, int Height)
        {
            this.Width = Width;
            this.Height = Height;
        }

        internal void Add(in CompositorRectangle Rectangle)
        {
            Order.Add((false, Rectangles.Count));
            Rectangles.Add(Rectangle);
        }

        internal void Add(in CompositorTexture Texture)
        {
            Order.Add((true, Textures.Count));
            Textures.Add(Texture);
        }
    }

    // The renderer takes no lock and touches no guest memory, because it runs on a host task.
    internal static class CompositorRenderer
    {
        private const uint Black = 0xFF000000;

        internal static CompositorFrame Render(CompositorDisplayList List)
        {
            int Count = List.Width * List.Height;
            uint[] Pixels = Win32kHelper.RentGuiPixels(Count, out bool Pooled);
            Pixels.AsSpan(0, Count).Fill(Black);
            foreach ((bool Texture, int Index) in List.Order)
            {
                if (Texture)
                    Draw(Pixels, List.Width, List.Height, List.Textures[Index]);
                else
                    Fill(Pixels, List.Width, List.Height, List.Rectangles[Index]);
            }

            return new CompositorFrame(Pixels, Pooled);
        }

        private static void Fill(uint[] Pixels, int Width, int Height, in CompositorRectangle Rectangle)
        {
            float Alpha = Math.Clamp(Rectangle.Alpha, 0f, 1f);
            if (!(Alpha > 0f))
                return;

            int Left = Edge(Rectangle.Left, Width);
            int Right = Edge(Rectangle.Right, Width);
            int Top = Edge(Rectangle.Top, Height);
            int Bottom = Edge(Rectangle.Bottom, Height);
            if (Left >= Right || Top >= Bottom)
                return;

            uint Red = Channel(Rectangle.Red);
            uint Green = Channel(Rectangle.Green);
            uint Blue = Channel(Rectangle.Blue);
            if (Alpha >= 1f)
            {
                uint Color = Black | Red << 16 | Green << 8 | Blue;
                for (int Row = Top; Row < Bottom; Row++)
                    Pixels.AsSpan(Row * Width + Left, Right - Left).Fill(Color);

                return;
            }

            // DWM's blend of a half opaque sprite fits an alpha that drops its fraction.
            uint Weight = (uint)(Alpha * 255f);
            uint Rest = 255 - Weight;
            for (int Row = Top; Row < Bottom; Row++)
            {
                Span<uint> Line = Pixels.AsSpan(Row * Width + Left, Right - Left);
                for (int Index = 0; Index < Line.Length; Index++)
                {
                    uint Pixel = Line[Index];
                    uint R = (Red * Weight + (Pixel >> 16 & 0xFF) * Rest + 127) / 255;
                    uint G = (Green * Weight + (Pixel >> 8 & 0xFF) * Rest + 127) / 255;
                    uint B = (Blue * Weight + (Pixel & 0xFF) * Rest + 127) / 255;
                    Line[Index] = Black | R << 16 | G << 8 | B;
                }
            }
        }

        // DWM samples bilinearly from texel centers, so a surface drawn at its own size on whole pixels copies texel for texel.
        private static void Draw(uint[] Pixels, int Width, int Height, in CompositorTexture Texture)
        {
            float Opacity = Math.Clamp(Texture.Opacity, 0f, 1f);
            CompositorSurfaceCopy Surface = Texture.Surface;
            int SourceLeft = Math.Clamp(Texture.SourceLeft, 0, Surface.Width);
            int SourceRight = Math.Clamp(Texture.SourceRight, 0, Surface.Width);
            int SourceTop = Math.Clamp(Texture.SourceTop, 0, Surface.Height);
            int SourceBottom = Math.Clamp(Texture.SourceBottom, 0, Surface.Height);
            float DestinationWidth = Texture.Right - Texture.Left;
            float DestinationHeight = Texture.Bottom - Texture.Top;
            if (!(Opacity > 0f) || SourceLeft >= SourceRight || SourceTop >= SourceBottom || !(DestinationWidth > 0f) || !(DestinationHeight > 0f))
                return;

            int Left = Edge(Texture.Left, Width);
            int Right = Edge(Texture.Right, Width);
            int Top = Edge(Texture.Top, Height);
            int Bottom = Edge(Texture.Bottom, Height);
            int Columns = Right - Left;
            if (Columns <= 0 || Top >= Bottom)
                return;

            float ScaleX = (SourceRight - SourceLeft) / DestinationWidth;
            float ScaleY = (SourceBottom - SourceTop) / DestinationHeight;
            uint Weight = (uint)(Opacity * 255f);
            TexelPair[] Samples = ArrayPool<TexelPair>.Shared.Rent(Columns);
            try
            {
                for (int Index = 0; Index < Columns; Index++)
                    Samples[Index] = Sample(SourceLeft + (Left + Index + 0.5f - Texture.Left) * ScaleX - 0.5f, SourceLeft, SourceRight);

                for (int Row = Top; Row < Bottom; Row++)
                {
                    TexelPair Y = Sample(SourceTop + (Row + 0.5f - Texture.Top) * ScaleY - 0.5f, SourceTop, SourceBottom);
                    Span<uint> Line = Pixels.AsSpan(Row * Width + Left, Columns);
                    ReadOnlySpan<uint> Upper = Surface.Pixels.AsSpan(Y.Near * Surface.Width, Surface.Width);
                    ReadOnlySpan<uint> Lower = Surface.Pixels.AsSpan(Y.Far * Surface.Width, Surface.Width);
                    for (int Index = 0; Index < Line.Length; Index++)
                    {
                        TexelPair X = Samples[Index];
                        uint Texel = X.Weight == 0 && Y.Weight == 0
                            ? Upper[X.Near]
                            : Bilinear(Upper[X.Near], Upper[X.Far], Lower[X.Near], Lower[X.Far], X.Weight, Y.Weight);
                        Line[Index] = Texture.Opaque ? Black | Texel : Over(Texel, Line[Index], Weight);
                    }
                }
            }
            finally
            {
                ArrayPool<TexelPair>.Shared.Return(Samples);
            }
        }

        private readonly record struct TexelPair(int Near, int Far, int Weight);

        private static TexelPair Sample(float Position, int First, int End)
        {
            float Floor = MathF.Floor(Position);
            return new TexelPair(Math.Clamp((int)Floor, First, End - 1), Math.Clamp((int)Floor + 1, First, End - 1),
                Math.Clamp((int)((Position - Floor) * 256f + 0.5f), 0, 256));
        }

        private static uint Bilinear(uint TopLeft, uint TopRight, uint BottomLeft, uint BottomRight, int Wx, int Wy)
            => Lerp(TopLeft, TopRight, BottomLeft, BottomRight, 24, Wx, Wy) << 24 | Lerp(TopLeft, TopRight, BottomLeft, BottomRight, 16, Wx, Wy) << 16
               | Lerp(TopLeft, TopRight, BottomLeft, BottomRight, 8, Wx, Wy) << 8 | Lerp(TopLeft, TopRight, BottomLeft, BottomRight, 0, Wx, Wy);

        private static uint Lerp(uint TopLeft, uint TopRight, uint BottomLeft, uint BottomRight, int Shift, int Wx, int Wy)
        {
            int Upper = (int)(TopLeft >> Shift & 0xFF) * (256 - Wx) + (int)(TopRight >> Shift & 0xFF) * Wx;
            int Lower = (int)(BottomLeft >> Shift & 0xFF) * (256 - Wx) + (int)(BottomRight >> Shift & 0xFF) * Wx;
            return (uint)((Upper * (256 - Wy) + Lower * Wy + 32768) >> 16);
        }

        private static uint Over(uint Texel, uint Pixel, uint Weight)
        {
            uint Alpha = ((Texel >> 24) * Weight + 127) / 255;
            uint Rest = 255 - Alpha;
            uint R = Math.Min(((Texel >> 16 & 0xFF) * Weight + 127) / 255 + ((Pixel >> 16 & 0xFF) * Rest + 127) / 255, 255);
            uint G = Math.Min(((Texel >> 8 & 0xFF) * Weight + 127) / 255 + ((Pixel >> 8 & 0xFF) * Rest + 127) / 255, 255);
            uint B = Math.Min(((Texel & 0xFF) * Weight + 127) / 255 + ((Pixel & 0xFF) * Rest + 127) / 255, 255);
            return Black | R << 16 | G << 8 | B;
        }

        private static int Edge(float Value, int Limit) => float.IsNaN(Value) ? 0 : (int)Math.Clamp(MathF.Round(Value), 0f, Limit);

        private static uint Channel(float Value) => float.IsNaN(Value) ? 0 : (uint)MathF.Round(Math.Clamp(Value, 0f, 1f) * 255f);
    }
}
