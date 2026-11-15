using System;
using System.Collections.Generic;
using System.Text;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal sealed class X11MessageBox : IHostMessageBox
    {
        private const int Margin = 16;
        private const int MaxTextWidth = 480;
        private const int ButtonMinWidth = 80;
        private const int ButtonPadding = 12;
        private const int ButtonGap = 8;
        private const uint MouseLeft = 1;

        private const long KeyReturn = 0xFF0D;
        private const long KeyPadEnter = 0xFF8D;
        private const long KeyEscape = 0xFF1B;
        private const long KeyTab = 0xFF09;
        private const long KeyLeft = 0xFF51;
        private const long KeyRight = 0xFF53;
        private const long KeySpace = 0x20;

        private static readonly string[] FontNames =
        {
            "-*-helvetica-medium-r-normal--14-*-*-*-*-*-iso8859-1",
            "-*-dejavu sans-medium-r-normal--14-*-*-*-*-*-iso8859-1",
            "fixed",
        };

        public unsafe int Show(HostMessageBoxRequest Request)
        {
            IntPtr Display;
            try
            {
                Display = X11.OpenDisplay();
            }
            catch (DllNotFoundException)
            {
                return 0;
            }

            if (Display == IntPtr.Zero)
                return 0;

            IntPtr Font = IntPtr.Zero;
            IntPtr Window = IntPtr.Zero;
            IntPtr Gc = IntPtr.Zero;
            try
            {
                foreach (string Name in FontNames)
                {
                    Font = X11.XLoadQueryFont(Display, Name);
                    if (Font != IntPtr.Zero)
                        break;
                }

                if (Font == IntPtr.Zero)
                    return 0;

                Layout Box = new Layout(Font, Request);
                int Screen = X11.XDefaultScreen(Display);
                IntPtr Root = X11.XRootWindow(Display, Screen);
                nuint White = X11.XWhitePixel(Display, Screen);
                nuint Black = X11.XBlackPixel(Display, Screen);
                int X = Math.Max(0, (X11.XDisplayWidth(Display, Screen) - Box.Width) / 2);
                int Y = Math.Max(0, (X11.XDisplayHeight(Display, Screen) - Box.Height) / 2);

                Window = X11.XCreateSimpleWindow(Display, Root, X, Y, (uint)Box.Width, (uint)Box.Height, 1, Black, White);
                SetTitle(Display, Window, Request.Caption);
                SetDialogHints(Display, Window, Box.Width, Box.Height);

                IntPtr DeleteWindow = X11.XInternAtom(Display, "WM_DELETE_WINDOW", 0);
                X11.XSetWMProtocols(Display, Window, new[] { DeleteWindow }, 1);
                X11.XSelectInput(Display, Window, X11.ExposureMask | X11.KeyPressMask | X11.ButtonPressMask | X11.ButtonReleaseMask);

                Gc = X11.XCreateGC(Display, Window, 0, IntPtr.Zero);
                X11.XSetFont(Display, Gc, ((X11.XFontStruct*)Font)->Fid);
                X11.XMapWindow(Display, Window);
                X11.XFlush(Display);

                int Focus = Request.DefaultIndex;
                int Pressed = -1;
                byte* KeyText = stackalloc byte[8];

                while (true)
                {
                    X11.XNextEvent(Display, out X11.XEvent Event);
                    switch (Event.Type)
                    {
                        case X11.Expose:
                            Draw(Display, Window, Gc, White, Black, Box, Focus);
                            break;

                        case X11.ButtonPress:
                        case X11.ButtonRelease:
                        {
                            X11.XButtonEvent* Button = (X11.XButtonEvent*)&Event;
                            if (Button->Button != MouseLeft)
                                break;

                            int Hit = Box.HitButton(Button->X, Button->Y);
                            if (Event.Type == X11.ButtonPress)
                                Pressed = Hit;
                            else if (Hit >= 0 && Hit == Pressed)
                                return Request.Buttons[Hit].Id;
                            break;
                        }

                        case X11.KeyPress:
                        {
                            X11.XLookupString(&Event, KeyText, 8, out IntPtr KeySym, IntPtr.Zero);
                            long Key = (long)KeySym;
                            if (Key == KeyReturn || Key == KeyPadEnter || Key == KeySpace)
                                return Request.Buttons[Focus].Id;

                            if (Key == KeyEscape && Request.EscapeId != 0)
                                return Request.EscapeId;

                            if (Key == KeyTab || Key == KeyRight || Key == KeyLeft)
                            {
                                int Step = Key == KeyLeft ? Box.Captions.Length - 1 : 1;
                                Focus = (Focus + Step) % Box.Captions.Length;
                                Draw(Display, Window, Gc, White, Black, Box, Focus);
                            }

                            break;
                        }

                        case X11.ClientMessage:
                        {
                            X11.XClientMessageEvent* Message = (X11.XClientMessageEvent*)&Event;
                            if (Message->Data0 == DeleteWindow && Request.EscapeId != 0)
                                return Request.EscapeId;
                            break;
                        }
                    }
                }
            }
            finally
            {
                if (Gc != IntPtr.Zero)
                    X11.XFreeGC(Display, Gc);

                if (Window != IntPtr.Zero)
                    X11.XDestroyWindow(Display, Window);

                if (Font != IntPtr.Zero)
                    X11.XFreeFont(Display, Font);

                X11.XCloseDisplay(Display);
            }
        }

        // Core fonts draw ISO 8859-1 only.
        private sealed class Layout
        {
            public readonly List<byte[]> Lines;
            public readonly byte[][] Captions;
            public readonly int[] CaptionWidths;
            public readonly int Ascent;
            public readonly int LineHeight;
            public readonly int ButtonWidth;
            public readonly int ButtonHeight;
            public readonly int ButtonsLeft;
            public readonly int ButtonsTop;
            public readonly int Width;
            public readonly int Height;

            public unsafe Layout(IntPtr Font, HostMessageBoxRequest Request)
            {
                X11.XFontStruct* Metrics = (X11.XFontStruct*)Font;
                Ascent = Metrics->Ascent;
                LineHeight = Metrics->Ascent + Metrics->Descent + 2;
                Lines = Wrap(Font, Encoding.Latin1.GetBytes(Request.Text));

                Captions = new byte[Request.Buttons.Length][];
                CaptionWidths = new int[Captions.Length];
                ButtonWidth = ButtonMinWidth;
                for (int i = 0; i < Captions.Length; i++)
                {
                    Captions[i] = Encoding.Latin1.GetBytes(Request.Buttons[i].Caption);
                    CaptionWidths[i] = TextWidth(Font, Captions[i]);
                    ButtonWidth = Math.Max(ButtonWidth, CaptionWidths[i] + 2 * ButtonPadding);
                }

                int TextWidthMax = 0;
                foreach (byte[] Line in Lines)
                    TextWidthMax = Math.Max(TextWidthMax, TextWidth(Font, Line));

                int ButtonsWidth = Captions.Length * ButtonWidth + (Captions.Length - 1) * ButtonGap;
                ButtonHeight = LineHeight + ButtonPadding;
                Width = Math.Max(TextWidthMax, ButtonsWidth) + 2 * Margin;
                Height = Margin + Lines.Count * LineHeight + Margin + ButtonHeight + Margin;
                ButtonsLeft = Width - Margin - ButtonsWidth;
                ButtonsTop = Height - Margin - ButtonHeight;
            }

            public int ButtonLeft(int Index) => ButtonsLeft + Index * (ButtonWidth + ButtonGap);

            public int HitButton(int X, int Y)
            {
                if (Y < ButtonsTop || Y >= ButtonsTop + ButtonHeight)
                    return -1;

                for (int i = 0; i < Captions.Length; i++)
                {
                    int Left = ButtonLeft(i);
                    if (X >= Left && X < Left + ButtonWidth)
                        return i;
                }

                return -1;
            }
        }

        private static void Draw(IntPtr Display, IntPtr Window, IntPtr Gc, nuint White, nuint Black, Layout Box, int Focus)
        {
            X11.XSetForeground(Display, Gc, White);
            X11.XFillRectangle(Display, Window, Gc, 0, 0, (uint)Box.Width, (uint)Box.Height);
            X11.XSetForeground(Display, Gc, Black);

            int Baseline = Margin + Box.Ascent;
            foreach (byte[] Line in Box.Lines)
            {
                DrawText(Display, Window, Gc, Margin, Baseline, Line);
                Baseline += Box.LineHeight;
            }

            int CaptionBaseline = Box.ButtonsTop + ButtonPadding / 2 + Box.Ascent + 1;
            for (int i = 0; i < Box.Captions.Length; i++)
            {
                int Left = Box.ButtonLeft(i);
                X11.XDrawRectangle(Display, Window, Gc, Left, Box.ButtonsTop, (uint)Box.ButtonWidth - 1, (uint)Box.ButtonHeight - 1);
                if (i == Focus)
                    X11.XDrawRectangle(Display, Window, Gc, Left + 1, Box.ButtonsTop + 1, (uint)Box.ButtonWidth - 3, (uint)Box.ButtonHeight - 3);

                DrawText(Display, Window, Gc, Left + (Box.ButtonWidth - Box.CaptionWidths[i]) / 2, CaptionBaseline, Box.Captions[i]);
            }

            X11.XFlush(Display);
        }

        private static List<byte[]> Wrap(IntPtr Font, byte[] Text)
        {
            List<byte[]> Lines = new List<byte[]>();
            int Start = 0;
            while (Start <= Text.Length)
            {
                int Break = Array.IndexOf(Text, (byte)'\n', Start);
                int End = Break < 0 ? Text.Length : Break;
                WrapParagraph(Font, Text.AsSpan(Start, End - Start), Lines);
                if (Break < 0)
                    break;

                Start = Break + 1;
            }

            return Lines;
        }

        private static void WrapParagraph(IntPtr Font, ReadOnlySpan<byte> Paragraph, List<byte[]> Lines)
        {
            if (Paragraph.IsEmpty)
                Lines.Add(Array.Empty<byte>());

            while (Paragraph.Length > 0)
            {
                int Fit = Paragraph.Length;
                while (Fit > 1 && TextWidth(Font, Paragraph.Slice(0, Fit)) > MaxTextWidth)
                {
                    int Space = Paragraph.Slice(0, Fit - 1).LastIndexOf((byte)' ');
                    Fit = Space > 0 ? Space : Fit - 1;
                }

                Lines.Add(Paragraph.Slice(0, Fit).ToArray());
                Paragraph = Paragraph.Slice(Fit);
                while (Paragraph.Length > 0 && Paragraph[0] == (byte)' ')
                    Paragraph = Paragraph.Slice(1);
            }
        }

        private static unsafe int TextWidth(IntPtr Font, ReadOnlySpan<byte> Text)
        {
            fixed (byte* Bytes = Text)
                return X11.XTextWidth(Font, Bytes, Text.Length);
        }

        private static unsafe void DrawText(IntPtr Display, IntPtr Window, IntPtr Gc, int X, int Y, byte[] Text)
        {
            fixed (byte* Bytes = Text)
                X11.XDrawString(Display, Window, Gc, X, Y, Bytes, Text.Length);
        }

        private static unsafe void SetTitle(IntPtr Display, IntPtr Window, string Caption)
        {
            X11.XStoreName(Display, Window, Caption);

            byte[] Utf8 = Encoding.UTF8.GetBytes(Caption);
            IntPtr NetWmName = X11.XInternAtom(Display, "_NET_WM_NAME", 0);
            IntPtr Utf8String = X11.XInternAtom(Display, "UTF8_STRING", 0);
            fixed (byte* Bytes = Utf8)
                X11.XChangeProperty(Display, Window, NetWmName, Utf8String, 8, X11.PropModeReplace, (IntPtr)Bytes, Utf8.Length);
        }

        private static unsafe void SetDialogHints(IntPtr Display, IntPtr Window, int Width, int Height)
        {
            X11.XSizeHints Hints = new X11.XSizeHints
            {
                Flags = X11.PMinSize | X11.PMaxSize,
                MinWidth = Width,
                MinHeight = Height,
                MaxWidth = Width,
                MaxHeight = Height,
            };
            X11.XSetWMNormalHints(Display, Window, ref Hints);

            IntPtr* Atoms = stackalloc IntPtr[1];
            Atoms[0] = X11.XInternAtom(Display, "_NET_WM_WINDOW_TYPE_DIALOG", 0);
            X11.XChangeProperty(Display, Window, X11.XInternAtom(Display, "_NET_WM_WINDOW_TYPE", 0), (IntPtr)X11.XA_ATOM, 32,
                X11.PropModeReplace, (IntPtr)Atoms, 1);

            Atoms[0] = X11.XInternAtom(Display, "_NET_WM_STATE_ABOVE", 0);
            X11.XChangeProperty(Display, Window, X11.XInternAtom(Display, "_NET_WM_STATE", 0), (IntPtr)X11.XA_ATOM, 32,
                X11.PropModeReplace, (IntPtr)Atoms, 1);
        }
    }
}
