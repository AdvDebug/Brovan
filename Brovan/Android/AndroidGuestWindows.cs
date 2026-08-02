using System;
using System.Collections.Generic;
using System.Threading;
using Brovan.Core.Emulation.OS.Windows;

namespace Brovan.Android
{
    internal readonly struct GuestWindowInfo
    {
        public GuestWindowInfo(ulong hwnd, string title, string className, int width, int height, bool visible)
        {
            Hwnd = hwnd;
            Title = title;
            ClassName = className;
            Width = width;
            Height = height;
            Visible = visible;
        }

        public ulong Hwnd { get; }

        public string Title { get; }

        public string ClassName { get; }

        public int Width { get; }

        public int Height { get; }

        public bool Visible { get; }
    }

    internal static class AndroidGuestWindows
    {
        private static ulong _selected;

        public static ulong Selected => Volatile.Read(ref _selected);

        public static void Select(ulong hwnd)
        {
            Volatile.Write(ref _selected, hwnd);
        }

        public static List<GuestWindowInfo> Enumerate()
        {
            List<GuestWindowInfo> windows = new List<GuestWindowInfo>();

            WinSysHelper helper = Variables.Emulator?.WinHelper;
            if (helper == null)
                return windows;

            // The guest owns this list from its own threads; a snapshot can tear while a window is being
            // created or destroyed, and an inspector must never be the thing that crashes the emulator.
            try
            {
                foreach (ulong hwnd in helper.TopLevelWindows.ToArray())
                {
                    WinWindow window = helper.GetWindow(hwnd);
                    if (window == null || window.Destroyed)
                        continue;

                    windows.Add(new GuestWindowInfo(
                        window.Hwnd,
                        string.IsNullOrEmpty(window.Title) ? window.ClassName ?? string.Empty : window.Title,
                        window.ClassName ?? string.Empty,
                        (int)window.Width,
                        (int)window.Height,
                        window.Visible));
                }
            }
            catch (Exception exception)
            {
                AndroidLog.Write(AndroidNative.LogWarn, $"[brovan] Window enumeration failed: {exception.Message}");
            }

            return windows;
        }
    }
}
