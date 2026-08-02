using System;
using System.Runtime.InteropServices;

namespace Brovan.Android
{
    internal static partial class AndroidNative
    {
        public const int LogInfo = 4;
        public const int LogWarn = 5;
        public const int LogError = 6;

        [LibraryImport("libandroid.so", EntryPoint = "ANativeWindow_acquire")]
        public static partial void NativeWindowAcquire(IntPtr window);

        [LibraryImport("libandroid.so", EntryPoint = "ANativeWindow_release")]
        public static partial void NativeWindowRelease(IntPtr window);

        [LibraryImport("libandroid.so", EntryPoint = "ANativeWindow_getWidth")]
        public static partial int NativeWindowGetWidth(IntPtr window);

        [LibraryImport("libandroid.so", EntryPoint = "ANativeWindow_getHeight")]
        public static partial int NativeWindowGetHeight(IntPtr window);

        public const int WindowFormatRgba8888 = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct NativeWindowBuffer
        {
            public int Width;
            public int Height;
            public int Stride;
            public int Format;
            public IntPtr Bits;
            public uint Reserved0;
            public uint Reserved1;
            public uint Reserved2;
            public uint Reserved3;
            public uint Reserved4;
            public uint Reserved5;
        }

        [LibraryImport("libandroid.so", EntryPoint = "ANativeWindow_setBuffersGeometry")]
        public static partial int NativeWindowSetBuffersGeometry(IntPtr window, int width, int height, int format);

        [LibraryImport("libandroid.so", EntryPoint = "ANativeWindow_lock")]
        public static unsafe partial int NativeWindowLock(IntPtr window, NativeWindowBuffer* buffer, IntPtr dirtyBounds);

        [LibraryImport("libandroid.so", EntryPoint = "ANativeWindow_unlockAndPost")]
        public static partial int NativeWindowUnlockAndPost(IntPtr window);

        [LibraryImport("liblog.so", EntryPoint = "__android_log_write", StringMarshalling = StringMarshalling.Utf8)]
        public static partial int LogWrite(int priority, string tag, string text);

        [LibraryImport("libc", EntryPoint = "pipe", SetLastError = true)]
        public static unsafe partial int Pipe(int* fds);

        [LibraryImport("libc", EntryPoint = "dup2", SetLastError = true)]
        public static partial int Dup2(int oldFd, int newFd);

        [LibraryImport("libc", EntryPoint = "realpath", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
        public static partial IntPtr RealPath(string path, IntPtr resolved);

        [LibraryImport("libc", EntryPoint = "free")]
        public static partial void Free(IntPtr pointer);
    }
}
