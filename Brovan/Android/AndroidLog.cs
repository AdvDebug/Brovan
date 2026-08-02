using System;
using System.Buffers;
using System.IO;
using System.Text;
using System.Threading;

namespace Brovan.Android
{
    internal static class AndroidLog
    {
        private const string Tag = "Brovan";

        private static IntPtr _sink;

        public static void SetSink(IntPtr sink)
        {
            Volatile.Write(ref _sink, sink);
        }

        public static unsafe void Write(int priority, string line)
        {
            if (string.IsNullOrEmpty(line))
                return;

            try
            {
                AndroidNative.LogWrite(priority, Tag, line);
            }
            catch (DllNotFoundException)
            {
            }
            catch (EntryPointNotFoundException)
            {
            }

            IntPtr sink = Volatile.Read(ref _sink);
            if (sink == IntPtr.Zero)
                return;

            int capacity = Encoding.UTF8.GetMaxByteCount(line.Length) + 1;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(capacity);
            try
            {
                int written = Encoding.UTF8.GetBytes(line, buffer);
                buffer[written] = 0;

                fixed (byte* text = buffer)
                    ((delegate* unmanaged<byte*, void>)sink)(text);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public static unsafe void RedirectStandardStreams()
        {
            int* descriptors = stackalloc int[2];
            if (AndroidNative.Pipe(descriptors) != 0)
                return;

            int readEnd = descriptors[0];
            if (AndroidNative.Dup2(descriptors[1], 1) < 0 || AndroidNative.Dup2(descriptors[1], 2) < 0)
                return;

            Thread pump = new Thread(() => Pump(readEnd))
            {
                IsBackground = true,
                Name = "BrovanStdioLog",
            };

            pump.Start();
        }

        private static unsafe void Pump(int readEnd)
        {
            byte[] buffer = new byte[4096];
            StringBuilder line = new StringBuilder();

            while (true)
            {
                nint read;
                fixed (byte* target = buffer)
                    read = Core.Emulation.OS.SharedHelpers.Posix.Read(readEnd, target, (nuint)buffer.Length);

                if (read <= 0)
                    return;

                for (int i = 0; i < read; i++)
                {
                    char value = (char)buffer[i];
                    if (value == '\r')
                        continue;

                    if (value != '\n')
                    {
                        line.Append(value);
                        continue;
                    }

                    Write(AndroidNative.LogInfo, line.ToString());
                    line.Clear();
                }
            }
        }
    }

    internal sealed class AndroidLogWriter : TextWriter
    {
        private const int MaximumLineLength = 4000;

        private readonly int _priority;
        private readonly StringBuilder _pending = new();

        public AndroidLogWriter(int priority)
        {
            _priority = priority;
        }

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(char value)
        {
            lock (_pending)
                AppendLocked(value);
        }

        public override void Write(string value)
        {
            if (string.IsNullOrEmpty(value))
                return;

            lock (_pending)
            {
                for (int i = 0; i < value.Length; i++)
                    AppendLocked(value[i]);
            }
        }

        public override void WriteLine(string value)
        {
            Write(value);
            Write('\n');
        }

        public override void Flush()
        {
            lock (_pending)
                EmitLocked();
        }

        private void AppendLocked(char value)
        {
            if (value == '\r')
                return;

            if (value != '\n')
            {
                _pending.Append(value);
                if (_pending.Length < MaximumLineLength)
                    return;
            }

            EmitLocked();
        }

        private void EmitLocked()
        {
            if (_pending.Length == 0)
                return;

            AndroidLog.Write(_priority, _pending.ToString());
            _pending.Clear();
        }
    }
}
