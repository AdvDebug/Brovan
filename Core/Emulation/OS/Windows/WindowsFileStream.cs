using System;
using System.IO;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Provides overlay-backed Windows file IO where writes always materialize into the Windows VFS and reads prefer the VFS before falling back to an allowed host file.
    /// </summary>
    public sealed class WindowsFileStream : Stream
    {
        private const int CopyBufferSize = 81920;

        private long PositionValue;

        public string GuestPath { get; }
        public string ReadHostPath { get; }
        public string WriteHostPath { get; }

        public WindowsFileStream(string GuestPath, string ReadHostPath, string WriteHostPath)
        {
            this.GuestPath = GuestPath ?? string.Empty;
            this.ReadHostPath = ReadHostPath ?? string.Empty;
            this.WriteHostPath = WriteHostPath ?? string.Empty;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => true;

        public override long Length
        {
            get
            {
                string HostPath = EffectiveReadHostPath;
                if (string.IsNullOrWhiteSpace(HostPath) || !File.Exists(HostPath))
                    return 0;

                return new FileInfo(HostPath).Length;
            }
        }

        public override long Position
        {
            get => PositionValue;
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(value));

                PositionValue = value;
            }
        }

        public string EffectiveReadHostPath
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(WriteHostPath) && (File.Exists(WriteHostPath) || Directory.Exists(WriteHostPath)))
                    return WriteHostPath;

                return ReadHostPath;
            }
        }

        public bool ExistsAsFile
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(WriteHostPath) && File.Exists(WriteHostPath))
                    return true;

                if (!string.IsNullOrWhiteSpace(WriteHostPath) && Directory.Exists(WriteHostPath))
                    return false;

                return !string.IsNullOrWhiteSpace(ReadHostPath) && File.Exists(ReadHostPath);
            }
        }

        public bool ExistsAsDirectory
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(WriteHostPath) && Directory.Exists(WriteHostPath))
                    return true;

                if (!string.IsNullOrWhiteSpace(WriteHostPath) && File.Exists(WriteHostPath))
                    return false;

                return !string.IsNullOrWhiteSpace(ReadHostPath) && Directory.Exists(ReadHostPath);
            }
        }

        public static WindowsFileStream FromGuestPath(string GuestPath, bool CreateWriteDirectories = false)
        {
            string ReadHostPath = GeneralHelper.IO.ResolveHostPath(GuestPath, BinaryFormat.PE);
            string WriteHostPath = GeneralHelper.IO.ResolveVirtualHostPath(GuestPath, BinaryFormat.PE, CreateWriteDirectories);
            return new WindowsFileStream(GuestPath, ReadHostPath, WriteHostPath);
        }

        public byte[] ReadAllBytes()
        {
            string HostPath = GetReadableFilePath();
            return File.ReadAllBytes(HostPath);
        }

        public void WriteAllBytes(byte[] Data)
        {
            ValidateBuffer(Data, 0, Data.Length);
            EnsureWriteStore(false);

            using FileStream Stream = new FileStream(WriteHostPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            if (Data.Length != 0)
                Stream.Write(Data, 0, Data.Length);

            Stream.Flush();
            PositionValue = Data.Length;
        }

        public bool TryReadAllBytes(out byte[] Data)
        {
            try
            {
                Data = ReadAllBytes();
                return true;
            }
            catch
            {
                Data = null;
                return false;
            }
        }

        public override void Flush()
        {
            if (string.IsNullOrWhiteSpace(WriteHostPath) || !File.Exists(WriteHostPath))
                return;

            using FileStream Stream = new FileStream(WriteHostPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            Stream.Flush(true);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int BytesRead = ReadAt(PositionValue, buffer, offset, count);
            PositionValue += BytesRead;
            return BytesRead;
        }

        public int ReadAt(long position, byte[] buffer, int offset, int count)
        {
            if (position < 0)
                throw new ArgumentOutOfRangeException(nameof(position));

            ValidateBuffer(buffer, offset, count);
            return ReadAt(position, buffer.AsSpan(offset, count));
        }

        public int ReadAt(long position, Span<byte> buffer)
        {
            if (position < 0)
                throw new ArgumentOutOfRangeException(nameof(position));

            string HostPath = GetReadableFilePath();
            using FileStream Stream = new FileStream(HostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (position >= Stream.Length)
                return 0;

            Stream.Seek(position, SeekOrigin.Begin);
            return Stream.Read(buffer);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteAt(PositionValue, buffer, offset, count);
            PositionValue += count;
        }

        public void WriteAt(long position, byte[] buffer, int offset, int count)
        {
            if (position < 0)
                throw new ArgumentOutOfRangeException(nameof(position));

            ValidateBuffer(buffer, offset, count);
            WriteAt(position, buffer.AsSpan(offset, count));
        }

        public void WriteAt(long position, ReadOnlySpan<byte> buffer)
        {
            if (position < 0)
                throw new ArgumentOutOfRangeException(nameof(position));

            EnsureWriteStore(true);

            using FileStream Stream = new FileStream(WriteHostPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            Stream.Seek(position, SeekOrigin.Begin);
            Stream.Write(buffer);
            Stream.Flush();
        }

        public void WriteAppend(byte[] buffer, int offset, int count)
        {
            ValidateBuffer(buffer, offset, count);
            EnsureWriteStore(true);

            using FileStream Stream = new FileStream(WriteHostPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            Stream.Seek(0, SeekOrigin.End);
            Stream.Write(buffer, offset, count);
            Stream.Flush();
            PositionValue = Stream.Position;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long BaseOffset = origin switch
            {
                SeekOrigin.Begin => 0,
                SeekOrigin.Current => PositionValue,
                SeekOrigin.End => Length,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };

            long NewPosition = checked(BaseOffset + offset);
            if (NewPosition < 0)
                throw new IOException("Negative seek offset.");

            PositionValue = NewPosition;
            return PositionValue;
        }

        public override void SetLength(long value)
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(value));

            EnsureWriteStore(true);
            using FileStream Stream = new FileStream(WriteHostPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            Stream.SetLength(value);

            if (PositionValue > value)
                PositionValue = value;
        }

        public void Truncate()
        {
            EnsureWriteParentExists();
            using FileStream Stream = new FileStream(WriteHostPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            Stream.SetLength(0);
            PositionValue = 0;
        }

        public void CreateDirectory()
        {
            if (string.IsNullOrWhiteSpace(WriteHostPath))
                throw new UnauthorizedAccessException("No Windows VFS write path is available.");

            if (File.Exists(WriteHostPath))
                throw new IOException("The Windows VFS write path is a file.");

            Directory.CreateDirectory(WriteHostPath);
        }

        private string GetReadableFilePath()
        {
            string HostPath = EffectiveReadHostPath;
            if (string.IsNullOrWhiteSpace(HostPath) || !File.Exists(HostPath))
                throw new FileNotFoundException(GuestPath);

            return HostPath;
        }

        private void EnsureWriteStore(bool CopyExisting)
        {
            if (string.IsNullOrWhiteSpace(WriteHostPath))
                throw new UnauthorizedAccessException("No Windows VFS write path is available.");

            if (File.Exists(WriteHostPath))
                return;

            if (Directory.Exists(WriteHostPath))
                throw new UnauthorizedAccessException("The Windows VFS write path is a directory.");

            EnsureWriteParentExists();

            if (CopyExisting && !IsSamePath(ReadHostPath, WriteHostPath) && !string.IsNullOrWhiteSpace(ReadHostPath) && File.Exists(ReadHostPath))
            {
                using FileStream Source = new FileStream(ReadHostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using FileStream Destination = new FileStream(WriteHostPath, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                Source.CopyTo(Destination, CopyBufferSize);
                return;
            }

            using FileStream Stream = new FileStream(WriteHostPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        }

        private void EnsureWriteParentExists()
        {
            string Parent = Path.GetDirectoryName(WriteHostPath);
            if (string.IsNullOrEmpty(Parent))
                throw new DirectoryNotFoundException(WriteHostPath);

            Directory.CreateDirectory(Parent);
        }

        private static void ValidateBuffer(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            if (offset < 0 || count < 0 || offset > buffer.Length - count)
                throw new ArgumentOutOfRangeException();
        }

        private static bool IsSamePath(string A, string B)
        {
            if (string.IsNullOrWhiteSpace(A) || string.IsNullOrWhiteSpace(B))
                return false;

            try
            {
                string FullA = Path.GetFullPath(A);
                string FullB = Path.GetFullPath(B);
                return string.Equals(FullA, FullB, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            }
            catch
            {
                return string.Equals(A, B, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            }
        }
    }
}
