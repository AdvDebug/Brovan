using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Writev : ILinuxSyscall
    {
        private const int O_ACCMODE = 0x3;
        private const int O_RDONLY = 0x0;
        private const int O_APPEND = 0x400;
        private const int O_PATH = 0x200000;
        private const ulong MAX_RW_COUNT = 0x7ffff000;
        private const int UIO_MAXIOV = 1024;

        private struct IoVector
        {
            public ulong Base;
            public ulong Length;
            public ulong EffectiveLength;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            ulong iovAddress = Context.Arg1;
            ulong iovCountValue = Context.Arg2;

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(fd);
            if (Entry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (Entry.Object is SocketObject SocketDesc)
            {
                WriteSocketVectors(Instance, Helper, Context, SocketDesc, iovAddress, iovCountValue);
                return;
            }

            if (Entry.Object is not FileObject FObj)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if ((FObj.StatusFlags & O_ACCMODE) == O_RDONLY || (FObj.StatusFlags & O_PATH) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (FObj.IsReadOnlyMount)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EROFS);
                return;
            }

            if (FObj.IsDirectory)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EISDIR);
                return;
            }

            if (iovCountValue > UIO_MAXIOV)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            int IovCount = (int)iovCountValue;
            if (IovCount == 0)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            ulong IovElementSize = Context.Abi == SyscallAbi.X64 ? 16UL : 8UL;
            if (!TryMultiply(IovElementSize, (ulong)IovCount, out ulong IovTableSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (!Instance.IsRegionMapped(iovAddress, IovTableSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            IoVector[] Vectors = new IoVector[IovCount];
            ulong TotalLength = 0;

            for (int i = 0; i < IovCount; i++)
            {
                if (!TryReadIoVector(Instance, Context.Abi, iovAddress + ((ulong)i * IovElementSize), out IoVector Vector))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                ulong Remaining = MAX_RW_COUNT > TotalLength ? MAX_RW_COUNT - TotalLength : 0;
                if (Remaining != 0)
                {
                    Vector.EffectiveLength = Math.Min(Vector.Length, Remaining);
                    TotalLength += Vector.EffectiveLength;
                }
                else
                {
                    Vector.EffectiveLength = 0;
                }

                Vectors[i] = Vector;
            }

            if (TotalLength == 0)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if (FObj.IsSpecialPath)
            {
                WriteSpecialPath(Instance, Helper, Context, FObj, Vectors);
                return;
            }

            for (int i = 0; i < Vectors.Length; i++)
            {
                IoVector Vector = Vectors[i];
                if (Vector.EffectiveLength == 0)
                    continue;

                if (!Instance.IsRegionMapped(Vector.Base, Vector.EffectiveLength))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            try
            {
                long TotalWritten = 0;

                if (FObj.FileStream != null)
                {
                    if ((FObj.StatusFlags & O_APPEND) != 0)
                        FObj.FileStream.Position = FObj.FileStream.Length;
                    else
                        FObj.FileStream.Position = (long)FObj.Offset;

                    for (int i = 0; i < Vectors.Length; i++)
                    {
                        IoVector Vector = Vectors[i];
                        if (Vector.EffectiveLength == 0)
                            continue;

                        int ChunkLength = checked((int)Vector.EffectiveLength);
                        Span<byte> Transfer = Helper.Shared.GetSpan((ulong)ChunkLength);
                        if (!Instance.ReadMemory(Vector.Base, Transfer))
                        {
                            Helper.SetReturnValue(Instance, Context, TotalWritten == 0 ? -(long)LinuxErrno.EFAULT : TotalWritten);
                            return;
                        }

                        FObj.FileStream.Write(Transfer);
                        TotalWritten += ChunkLength;
                    }

                    FObj.Offset = (ulong)FObj.FileStream.Position;
                }
                else
                {
                    using FileStream Output = new FileStream(FObj.HostPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);

                    if ((FObj.StatusFlags & O_APPEND) != 0)
                        Output.Seek(0, SeekOrigin.End);
                    else
                        Output.Seek((long)FObj.Offset, SeekOrigin.Begin);

                    for (int i = 0; i < Vectors.Length; i++)
                    {
                        IoVector Vector = Vectors[i];
                        if (Vector.EffectiveLength == 0)
                            continue;

                        int ChunkLength = checked((int)Vector.EffectiveLength);
                        Span<byte> Transfer = Helper.Shared.GetSpan((ulong)ChunkLength);
                        if (!Instance.ReadMemory(Vector.Base, Transfer))
                        {
                            Helper.SetReturnValue(Instance, Context, TotalWritten == 0 ? -(long)LinuxErrno.EFAULT : TotalWritten);
                            return;
                        }

                        Output.Write(Transfer);
                        TotalWritten += ChunkLength;
                    }

                    Output.Flush();
                    FObj.Offset = (ulong)Output.Position;
                }

                Helper.SetReturnValue(Instance, Context, TotalWritten);
            }
            catch (UnauthorizedAccessException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
            }
            catch (DirectoryNotFoundException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
            }
            catch (FileNotFoundException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
            }
            catch (IOException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EIO);
            }
        }

        private static void WriteSocketVectors(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, SocketObject SocketDesc, ulong IovAddress, ulong IovCountValue)
        {
            if (IovCountValue > UIO_MAXIOV)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            int IovCount = (int)IovCountValue;
            if (IovCount == 0)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            ulong IovElementSize = Context.Abi == SyscallAbi.X64 ? 16UL : 8UL;
            if (!TryMultiply(IovElementSize, (ulong)IovCount, out ulong IovTableSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (!Instance.IsRegionMapped(IovAddress, IovTableSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            IoVector[] Vectors = new IoVector[IovCount];
            ulong TotalLength = 0;

            for (int i = 0; i < IovCount; i++)
            {
                if (!TryReadIoVector(Instance, Context.Abi, IovAddress + ((ulong)i * IovElementSize), out IoVector Vector))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                ulong Remaining = MAX_RW_COUNT > TotalLength ? MAX_RW_COUNT - TotalLength : 0;
                if (Remaining != 0)
                {
                    Vector.EffectiveLength = Math.Min(Vector.Length, Remaining);
                    TotalLength += Vector.EffectiveLength;
                }
                else
                {
                    Vector.EffectiveLength = 0;
                }

                Vectors[i] = Vector;
            }

            if (TotalLength == 0)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            for (int i = 0; i < Vectors.Length; i++)
            {
                IoVector Vector = Vectors[i];
                if (Vector.EffectiveLength == 0)
                    continue;

                if (!Instance.IsRegionMapped(Vector.Base, Vector.EffectiveLength))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            if (SocketDesc.NonBlocking && SocketHelpers.WouldBlock(SocketDesc, SelectMode.SelectWrite))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            if (!SocketHelpers.TryCheckSocketRemotePolicy(Instance, SocketDesc, true, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            long TotalSent = 0;

            try
            {
                for (int i = 0; i < Vectors.Length; i++)
                {
                    IoVector Vector = Vectors[i];
                    if (Vector.EffectiveLength == 0)
                        continue;

                    int ChunkLength = checked((int)Vector.EffectiveLength);
                    Span<byte> Transfer = Helper.Shared.GetSpan((ulong)ChunkLength);
                    if (!Instance.ReadMemory(Vector.Base, Transfer))
                    {
                        Helper.SetReturnValue(Instance, Context, TotalSent == 0 ? -(long)LinuxErrno.EFAULT : TotalSent);
                        return;
                    }

                    int Sent = SocketDesc.Handle.Send(Transfer, SocketFlags.None);
                    TotalSent += Sent;
                    if (Sent < ChunkLength)
                        break;
                }

                Helper.SetReturnValue(Instance, Context, TotalSent);
            }
            catch (SocketException Ex)
            {
                if (TotalSent != 0)
                {
                    Helper.SetReturnValue(Instance, Context, TotalSent);
                    return;
                }

                LinuxErrno TranslatedError = SocketHelpers.TranslateSocketError(Ex.SocketErrorCode);
                Helper.SetReturnValue(Instance, Context, -(long)TranslatedError);
            }
            catch (ObjectDisposedException)
            {
                Helper.SetReturnValue(Instance, Context, TotalSent == 0 ? -(long)LinuxErrno.EBADF : TotalSent);
            }
        }

        private static void WriteSpecialPath(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, FileObject FileDesc, IoVector[] Vectors)
        {
            long TotalWritten = 0;

            for (int i = 0; i < Vectors.Length; i++)
            {
                IoVector Vector = Vectors[i];
                if (Vector.EffectiveLength == 0)
                    continue;

                long Result;
                if (!Helper.SpecialPathsHandler.TryHandle(Instance, Helper, FileDesc, Vector.Base, Vector.EffectiveLength, true, out Result))
                {
                    Instance.TriggerEventMessage($"[!] Special path handler not set for {FileDesc.Path}.", LogFlags.Important);
                    Helper.SetReturnValue(Instance, Context, TotalWritten == 0 ? -(long)LinuxErrno.ENODEV : TotalWritten);
                    return;
                }

                if (Result < 0)
                {
                    Helper.SetReturnValue(Instance, Context, TotalWritten == 0 ? Result : TotalWritten);
                    return;
                }

                TotalWritten += Result;
                if ((ulong)Result < Vector.EffectiveLength)
                {
                    Helper.SetReturnValue(Instance, Context, TotalWritten);
                    return;
                }
            }

            Helper.SetReturnValue(Instance, Context, TotalWritten);
        }

        private static bool TryReadIoVector(BinaryEmulator Instance, SyscallAbi Abi, ulong Address, out IoVector Vector)
        {
            Vector = default;

            if (Abi == SyscallAbi.X64)
            {
                if (!Instance.IsRegionMapped(Address, 16))
                    return false;

                Span<byte> Data = stackalloc byte[16];
                if (!Instance.ReadMemory(Address, Data))
                    return false;

                Vector.Base = BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(0, 8));
                Vector.Length = BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(8, 8));
                return true;
            }

            if (!Instance.IsRegionMapped(Address, 8))
                return false;

            Span<byte> CompatData = stackalloc byte[8];
            if (!Instance.ReadMemory(Address, CompatData))
                return false;

            Vector.Base = BinaryPrimitives.ReadUInt32LittleEndian(CompatData.Slice(0, 4));
            Vector.Length = BinaryPrimitives.ReadUInt32LittleEndian(CompatData.Slice(4, 4));
            return true;
        }

        private static bool TryMultiply(ulong Left, ulong Right, out ulong Result)
        {
            Result = 0;
            if (Left == 0 || Right == 0)
                return true;

            if (Left > ulong.MaxValue / Right)
                return false;

            Result = Left * Right;
            return true;
        }
    }
}
