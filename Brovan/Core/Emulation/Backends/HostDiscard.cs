using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation
{
    // A backend discards in the same step where it frees whole blocks.
    internal static class HostDiscard
    {
        private const uint MemDecommit = 0x4000;
        private const int MadvDontNeed = 4;

        internal static readonly bool Disabled = Environment.GetEnvironmentVariable("BROVAN_NO_HOST_MEM_DISCARD") == "1";

        internal static bool Release(IntPtr Start, ulong Size)
        {
            bool Released = GeneralHelper.IsWindows
                ? NativeWinImports.VirtualFree(Start, (UIntPtr)Size, MemDecommit)
                : NativeUnixImports.Madvise(Start, (UIntPtr)Size, MadvDontNeed) == 0;
            if (!Released)
                Utils.LogError($"[HostDiscard] Discard of 0x{Size:X} host bytes at 0x{Start.ToInt64():X} failed with {Marshal.GetLastWin32Error()}.");
            return Released;
        }

        // Makes committed memory read zero while another thread may still copy through it. A decommit would fault that
        // thread on Windows, so Windows clears in place, which makes untouched pages resident; MADV_DONTNEED faults nothing.
        internal static unsafe bool ZeroUnderReaders(IntPtr Start, ulong Size)
        {
            if (!GeneralHelper.IsWindows)
                return Release(Start, Size);

            byte* Cursor = (byte*)Start;
            for (ulong Left = Size; Left != 0;)
            {
                int Chunk = (int)Math.Min(Left, 1UL << 30);
                new Span<byte>(Cursor, Chunk).Clear();
                Cursor += Chunk;
                Left -= (ulong)Chunk;
            }
            return true;
        }
    }

    internal sealed class HostDiscardRuns
    {
        internal struct Run
        {
            public IntPtr Key;
            public IntPtr Start;
            public ulong Size;
        }

        private readonly List<Run> _runs = new();

        internal int Count => _runs.Count;

        internal Run this[int index] => _runs[index];

        internal void Add(IntPtr key, IntPtr start, ulong size)
        {
            if (_runs.Count != 0 && _runs[^1].Key == key)
            {
                Run last = _runs[^1];
                if ((ulong)last.Start + last.Size == (ulong)start)
                {
                    last.Size += size;
                    _runs[^1] = last;
                    return;
                }

                if ((ulong)start + size == (ulong)last.Start)
                {
                    last.Start = start;
                    last.Size += size;
                    _runs[^1] = last;
                    return;
                }
            }

            _runs.Add(new Run { Key = key, Start = start, Size = size });
        }

        // The parts of a run before and after [start, start + size); either can be empty.
        private static bool TrySplit(in Run run, IntPtr start, ulong size, out Run head, out Run tail)
        {
            ulong runStart = (ulong)run.Start;
            ulong runEnd = runStart + run.Size;
            ulong cutStart = (ulong)start;
            ulong cutEnd = cutStart + size;
            head = default;
            tail = default;
            if (cutStart >= runEnd || cutEnd <= runStart)
                return false;

            if (cutStart > runStart)
                head = new Run { Key = run.Key, Start = run.Start, Size = cutStart - runStart };
            if (cutEnd < runEnd)
                tail = new Run { Key = run.Key, Start = (IntPtr)(long)cutEnd, Size = runEnd - cutEnd };
            return true;
        }

        // Returns the bytes that left the runs.
        internal ulong Withdraw(IntPtr key, IntPtr start, ulong size)
        {
            ulong gone = 0;
            for (int i = 0; i < _runs.Count; i++)
            {
                if (_runs[i].Key != key || !TrySplit(_runs[i], start, size, out Run head, out Run tail))
                    continue;

                gone += _runs[i].Size - head.Size - tail.Size;
                if (tail.Size != 0)
                    _runs.Add(tail);
                if (head.Size != 0)
                    _runs[i] = head;
                else
                    _runs.RemoveAt(i--);
            }
            return gone;
        }

        internal void Remove(IntPtr key)
        {
            int kept = 0;
            for (int i = 0; i < _runs.Count; i++)
            {
                if (_runs[i].Key != key)
                    _runs[kept++] = _runs[i];
            }

            _runs.RemoveRange(kept, _runs.Count - kept);
        }

        internal void Clear() => _runs.Clear();
    }
}
