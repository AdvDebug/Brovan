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

        internal static void Release(IntPtr Start, ulong Size)
        {
            bool Released = GeneralHelper.IsWindows
                ? NativeWinImports.VirtualFree(Start, (UIntPtr)Size, MemDecommit)
                : NativeUnixImports.Madvise(Start, (UIntPtr)Size, MadvDontNeed) == 0;
            if (!Released)
                Utils.LogError($"[HostDiscard] Discard of 0x{Size:X} host bytes at 0x{Start.ToInt64():X} failed with {Marshal.GetLastWin32Error()}.");
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
