using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows
{
    // A wait with a timeout runs on a host thread in chunks, and the parked guest reruns the syscall after each one.
    internal sealed unsafe class BrovVulkWaits
    {
        internal const int MaxWaitObjects = 64;

        private const long ChunkMilliseconds = 50;
        private const ulong ChunkNanoseconds = (ulong)ChunkMilliseconds * 1_000_000;
        private const int WaitThreadStackBytes = 256 * 1024;

        internal static readonly bool Disabled =
            string.Equals(Environment.GetEnvironmentVariable("BROVVULK_NO_PARKED_WAIT"), "1", StringComparison.Ordinal);

        internal abstract class Call
        {
            internal IntPtr Device;
            internal uint DeviceId;
            internal ulong Timeout;
            internal long Deadline;
            internal int Result;
            internal bool Finished;
            internal WakeSignal Wake;
            internal TaskCompletionSource<Call> Done;
            internal WaitThread Thread;
            internal readonly List<(IntPtr Handle, string Type)> Pins = new List<(IntPtr, string)>();

            protected Call(GenState st, IntPtr device)
            {
                Device = device;
                DeviceId = st.IdOf(device, "VkDevice");
            }

            internal abstract int ScratchBytes { get; }

            // Runs on a waiter thread without BrovVulkDevice.Lock, so it reads only the call's own copies.
            internal abstract int Run(IntPtr scratch, ulong timeoutNs);

            internal abstract void AddWaitedHandles(List<(IntPtr Handle, string Type)> pins);
        }

        private sealed class FenceCall : Call
        {
            private readonly IntPtr[] _fences;
            private readonly uint[] _fenceIds;
            private readonly uint _waitAll;

            internal FenceCall(GenState st, IntPtr device, uint count, IntPtr pFences, uint waitAll) : base(st, device)
            {
                _fences = new IntPtr[count];
                _fenceIds = new uint[count];
                for (int i = 0; i < _fences.Length; i++)
                {
                    _fences[i] = *(IntPtr*)(pFences + i * 8);
                    _fenceIds[i] = st.IdOf(_fences[i], "VkFence");
                }

                _waitAll = waitAll;
            }

            internal bool Matches(GenState st, IntPtr device, uint count, IntPtr pFences, uint waitAll, ulong timeout)
            {
                if (st.IdOf(device, "VkDevice") != DeviceId || count != (uint)_fences.Length || waitAll != _waitAll || timeout != Timeout)
                    return false;

                for (int i = 0; i < _fences.Length; i++)
                {
                    if (st.IdOf(*(IntPtr*)(pFences + i * 8), "VkFence") != _fenceIds[i])
                        return false;
                }

                return true;
            }

            internal override int ScratchBytes => _fences.Length * 8;

            internal override int Run(IntPtr scratch, ulong timeoutNs)
            {
                for (int i = 0; i < _fences.Length; i++)
                    *(IntPtr*)(scratch + i * 8) = _fences[i];

                return BrovVulkApi.vkWaitForFences(Device, (uint)_fences.Length, scratch, _waitAll, timeoutNs);
            }

            internal override void AddWaitedHandles(List<(IntPtr Handle, string Type)> pins)
            {
                foreach (IntPtr fence in _fences)
                    pins.Add((fence, "VkFence"));
            }
        }

        private sealed class SemaphoreCall : Call
        {
            private static readonly int InfoBytes = (BrovVulkLayout.StructSize["VkSemaphoreWaitInfo"] + 7) & ~7;
            private static readonly int NextOffset = BrovVulkLayout.MemberOffset["VkSemaphoreWaitInfo.pNext"];
            private static readonly int FlagsOffset = BrovVulkLayout.MemberOffset["VkSemaphoreWaitInfo.flags"];
            private static readonly int CountOffset = BrovVulkLayout.MemberOffset["VkSemaphoreWaitInfo.semaphoreCount"];
            private static readonly int SemaphoresOffset = BrovVulkLayout.MemberOffset["VkSemaphoreWaitInfo.pSemaphores"];
            private static readonly int ValuesOffset = BrovVulkLayout.MemberOffset["VkSemaphoreWaitInfo.pValues"];

            private readonly uint _sType;
            private readonly uint _flags;
            private readonly IntPtr[] _semaphores;
            private readonly uint[] _semaphoreIds;
            private readonly ulong[] _values;

            internal SemaphoreCall(GenState st, IntPtr device, IntPtr info) : base(st, device)
            {
                _sType = *(uint*)info;
                _flags = *(uint*)(info + FlagsOffset);
                uint count = *(uint*)(info + CountOffset);
                IntPtr semaphores = *(IntPtr*)(info + SemaphoresOffset);
                IntPtr values = *(IntPtr*)(info + ValuesOffset);

                _semaphores = new IntPtr[count];
                _semaphoreIds = new uint[count];
                _values = new ulong[count];
                for (int i = 0; i < _semaphores.Length; i++)
                {
                    _semaphores[i] = *(IntPtr*)(semaphores + i * 8);
                    _semaphoreIds[i] = st.IdOf(_semaphores[i], "VkSemaphore");
                    _values[i] = *(ulong*)(values + i * 8);
                }
            }

            internal static bool CanCopy(IntPtr info, out uint count)
            {
                count = 0;
                if (info == IntPtr.Zero || *(IntPtr*)(info + NextOffset) != IntPtr.Zero)
                    return false;

                count = *(uint*)(info + CountOffset);
                return *(IntPtr*)(info + SemaphoresOffset) != IntPtr.Zero && *(IntPtr*)(info + ValuesOffset) != IntPtr.Zero;
            }

            internal bool Matches(GenState st, IntPtr device, IntPtr info, ulong timeout)
            {
                if (info == IntPtr.Zero || st.IdOf(device, "VkDevice") != DeviceId || timeout != Timeout || *(uint*)(info + FlagsOffset) != _flags
                    || *(uint*)(info + CountOffset) != (uint)_semaphores.Length)
                    return false;

                IntPtr semaphores = *(IntPtr*)(info + SemaphoresOffset);
                IntPtr values = *(IntPtr*)(info + ValuesOffset);
                for (int i = 0; i < _semaphores.Length; i++)
                {
                    if (st.IdOf(*(IntPtr*)(semaphores + i * 8), "VkSemaphore") != _semaphoreIds[i] || *(ulong*)(values + i * 8) != _values[i])
                        return false;
                }

                return true;
            }

            internal override int ScratchBytes => InfoBytes + _semaphores.Length * 16;

            internal override int Run(IntPtr scratch, ulong timeoutNs)
            {
                IntPtr semaphores = scratch + InfoBytes;
                IntPtr values = semaphores + _semaphores.Length * 8;
                new Span<byte>((void*)scratch, InfoBytes).Clear();
                *(uint*)scratch = _sType;
                *(uint*)(scratch + FlagsOffset) = _flags;
                *(uint*)(scratch + CountOffset) = (uint)_semaphores.Length;
                *(IntPtr*)(scratch + SemaphoresOffset) = semaphores;
                *(IntPtr*)(scratch + ValuesOffset) = values;
                for (int i = 0; i < _semaphores.Length; i++)
                {
                    *(IntPtr*)(semaphores + i * 8) = _semaphores[i];
                    *(ulong*)(values + i * 8) = _values[i];
                }

                return BrovVulkApi.vkWaitSemaphores(Device, scratch, timeoutNs);
            }

            internal override void AddWaitedHandles(List<(IntPtr Handle, string Type)> pins)
            {
                foreach (IntPtr semaphore in _semaphores)
                    pins.Add((semaphore, "VkSemaphore"));
            }
        }

        internal sealed class WaitThread
        {
            internal readonly SemaphoreSlim Go = new SemaphoreSlim(0);
            internal Call Call;
            internal bool Running;
        }

        private readonly struct DeferredDestroy
        {
            public readonly uint Command;
            public readonly string Type;
            public readonly IntPtr Parent;
            public readonly IntPtr Handle;

            public DeferredDestroy(uint command, string type, IntPtr parent, IntPtr handle)
            {
                Command = command;
                Type = type;
                Parent = parent;
                Handle = handle;
            }
        }

        private readonly object _lock = new object();
        private readonly Dictionary<(IntPtr Handle, string Type), int> _pins = new Dictionary<(IntPtr, string), int>();
        private readonly List<DeferredDestroy> _deferred = new List<DeferredDestroy>();
        private readonly List<WaitThread> _threads = new List<WaitThread>();
        private readonly Stack<WaitThread> _idle = new Stack<WaitThread>();
        private int _pinnedHandles;

        // These fields hold the state of the current command and are used only under BrovVulkDevice.Lock.
        private bool _canPark;
        private Task _rerun;
        private Call _parked;

        internal bool Waited { get; private set; }

        internal void BeginCommand(bool canPark, Task rerun)
        {
            _canPark = canPark;
            _rerun = rerun;
            _parked = null;
            Waited = false;
        }

        internal Call TakeParked()
        {
            Call parked = _parked;
            _parked = null;
            return parked;
        }

        internal void EndCommand()
        {
            Call left = _parked;
            _canPark = false;
            _rerun = null;
            _parked = null;
            Waited = false;
            if (left != null)
                Release(left);
        }

        internal static int WaitForFences(GenState st, IGuestMemory inst, IntPtr device, uint fenceCount, IntPtr pFences, uint waitAll, ulong timeout)
        {
            BrovVulkWaits waits = st.Waits;
            if (waits.TakeRerun() is FenceCall resumed && resumed.Matches(st, device, fenceCount, pFences, waitAll, timeout))
                return waits.Resume(st, resumed);

            int rr = BrovVulkApi.vkWaitForFences(device, fenceCount, pFences, waitAll, 0);
            if (rr != BrovVulkConstants.VK_TIMEOUT || timeout == 0 || !waits.CanWait(fenceCount))
                return rr;

            return waits.Park(st, new FenceCall(st, device, fenceCount, pFences, waitAll), timeout, rr);
        }

        internal static int WaitSemaphores(GenState st, IGuestMemory inst, IntPtr device, IntPtr pWaitInfo, ulong timeout)
        {
            if (pWaitInfo == IntPtr.Zero)
                return BrovVulkConstants.VK_ERROR_INITIALIZATION_FAILED;

            BrovVulkWaits waits = st.Waits;
            if (waits.TakeRerun() is SemaphoreCall resumed && resumed.Matches(st, device, pWaitInfo, timeout))
                return waits.Resume(st, resumed);

            int rr = BrovVulkApi.vkWaitSemaphores(device, pWaitInfo, 0);
            if (rr != BrovVulkConstants.VK_TIMEOUT || timeout == 0)
                return rr;

            if (!SemaphoreCall.CanCopy(pWaitInfo, out uint count))
            {
                Stats.Fallback(FallbackReason.Chain);
                return rr;
            }

            if (!waits.CanWait(count))
                return rr;

            return waits.Park(st, new SemaphoreCall(st, device, pWaitInfo), timeout, rr);
        }

        internal Call TakeRerun()
        {
            Task rerun = _rerun;
            _rerun = null;
            return rerun is Task<Call> { IsCompletedSuccessfully: true } done ? done.Result : null;
        }

        internal bool CanWait(uint count)
        {
            if (!_canPark)
            {
                Stats.Fallback(Disabled ? FallbackReason.Off : FallbackReason.NoPark);
                return false;
            }

            if (count == 0 || count > MaxWaitObjects)
            {
                Stats.Fallback(FallbackReason.TooMany);
                return false;
            }

            return true;
        }

        internal int Park(GenState st, Call call, ulong timeout, int poll)
        {
            call.Timeout = timeout;
            call.Deadline = DeadlineAfter(timeout);
            return Arm(st, call, poll);
        }

        internal int Resume(GenState st, Call call)
        {
            if (call.Finished)
            {
                Stats.Consume();
                Waited = call.Result == BrovVulkConstants.VK_TIMEOUT;
                return call.Result;
            }

            if (Stopwatch.GetTimestamp() >= call.Deadline)
            {
                Stats.Consume();
                Waited = true;
                return BrovVulkConstants.VK_TIMEOUT;
            }

            if (!_canPark)
            {
                Stats.Fallback(Disabled ? FallbackReason.Off : FallbackReason.NoPark);
                return BrovVulkConstants.VK_TIMEOUT;
            }

            Stats.Rearm();
            return Arm(st, call, BrovVulkConstants.VK_TIMEOUT);
        }

        private int Arm(GenState st, Call call, int poll)
        {
            if (call.Pins.Count == 0)
            {
                call.AddWaitedHandles(call.Pins);
                call.Pins.Add((call.Device, "VkDevice"));
                IntPtr instance = st.InstanceOfDevice(call.Device);
                if (instance != IntPtr.Zero)
                    call.Pins.Add((instance, "VkInstance"));
            }

            lock (_lock)
            {
                WaitThread thread = ReserveThread();
                if (thread == null)
                {
                    Stats.Fallback(FallbackReason.NoThread);
                    return poll;
                }

                call.Finished = false;
                call.Result = 0;
                call.Done = new TaskCompletionSource<Call>();
                call.Thread = thread;
                thread.Call = call;
                Pin(call);
            }

            _parked = call;
            Stats.Park();
            return poll;
        }

        internal void Start(Call call, WakeSignal wake)
        {
            call.Wake = wake;
            lock (_lock)
                call.Thread.Running = true;
            call.Thread.Go.Release();
        }

        internal void Release(Call call)
        {
            List<DeferredDestroy> due;
            lock (_lock)
            {
                WaitThread thread = call.Thread;
                if (thread == null || thread.Running)
                    return;

                due = Unpin(call);
                thread.Call = null;
                call.Thread = null;
                _idle.Push(thread);
            }

            RunDestroys(due);
        }

        private WaitThread ReserveThread()
        {
            while (_idle.Count != 0)
            {
                WaitThread idle = _idle.Pop();
                if (idle.Call == null)
                    return idle;
            }

            if (_threads.Count >= MemoryBudget.VulkanWaitThreads)
                return null;

            WaitThread created = new WaitThread();
            Thread host = new Thread(WaiterLoop, WaitThreadStackBytes) { IsBackground = true, Name = "BrovVulk wait" };
            host.Start(created);
            _threads.Add(created);
            return created;
        }

        private void WaiterLoop(object? state)
        {
            WaitThread self = (WaitThread)state;
            IntPtr scratch = IntPtr.Zero;
            int scratchBytes = 0;
            while (true)
            {
                self.Go.Wait();
                Call call = self.Call;
                int rr;
                try
                {
                    if (call.ScratchBytes > scratchBytes)
                    {
                        scratch = scratch == IntPtr.Zero ? Marshal.AllocHGlobal(call.ScratchBytes) : Marshal.ReAllocHGlobal(scratch, call.ScratchBytes);
                        scratchBytes = call.ScratchBytes;
                    }

                    rr = call.Run(scratch, ChunkFor(call));
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[BrovVulk] parked wait failed: {ex.Message}");
                    rr = BrovVulkConstants.VK_ERROR_INITIALIZATION_FAILED;
                }

                call.Result = rr;
                call.Finished = rr != BrovVulkConstants.VK_TIMEOUT || Stopwatch.GetTimestamp() >= call.Deadline;

                List<DeferredDestroy> due;
                lock (_lock)
                {
                    due = Unpin(call);
                    self.Call = null;
                    self.Running = false;
                    call.Thread = null;
                    _idle.Push(self);
                    Monitor.PulseAll(_lock);
                }

                RunDestroys(due);
                call.Done.SetResult(call);
                call.Wake.Bump();
            }
        }

        private static ulong ChunkFor(Call call)
        {
            if (call.Deadline == long.MaxValue)
                return ChunkNanoseconds;

            long left = call.Deadline - Stopwatch.GetTimestamp();
            if (left <= 0)
                return 0;

            UInt128 ns = (UInt128)(ulong)left * 1_000_000_000 / (ulong)Stopwatch.Frequency;
            return ns < ChunkNanoseconds ? (ulong)ns : ChunkNanoseconds;
        }

        private static long DeadlineAfter(ulong timeoutNs)
        {
            long now = Stopwatch.GetTimestamp();
            if (timeoutNs == ulong.MaxValue)
                return long.MaxValue;

            UInt128 ticks = (UInt128)timeoutNs * (ulong)Stopwatch.Frequency / 1_000_000_000;
            return ticks >= (ulong)(long.MaxValue - now) ? long.MaxValue : now + (long)(ulong)ticks;
        }

        private void Pin(Call call)
        {
            foreach ((IntPtr, string) pin in call.Pins)
                _pins[pin] = _pins.TryGetValue(pin, out int count) ? count + 1 : 1;
            Volatile.Write(ref _pinnedHandles, _pins.Count);
        }

        // Vulkan makes the guest destroy children before their parent, so the due destroys run in the guest's order.
        private List<DeferredDestroy> Unpin(Call call)
        {
            foreach ((IntPtr, string) pin in call.Pins)
            {
                if (!_pins.TryGetValue(pin, out int count))
                    continue;
                if (count > 1)
                    _pins[pin] = count - 1;
                else
                    _pins.Remove(pin);
            }

            Volatile.Write(ref _pinnedHandles, _pins.Count);

            List<DeferredDestroy> due = null;
            for (int i = 0; i < _deferred.Count; i++)
            {
                if (_pins.ContainsKey((_deferred[i].Handle, _deferred[i].Type)))
                    continue;

                (due ??= new List<DeferredDestroy>()).Add(_deferred[i]);
                _deferred.RemoveAt(i--);
            }

            return due;
        }

        private static void RunDestroys(List<DeferredDestroy> due)
        {
            if (due == null)
                return;

            foreach (DeferredDestroy destroy in due)
                BrovVulkGenDispatch.RunDeferredDestroy(destroy.Command, destroy.Parent, destroy.Handle);
        }

        // A parked wait still reads the handle, so its destroy runs when the wait lets go of it.
        internal bool TryDeferDestroy(uint command, string type, IntPtr parent, IntPtr handle)
        {
            if (Volatile.Read(ref _pinnedHandles) == 0 || handle == IntPtr.Zero)
                return false;

            lock (_lock)
            {
                if (!_pins.ContainsKey((handle, type)))
                    return false;

                _deferred.Add(new DeferredDestroy(command, type, parent, handle));
            }

            Stats.Defer();
            return true;
        }

        internal void EndCalls()
        {
            long limit = Environment.TickCount64 + 2 * ChunkMilliseconds;
            lock (_lock)
            {
                while (HasRunningCall())
                {
                    long left = limit - Environment.TickCount64;
                    if (left <= 0)
                    {
                        Utils.LogError("[BrovVulk] a parked wait did not end before dispose; its host objects stay alive.");
                        return;
                    }

                    Monitor.Wait(_lock, (int)left);
                }
            }
        }

        private bool HasRunningCall()
        {
            foreach (WaitThread thread in _threads)
            {
                if (thread.Running)
                    return true;
            }

            return false;
        }

        private enum FallbackReason
        {
            Off,
            NoPark,
            TooMany,
            Chain,
            NoThread,
        }

        private static class Stats
        {
            private static readonly BrovVulkStats Log = new BrovVulkStats("BROVVULK_WAIT_STATS", "BrovVulk wait stats:", Describe);

            private static readonly long[] Fallbacks = new long[Enum.GetValues<FallbackReason>().Length];
            private static long _parks;
            private static long _rearms;
            private static long _consumes;
            private static long _defers;

            internal static void Park() => Count(ref _parks);

            internal static void Rearm() => Count(ref _rearms);

            internal static void Consume() => Count(ref _consumes);

            internal static void Defer() => Count(ref _defers);

            internal static void Fallback(FallbackReason reason) => Count(ref Fallbacks[(int)reason]);

            private static void Count(ref long counter)
            {
                if (!Log.Enabled)
                    return;

                counter++;
                Log.Tick();
            }

            private static void Describe(StringBuilder sb)
            {
                sb.Append(" parks=").Append(_parks).Append(" rearms=").Append(_rearms).Append(" consumes=").Append(_consumes)
                  .Append(" deferredDestroys=").Append(_defers).Append(" | poll:");
                for (int i = 0; i < Fallbacks.Length; i++)
                    sb.Append(' ').Append((FallbackReason)i).Append('=').Append(Fallbacks[i]);
            }
        }
    }
}
