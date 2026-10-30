using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Brovan.Core.Helpers
{
    internal sealed unsafe class HostFileReadLease : IDisposable
    {
        private const uint RequestOplock = (9u << 16) | (144u << 2);
        private const uint OplockLevelRead = 1;
        private const uint OplockLevelWrite = 4;
        private const uint OplockRequestFlag = 1;
        private const uint OplockAcknowledgeFlag = 2;
        private const uint OplockAcknowledgeRequired = 1;
        private const int SetLease = 1024;
        private const int GetLease = 1025;
        private const int ReadLock = 0;
        private const int Unlock = 2;
        private const int TryAgain = 11;
        private const PosixSignal SignalIo = (PosixSignal)29;

        private static readonly object UnixSignalSync = new();
        private static PosixSignalRegistration? UnixSignalCancellation;

        [StructLayout(LayoutKind.Sequential)]
        private struct OplockInput
        {
            public ushort Version;
            public ushort Length;
            public uint Level;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OplockOutput
        {
            public ushort Version;
            public ushort Length;
            public uint OriginalLevel;
            public uint NewLevel;
            public uint Flags;
            public uint Access;
            public ushort Share;
        }

        private struct OplockRequest
        {
            public NativeOverlapped Overlapped;
            public OplockInput Input;
            public OplockOutput Output;
        }

        private readonly object Sync = new();
        private int* Guard;
        private SafeFileHandle? HeldHandle;
        private bool HandleReference;
        private bool Disposed;
        private OplockRequest* WindowsRequest;
        private EventWaitHandle? WindowsEvent;
        private RegisteredWaitHandle? WindowsWait;
        private bool WindowsRequestIssued;
        private bool WindowsAcknowledging;
        private bool WindowsAcknowledgeRequired;
        private PosixSignalRegistration? UnixSignal;
        private bool UnixLeaseHeld;

        public long MaximumDurationMilliseconds { get; private set; }

        public bool IsValid
        {
            get
            {
                lock (Sync)
                    return Guard != null && Volatile.Read(ref *Guard) != 0;
            }
        }

        // Linux reports a lease it has started to break as unlocked before SIGIO arrives.
        public bool IsHeldByHost()
        {
            lock (Sync)
                return Guard != null && Volatile.Read(ref *Guard) != 0 && (!UnixLeaseHeld || UnixReadLockHeld());
        }

        private HostFileReadLease(int* Guard)
        {
            this.Guard = Guard;
            Volatile.Write(ref *Guard, 1);
        }

        public static HostFileReadLease? TryAcquire(SafeFileHandle Handle, int* Guard)
        {
            if (Handle == null || Handle.IsInvalid || Handle.IsClosed)
                return null;

            HostFileReadLease Lease = new HostFileReadLease(Guard);
            bool Acquired = false;
            try
            {
                lock (Lease.Sync)
                {
                    if (GeneralHelper.IsWindows)
                        Acquired = Lease.TryAcquireWindows(Handle);
                    else if (GeneralHelper.IsLinux)
                        Acquired = Lease.TryAcquireUnix(Handle);
                }
                return Acquired ? Lease : null;
            }
            catch (Exception Ex) when (Ex is IOException or UnauthorizedAccessException
                or NotSupportedException or OutOfMemoryException or ObjectDisposedException)
            {
                Utils.LogError($"[HostFileReadLease] Acquire: {Ex.Message}");
                return null;
            }
            finally
            {
                if (!Acquired)
                    Lease.Dispose();
            }
        }

        private void HoldHandle(SafeFileHandle Handle)
        {
            Handle.DangerousAddRef(ref HandleReference);
            HeldHandle = Handle;
        }

        // NT grants an RW oplock only on an overlapped handle.
        [SupportedOSPlatform("windows")]
        private bool TryAcquireWindows(SafeFileHandle Handle)
        {
            HoldHandle(Handle);
            WindowsEvent = new EventWaitHandle(false, EventResetMode.ManualReset);
            WindowsRequest = (OplockRequest*)NativeMemory.AllocZeroed((nuint)sizeof(OplockRequest));

            PrepareWindowsRequest(OplockLevelRead | OplockLevelWrite, OplockRequestFlag);
            bool Completed = SubmitWindowsRequest();
            if (!Completed && Marshal.GetLastPInvokeError() != NativeWinImports.ErrorIoPending)
                return false;

            WindowsRequestIssued = true;
            WindowsWait = ThreadPool.RegisterWaitForSingleObject(WindowsEvent,
                static (State, _) => ((HostFileReadLease)State!).OnWindowsBreak(),
                this, Timeout.Infinite, true);
            return !Completed;
        }

        [SupportedOSPlatform("windows")]
        private void PrepareWindowsRequest(uint Level, uint Flags)
        {
            *WindowsRequest = default;
            WindowsEvent!.Reset();
            WindowsRequest->Overlapped.EventHandle = GeneralHelper.IO.OverlappedEvent(WindowsEvent);
            WindowsRequest->Input = new OplockInput
            {
                Version = 1,
                Length = (ushort)sizeof(OplockInput),
                Level = Level,
                Flags = Flags
            };
        }

        [SupportedOSPlatform("windows")]
        private bool SubmitWindowsRequest()
        {
            return NativeWinImports.DeviceIoControl(HeldHandle!.DangerousGetHandle(), RequestOplock,
                (IntPtr)(&WindowsRequest->Input), sizeof(OplockInput),
                (IntPtr)(&WindowsRequest->Output), sizeof(OplockOutput), IntPtr.Zero,
                (IntPtr)(&WindowsRequest->Overlapped));
        }

        private bool TryAcquireUnix(SafeFileHandle Handle)
        {
            if (RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
                return false;

            string TimeoutText = File.ReadAllText("/proc/sys/fs/lease-break-time");
            if (!long.TryParse(TimeoutText, NumberStyles.Integer, CultureInfo.InvariantCulture, out long Seconds)
                || Seconds <= 0)
                return false;

            // The guest stops trusting the lease before Linux can break it by force.
            MaximumDurationMilliseconds = Seconds == 1 ? 500 : 1000;
            HoldHandle(Handle);
            int Descriptor = (int)Handle.DangerousGetHandle();
            const int GetFlags = 3;
            const int AccessMode = 3;
            const int SetOwner = 8;
            int Flags = NativeUnixImports.Fcntl(Descriptor, GetFlags, 0);
            if (Flags < 0 || (Flags & AccessMode) != 0
                || NativeUnixImports.Fcntl(Descriptor, GetLease, 0) != Unlock)
                return false;

            lock (UnixSignalSync)
            {
                // SIGIO can remain queued in the runtime after the last lease is unlocked.
                UnixSignalCancellation ??= PosixSignalRegistration.Create(SignalIo,
                    static Context => Context.Cancel = true);
                UnixSignal = PosixSignalRegistration.Create(SignalIo, OnUnixSignal);
            }
            if (NativeUnixImports.Fcntl(Descriptor, SetOwner, Environment.ProcessId) != 0
                || NativeUnixImports.Fcntl(Descriptor, SetLease, ReadLock) != 0)
                return false;

            UnixLeaseHeld = true;
            return true;
        }

        private void OnWindowsBreak()
        {
            try
            {
                Revoke();
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[HostFileReadLease] Oplock break: {Ex.Message}");
            }
        }

        private void OnUnixSignal(PosixSignalContext Context)
        {
            Context.Cancel = true;
            try
            {
                lock (Sync)
                {
                    if (!UnixLeaseHeld || UnixReadLockHeld())
                        return;
                }
                Revoke();
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[HostFileReadLease] Lease break: {Ex.Message}");
            }
        }

        private bool UnixReadLockHeld()
            => NativeUnixImports.Fcntl((int)HeldHandle!.DangerousGetHandle(), GetLease, 0) == ReadLock;

        public void Revoke()
        {
            PosixSignalRegistration? Signal;
            lock (Sync)
            {
                if (Disposed)
                    return;
                Interlocked.Exchange(ref *Guard, 0);

                if (GeneralHelper.IsWindows)
                    ReleaseWindows();
                else if (UnixLeaseHeld)
                    ReleaseUnix();

                Signal = UnixSignal;
                UnixSignal = null;
                if (HandleReference)
                {
                    HeldHandle!.DangerousRelease();
                    HandleReference = false;
                    HeldHandle = null;
                }
            }

            Signal?.Dispose();
        }

        private void ReleaseUnix()
        {
            if (NativeUnixImports.Fcntl((int)HeldHandle!.DangerousGetHandle(), SetLease, Unlock) != 0)
            {
                int Error = Marshal.GetLastPInvokeError();
                // Linux returns EAGAIN after a forced break has removed the lease.
                if (Error != TryAgain)
                    throw new Win32Exception(Error);
            }
            UnixLeaseHeld = false;
        }

        [SupportedOSPlatform("windows")]
        private void ReleaseWindows()
        {
            if (WindowsRequestIssued)
            {
                IntPtr Handle = HeldHandle!.DangerousGetHandle();
                IntPtr Overlapped = (IntPtr)(&WindowsRequest->Overlapped);
                NativeWinImports.CancelIoEx(Handle, Overlapped);
                bool Completed = FinishWindowsRequest();
                WindowsRequestIssued = false;
                if (WindowsAcknowledging)
                {
                    if (Completed)
                        WindowsAcknowledgeRequired = false;
                    WindowsAcknowledging = false;
                }
                else if (Completed && (WindowsRequest->Output.Flags & OplockAcknowledgeRequired) != 0)
                    WindowsAcknowledgeRequired = true;
            }

            if (WindowsAcknowledgeRequired)
            {
                // NT requires an explicit acknowledgement after an RW oplock break.
                PrepareWindowsRequest(0, OplockAcknowledgeFlag);
                bool Acknowledged = SubmitWindowsRequest();
                int Error = Marshal.GetLastPInvokeError();
                if (!Acknowledged && Error == NativeWinImports.ErrorIoPending)
                {
                    WindowsAcknowledging = true;
                    WindowsRequestIssued = true;
                    Acknowledged = FinishWindowsRequest();
                    Error = Marshal.GetLastPInvokeError();
                    WindowsRequestIssued = false;
                    WindowsAcknowledging = false;
                }
                if (!Acknowledged)
                    throw new Win32Exception(Error);
                WindowsAcknowledgeRequired = false;
            }

            WindowsWait?.Unregister(null);
            WindowsWait = null;
            NativeMemory.Free(WindowsRequest);
            WindowsRequest = null;
            WindowsEvent?.Dispose();
            WindowsEvent = null;
        }

        [SupportedOSPlatform("windows")]
        private bool FinishWindowsRequest()
        {
            bool Completed = NativeWinImports.GetOverlappedResult(HeldHandle!.DangerousGetHandle(),
                (IntPtr)(&WindowsRequest->Overlapped), out _, true);
            if (WindowsRequest->Overlapped.InternalLow == (IntPtr)NativeWinImports.StatusPending)
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            return Completed;
        }

        public void Dispose()
        {
            Revoke();
            lock (Sync)
            {
                Disposed = true;
                Guard = null;
            }
        }
    }
}
