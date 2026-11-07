using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class MmcssDevice : IWinDevice
    {
        private const int EaSize = 272;
        private const int EaValueLength = 263;
        private const int SecondTaskFlagOffset = 11;
        private const int TaskIndexOffset = 12;
        private const int FirstTaskOffset = 16;
        private const int SecondTaskOffset = 144;

        public string DeviceName => "\\Device\\MMCSS\\MmThread";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            return Create(Instance, DevicePath, EaBuffer, out InternalPath, out Handler, out _);
        }

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler,
            out ulong Information)
        {
            InternalPath = null;
            Handler = null;
            Information = 0;

            Mmcss Scheduler = Instance.WinHelper.Mmcss;
            NTSTATUS Status = Scheduler.DeviceStatus;
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (EaBuffer == null || EaBuffer.Length != EaSize || !IsValidEaHeader(EaBuffer))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            MmcssTask Task = Scheduler.FindTask(ReadTaskName(EaBuffer, FirstTaskOffset));
            if (Task != null && EaBuffer[SecondTaskFlagOffset] == 1)
            {
                MmcssTask Second = Scheduler.FindTask(ReadTaskName(EaBuffer, SecondTaskOffset));
                Task = Second == null ? null : Second.BasePriority > Task.BasePriority ? Second : Task;
            }

            if (Task == null)
                return NTSTATUS.STATUS_INVALID_TASK_NAME;

            uint JoinIndex = BinaryPrimitives.ReadUInt32LittleEndian(EaBuffer.AsSpan(TaskIndexOffset));
            MmcssTaskIndex Index = null;
            if (JoinIndex != 0 && !Scheduler.TryFindIndex(JoinIndex, Task, out Index))
                return NTSTATUS.STATUS_INVALID_TASK_INDEX;

            EmulatedThread Thread = Instance.CurrentThread;
            WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
            if (State == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Scheduler.HasThreadRoom)
                return NTSTATUS.STATUS_TOO_MANY_THREADS;

            if (State.MmcssRegistration != null)
                return NTSTATUS.STATUS_THREAD_ALREADY_IN_TASK;

            Index ??= Scheduler.CreateIndex(Task);
            Scheduler.Reference(Index);
            Scheduler.AddThread();
            MmThreadClient Client = new MmThreadClient(Thread, Index);
            State.MmcssRegistration = Client;

            // NT leaves a Low task's thread at its priority until its relative priority is set.
            if (Task.Category != Mmcss.CategoryLow)
                Client.ApplyPriority(Instance, 0);

            InternalPath = DeviceName;
            Handler = Client.Handle;
            Information = Index.Value;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // A single FILE_FULL_EA_INFORMATION with no name, as avrt builds it.
        private static bool IsValidEaHeader(byte[] Ea)
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(Ea) == 0
                && Ea[4] == 0
                && Ea[5] == 0
                && BinaryPrimitives.ReadUInt16LittleEndian(Ea.AsSpan(6)) == EaValueLength
                && Ea[8] == 0 && Ea[9] == 0 && Ea[10] == 0
                && Ea[SecondTaskFlagOffset] <= 1;
        }

        private static string ReadTaskName(byte[] Ea, int Offset)
        {
            ReadOnlySpan<char> Name = MemoryMarshal.Cast<byte, char>(Ea.AsSpan(Offset, Mmcss.TaskNameChars * sizeof(char)));
            int End = Name.IndexOf('\0');
            return new string(End < 0 ? Name : Name.Slice(0, End));
        }
    }

    internal sealed class MmThreadClient : IWinDeviceFile
    {
        private readonly EmulatedThread Thread;
        private readonly MmcssTaskIndex Index;
        private bool Left;

        public MmThreadClient(EmulatedThread Thread, MmcssTaskIndex Index)
        {
            this.Thread = Thread;
            this.Index = Index;
        }

        internal void ApplyPriority(BinaryEmulator Instance, int Relative)
        {
            WinEmulatedThread.GetState(Thread).ActualBasePriority = Mmcss.ThreadPriority(Index.Task, Relative);
            Instance.WinHelper.ApplyThreadBasePriority(Thread);
        }

        internal NTSTATUS Handle(uint Code, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (!Mmcss.TryGetFunction(Code, in Data, Mmcss.ThreadClient, out uint Function))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Data.Information = 0;
            switch (Function)
            {
                case Mmcss.SetRelativePriority:
                    return SetPriority(Instance, Data.InputBuffer);

                case Mmcss.QueryResponsiveness:
                    // METHOD_NEITHER, so the driver writes the caller's buffer itself and reports no byte count.
                    return Instance.WinHelper.WriteUInt32(Data.UserBuffer, Instance.WinHelper.Mmcss.Responsiveness)
                        ? NTSTATUS.STATUS_SUCCESS
                        : NTSTATUS.STATUS_ACCESS_VIOLATION;

                case Mmcss.OpenTaskIndex:
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;

                default:
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }
        }

        private NTSTATUS SetPriority(BinaryEmulator Instance, byte[] Input)
        {
            sbyte Relative = (sbyte)Input[0];
            if (Relative < -2 || Relative > 2 || Left)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ApplyPriority(Instance, Relative);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // Runs at the last handle close or at thread exit, whichever comes first.
        internal void Leave(BinaryEmulator Instance)
        {
            if (Left)
                return;

            Left = true;
            WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
            if (State != null && State.MmcssRegistration == this)
            {
                State.MmcssRegistration = null;
                State.ActualBasePriority = 0;
                if (Thread.State != EmulatedThreadState.Terminated)
                    Instance.WinHelper.ApplyThreadBasePriority(Thread);
            }

            Mmcss Scheduler = Instance.WinHelper.Mmcss;
            Scheduler.RemoveThread();
            Scheduler.Release(Index);
        }

        public void Closed(BinaryEmulator Instance, WinFile File)
        {
            Leave(Instance);
        }
    }
}
