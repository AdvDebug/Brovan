using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Clone : ILinuxSyscall
    {
        private const ulong CLONE_VM = 0x00000100;
        private const ulong CLONE_FS = 0x00000200;
        private const ulong CLONE_FILES = 0x00000400;
        private const ulong CLONE_SIGHAND = 0x00000800;
        private const ulong CLONE_PARENT_SETTID = 0x00100000;
        private const ulong CLONE_CHILD_CLEARTID = 0x00200000;
        private const ulong CLONE_SETTLS = 0x00080000;
        private const ulong CLONE_CHILD_SETTID = 0x01000000;
        private const ulong CLONE_THREAD = 0x00010000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong flags = Context.Arg0;
            ulong child_stack = Context.Arg1;
            ulong parent_tidptr = Context.Arg2;
            ulong child_tidptr = Context.Abi == SyscallAbi.X64 ? Context.Arg3 : Context.Arg4;
            ulong tls = Context.Abi == SyscallAbi.X64 ? Context.Arg4 : Context.Arg3;

            EmulatedThread Parent = Instance.CurrentThread;
            if (Parent == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((flags & CLONE_THREAD) == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOSYS);
                return;
            }

            if ((flags & CLONE_SIGHAND) != 0 && (flags & CLONE_VM) == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((flags & CLONE_THREAD) != 0 && ((flags & CLONE_SIGHAND) == 0 || (flags & CLONE_VM) == 0))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (child_stack == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            uint ThreadId = (uint)Instance.NextThreadId++;
            if ((flags & CLONE_PARENT_SETTID) != 0 && !TryWriteTid(Instance, Context, parent_tidptr, ThreadId))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if ((flags & CLONE_CHILD_SETTID) != 0 && !TryWriteTid(Instance, Context, child_tidptr, ThreadId))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            LinuxThreadState ParentState = Parent.GuestState as LinuxThreadState;
            LinuxThreadState ChildState = new LinuxThreadState
            {
                CpuidEnabled = ParentState?.CpuidEnabled ?? Helper.CpuidEnabled,
                FsBase = ParentState?.FsBase ?? (Instance.IsX64Guest ? Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE) : 0),
                GsBase = ParentState?.GsBase ?? (Instance.IsX64Guest ? Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE) : 0),
                TIDPtr = (flags & CLONE_CHILD_CLEARTID) != 0 ? child_tidptr : 0,
                SignalMask = ParentState?.SignalMask != null ? (byte[])ParentState.SignalMask.Clone() : new byte[LinuxThreadState.SignalSetSize],
                AlternateSignalStack = ParentState?.AlternateSignalStack ?? default
            };

            CpuContext ChildContext = CaptureCurrentContext(Instance, Context);
            ChildContext.RAX = 0;
            ChildContext.RSP = child_stack;
            if ((flags & CLONE_SETTLS) != 0)
            {
                if (Context.Abi == SyscallAbi.X64)
                {
                    ChildState.FsBase = tls;
                    ChildContext.FS = tls;
                }
                else
                {
                    ChildState.FsBase = tls;
                }
            }

            GetStackBounds(Instance, child_stack, out ulong StackBase, out ulong StackSize);
            EmulatedThread Child = new EmulatedThread
            {
                Context = ChildContext,
                ThreadId = ThreadId,
                Name = $"LinuxThread_{ThreadId}",
                State = EmulatedThreadState.Ready,
                BasePriority = Parent.BasePriority,
                DynamicBoost = 0,
                QueueLevel = Parent.QueueLevel,
                LastReadyTick = 0,
                LastRunTick = 0,
                StartAddress = ChildContext.RIP,
                Parameter = 0,
                StackAddress = StackBase,
                StackSize = StackSize,
                GuestState = ChildState
            };

            Helper.RegisterThread(Child);
            Helper.CurrentThreadId = (int)Parent.ThreadId;
            Instance.Threads[ThreadId] = Child;
            Instance.ThreadOrder.Add((int)ThreadId);
            Helper.SetReturnValue(Instance, Context, ThreadId);
        }

        private static CpuContext CaptureCurrentContext(BinaryEmulator Instance, LinuxSyscallContext Context)
        {
            return new CpuContext
            {
                RAX = Instance.ReadRegister(Registers.UC_X86_REG_RAX),
                RBX = Instance.ReadRegister(Registers.UC_X86_REG_RBX),
                RCX = Instance.ReadRegister(Registers.UC_X86_REG_RCX),
                RDX = Instance.ReadRegister(Registers.UC_X86_REG_RDX),
                RSI = Instance.ReadRegister(Registers.UC_X86_REG_RSI),
                RDI = Instance.ReadRegister(Registers.UC_X86_REG_RDI),
                RBP = Instance.ReadRegister(Registers.UC_X86_REG_RBP),
                RSP = Instance.ReadRegister(Registers.UC_X86_REG_RSP),
                R8 = Instance.ReadRegister(Registers.UC_X86_REG_R8),
                R9 = Instance.ReadRegister(Registers.UC_X86_REG_R9),
                R10 = Instance.ReadRegister(Registers.UC_X86_REG_R10),
                R11 = Instance.ReadRegister(Registers.UC_X86_REG_R11),
                R12 = Instance.ReadRegister(Registers.UC_X86_REG_R12),
                R13 = Instance.ReadRegister(Registers.UC_X86_REG_R13),
                R14 = Instance.ReadRegister(Registers.UC_X86_REG_R14),
                R15 = Instance.ReadRegister(Registers.UC_X86_REG_R15),
                RIP = LinuxGuest.GetCurrentSyscallReturnAddress(Instance, Context),
                RFLAGS = Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS),
                FS = Instance.IsX64Guest ? Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE) : 0,
                GS = Instance.IsX64Guest ? Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE) : 0
            };
        }

        private static bool TryWriteTid(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, uint ThreadId)
        {
            if (Address == 0 || !Instance.IsRegionMapped(Address, 4))
                return false;

            return Instance.WriteMemory(Address, BitConverter.GetBytes(ThreadId));
        }

        private static void GetStackBounds(BinaryEmulator Instance, ulong StackPointer, out ulong StackBase, out ulong StackSize)
        {
            StackBase = 0;
            StackSize = 0;
            if (StackPointer == 0 || !Instance.TryFindMemoryRegion(StackPointer - 1, out MemoryRegion Region))
                return;

            StackBase = Region.BaseAddress;
            StackSize = Instance.AlignToPageSize(Region.Size);
        }
    }
}
