using System;
using System.Collections.Generic;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.Guests
{
    internal sealed class GenericGuest : IGuestEnvironment
    {
        private const int UC_ARM_REG_CPSR = 3;
        private const int UC_ARM_REG_LR = 10;
        private const int UC_ARM_REG_PC = 11;
        private const int UC_ARM_REG_SP = 12;
        private const int UC_ARM_REG_R0 = 66;
        private const int UC_ARM_REG_R1 = 67;
        private const int UC_ARM_REG_R2 = 68;
        private const int UC_ARM_REG_R3 = 69;
        private const int UC_ARM_REG_R4 = 70;
        private const int UC_ARM_REG_R5 = 71;
        private const int UC_ARM_REG_R6 = 72;
        private const int UC_ARM_REG_R7 = 73;
        private const int UC_ARM_REG_R8 = 74;
        private const int UC_ARM_REG_R9 = 75;
        private const int UC_ARM_REG_R10 = 76;
        private const int UC_ARM_REG_R11 = 77;
        private const int UC_ARM_REG_R12 = 78;

        private readonly Dictionary<string, int> RegisterNames;

        public GuestOsKind Os => GuestOsKind.Generic;
        public Arch UnicornArch { get; }
        public Mode UnicornMode { get; }
        public ulong LoadAddress { get; }
        public ulong EntryAddress { get; }
        public ulong StackSize { get; }
        public ulong MappedBase { get; private set; }
        public ulong StackBase { get; private set; }
        public ulong InitialStackPointer { get; private set; }
        public int ProgramCounterRegister { get; }
        public int StackPointerRegister { get; }
        public bool IsX86 => UnicornArch == Arch.X86;
        public bool IsArm => UnicornArch == Arch.ARM;
        public bool Is64Bit => UnicornArch == Arch.X86 && UnicornMode == Mode.MODE_64;
        public bool IsThumb => UnicornArch == Arch.ARM && UnicornMode == Mode.THUMB;

        public GenericGuest(Arch UnicornArch, Mode UnicornMode, ulong LoadAddress, ulong EntryAddress, ulong StackSize)
        {
            this.UnicornArch = UnicornArch;
            this.UnicornMode = UnicornMode;
            this.LoadAddress = LoadAddress;
            this.EntryAddress = EntryAddress;
            this.StackSize = StackSize;
            RegisterNames = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            if (UnicornArch == Arch.X86)
            {
                if (UnicornMode == Mode.MODE_64)
                {
                    ProgramCounterRegister = (int)Registers.UC_X86_REG_RIP;
                    StackPointerRegister = (int)Registers.UC_X86_REG_RSP;
                    AddX64RegisterNames();
                }
                else
                {
                    ProgramCounterRegister = (int)Registers.UC_X86_REG_EIP;
                    StackPointerRegister = (int)Registers.UC_X86_REG_ESP;
                    AddX86RegisterNames();
                }
            }
            else if (UnicornArch == Arch.ARM)
            {
                ProgramCounterRegister = UC_ARM_REG_PC;
                StackPointerRegister = UC_ARM_REG_SP;
                AddArmRegisterNames();
            }
            else
            {
                throw new NotSupportedException($"Unsupported generic architecture: {UnicornArch}.");
            }
        }

        public void Initialize(BinaryEmulator Instance, BinaryFile Binary)
        {
            ReadOnlySpan<byte> Data = Binary.GetBinaryData();
            ulong ImageSize = Instance.AlignToPageSize((ulong)Math.Max(Data.Length, 1));
            ulong RequestedBase = LoadAddress;

            if (RequestedBase == 0 || Instance.IsRegionMapped(RequestedBase, ImageSize))
                MappedBase = Instance.MapUniqueAddress(ImageSize, MemoryProtection.All);
            else
                MappedBase = Instance.MapMemoryRegion(RequestedBase, ImageSize, MemoryProtection.All);

            if (MappedBase == 0)
                throw new InvalidOperationException("Failed to map the generic guest image.");

            if (Data.Length != 0)
                Instance._emulator.WriteMemory(MappedBase, Data);

            ulong GuestStackSize = StackSize == 0 ? (Is64Bit ? 0x200000UL : 0x100000UL) : StackSize;

            GuestStackSize = Instance.AlignToPageSize(GuestStackSize);
            StackBase = Instance.MapUniqueAddress(GuestStackSize, MemoryProtection.ReadWrite);
            if (StackBase == 0)
                throw new InvalidOperationException("Failed to map the generic guest stack.");

            InitialStackPointer = StackBase + GuestStackSize - (Is64Bit ? 0x20UL : 0x10UL);

            ulong GuestEntry;
            if (EntryAddress == 0)
            {
                GuestEntry = MappedBase;
            }
            else if (LoadAddress != 0 && EntryAddress >= LoadAddress && EntryAddress < LoadAddress + ImageSize)
            {
                GuestEntry = MappedBase + (EntryAddress - LoadAddress);
            }
            else
            {
                GuestEntry = EntryAddress;
            }

            if (UnicornArch == Arch.X86)
            {
                if (Is64Bit)
                {
                    Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_RSP, InitialStackPointer);
                    Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_RBP, InitialStackPointer);
                    Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_RIP, GuestEntry);
                    Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_RFLAGS, 0x202);
                }
                else
                {
                    Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_ESP, InitialStackPointer);
                    Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_EBP, InitialStackPointer);
                    Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_EIP, GuestEntry);
                    Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_EFLAGS, 0x202);
                }
            }
            else
            {
                Instance._emulator.WriteRegister(StackPointerRegister, InitialStackPointer);
                Instance._emulator.WriteRegister(ProgramCounterRegister, GuestEntry);
                Instance._emulator.WriteRegister(UC_ARM_REG_LR, 0);
                Instance._emulator.WriteRegister32(UC_ARM_REG_CPSR, IsThumb ? 0x20u : 0u);
            }
        }

        public void Start(BinaryEmulator Instance)
        {
            ulong Pc = Instance._emulator.ReadRegister(ProgramCounterRegister);
            Instance.StartEmulation(Pc, 0);
        }

        public bool TryHandleSyscall(BinaryEmulator Instance)
        {
            Instance.TriggerEventMessage($"[!] Generic guest hit a syscall at 0x{Instance._emulator.ReadRegister(ProgramCounterRegister):X}.", LogFlags.Issues);
            return false;
        }

        public bool TryHandleInterrupt(BinaryEmulator Instance, uint InterruptNumber)
        {
            Instance.TriggerEventMessage($"[!] Generic guest hit interrupt 0x{InterruptNumber:X} at 0x{Instance._emulator.ReadRegister(ProgramCounterRegister):X}.", LogFlags.Issues);
            return false;
        }

        public void HandlePrivilegedInstruction(BinaryEmulator Instance)
        {
            Instance.TriggerEventMessage($"[!] Generic guest executed a privileged instruction at 0x{Instance._emulator.ReadRegister(ProgramCounterRegister):X}.", LogFlags.Issues);
        }

        public void HandleInvalidInstruction(BinaryEmulator Instance)
        {
            Instance.TriggerEventMessage($"[!] Generic guest executed an invalid instruction at 0x{Instance._emulator.ReadRegister(ProgramCounterRegister):X}.", LogFlags.Issues);
            Instance.StopEmulation();
        }

        public bool HandleInvalidMemory(BinaryEmulator Instance, MemoryType Type, ulong Address, uint Size, ulong Value)
        {
            Instance.TriggerEventMessage($"[!] Generic guest {Type} at 0x{Address:X} (size {Size}) from 0x{Instance._emulator.ReadRegister(ProgramCounterRegister):X}.", LogFlags.Issues);
            return false;
        }

        public ulong CreateInitialThread(BinaryEmulator Instance)
        {
            return 0;
        }

        public EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name = null, ulong Parameter = 0, ulong? StackSizeOverride = null, int BasePriority = 8)
        {
            Instance.TriggerEventMessage("[!] Generic guest threading is not supported.", LogFlags.General);
            return null;
        }

        public void OnThreadContextLoaded(BinaryEmulator Instance, EmulatedThread Thread)
        {
        }

        public bool HasPendingGuestWork(BinaryEmulator Instance, EmulatedThread Thread)
        {
            return false;
        }

        public bool IsHandleSignaled(BinaryEmulator Instance, ulong Handle)
        {
            return false;
        }

        public bool ExecuteThreadSlice(BinaryEmulator Instance, EmulatedThread Thread, uint QuantumInstructions, out bool State)
        {
            State = false;
            return false;
        }

        public void OnThreadWaitSatisfied(BinaryEmulator Instance, EmulatedThread Thread)
        {
        }

        public bool TryGetRegister(string Name, out int Register, out string CanonicalName)
        {
            Register = 0;
            CanonicalName = string.Empty;

            if (string.IsNullOrWhiteSpace(Name))
                return false;

            if (!RegisterNames.TryGetValue(Name, out Register))
                return false;

            CanonicalName = GetRegisterName(Register);
            return true;
        }

        public string GetRegisterName(int Register)
        {
            foreach (KeyValuePair<string, int> Entry in RegisterNames)
            {
                if (Entry.Value == Register)
                    return Entry.Key.ToUpperInvariant();
            }

            return $"REG_{Register}";
        }

        public string GetRegisterDump(BinaryEmulator Instance)
        {
            StringBuilder Builder = new StringBuilder();

            if (UnicornArch == Arch.ARM)
            {
                Builder.AppendLine("Registers:");
                Builder.AppendLine($"R0 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R0):X8}    R1 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R1):X8}    R2 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R2):X8}    R3 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R3):X8}");
                Builder.AppendLine($"R4 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R4):X8}    R5 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R5):X8}    R6 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R6):X8}    R7 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R7):X8}");
                Builder.AppendLine($"R8 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R8):X8}    R9 : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R9):X8}    R10: 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R10):X8}    R11: 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R11):X8}");
                Builder.AppendLine($"R12: 0x{Instance._emulator.ReadRegister(UC_ARM_REG_R12):X8}    SP : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_SP):X8}    LR : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_LR):X8}    PC : 0x{Instance._emulator.ReadRegister(UC_ARM_REG_PC):X8}");
                Builder.AppendLine($"CPSR: 0x{Instance._emulator.ReadRegister(UC_ARM_REG_CPSR):X8}{(IsThumb ? " (Thumb)" : " (ARM)")}");
                return Builder.ToString();
            }

            return string.Empty;
        }

        private void AddAlias(string Name, int Register)
        {
            RegisterNames[Name] = Register;
        }

        private void AddX86RegisterNames()
        {
            AddAlias("eax", (int)Registers.UC_X86_REG_EAX);
            AddAlias("ebx", (int)Registers.UC_X86_REG_EBX);
            AddAlias("ecx", (int)Registers.UC_X86_REG_ECX);
            AddAlias("edx", (int)Registers.UC_X86_REG_EDX);
            AddAlias("esi", (int)Registers.UC_X86_REG_ESI);
            AddAlias("edi", (int)Registers.UC_X86_REG_EDI);
            AddAlias("ebp", (int)Registers.UC_X86_REG_EBP);
            AddAlias("esp", (int)Registers.UC_X86_REG_ESP);
            AddAlias("eip", (int)Registers.UC_X86_REG_EIP);
            AddAlias("eflags", (int)Registers.UC_X86_REG_EFLAGS);
        }

        private void AddX64RegisterNames()
        {
            AddAlias("rax", (int)Registers.UC_X86_REG_RAX);
            AddAlias("rbx", (int)Registers.UC_X86_REG_RBX);
            AddAlias("rcx", (int)Registers.UC_X86_REG_RCX);
            AddAlias("rdx", (int)Registers.UC_X86_REG_RDX);
            AddAlias("rsi", (int)Registers.UC_X86_REG_RSI);
            AddAlias("rdi", (int)Registers.UC_X86_REG_RDI);
            AddAlias("rbp", (int)Registers.UC_X86_REG_RBP);
            AddAlias("rsp", (int)Registers.UC_X86_REG_RSP);
            AddAlias("rip", (int)Registers.UC_X86_REG_RIP);
            AddAlias("r8", (int)Registers.UC_X86_REG_R8);
            AddAlias("r9", (int)Registers.UC_X86_REG_R9);
            AddAlias("r10", (int)Registers.UC_X86_REG_R10);
            AddAlias("r11", (int)Registers.UC_X86_REG_R11);
            AddAlias("r12", (int)Registers.UC_X86_REG_R12);
            AddAlias("r13", (int)Registers.UC_X86_REG_R13);
            AddAlias("r14", (int)Registers.UC_X86_REG_R14);
            AddAlias("r15", (int)Registers.UC_X86_REG_R15);
            AddAlias("rflags", (int)Registers.UC_X86_REG_RFLAGS);
        }

        private void AddArmRegisterNames()
        {
            AddAlias("r0", UC_ARM_REG_R0);
            AddAlias("r1", UC_ARM_REG_R1);
            AddAlias("r2", UC_ARM_REG_R2);
            AddAlias("r3", UC_ARM_REG_R3);
            AddAlias("r4", UC_ARM_REG_R4);
            AddAlias("r5", UC_ARM_REG_R5);
            AddAlias("r6", UC_ARM_REG_R6);
            AddAlias("r7", UC_ARM_REG_R7);
            AddAlias("r8", UC_ARM_REG_R8);
            AddAlias("r9", UC_ARM_REG_R9);
            AddAlias("r10", UC_ARM_REG_R10);
            AddAlias("r11", UC_ARM_REG_R11);
            AddAlias("r12", UC_ARM_REG_R12);
            AddAlias("r13", UC_ARM_REG_SP);
            AddAlias("r14", UC_ARM_REG_LR);
            AddAlias("r15", UC_ARM_REG_PC);
            AddAlias("sp", UC_ARM_REG_SP);
            AddAlias("lr", UC_ARM_REG_LR);
            AddAlias("pc", UC_ARM_REG_PC);
            AddAlias("cpsr", UC_ARM_REG_CPSR);
            AddAlias("fp", UC_ARM_REG_R11);
            AddAlias("ip", UC_ARM_REG_R12);
            AddAlias("sb", UC_ARM_REG_R9);
            AddAlias("sl", UC_ARM_REG_R10);
        }
    }
}
