using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation
{
    /// <summary>
    /// Unicorn errors.
    /// </summary>
    public enum UCErrors
    {
        UC_ERR_OK = 0,
        UC_ERR_NOMEM,
        UC_ERR_ARCH,
        UC_ERR_HANDLE,
        UC_ERR_MODE,
        UC_ERR_VERSION,
        UC_ERR_READ_UNMAPPED,
        UC_ERR_WRITE_UNMAPPED,
        UC_ERR_FETCH_UNMAPPED,
        UC_ERR_HOOK,
        UC_ERR_INSN_INVALID,
        UC_ERR_MAP,
        UC_ERR_WRITE_PROT,
        UC_ERR_READ_PROT,
        UC_ERR_FETCH_PROT,
        UC_ERR_ARG,
        UC_ERR_READ_UNALIGNED,
        UC_ERR_WRITE_UNALIGNED,
        UC_ERR_FETCH_UNALIGNED,
        UC_ERR_HOOK_EXIST,
        UC_ERR_RESOURCE,
        UC_ERR_EXCEPTION,
        UC_ERR_OVERFLOW,
        UC_ERR_CFG // manually added (this is bad i know)
    }

    /// <summary>
    /// Architecture for the VCPU.
    /// </summary>
    public enum Arch
    {
        ARM = 1,
        ARM64,
        MIPS,
        X86,
        PPC,
        SPARC,
        M68K,
        RISCV,
        S390X,
        TRICORE,
        MAX,
    }

    public enum Mode
    {
        LITTLE_ENDIAN = 0,
        BIG_ENDIAN = 1 << 30,
        ARM = 0,
        THUMB = 1 << 4,
        MCLASS = 1 << 5,
        V8 = 1 << 6,
        ARMBE8 = 1 << 10,
        MIPS32 = 1 << 2,
        MIPS64 = 1 << 3,
        MODE_16 = 1 << 1,
        MODE_32 = 1 << 2,
        MODE_64 = 1 << 3,
        PPC32 = 1 << 2,
        SPARC32 = 1 << 2,
        SPARC64 = 1 << 3,
        RISCV32 = 1 << 2,
        RISCV64 = 1 << 3,
    }

    /// <summary>
    /// CPU Registers.
    /// </summary>
    public enum Registers
    {
        UC_X86_REG_INVALID = 0,
        UC_X86_REG_AH,
        UC_X86_REG_AL,
        UC_X86_REG_AX,
        UC_X86_REG_BH,
        UC_X86_REG_BL,
        UC_X86_REG_BP,
        UC_X86_REG_BPL,
        UC_X86_REG_BX,
        UC_X86_REG_CH,
        UC_X86_REG_CL,
        UC_X86_REG_CS,
        UC_X86_REG_CX,
        UC_X86_REG_DH,
        UC_X86_REG_DI,
        UC_X86_REG_DIL,
        UC_X86_REG_DL,
        UC_X86_REG_DS,
        UC_X86_REG_DX,
        UC_X86_REG_EAX,
        UC_X86_REG_EBP,
        UC_X86_REG_EBX,
        UC_X86_REG_ECX,
        UC_X86_REG_EDI,
        UC_X86_REG_EDX,
        UC_X86_REG_EFLAGS,
        UC_X86_REG_EIP,
        UC_X86_REG_ES = UC_X86_REG_EIP + 2,
        UC_X86_REG_ESI,
        UC_X86_REG_ESP,
        UC_X86_REG_FPSW,
        UC_X86_REG_FS,
        UC_X86_REG_GS,
        UC_X86_REG_IP,
        UC_X86_REG_RAX,
        UC_X86_REG_RBP,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDI,
        UC_X86_REG_RDX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSI = UC_X86_REG_RIP + 2,
        UC_X86_REG_RSP,
        UC_X86_REG_SI,
        UC_X86_REG_SIL,
        UC_X86_REG_SP,
        UC_X86_REG_SPL,
        UC_X86_REG_SS,
        UC_X86_REG_CR0,
        UC_X86_REG_CR1,
        UC_X86_REG_CR2,
        UC_X86_REG_CR3,
        UC_X86_REG_CR4,
        UC_X86_REG_CR8 = UC_X86_REG_CR4 + 4,
        UC_X86_REG_DR0 = UC_X86_REG_CR8 + 8,
        UC_X86_REG_DR1,
        UC_X86_REG_DR2,
        UC_X86_REG_DR3,
        UC_X86_REG_DR4,
        UC_X86_REG_DR5,
        UC_X86_REG_DR6,
        UC_X86_REG_DR7,
        UC_X86_REG_FP0 = UC_X86_REG_DR7 + 9,
        UC_X86_REG_FP1,
        UC_X86_REG_FP2,
        UC_X86_REG_FP3,
        UC_X86_REG_FP4,
        UC_X86_REG_FP5,
        UC_X86_REG_FP6,
        UC_X86_REG_FP7,
        UC_X86_REG_K0,
        UC_X86_REG_K1,
        UC_X86_REG_K2,
        UC_X86_REG_K3,
        UC_X86_REG_K4,
        UC_X86_REG_K5,
        UC_X86_REG_K6,
        UC_X86_REG_K7,
        UC_X86_REG_MM0,
        UC_X86_REG_MM1,
        UC_X86_REG_MM2,
        UC_X86_REG_MM3,
        UC_X86_REG_MM4,
        UC_X86_REG_MM5,
        UC_X86_REG_MM6,
        UC_X86_REG_MM7,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
        UC_X86_REG_ST0,
        UC_X86_REG_ST1,
        UC_X86_REG_ST2,
        UC_X86_REG_ST3,
        UC_X86_REG_ST4,
        UC_X86_REG_ST5,
        UC_X86_REG_ST6,
        UC_X86_REG_ST7,
        UC_X86_REG_XMM0,
        UC_X86_REG_XMM1,
        UC_X86_REG_XMM2,
        UC_X86_REG_XMM3,
        UC_X86_REG_XMM4,
        UC_X86_REG_XMM5,
        UC_X86_REG_XMM6,
        UC_X86_REG_XMM7,
        UC_X86_REG_XMM8,
        UC_X86_REG_XMM9,
        UC_X86_REG_XMM10,
        UC_X86_REG_XMM11,
        UC_X86_REG_XMM12,
        UC_X86_REG_XMM13,
        UC_X86_REG_XMM14,
        UC_X86_REG_XMM15,
        UC_X86_REG_XMM16,
        UC_X86_REG_XMM17,
        UC_X86_REG_XMM18,
        UC_X86_REG_XMM19,
        UC_X86_REG_XMM20,
        UC_X86_REG_XMM21,
        UC_X86_REG_XMM22,
        UC_X86_REG_XMM23,
        UC_X86_REG_XMM24,
        UC_X86_REG_XMM25,
        UC_X86_REG_XMM26,
        UC_X86_REG_XMM27,
        UC_X86_REG_XMM28,
        UC_X86_REG_XMM29,
        UC_X86_REG_XMM30,
        UC_X86_REG_XMM31,
        UC_X86_REG_YMM0,
        UC_X86_REG_YMM1,
        UC_X86_REG_YMM2,
        UC_X86_REG_YMM3,
        UC_X86_REG_YMM4,
        UC_X86_REG_YMM5,
        UC_X86_REG_YMM6,
        UC_X86_REG_YMM7,
        UC_X86_REG_YMM8,
        UC_X86_REG_YMM9,
        UC_X86_REG_YMM10,
        UC_X86_REG_YMM11,
        UC_X86_REG_YMM12,
        UC_X86_REG_YMM13,
        UC_X86_REG_YMM14,
        UC_X86_REG_YMM15,
        UC_X86_REG_YMM16,
        UC_X86_REG_YMM17,
        UC_X86_REG_YMM18,
        UC_X86_REG_YMM19,
        UC_X86_REG_YMM20,
        UC_X86_REG_YMM21,
        UC_X86_REG_YMM22,
        UC_X86_REG_YMM23,
        UC_X86_REG_YMM24,
        UC_X86_REG_YMM25,
        UC_X86_REG_YMM26,
        UC_X86_REG_YMM27,
        UC_X86_REG_YMM28,
        UC_X86_REG_YMM29,
        UC_X86_REG_YMM30,
        UC_X86_REG_YMM31,
        UC_X86_REG_ZMM0,
        UC_X86_REG_ZMM1,
        UC_X86_REG_ZMM2,
        UC_X86_REG_ZMM3,
        UC_X86_REG_ZMM4,
        UC_X86_REG_ZMM5,
        UC_X86_REG_ZMM6,
        UC_X86_REG_ZMM7,
        UC_X86_REG_ZMM8,
        UC_X86_REG_ZMM9,
        UC_X86_REG_ZMM10,
        UC_X86_REG_ZMM11,
        UC_X86_REG_ZMM12,
        UC_X86_REG_ZMM13,
        UC_X86_REG_ZMM14,
        UC_X86_REG_ZMM15,
        UC_X86_REG_ZMM16,
        UC_X86_REG_ZMM17,
        UC_X86_REG_ZMM18,
        UC_X86_REG_ZMM19,
        UC_X86_REG_ZMM20,
        UC_X86_REG_ZMM21,
        UC_X86_REG_ZMM22,
        UC_X86_REG_ZMM23,
        UC_X86_REG_ZMM24,
        UC_X86_REG_ZMM25,
        UC_X86_REG_ZMM26,
        UC_X86_REG_ZMM27,
        UC_X86_REG_ZMM28,
        UC_X86_REG_ZMM29,
        UC_X86_REG_ZMM30,
        UC_X86_REG_ZMM31,
        UC_X86_REG_R8B,
        UC_X86_REG_R9B,
        UC_X86_REG_R10B,
        UC_X86_REG_R11B,
        UC_X86_REG_R12B,
        UC_X86_REG_R13B,
        UC_X86_REG_R14B,
        UC_X86_REG_R15B,
        UC_X86_REG_R8D,
        UC_X86_REG_R9D,
        UC_X86_REG_R10D,
        UC_X86_REG_R11D,
        UC_X86_REG_R12D,
        UC_X86_REG_R13D,
        UC_X86_REG_R14D,
        UC_X86_REG_R15D,
        UC_X86_REG_R8W,
        UC_X86_REG_R9W,
        UC_X86_REG_R10W,
        UC_X86_REG_R11W,
        UC_X86_REG_R12W,
        UC_X86_REG_R13W,
        UC_X86_REG_R14W,
        UC_X86_REG_R15W,
        UC_X86_REG_IDTR,
        UC_X86_REG_GDTR,
        UC_X86_REG_LDTR,
        UC_X86_REG_TR,
        UC_X86_REG_FPCW,
        UC_X86_REG_FPTAG,
        UC_X86_REG_MSR,
        UC_X86_REG_MXCSR,
        UC_X86_REG_FS_BASE,
        UC_X86_REG_GS_BASE,
        UC_X86_REG_FLAGS,
        UC_X86_REG_RFLAGS,
        UC_X86_REG_FIP,
        UC_X86_REG_FCS,
        UC_X86_REG_FDP,
        UC_X86_REG_FDS,
        UC_X86_REG_FOP
    }

    /// <summary>
    /// CPU Flags.
    /// </summary>
    [Flags]
    public enum CPUFlags : ulong
    {
        CF = 0x0001,
        PF = 0x0004,
        AF = 0x0010,
        ZF = 0x0040,
        SF = 0x0080,
        TF = 0x0100,
        IF = 0x0200,
        DF = 0x0400,
        OF = 0x0800,
        IOPL = 0x3000,
        NT = 0x4000,
        RF = 0x10000,
        VM = 0x20000,
        AC = 0x40000,
        VIF = 0x80000,
        VIP = 0x100000,
        ID = 0x200000,
        SYSRET = 0x40000000
    }

    /// <summary>
    /// Instruction hooks supported by unicorn.
    /// </summary>
    public enum INSTHooks
    {
        UC_X86_INS_CPUID = 113,
        UC_X86_INS_IN = 218,
        UC_X86_INS_OUT = 500,
        UC_X86_INS_RDTSC = 608,
        UC_X86_INS_RDTSCP = 609,
        UC_X86_INS_SYSCALL = 699,
        UC_X86_INS_SYSENTER = 700,
        UC_X86_INS_HLT = 212,
    }

    /// <summary>
    /// Unicorn hooks.
    /// </summary>
    public enum Hooks : uint
    {
        // Hook all interrupt/syscall events
        UC_HOOK_INTR = 1 << 0,
        // Hook a particular instruction - only a very small subset of instructions
        // supported here
        UC_HOOK_INSN = 1 << 1,
        // Hook a range of code
        UC_HOOK_CODE = 1 << 2,
        // Hook basic blocks
        UC_HOOK_BLOCK = 1 << 3,
        // Hook for memory read on unmapped memory
        UC_HOOK_MEM_READ_UNMAPPED = 1 << 4,
        // Hook for invalid memory write events
        UC_HOOK_MEM_WRITE_UNMAPPED = 1 << 5,
        // Hook for invalid memory fetch for execution events
        UC_HOOK_MEM_FETCH_UNMAPPED = 1 << 6,
        // Hook for memory read on read-protected memory
        UC_HOOK_MEM_READ_PROT = 1 << 7,
        // Hook for memory write on write-protected memory
        UC_HOOK_MEM_WRITE_PROT = 1 << 8,
        // Hook for memory fetch on non-executable memory
        UC_HOOK_MEM_FETCH_PROT = 1 << 9,
        // Hook memory read events.
        UC_HOOK_MEM_READ = 1 << 10,
        // Hook memory write events.
        UC_HOOK_MEM_WRITE = 1 << 11,
        // Hook memory fetch for execution events
        UC_HOOK_MEM_FETCH = 1 << 12,
        // Hook memory read events, but only successful access.
        // The callback will be triggered after successful read.
        UC_HOOK_MEM_READ_AFTER = 1 << 13,
        // Hook invalid instructions exceptions.
        UC_HOOK_INSN_INVALID = 1 << 14,
        // Hook on new edge generation. Could be useful in program analysis.
        //
        // NOTE: This is different from UC_HOOK_BLOCK in 2 ways:
        //       1. The hook is called before executing code.
        //       2. The hook is only called when generation is triggered.
        UC_HOOK_EDGE_GENERATED = 1 << 15,
        // Hook on specific tcg op code. The usage of this hook is similar to
        // UC_HOOK_INSN.
        UC_HOOK_TCG_OPCODE = 1 << 16,
        // Hook on tlb fill requests.
        // Register tlb fill request hook on the virtuall addresses.
        // The callback will be triggert if the tlb cache don't contain an address.
        UC_HOOK_TLB_FILL = 1 << 17,
    }

    /// <summary>
    /// Memory protections for pages.
    /// </summary>
    [Flags]
    public enum MemoryProtection
    {
        None = 0,
        Read = 1,
        Write = 2,
        Execute = 4,
        ReadWrite = Read | Write,
        WriteExecute = Write | Execute,
        ReadExecute = Read | Execute,
        All = Read | Write | Execute,
    }

    /// <summary>
    /// Unicorn memory types.
    /// </summary>
    public enum MemoryType
    {
        UC_MEM_READ = 16,      // Memory is read from
        UC_MEM_WRITE,          // Memory is written to
        UC_MEM_FETCH,          // Memory is fetched
        UC_MEM_READ_UNMAPPED,  // Unmapped memory is read from
        UC_MEM_WRITE_UNMAPPED, // Unmapped memory is written to
        UC_MEM_FETCH_UNMAPPED, // Unmapped memory is fetched
        UC_MEM_WRITE_PROT,     // Write to write protected, but mapped, memory
        UC_MEM_READ_PROT,      // Read from read protected, but mapped, memory
        UC_MEM_FETCH_PROT,     // Fetch from non-executable, but mapped, memory
        UC_MEM_READ_AFTER,     // Memory is read from (successful access)
    }

    public enum UcTlbType : int
    {
        Cpu = 0,
        Virtual = 1
    }
}
