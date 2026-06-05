using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Brovan.Core.Emulation.OS.Linux;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation
{
    /// <summary>
    /// Windows syscall handling interface.
    /// </summary>
    public interface IWinSyscall
    {
        /// <summary>
        /// Handler for Windows syscalls.
        /// </summary>
        /// <param name="Instance">The emulator's instance.</param>
        /// <returns>returns the status of the operation done by the syscall.</returns>
        /// <remarks>
        /// <para>
        /// Uses the convention for x64 as follows to emulate syscalls: parameters by order is R10 (moved from RCX), RDX, R8, R9 and the rest is on the stack.
        /// </para>
        /// <para>
        /// Uses the convention for x86 as follows to emulate syscalls: all parameters are on the stack while keeping in mind to skip the return address (e.g. ESP+4).
        /// </para>
        /// </remarks>
        public NTSTATUS Handle(BinaryEmulator Instance);
    }

    public enum SyscallAbi
    {
        X86,
        X64
    }

    public struct LinuxSyscallContext
    {
        public SyscallAbi Abi;
        public ulong Arg0;
        public ulong Arg1;
        public ulong Arg2;
        public ulong Arg3;
        public ulong Arg4;
        public ulong Arg5;
    }

    /// <summary>
    /// Linux syscall handling interface.
    /// </summary>
    public interface ILinuxSyscall
    {
        /// <summary>
        /// Handler for Linux syscalls.
        /// </summary>
        /// <param name="Instance">the emulator's instance.</param>
        /// <remarks>
        /// <para>
        /// The convention for x64 linux syscalls by parameter order is RDI, RSI, RDX, R10, R8, R9.
        /// </para>
        /// <para>
        /// The convention for x86 linux syscalls by parameter order is EBX, ECX, EDX, ESI, EDI, EBP.
        /// </para>
        /// </remarks>
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context);
    }

    public enum GuestOsKind
    {
        Windows,
        Linux,
        Generic
    }

    public interface IGuestEnvironment
    {
        GuestOsKind Os { get; }

        void Initialize(BinaryEmulator Instance, BinaryFile Binary);
        void Start(BinaryEmulator Instance);

        bool TryHandleSyscall(BinaryEmulator Instance);
        bool TryHandleInterrupt(BinaryEmulator Instance, uint InterruptNumber);
        void HandlePrivilegedInstruction(BinaryEmulator Instance);
        void HandleInvalidInstruction(BinaryEmulator Instance);
        bool HandleInvalidMemory(BinaryEmulator Instance, MemoryType Type, ulong Address, uint Size, ulong Value);

        ulong CreateInitialThread(BinaryEmulator Instance);
        EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name = null!, ulong Parameter = 0, ulong? StackSizeOverride = null, int BasePriority = 8);
        void OnThreadContextLoaded(BinaryEmulator Instance, EmulatedThread Thread);
        bool HasPendingGuestWork(BinaryEmulator Instance, EmulatedThread Thread);
        bool IsHandleSignaled(BinaryEmulator Instance, ulong Handle);
        bool ExecuteThreadSlice(BinaryEmulator Instance, EmulatedThread Thread, uint QuantumInstructions, out bool State);
        void OnThreadWaitSatisfied(BinaryEmulator Instance, EmulatedThread Thread);
    }

    internal delegate void InstDelegate(IntPtr uc, IntPtr user_data);

    internal delegate bool InstBoolDelegate(IntPtr uc, IntPtr user_data);

    internal delegate void InterruptDelegate(IntPtr uc, uint interrupt_number);

    internal delegate bool MemoryDelegate(IntPtr uc, MemoryType Type, ulong Address, uint Size, ulong value, IntPtr user_data);

    [Flags]
    public enum SpecialProtections
    {
        None = 0,
        Guard = 1 << 0
    }

    [Flags]
    public enum AllocationType
    {
        None = 1 << 0,
        Reserved = 1 << 1,
        Commited = 1 << 2,
        Image = 1 << 3,
    }

    public struct MemoryRegion
    {
        /// <summary>
        /// The base address of the memory region.
        /// </summary>
        public ulong BaseAddress;

        /// <summary>
        /// The size of the memory region.
        /// </summary>
        public ulong Size;

        public ulong RequestedSize;

        public ulong AllocationBase;

        public uint AllocationProtect;

        public uint Protect;

        public bool IsReserved;
        public bool IsCommitted;
        public bool IsReset;

        /// <summary>
        /// Initial memory protections when the region was allocated.
        /// </summary>
        public MemoryProtection InitialProtections;

        /// <summary>
        /// Memory protections.
        /// </summary>
        public MemoryProtection Protections;

        /// <summary>
        /// Special protections for the memory region (other than read, write or execute)
        /// </summary>
        public SpecialProtections SpecialProtections;

        /// <summary>
        /// Allocation flags for the memory region.
        /// </summary>
        public AllocationType Flags;

        /// <summary>
        /// Indicates the start and end of the poisoned memory. will only be set if the page size is not aligned.
        /// </summary>
        public ValueTuple<ulong, ulong> PoisonedMemory;
    }

    public class EmulatorSnapshot
    {
        public bool IsLazy;
        public Dictionary<Registers, ulong> Registers { get; set; }
        public Dictionary<ulong, byte[]> MemoryRegions { get; set; }
        public HashSet<ulong> OriginalRegionAddresses { get; set; }
    }

    public readonly struct ApiSetOverrideKey : IEquatable<ApiSetOverrideKey>
    {
        public readonly string ContractName;
        public readonly string ImportingModuleName;

        public ApiSetOverrideKey(string ContractName, string ImportingModuleName)
        {
            this.ContractName = ContractName ?? string.Empty;
            this.ImportingModuleName = ImportingModuleName ?? string.Empty;
        }

        public bool Equals(ApiSetOverrideKey Other)
        {
            return string.Equals(ContractName, Other.ContractName, StringComparison.OrdinalIgnoreCase)
                && string.Equals(ImportingModuleName, Other.ImportingModuleName, StringComparison.OrdinalIgnoreCase);
        }

        public override bool Equals(object Obj)
        {
            return Obj is ApiSetOverrideKey Other && Equals(Other);
        }

        public override int GetHashCode()
        {
            int Hash1 = StringComparer.OrdinalIgnoreCase.GetHashCode(ContractName);
            int Hash2 = StringComparer.OrdinalIgnoreCase.GetHashCode(ImportingModuleName);
            return unchecked((Hash1 * 397) ^ Hash2);
        }
    }

    /// <summary>
    /// Helper functions for handling windows emulation
    /// </summary>
    public class HelperFunctions
    {
        /// <summary>
        /// Internal mapping of known API Set DLLs to their actual host DLLs.
        /// </summary>
        public static readonly Dictionary<string, string> ApiSetMap = new()
        {
            ["api-ms-onecoreuap-print-render-l1-1-0.dll"] = "printrenderapihost.dll",
            ["api-ms-win-appmodel-advertisingid-l1-1-0.dll"] = "kernel.appcore.dll",
            ["api-ms-win-appmodel-identity-l1-2-0.dll"] = "kernel.appcore.dll",
            ["api-ms-win-appmodel-lifecyclepolicy-l1-1-0.dll"] = "rmclient.dll",
            ["api-ms-win-appmodel-runtime-internal-l1-1-11.dll"] = "kernel.appcore.dll",
            ["api-ms-win-appmodel-runtime-l1-1-7.dll"] = "kernel.appcore.dll",
            ["api-ms-win-appmodel-state-l1-1-2.dll"] = "kernel.appcore.dll",
            ["api-ms-win-appmodel-state-l1-2-0.dll"] = "kernel.appcore.dll",
            ["api-ms-win-appmodel-unlock-l1-1-0.dll"] = "kernel.appcore.dll",
            ["api-ms-win-audiocore-spatial-config-l1-1-0.dll"] = "windows.media.devices.dll",
            ["api-ms-win-base-bootconfig-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-base-util-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-composition-redirection-l1-1-0.dll"] = "dwmredir.dll",
            ["api-ms-win-composition-windowmanager-l1-1-0.dll"] = "udwm.dll",
            ["api-ms-win-containers-cmclient-l1-1-1.dll"] = "cmclient.dll",
            ["api-ms-win-containers-cmclient-l1-2-0.dll"] = "cmclient.dll",
            ["api-ms-win-containers-cmclient-l1-3-0.dll"] = "cmclient.dll",
            ["api-ms-win-containers-cmclient-l1-4-0.dll"] = "cmclient.dll",
            ["api-ms-win-containers-cmclient-l1-5-3.dll"] = "cmclient.dll",
            ["api-ms-win-containers-cmdiagclient-l1-1-2.dll"] = "cmclient.dll",
            ["api-ms-win-containers-cmservicingclient-l1-1-1.dll"] = "cmclient.dll",
            ["api-ms-win-containers-cmservicingclient-l1-2-2.dll"] = "cmclient.dll",
            ["api-ms-win-core-apiquery-l1-1-2.dll"] = "ntdll.dll",
            ["api-ms-win-core-apiquery-l2-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-appcompat-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-appinit-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-atoms-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-backgroundtask-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-bicltapi-l1-1-6.dll"] = "bi.dll",
            ["api-ms-win-core-biplmapi-l1-1-5.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-biplmapi-l1-2-0.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-biptcltapi-l1-1-7.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-calendar-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-com-l1-1-3.dll"] = "combase.dll",
            ["api-ms-win-core-com-l2-1-1.dll"] = "coml2.dll",
            ["api-ms-win-core-com-midlproxystub-l1-1-0.dll"] = "combase.dll",
            ["api-ms-win-core-com-private-l1-1-1.dll"] = "combase.dll",
            ["api-ms-win-core-com-private-l1-2-0.dll"] = "combase.dll",
            ["api-ms-win-core-com-private-l1-3-1.dll"] = "combase.dll",
            ["api-ms-win-core-comm-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-commandlinetoargv-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-console-ansi-l2-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-console-internal-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-console-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-console-l1-2-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-console-l2-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-console-l2-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-console-l3-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-console-l3-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-crt-l1-1-0.dll"] = "ntdll.dll",
            ["api-ms-win-core-crt-l2-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-datetime-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-debug-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-debug-minidump-l1-1-0.dll"] = "dbgcore.dll",
            ["api-ms-win-core-delayload-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-enclave-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-errorhandling-l1-1-3.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-featurestaging-l1-1-1.dll"] = "shcore.dll",
            ["api-ms-win-core-featuretoggles-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-fibers-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-fibers-l2-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-file-ansi-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-file-ansi-l2-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-file-fromapp-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-file-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-file-l1-2-5.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-file-l2-1-4.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-firmware-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-guard-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-handle-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-heap-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-heap-l1-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-heap-l2-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-heap-obsolete-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-interlocked-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-interlocked-l1-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-io-l1-1-1.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-ioring-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-job-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-job-l2-1-1.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-kernel32-legacy-ansi-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-kernel32-legacy-l1-1-6.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-kernel32-private-l1-1-2.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-kernel32-private-l1-2-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-largeinteger-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-libraryloader-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-libraryloader-l1-2-3.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-libraryloader-l2-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-libraryloader-private-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-localization-ansi-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-localization-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-localization-l1-2-4.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-localization-l2-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-localization-obsolete-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-localization-obsolete-l1-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-localization-obsolete-l1-3-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-localization-private-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-localregistry-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-marshal-l1-1-0.dll"] = "combase.dll",
            ["api-ms-win-core-memory-l1-1-9.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-misc-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-multipleproviderrouter-l1-1-0.dll"] = "mpr.dll",
            ["api-ms-win-core-namedpipe-ansi-l1-1-1.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-namedpipe-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-namedpipe-l1-2-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-namespace-ansi-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-namespace-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-normalization-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-path-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-pcw-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-perfcounters-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-perfcounters-l1-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-privateprofile-l1-1-1.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-processenvironment-ansi-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-processenvironment-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-processenvironment-l1-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-processsecurity-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-processsnapshot-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-processthreads-l1-1-8.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-processtopology-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-processtopology-l1-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-processtopology-obsolete-l1-1-1.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-processtopology-private-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-profile-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-psapi-ansi-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-psapi-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-psapi-obsolete-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-psapiansi-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-psm-app-l1-1-0.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-psm-appnotify-l1-1-1.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-psm-info-l1-1-1.dll"] = "appsruprov.dll",
            ["api-ms-win-core-psm-key-l1-1-3.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-psm-plm-l1-1-3.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-psm-plm-l1-2-0.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-psm-plm-l1-3-0.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-psm-rtimer-l1-1-1.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-psm-tc-l1-1-1.dll"] = "twinapi.appcore.dll",
            ["api-ms-win-core-quirks-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-realtime-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-registry-fromapp-l1-1-0.dll"] = "reguwpapi.dll",
            ["api-ms-win-core-registry-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-registry-l2-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-core-registry-l2-2-0.dll"] = "advapi32.dll",
            ["api-ms-win-core-registry-l2-3-0.dll"] = "advapi32.dll",
            ["api-ms-win-core-registry-private-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-core-registryuserspecific-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-rtlsupport-l1-1-1.dll"] = "ntdll.dll",
            ["api-ms-win-core-rtlsupport-l1-2-2.dll"] = "ntdll.dll",
            ["api-ms-win-core-shlwapi-legacy-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-shlwapi-obsolete-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-shlwapi-obsolete-l1-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-shutdown-ansi-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-core-shutdown-l1-1-1.dll"] = "advapi32.dll",
            ["api-ms-win-core-sidebyside-ansi-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-sidebyside-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-slapi-l1-1-0.dll"] = "clipc.dll",
            ["api-ms-win-core-state-helpers-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-string-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-string-l2-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-string-obsolete-l1-1-1.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-stringansi-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-stringloader-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-synch-ansi-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-synch-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-synch-l1-2-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-sysinfo-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-sysinfo-l1-2-8.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-sysinfo-l2-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-core-systemtopology-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-textinput-client-l1-1-1.dll"] = "textinputframework.dll",
            ["api-ms-win-core-textinput-client-l1-2-0.dll"] = "textinputframework.dll",
            ["api-ms-win-core-threadpool-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-threadpool-l1-2-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-threadpool-legacy-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-threadpool-private-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-timezone-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-timezone-private-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-toolhelp-l1-1-1.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-ums-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-url-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-util-l1-1-1.dll"] = "KERNEL32.dll",
            ["api-ms-win-core-version-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-version-private-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-versionansi-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-windowsceip-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-windowserrorreporting-l1-1-3.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-winrt-error-l1-1-1.dll"] = "combase.dll",
            ["api-ms-win-core-winrt-errorprivate-l1-1-1.dll"] = "combase.dll",
            ["api-ms-win-core-winrt-l1-1-0.dll"] = "combase.dll",
            ["api-ms-win-core-winrt-propertysetprivate-l1-1-1.dll"] = "wintypes.dll",
            ["api-ms-win-core-winrt-registration-l1-1-0.dll"] = "combase.dll",
            ["api-ms-win-core-winrt-robuffer-l1-1-0.dll"] = "wintypes.dll",
            ["api-ms-win-core-winrt-roparameterizediid-l1-1-0.dll"] = "combase.dll",
            ["api-ms-win-core-winrt-string-l1-1-1.dll"] = "combase.dll",
            ["api-ms-win-core-wow64-l1-1-3.dll"] = "KERNELBASE.dll",
            ["api-ms-win-core-xstate-l1-1-3.dll"] = "ntdll.dll",
            ["api-ms-win-core-xstate-l2-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-crt-conio-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-convert-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-environment-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-filesystem-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-heap-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-locale-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-math-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-multibyte-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-private-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-process-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-runtime-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-stdio-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-string-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-time-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-crt-utility-l1-1-0.dll"] = "ucrtbase.dll",
            ["api-ms-win-deprecated-apis-obsolete-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-devices-config-l1-1-2.dll"] = "cfgmgr32.dll",
            ["api-ms-win-devices-query-l1-1-1.dll"] = "cfgmgr32.dll",
            ["api-ms-win-devices-swdevice-l1-1-1.dll"] = "cfgmgr32.dll",
            ["api-ms-win-downlevel-advapi32-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-downlevel-advapi32-l2-1-0.dll"] = "sechost.dll",
            ["api-ms-win-downlevel-advapi32-l3-1-0.dll"] = "ntmarta.dll",
            ["api-ms-win-downlevel-advapi32-l4-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-downlevel-kernel32-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-downlevel-kernel32-l2-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-downlevel-normaliz-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-downlevel-ole32-l1-1-0.dll"] = "combase.dll",
            ["api-ms-win-downlevel-shell32-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-downlevel-shlwapi-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-downlevel-shlwapi-l2-1-0.dll"] = "shcore.dll",
            ["api-ms-win-downlevel-user32-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-downlevel-version-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-dwmapi-l1-1-0.dll"] = "dwmapi.dll",
            ["api-ms-win-dx-d3dkmt-l1-1-8.dll"] = "gdi32.dll",
            ["api-ms-win-eventing-classicprovider-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-eventing-consumer-l1-1-2.dll"] = "sechost.dll",
            ["api-ms-win-eventing-controller-l1-1-1.dll"] = "sechost.dll",
            ["api-ms-win-eventing-legacy-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-eventing-obsolete-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-eventing-provider-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-eventing-tdh-l1-1-2.dll"] = "tdh.dll",
            ["api-ms-win-eventlog-legacy-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-gaming-deviceinformation-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-gaming-expandedresources-l1-1-0.dll"] = "gamemode.dll",
            ["api-ms-win-gaming-experience-l1-1-0.dll"] = "gamemode.dll",
            ["api-ms-win-gaming-tcui-l1-1-4.dll"] = "gamingtcui.dll",
            ["api-ms-win-gdi-dpiinfo-l1-1-0.dll"] = "gdi32.dll",
            ["api-ms-win-gdi-internal-uap-l1-1-0.dll"] = "gdi32full.dll",
            ["api-ms-win-ham-apphistory-l1-1-0.dll"] = "rmclient.dll",
            ["api-ms-win-ham-hamplm-l1-1-0.dll"] = "rmclient.dll",
            ["api-ms-win-http-time-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-legacy-shlwapi-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-mm-joystick-l1-1-0.dll"] = "winmm.dll",
            ["api-ms-win-mm-mci-l1-1-0.dll"] = "winmm.dll",
            ["api-ms-win-mm-misc-l1-1-1.dll"] = "winmmbase.dll",
            ["api-ms-win-mm-misc-l2-1-0.dll"] = "winmm.dll",
            ["api-ms-win-mm-mme-l1-1-0.dll"] = "winmmbase.dll",
            ["api-ms-win-mm-playsound-l1-1-0.dll"] = "winmm.dll",
            ["api-ms-win-mm-time-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-net-isolation-l1-1-1.dll"] = "firewallapi.dll",
            ["api-ms-win-networking-interfacecontexts-l1-1-0.dll"] = "ondemandconnroutehelper.dll",
            ["api-ms-win-ngc-serialization-l1-1-1.dll"] = "ngckeyenum.dll",
            ["api-ms-win-ntuser-ie-message-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-ntuser-ie-window-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-ntuser-ie-wmpointer-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-ntuser-rectangle-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-ntuser-sysparams-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-obsolete-localization-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-obsolete-psapi-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-obsolete-shlwapi-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-ole32-ie-l1-1-0.dll"] = "ole32.dll",
            ["api-ms-win-oobe-notification-l1-1-0.dll"] = "KERNEL32.dll",
            ["api-ms-win-perf-legacy-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-power-base-l1-1-0.dll"] = "powrprof.dll",
            ["api-ms-win-power-limitsmanagement-l1-1-0.dll"] = "powrprof.dll",
            ["api-ms-win-power-setting-l1-1-1.dll"] = "powrprof.dll",
            ["api-ms-win-privacy-coreprivacysettingsstore-l1-1-0.dll"] = "coreprivacysettingsstore.dll",
            ["api-ms-win-ro-typeresolution-l1-1-1.dll"] = "wintypes.dll",
            ["api-ms-win-rtcore-ntuser-clipboard-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-draw-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-powermanagement-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-private-l1-1-11.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-shell-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-synch-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-window-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-winevent-l1-1-0.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-wmpointer-l1-1-3.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ntuser-wmpointer-l1-2-0.dll"] = "user32.dll",
            ["api-ms-win-rtcore-ole32-clipboard-l1-1-1.dll"] = "ole32.dll",
            ["api-ms-win-security-accesshlpr-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-security-activedirectoryclient-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-security-appcontainer-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-security-audit-l1-1-1.dll"] = "sechost.dll",
            ["api-ms-win-security-base-ansi-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-security-base-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-security-base-l1-2-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-security-base-private-l1-1-2.dll"] = "KERNELBASE.dll",
            ["api-ms-win-security-capability-l1-1-1.dll"] = "sechost.dll",
            ["api-ms-win-security-cpwl-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-security-credentials-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-security-credentials-l2-1-1.dll"] = "sechost.dll",
            ["api-ms-win-security-cryptoapi-l1-1-0.dll"] = "cryptsp.dll",
            ["api-ms-win-security-grouppolicy-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-security-isolatedcontainer-l1-1-1.dll"] = "shcore.dll",
            ["api-ms-win-security-isolationapi-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-security-isolationapi-l1-2-0.dll"] = "sechost.dll",
            ["api-ms-win-security-isolationpolicy-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-security-isolationpolicy-l1-2-0.dll"] = "sechost.dll",
            ["api-ms-win-security-licenseprotection-l1-1-0.dll"] = "licenseprotection.dll",
            ["api-ms-win-security-logon-l1-1-1.dll"] = "advapi32.dll",
            ["api-ms-win-security-lsalookup-ansi-l2-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-security-lsalookup-l1-1-2.dll"] = "sechost.dll",
            ["api-ms-win-security-lsalookup-l2-1-1.dll"] = "advapi32.dll",
            ["api-ms-win-security-lsapolicy-l1-1-2.dll"] = "sechost.dll",
            ["api-ms-win-security-provider-ansi-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-security-provider-l1-1-0.dll"] = "ntmarta.dll",
            ["api-ms-win-security-sddl-ansi-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-security-sddl-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-security-sddl-private-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-security-sddlparsecond-l1-1-1.dll"] = "sechost.dll",
            ["api-ms-win-security-systemfunctions-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-security-trustee-l1-1-2.dll"] = "advapi32.dll",
            ["api-ms-win-service-core-ansi-l1-1-1.dll"] = "advapi32.dll",
            ["api-ms-win-service-core-l1-1-5.dll"] = "sechost.dll",
            ["api-ms-win-service-legacy-l1-1-0.dll"] = "advapi32.dll",
            ["api-ms-win-service-management-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-service-management-l2-1-0.dll"] = "sechost.dll",
            ["api-ms-win-service-private-l1-1-5.dll"] = "sechost.dll",
            ["api-ms-win-service-private-l1-2-2.dll"] = "sechost.dll",
            ["api-ms-win-service-winsvc-l1-1-0.dll"] = "sechost.dll",
            ["api-ms-win-service-winsvc-l1-2-0.dll"] = "sechost.dll",
            ["api-ms-win-shcore-comhelpers-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shcore-obsolete-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shcore-path-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shcore-registry-l1-1-1.dll"] = "shcore.dll",
            ["api-ms-win-shcore-scaling-l1-1-2.dll"] = "shcore.dll",
            ["api-ms-win-shcore-stream-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shcore-stream-winrt-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shcore-sysinfo-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shcore-taskpool-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shcore-thread-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shcore-unicodeansi-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shell-associations-l1-1-3.dll"] = "windows.storage.dll",
            ["api-ms-win-shell-changenotify-l1-1-1.dll"] = "windows.storage.dll",
            ["api-ms-win-shell-dataobject-l1-1-1.dll"] = "windows.storage.dll",
            ["api-ms-win-shell-namespace-l1-1-1.dll"] = "windows.storage.dll",
            ["api-ms-win-shell-shdirectory-l1-1-0.dll"] = "shcore.dll",
            ["api-ms-win-shell-shellcom-l1-1-0.dll"] = "KERNELBASE.dll",
            ["api-ms-win-shell-shellfolders-l1-1-1.dll"] = "windows.storage.dll",
            ["api-ms-win-shlwapi-ie-l1-1-0.dll"] = "shlwapi.dll",
            ["api-ms-win-shlwapi-winrt-storage-l1-1-1.dll"] = "shlwapi.dll",
            ["api-ms-win-stateseparation-helpers-l1-1-1.dll"] = "KERNELBASE.dll",
            ["api-ms-win-storage-exports-external-l1-1-2.dll"] = "windows.storage.dll",
            ["api-ms-win-storage-exports-internal-l1-1-0.dll"] = "windows.storage.dll",
            ["api-ms-win-storage-reserve-l1-1-0.dll"] = "storageusage.dll",
            ["api-ms-win-winrt-search-folder-l1-1-1.dll"] = "windows.storage.search.dll",
            ["api-ms-win-wsl-api-l1-1-0.dll"] = "wslapi.dll",
            ["ext-ms-net-eap-sim-l1-1-0.dll"] = "eapsimextdesktop.dll",
            ["ext-ms-net-vpn-soh-l1-1-0.dll"] = "vpnsohdesktop.dll",
            ["ext-ms-onecore-appdefaults-l1-1-0.dll"] = "windows.storage.dll",
            ["ext-ms-onecore-appmodel-deployment-internal-l1-1-2.dll"] = "appxdeploymentclient.dll",
            ["ext-ms-onecore-appmodel-staterepository-appextension-l1-1-0.dll"] = "windows.staterepositoryclient.dll",
            ["ext-ms-onecore-appmodel-staterepository-cache-l1-1-5.dll"] = "windows.staterepositorycore.dll",
            ["ext-ms-onecore-appmodel-staterepository-internal-l1-1-7.dll"] = "windows.staterepositoryclient.dll",
            ["ext-ms-onecore-appmodel-staterepository-pkgextension-l1-1-0.dll"] = "windows.staterepositoryclient.dll",
            ["ext-ms-onecore-appmodel-tdlmigration-l1-1-1.dll"] = "tdlmigration.dll",
            ["ext-ms-onecore-dcomp-l1-1-0.dll"] = "dcomp.dll",
            ["ext-ms-onecore-hlink-l1-1-0.dll"] = "hlink.dll",
            ["ext-ms-onecore-hnetcfg-l1-1-0.dll"] = "hnetcfgclient.dll",
            ["ext-ms-onecore-ipnathlp-l1-1-0.dll"] = "ipnathlpclient.dll",
            ["ext-ms-onecore-service-devicedirectory-claims-l1-1-0.dll"] = "ddcclaimsapi.dll",
            ["ext-ms-onecore-shlwapi-l1-1-0.dll"] = "shlwapi.dll",
            ["ext-ms-win-accel-api-km-l1-1-0.dll"] = "winaccel.sys",
            ["ext-ms-win-adsi-activeds-l1-1-0.dll"] = "activeds.dll",
            ["ext-ms-win-advapi32-auth-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-encryptedfile-l1-1-1.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-eventlog-ansi-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-eventlog-l1-1-2.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-hwprof-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-idletask-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-lsa-l1-1-4.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-msi-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-npusername-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-ntmarta-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-psm-app-l1-1-0.dll"] = "twinapi.appcore.dll",
            ["ext-ms-win-advapi32-registry-l1-1-1.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-safer-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-advapi32-shutdown-l1-1-0.dll"] = "advapi32.dll",
            ["ext-ms-win-appcompat-aeinv-l1-1-1.dll"] = "aeinv.dll",
            ["ext-ms-win-appcompat-aepic-l1-1-0.dll"] = "aepic.dll",
            ["ext-ms-win-appcompat-apphelp-l1-1-2.dll"] = "apphelp.dll",
            ["ext-ms-win-appcompat-pcacli-l1-1-0.dll"] = "pcacli.dll",
            ["ext-ms-win-appmodel-activation-l1-1-2.dll"] = "activationmanager.dll",
            ["ext-ms-win-appmodel-appexecutionalias-l1-1-5.dll"] = "apisethost.appexecutionalias.dll",
            ["ext-ms-win-appmodel-daxcore-l1-1-3.dll"] = "daxexec.dll",
            ["ext-ms-win-appmodel-opc-l1-1-0.dll"] = "opcservices.dll",
            ["ext-ms-win-appmodel-registrycompatibility-l1-1-0.dll"] = "appxdeploymentextensions.desktop.dll",
            ["ext-ms-win-appmodel-restrictedappcontainer-internal-l1-1-0.dll"] = "kernel.appcore.dll",
            ["ext-ms-win-appmodel-shellexecute-l1-1-0.dll"] = "windows.storage.dll",
            ["ext-ms-win-appmodel-state-ext-l1-2-0.dll"] = "kernel.appcore.dll",
            ["ext-ms-win-appxdeploymentclient-appxdeploy-l1-1-1.dll"] = "appxdeploymentclient.dll",
            ["ext-ms-win-appxdeploymentclient-appxdeployonecore-l1-1-1.dll"] = "appxdeploymentclient.dll",
            ["ext-ms-win-audiocore-coreaudiopolicymanager-l1-1-0.dll"] = "coreaudiopolicymanagerext.dll",
            ["ext-ms-win-authz-claimpolicies-l1-1-0.dll"] = "authz.dll",
            ["ext-ms-win-authz-context-l1-1-0.dll"] = "authz.dll",
            ["ext-ms-win-authz-remote-l1-1-0.dll"] = "logoncli.dll",
            ["ext-ms-win-base-psapi-l1-1-0.dll"] = "psapi.dll",
            ["ext-ms-win-base-rstrtmgr-l1-1-0.dll"] = "rstrtmgr.dll",
            ["ext-ms-win-biometrics-winbio-core-l1-1-7.dll"] = "winbio.dll",
            ["ext-ms-win-biometrics-winbio-l1-1-0.dll"] = "winbioext.dll",
            ["ext-ms-win-biometrics-winbio-l1-2-0.dll"] = "winbioext.dll",
            ["ext-ms-win-biometrics-winbio-l1-3-0.dll"] = "winbioext.dll",
            ["ext-ms-win-bluetooth-apis-internal-l1-1-0.dll"] = "bluetoothapis.dll",
            ["ext-ms-win-bluetooth-apis-l1-1-0.dll"] = "bluetoothapis.dll",
            ["ext-ms-win-bluetooth-apis-private-l1-1-0.dll"] = "bluetoothapis.dll",
            ["ext-ms-win-branding-winbrand-l1-1-2.dll"] = "winbrand.dll",
            ["ext-ms-win-branding-winbrand-l1-2-0.dll"] = "winbrand.dll",
            ["ext-ms-win-capabilityaccessmanager-storage-l1-1-0.dll"] = "capabilityaccessmanager.desktop.storage.dll",
            ["ext-ms-win-casting-lockscreen-l1-1-0.dll"] = "miracastreceiverext.dll",
            ["ext-ms-win-casting-shell-l1-1-0.dll"] = "castingshellext.dll",
            ["ext-ms-win-ci-management-l1-1-3.dll"] = "manageci.dll",
            ["ext-ms-win-cluster-clusapi-l1-1-6.dll"] = "clusapi.dll",
            ["ext-ms-win-cluster-resutils-l1-1-3.dll"] = "resutils.dll",
            ["ext-ms-win-cmd-util-l1-1-0.dll"] = "cmdext.dll",
            ["ext-ms-win-cng-rng-l1-1-1.dll"] = "bcryptprimitives.dll",
            ["ext-ms-win-com-clbcatq-l1-1-0.dll"] = "clbcatq.dll",
            ["ext-ms-win-com-coml2-l1-1-1.dll"] = "coml2.dll",
            ["ext-ms-win-com-ole32-l1-1-5.dll"] = "ole32.dll",
            ["ext-ms-win-com-ole32-l1-2-0.dll"] = "ole32.dll",
            ["ext-ms-win-com-ole32-l1-3-0.dll"] = "ole32.dll",
            ["ext-ms-win-com-ole32-l1-4-0.dll"] = "ole32.dll",
            ["ext-ms-win-com-psmregister-l1-1-0.dll"] = "kernel.appcore.dll",
            ["ext-ms-win-com-psmregister-l1-2-2.dll"] = "kernel.appcore.dll",
            ["ext-ms-win-com-psmregister-l1-3-1.dll"] = "kernel.appcore.dll",
            ["ext-ms-win-com-sta-l1-1-0.dll"] = "ole32.dll",
            ["ext-ms-win-composition-ghost-l1-1-0.dll"] = "dwmghost.dll",
            ["ext-ms-win-composition-init-l1-1-0.dll"] = "dwminit.dll",
            ["ext-ms-win-compositor-hosting-l1-1-1.dll"] = "ism.dll",
            ["ext-ms-win-compositor-hosting-l1-2-1.dll"] = "ism.dll",
            ["ext-ms-win-compositor-hosting-l1-3-0.dll"] = "ism.dll",
            ["ext-ms-win-connectionattribution-api-l1-1-0.dll"] = "connectionattributionapi.dll",
            ["ext-ms-win-core-game-streaming-l1-1-0.dll"] = "gamestreamingext.dll",
            ["ext-ms-win-core-iuri-l1-1-0.dll"] = "urlmon.dll",
            ["ext-ms-win-core-marshal-l2-1-0.dll"] = "ole32.dll",
            ["ext-ms-win-core-pkeyhelper-l1-1-0.dll"] = "pkeyhelper.dll",
            ["ext-ms-win-core-psm-bi-l1-1-0.dll"] = "bisrv.dll",
            ["ext-ms-win-core-psm-bi-l1-2-0.dll"] = "bisrv.dll",
            ["ext-ms-win-core-psm-service-l1-1-6.dll"] = "psmserviceexthost.dll",
            ["ext-ms-win-core-resourcemanager-l1-1-0.dll"] = "rmclient.dll",
            ["ext-ms-win-core-resourcemanager-l1-2-1.dll"] = "rmclient.dll",
            ["ext-ms-win-core-resourcepolicy-l1-1-2.dll"] = "resourcepolicyclient.dll",
            ["ext-ms-win-core-resourcepolicyserver-l1-1-1.dll"] = "resourcepolicyserver.dll",
            ["ext-ms-win-core-storelicensing-l1-1-0.dll"] = "licensemanagerapi.dll",
            ["ext-ms-win-core-storelicensing-l1-2-1.dll"] = "licensemanagerapi.dll",
            ["ext-ms-win-core-symbolicnames-l1-1-0.dll"] = "tdhres.dll",
            ["ext-ms-win-core-win32k-base-export-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-baseinit-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-common-export-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-common-input-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-common-inputrim-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-common-user-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-dcomp-l1-1-3.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-ddccigdi-l1-1-1.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-dxgdi-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-dxgk-internal-l1-1-0.dll"] = "dxgkrnl.sys",
            ["ext-ms-win-core-win32k-dxgk-l1-1-0.dll"] = "dxgkrnl.sys",
            ["ext-ms-win-core-win32k-flipmgr-l1-1-1.dll"] = "dxgkrnl.sys",
            ["ext-ms-win-core-win32k-full-export-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-full-float-export-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-fulldcompbase-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-fulldwm-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-fullgdi-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-fulluser-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-fulluser64-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-core-win32k-fulluserbase-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-gdi-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-input-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-inputmit-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-inputrim-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-mininputmitbase-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-opmgdi-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-surfmgr-l1-1-1.dll"] = "dxgkrnl.sys",
            ["ext-ms-win-core-win32k-tokenmgr-l1-1-0.dll"] = "dxgkrnl.sys",
            ["ext-ms-win-core-win32k-user-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-userdisplay-l1-1-0.dll"] = "win32kbase.sys",
            ["ext-ms-win-core-win32k-userinit-l1-1-0.dll"] = "win32k.sys",
            ["ext-ms-win-core-winsrv-l1-1-0.dll"] = "winsrvext.dll",
            ["ext-ms-win-coreui-navshutdown-l1-1-0.dll"] = "navshutdown.dll",
            ["ext-ms-win-deployment-productenumerator-l1-1-0.dll"] = "productenumerator.dll",
            ["ext-ms-win-desktopappx-l1-1-7.dll"] = "daxexec.dll",
            ["ext-ms-win-desktopappx-l1-2-2.dll"] = "daxexec.dll",
            ["ext-ms-win-devmgmt-dm-l1-1-3.dll"] = "dmapisetextimpldesktop.dll",
            ["ext-ms-win-devmgmt-policy-l1-1-3.dll"] = "policymanager.dll",
            ["ext-ms-win-direct2d-desktop-l1-1-0.dll"] = "direct2ddesktop.dll",
            ["ext-ms-win-domainjoin-netjoin-l1-1-0.dll"] = "netjoin.dll",
            ["ext-ms-win-dot3-grouppolicy-l1-1-0.dll"] = "dot3gpclnt.dll",
            ["ext-ms-win-driver-recovery-l1-1-0.dll"] = "drvsetup.dll",
            ["ext-ms-win-driver-setup-l1-1-0.dll"] = "drvsetup.dll",
            ["ext-ms-win-driver-setup-wu-l1-1-1.dll"] = "drvsetup.dll",
            ["ext-ms-win-drvinst-desktop-l1-1-0.dll"] = "newdev.dll",
            ["ext-ms-win-dwmapi-ext-l1-1-2.dll"] = "dwmapi.dll",
            ["ext-ms-win-dwmapidxgi-ext-l1-1-1.dll"] = "dwmapi.dll",
            ["ext-ms-win-dx-d3d9-l1-1-0.dll"] = "d3d9.dll",
            ["ext-ms-win-dx-d3dkmt-dxcore-l1-1-5.dll"] = "dxcore.dll",
            ["ext-ms-win-dx-d3dkmt-gdi-l1-1-0.dll"] = "gdi32.dll",
            ["ext-ms-win-dx-ddraw-l1-1-0.dll"] = "ddraw.dll",
            ["ext-ms-win-dx-dinput8-l1-1-0.dll"] = "dinput8.dll",
            ["ext-ms-win-dx-dxdbhelper-l1-1-4.dll"] = "directxdatabasehelper.dll",
            ["ext-ms-win-dxcore-internal-l1-1-0.dll"] = "dxcore.dll",
            ["ext-ms-win-dxcore-l1-1-0.dll"] = "dxcore.dll",
            ["ext-ms-win-edputil-policy-l1-1-2.dll"] = "edputil.dll",
            ["ext-ms-win-els-elscore-l1-1-0.dll"] = "elscore.dll",
            ["ext-ms-win-eventing-pdh-l1-1-3.dll"] = "pdh.dll",
            ["ext-ms-win-eventing-rundown-l1-1-0.dll"] = "etwrundown.dll",
            ["ext-ms-win-eventing-tdh-ext-l1-1-0.dll"] = "tdh.dll",
            ["ext-ms-win-eventing-tdh-priv-l1-1-0.dll"] = "tdh.dll",
            ["ext-ms-win-eventing-wdi-l1-1-0.dll"] = "wdi.dll",
            ["ext-ms-win-familysafety-childaccount-l1-1-0.dll"] = "familysafetyext.dll",
            ["ext-ms-win-feclient-encryptedfile-l1-1-3.dll"] = "feclient.dll",
            ["ext-ms-win-firewallapi-webproxy-l1-1-1.dll"] = "firewallapi.dll",
            ["ext-ms-win-font-fontgroups-l1-1-0.dll"] = "fontgroupsoverride.dll",
            ["ext-ms-win-font-setup-l1-1-0.dll"] = "muifontsetup.dll",
            ["ext-ms-win-fs-clfs-l1-1-0.dll"] = "clfs.sys",
            ["ext-ms-win-fs-cscapi-l1-1-1.dll"] = "cscapi.dll",
            ["ext-ms-win-fs-vssapi-l1-1-0.dll"] = "vssapi.dll",
            ["ext-ms-win-fsutilext-ifsutil-l1-1-0.dll"] = "fsutilext.dll",
            ["ext-ms-win-fsutilext-ulib-l1-1-0.dll"] = "fsutilext.dll",
            ["ext-ms-win-fveapi-query-l1-1-0.dll"] = "fveapi.dll",
            ["ext-ms-win-gaming-gamechatoverlay-l1-1-0.dll"] = "gamechatoverlayext.dll",
            ["ext-ms-win-gaming-xblgamesave-l1-1-0.dll"] = "xblgamesaveext.dll",
            ["ext-ms-win-gaming-xinput-l1-1-0.dll"] = "xinputuap.dll",
            ["ext-ms-win-gdi-clipping-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-dc-create-l1-1-2.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-dc-l1-2-1.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-devcaps-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-draw-l1-1-3.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-font-l1-1-3.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-gdiplus-l1-1-0.dll"] = "gdiplus.dll",
            ["ext-ms-win-gdi-internal-desktop-l1-1-6.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-internal-uap-init-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-metafile-l1-1-2.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-path-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-print-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-private-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-render-l1-1-0.dll"] = "gdi32.dll",
            ["ext-ms-win-gdi-rgn-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-gdi-wcs-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-globalization-input-l1-1-3.dll"] = "globinputhost.dll",
            ["ext-ms-win-gpapi-grouppolicy-l1-1-0.dll"] = "gpapi.dll",
            ["ext-ms-win-gpsvc-grouppolicy-l1-1-0.dll"] = "gpsvc.dll",
            ["ext-ms-win-gui-dui70-l1-1-0.dll"] = "dui70.dll",
            ["ext-ms-win-gui-ieui-l1-1-0.dll"] = "ieui.dll",
            ["ext-ms-win-gui-uxinit-l1-1-1.dll"] = "uxinit.dll",
            ["ext-ms-win-hostactivitymanager-bi-ham-ext-l1-1-0.dll"] = "psmserviceexthost.dll",
            ["ext-ms-win-hostactivitymanager-ham-private-ext-l1-1-0.dll"] = "psmserviceexthost.dll",
            ["ext-ms-win-hostactivitymanager-hostidstore-l1-1-1.dll"] = "rmclient.dll",
            ["ext-ms-win-hyperv-compute-l1-2-5.dll"] = "computecore.dll",
            ["ext-ms-win-hyperv-compute-legacy-l1-1-0.dll"] = "vmcompute.dll",
            ["ext-ms-win-hyperv-computenetwork-l1-1-1.dll"] = "computenetwork.dll",
            ["ext-ms-win-hyperv-computestorage-l1-1-2.dll"] = "computestorage.dll",
            ["ext-ms-win-hyperv-devicevirtualization-l1-1-1.dll"] = "vmdevicehost.dll",
            ["ext-ms-win-hyperv-devicevirtualization-l1-2-2.dll"] = "vmdevicehost.dll",
            ["ext-ms-win-hyperv-hgs-l1-1-0.dll"] = "vmhgs.dll",
            ["ext-ms-win-hyperv-hvemulation-l1-1-0.dll"] = "winhvemulation.dll",
            ["ext-ms-win-hyperv-hvplatform-l1-1-5.dll"] = "winhvplatform.dll",
            ["ext-ms-win-imm-l1-1-3.dll"] = "imm32.dll",
            ["ext-ms-win-kernel32-appcompat-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-datetime-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-elevation-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-errorhandling-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-file-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-localization-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-package-current-l1-1-0.dll"] = "kernel.appcore.dll",
            ["ext-ms-win-kernel32-package-l1-1-2.dll"] = "kernel.appcore.dll",
            ["ext-ms-win-kernel32-process-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-quirks-l1-1-1.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-registry-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-sidebyside-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-transacted-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-updateresource-l1-1-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernel32-windowserrorreporting-l1-1-1.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernelbase-processthread-l1-1-3.dll"] = "KERNEL32.dll",
            ["ext-ms-win-kernelbase-processthread-l1-2-0.dll"] = "KERNEL32.dll",
            ["ext-ms-win-laps-l1-1-1.dll"] = "laps.dll",
            ["ext-ms-win-lighting-lamparray-l1-1-1.dll"] = "lamparray.dll",
            ["ext-ms-win-mapi-mapi32-l1-1-0.dll"] = "mapistub.dll",
            ["ext-ms-win-media-avi-l1-1-0.dll"] = "avifil32.dll",
            ["ext-ms-win-mf-vfw-l1-1-0.dll"] = "mfvfw.dll",
            ["ext-ms-win-mininput-cursorhost-l1-1-0.dll"] = "inputhost.dll",
            ["ext-ms-win-mininput-inputhost-l1-1-1.dll"] = "inputhost.dll",
            ["ext-ms-win-mininput-inputhost-l1-2-1.dll"] = "inputhost.dll",
            ["ext-ms-win-mininput-inputhost-l1-3-0.dll"] = "inputhost.dll",
            ["ext-ms-win-mininput-inputhost-l1-4-0.dll"] = "inputhost.dll",
            ["ext-ms-win-mininput-systeminputhost-l1-1-0.dll"] = "ism.dll",
            ["ext-ms-win-mininput-systeminputhost-l1-2-0.dll"] = "ism.dll",
            ["ext-ms-win-mm-io-l1-1-0.dll"] = "winmmbase.dll",
            ["ext-ms-win-mm-msacm-l1-1-0.dll"] = "msacm32.dll",
            ["ext-ms-win-mm-pehelper-l1-1-0.dll"] = "mf.dll",
            ["ext-ms-win-mm-wmvcore-l1-1-0.dll"] = "wmvcore.dll",
            ["ext-ms-win-moderncore-win32k-base-ntgdi-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-moderncore-win32k-base-ntuser-l1-1-0.dll"] = "win32kfull.sys",
            ["ext-ms-win-moderncore-win32k-base-sysentry-l1-1-0.dll"] = "win32k.sys",
            ["ext-ms-win-mpr-multipleproviderrouter-l1-1-0.dll"] = "mprext.dll",
            ["ext-ms-win-mrmcorer-resmanager-l1-1-0.dll"] = "mrmcorer.dll",
            ["ext-ms-win-msa-ui-l1-1-0.dll"] = "msauserext.dll",
            ["ext-ms-win-msa-user-l1-1-1.dll"] = "msauserext.dll",
            ["ext-ms-win-msi-misc-l1-1-0.dll"] = "msi.dll",
            ["ext-ms-win-msiltcfg-msi-l1-1-0.dll"] = "msiltcfg.dll",
            ["ext-ms-win-msimg-draw-l1-1-0.dll"] = "msimg32.dll",
            ["ext-ms-win-net-cmvpn-l1-1-0.dll"] = "cmintegrator.dll",
            ["ext-ms-win-net-httpproxyext-l1-1-0.dll"] = "httpprxc.dll",
            ["ext-ms-win-net-isoext-l1-1-0.dll"] = "firewallapi.dll",
            ["ext-ms-win-net-netbios-l1-1-0.dll"] = "netbios.dll",
            ["ext-ms-win-net-netshell-l1-1-0.dll"] = "netshell.dll",
            ["ext-ms-win-net-nfdapi-l1-1-1.dll"] = "ndfapi.dll",
            ["ext-ms-win-netio-l1-1-0.dll"] = "netio.sys",
            ["ext-ms-win-netprovision-netprovfw-l1-1-0.dll"] = "netprovfw.dll",
            ["ext-ms-win-networking-radiomonitor-l1-1-0.dll"] = "windows.devices.radios.dll",
            ["ext-ms-win-networking-teredo-l1-1-0.dll"] = "windows.networking.connectivity.dll",
            ["ext-ms-win-networking-wcmapi-l1-1-1.dll"] = "wcmapi.dll",
            ["ext-ms-win-networking-winipsec-l1-1-0.dll"] = "winipsec.dll",
            ["ext-ms-win-networking-wlanapi-l1-1-0.dll"] = "wlanapi.dll",
            ["ext-ms-win-newdev-config-l1-1-2.dll"] = "newdev.dll",
            ["ext-ms-win-nfc-semgr-l1-1-0.dll"] = "semgrsvc.dll",
            ["ext-ms-win-ntdsapi-activedirectoryclient-l1-1-1.dll"] = "ntdsapi.dll",
            ["ext-ms-win-ntos-clipsp-l1-1-0.dll"] = "clipsp.sys",
            ["ext-ms-win-ntos-globmerger-l1-1-0.dll"] = "globmerger.sys",
            ["ext-ms-win-ntos-kcminitcfg-l1-1-0.dll"] = "cmimcext.sys",
            ["ext-ms-win-ntos-tm-l1-1-0.dll"] = "tm.sys",
            ["ext-ms-win-ntos-ucode-l1-1-0.dll"] = "ntosext.sys",
            ["ext-ms-win-ntos-vmsvc-l1-1-0.dll"] = "vmsvcext.sys",
            ["ext-ms-win-ntos-werkernel-l1-1-1.dll"] = "werkernel.sys",
            ["ext-ms-win-ntos-win32k-l1-1-0.dll"] = "win32k.sys",
            ["ext-ms-win-ntuser-caret-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-chartranslation-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-dc-access-ext-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-dde-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-dialogbox-l1-1-3.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-draw-l1-1-2.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-gui-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-gui-l1-2-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-gui-l1-3-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-keyboard-ansi-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-keyboard-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-keyboard-l1-2-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-keyboard-l1-3-2.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-menu-l1-1-3.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-message-l1-1-3.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-misc-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-misc-l1-2-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-misc-l1-3-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-misc-l1-5-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-misc-l1-6-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-misc-l1-7-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-mit-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-mouse-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-powermanagement-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-private-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-private-l1-2-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-private-l1-3-3.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-private-l1-4-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-private-l1-5-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-private-l1-6-3.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-rawinput-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-rawinput-l1-2-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-rectangle-ext-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-rim-l1-1-2.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-rim-l1-2-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-rotationmanager-l1-1-2.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-server-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-string-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-synch-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-sysparams-ext-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-touch-hittest-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-uicontext-ext-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-window-l1-1-6.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-windowclass-l1-1-2.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-windowstation-ansi-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-ntuser-windowstation-l1-1-2.dll"] = "user32.dll",
            ["ext-ms-win-odbc-odbc32-l1-1-0.dll"] = "odbc32.dll",
            ["ext-ms-win-ole32-bindctx-l1-1-0.dll"] = "ole32.dll",
            ["ext-ms-win-ole32-ie-ext-l1-1-0.dll"] = "ole32.dll",
            ["ext-ms-win-ole32-oleautomation-l1-1-0.dll"] = "ole32.dll",
            ["ext-ms-win-oleacc-l1-1-2.dll"] = "oleacc.dll",
            ["ext-ms-win-onecore-shutdown-l1-1-0.dll"] = "twinapi.appcore.dll",
            ["ext-ms-win-packagevirtualizationcontext-l1-1-0.dll"] = "daxexec.dll",
            ["ext-ms-win-parentalcontrols-setup-l1-1-0.dll"] = "wpcapi.dll",
            ["ext-ms-win-pinenrollment-enrollment-l1-1-2.dll"] = "pinenrollmenthelper.dll",
            ["ext-ms-win-printer-prntvpt-l1-1-2.dll"] = "prntvpt.dll",
            ["ext-ms-win-printer-winspool-core-l1-1-0.dll"] = "winspool.drv",
            ["ext-ms-win-printer-winspool-l1-1-4.dll"] = "winspool.drv",
            ["ext-ms-win-printer-winspool-l1-2-0.dll"] = "winspool.drv",
            ["ext-ms-win-profile-extender-l1-1-0.dll"] = "userenv.dll",
            ["ext-ms-win-profile-profsvc-l1-1-0.dll"] = "profsvcext.dll",
            ["ext-ms-win-profile-userenv-l1-1-1.dll"] = "profext.dll",
            ["ext-ms-win-provisioning-platform-l1-1-2.dll"] = "provplatformdesktop.dll",
            ["ext-ms-win-ras-rasapi32-l1-1-2.dll"] = "rasapi32.dll",
            ["ext-ms-win-ras-rasdlg-l1-1-0.dll"] = "rasdlg.dll",
            ["ext-ms-win-ras-rasman-l1-1-0.dll"] = "rasman.dll",
            ["ext-ms-win-ras-tapi32-l1-1-1.dll"] = "tapi32.dll",
            ["ext-ms-win-raschapext-eap-l1-1-0.dll"] = "raschapext.dll",
            ["ext-ms-win-rastlsext-eap-l1-1-0.dll"] = "rastlsext.dll",
            ["ext-ms-win-rdr-davhlpr-l1-1-0.dll"] = "davhlpr.dll",
            ["ext-ms-win-reinfo-query-l1-1-0.dll"] = "reinfo.dll",
            ["ext-ms-win-resourcemanager-activitycoordinator-l1-1-1.dll"] = "rmclient.dll",
            ["ext-ms-win-resourcemanager-crm-l1-1-0.dll"] = "rmclient.dll",
            ["ext-ms-win-resourcemanager-crm-l1-2-0.dll"] = "rmclient.dll",
            ["ext-ms-win-resourcemanager-crm-private-ext-l1-1-0.dll"] = "psmserviceexthost.dll",
            ["ext-ms-win-resourcemanager-gamemode-l1-1-0.dll"] = "rmclient.dll",
            ["ext-ms-win-resourcemanager-gamemode-l1-2-1.dll"] = "rmclient.dll",
            ["ext-ms-win-resourcemanager-limits-l1-1-0.dll"] = "rmclient.dll",
            ["ext-ms-win-resources-deployment-l1-1-0.dll"] = "mrmdeploy.dll",
            ["ext-ms-win-resources-languageoverlay-l1-1-7.dll"] = "languageoverlayutil.dll",
            ["ext-ms-win-ro-typeresolution-l1-1-1.dll"] = "wintypes.dll",
            ["ext-ms-win-rometadata-dispenser-l1-1-0.dll"] = "rometadata.dll",
            ["ext-ms-win-rpc-firewallportuse-l1-1-0.dll"] = "rpcrtremote.dll",
            ["ext-ms-win-rpc-ssl-l1-1-0.dll"] = "rpcrtremote.dll",
            ["ext-ms-win-rtcore-gdi-devcaps-l1-1-1.dll"] = "gdi32.dll",
            ["ext-ms-win-rtcore-gdi-object-l1-1-0.dll"] = "gdi32.dll",
            ["ext-ms-win-rtcore-gdi-rgn-l1-1-1.dll"] = "gdi32.dll",
            ["ext-ms-win-rtcore-ntuser-controllernavigation-l1-1-2.dll"] = "inputhost.dll",
            ["ext-ms-win-rtcore-ntuser-cursor-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-dc-access-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-dpi-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-dpi-l1-2-2.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-iam-l1-1-2.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-inputintercept-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-integration-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-keyboard-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-message-ansi-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-message-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-rawinput-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-rawinput-l1-2-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-synch-ext-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-syscolors-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-sysparams-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-usersecurity-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-window-ansi-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-window-ext-l1-1-1.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-window-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-winevent-ext-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ntuser-wmpointer-l1-1-0.dll"] = "user32.dll",
            ["ext-ms-win-rtcore-ole32-dragdrop-l1-1-0.dll"] = "ole32.dll",
            ["ext-ms-win-rtcore-ole32-misc-l1-1-0.dll"] = "ole32.dll",
            ["ext-ms-win-samsrv-accountstore-l1-1-1.dll"] = "samsrv.dll",
            ["ext-ms-win-scesrv-server-l1-1-0.dll"] = "scesrv.dll",
            ["ext-ms-win-search-folder-l1-1-1.dll"] = "searchfolder.dll",
            ["ext-ms-win-search-lifetimemanager-l1-1-0.dll"] = "mssrch.dll",
            ["ext-ms-win-secur32-translatename-l1-1-0.dll"] = "secur32.dll",
            ["ext-ms-win-security-appinfoext-l1-1-0.dll"] = "appinfoext.dll",
            ["ext-ms-win-security-authbrokerui-l1-1-0.dll"] = "authbrokerui.dll",
            ["ext-ms-win-security-capauthz-l1-1-1.dll"] = "capauthz.dll",
            ["ext-ms-win-security-catalog-database-l1-1-0.dll"] = "cryptcatsvc.dll",
            ["ext-ms-win-security-certpoleng-l1-1-0.dll"] = "certpoleng.dll",
            ["ext-ms-win-security-cfl-l1-1-2.dll"] = "cflapi.dll",
            ["ext-ms-win-security-credui-internal-l1-1-1.dll"] = "wincredui.dll",
            ["ext-ms-win-security-credui-l1-1-1.dll"] = "credui.dll",
            ["ext-ms-win-security-cryptui-l1-1-1.dll"] = "cryptui.dll",
            ["ext-ms-win-security-efs-l1-1-1.dll"] = "efsext.dll",
            ["ext-ms-win-security-efswrt-l1-1-4.dll"] = "efswrt.dll",
            ["ext-ms-win-security-kerberos-l1-1-0.dll"] = "kerberos.dll",
            ["ext-ms-win-security-lsaadt-l1-1-0.dll"] = "lsaadt.dll",
            ["ext-ms-win-security-lsaadtpriv-l1-1-0.dll"] = "lsaadt.dll",
            ["ext-ms-win-security-lsaauditrpc-l1-1-0.dll"] = "lsaadt.dll",
            ["ext-ms-win-security-ngc-local-l1-1-0.dll"] = "ngclocal.dll",
            ["ext-ms-win-security-shutdownext-l1-1-0.dll"] = "shutdownext.dll",
            ["ext-ms-win-security-slc-l1-1-0.dll"] = "slc.dll",
            ["ext-ms-win-security-srp-l1-1-1.dll"] = "srpapi.dll",
            ["ext-ms-win-security-tokenbrokerui-l1-1-0.dll"] = "tokenbrokerui.dll",
            ["ext-ms-win-security-vaultcds-l1-1-0.dll"] = "vaultcds.dll",
            ["ext-ms-win-security-vaultcds-l1-2-0.dll"] = "vaultcds.dll",
            ["ext-ms-win-security-vaultcli-l1-1-1.dll"] = "vaultcli.dll",
            ["ext-ms-win-security-winscard-l1-1-1.dll"] = "winscard.dll",
            ["ext-ms-win-sensors-core-private-l1-1-8.dll"] = "sensorsnativeapi.dll",
            ["ext-ms-win-sensors-utilities-private-l1-1-5.dll"] = "sensorsutilsv2.dll",
            ["ext-ms-win-servicing-uapi-l1-1-2.dll"] = "servicinguapi.dll",
            ["ext-ms-win-session-candidateaccountmgr-l1-1-0.dll"] = "camext.dll",
            ["ext-ms-win-session-userinit-l1-1-0.dll"] = "userinitext.dll",
            ["ext-ms-win-session-usermgr-l1-1-0.dll"] = "usermgrcli.dll",
            ["ext-ms-win-session-usermgr-l1-2-1.dll"] = "usermgrcli.dll",
            ["ext-ms-win-session-usertoken-l1-1-0.dll"] = "wtsapi32.dll",
            ["ext-ms-win-session-wininit-l1-1-1.dll"] = "wininitext.dll",
            ["ext-ms-win-session-wininit-l1-2-0.dll"] = "wininitext.dll",
            ["ext-ms-win-session-winlogon-l1-1-2.dll"] = "winlogonext.dll",
            ["ext-ms-win-session-winsta-l1-1-6.dll"] = "winsta.dll",
            ["ext-ms-win-session-wtsapi32-l1-1-2.dll"] = "wtsapi32.dll",
            ["ext-ms-win-setupapi-classinstallers-l1-1-2.dll"] = "setupapi.dll",
            ["ext-ms-win-setupapi-inf-l1-1-1.dll"] = "setupapi.dll",
            ["ext-ms-win-setupapi-logging-l1-1-0.dll"] = "setupapi.dll",
            ["ext-ms-win-shell-aclui-l1-1-0.dll"] = "aclui.dll",
            ["ext-ms-win-shell-comctl32-da-l1-1-0.dll"] = "comctl32.dll",
            ["ext-ms-win-shell-comctl32-init-l1-1-1.dll"] = "comctl32.dll",
            ["ext-ms-win-shell-comctl32-l1-1-0.dll"] = "comctl32.dll",
            ["ext-ms-win-shell-comctl32-window-l1-1-0.dll"] = "comctl32.dll",
            ["ext-ms-win-shell-comdlg32-l1-1-1.dll"] = "comdlg32.dll",
            ["ext-ms-win-shell-directory-l1-1-0.dll"] = "windows.storage.dll",
            ["ext-ms-win-shell-efsadu-l1-1-0.dll"] = "efsadu.dll",
            ["ext-ms-win-shell-embeddedmode-l1-1-0.dll"] = "embeddedmodesvcapi.dll",
            ["ext-ms-win-shell-exports-internal-l1-1-1.dll"] = "shell32.dll",
            ["ext-ms-win-shell-fileplaceholder-l1-1-0.dll"] = "windows.fileexplorer.common.dll",
            ["ext-ms-win-shell-ntshrui-l1-1-0.dll"] = "ntshrui.dll",
            ["ext-ms-win-shell-propsys-l1-1-1.dll"] = "propsys.dll",
            ["ext-ms-win-shell-shdocvw-l1-1-0.dll"] = "shdocvw.dll",
            ["ext-ms-win-shell-shell32-l1-2-3.dll"] = "shell32.dll",
            ["ext-ms-win-shell-shell32-l1-3-0.dll"] = "shell32.dll",
            ["ext-ms-win-shell-shell32-l1-4-0.dll"] = "shell32.dll",
            ["ext-ms-win-shell-shell32-l1-5-0.dll"] = "shell32.dll",
            ["ext-ms-win-shell-shlwapi-l1-1-2.dll"] = "shlwapi.dll",
            ["ext-ms-win-shell-shlwapi-l1-2-1.dll"] = "shlwapi.dll",
            ["ext-ms-win-shell32-shellcom-l1-1-0.dll"] = "windows.storage.dll",
            ["ext-ms-win-shell32-shellfolders-l1-1-1.dll"] = "windows.storage.dll",
            ["ext-ms-win-shell32-shellfolders-l1-2-1.dll"] = "windows.storage.dll",
            ["ext-ms-win-smbshare-browser-l1-1-0.dll"] = "browser.dll",
            ["ext-ms-win-smbshare-browserclient-l1-1-0.dll"] = "browcli.dll",
            ["ext-ms-win-smbshare-sscore-l1-1-0.dll"] = "sscoreext.dll",
            ["ext-ms-win-spinf-inf-l1-1-0.dll"] = "spinf.dll",
            ["ext-ms-win-storage-hbaapi-l1-1-1.dll"] = "hbaapi.dll",
            ["ext-ms-win-storage-iscsidsc-l1-1-0.dll"] = "iscsidsc.dll",
            ["ext-ms-win-storage-sense-l1-1-0.dll"] = "storageusage.dll",
            ["ext-ms-win-storage-sense-l1-2-5.dll"] = "storageusage.dll",
            ["ext-ms-win-sxs-oleautomation-l1-1-0.dll"] = "sxs.dll",
            ["ext-ms-win-sysmain-pfapi-l1-1-1.dll"] = "pfclient.dll",
            ["ext-ms-win-sysmain-pfsapi-l1-1-0.dll"] = "pfclient.dll",
            ["ext-ms-win-sysmain-plmapi-l1-1-1.dll"] = "pfclient.dll",
            ["ext-ms-win-teapext-eap-l1-1-0.dll"] = "eapteapext.dll",
            ["ext-ms-win-tsf-inputsetting-l1-1-0.dll"] = "input.dll",
            ["ext-ms-win-tsf-msctf-l1-1-4.dll"] = "msctf.dll",
            ["ext-ms-win-ttlsext-eap-l1-1-0.dll"] = "ttlsext.dll",
            ["ext-ms-win-uiacore-l1-1-3.dll"] = "uiautomationcore.dll",
            ["ext-ms-win-umpoext-umpo-l1-1-0.dll"] = "umpoext.dll",
            ["ext-ms-win-usp10-l1-1-0.dll"] = "gdi32full.dll",
            ["ext-ms-win-uwf-servicing-apis-l1-1-1.dll"] = "uwfservicingapi.dll",
            ["ext-ms-win-uxtheme-themes-l1-1-3.dll"] = "uxtheme.dll",
            ["ext-ms-win-vmbus-hvsocket-l1-1-0.dll"] = "hvsocket.sys",
            ["ext-ms-win-wer-reporting-l1-1-3.dll"] = "wer.dll",
            ["ext-ms-win-wer-ui-l1-1-1.dll"] = "werui.dll",
            ["ext-ms-win-wer-wct-l1-1-0.dll"] = "wer.dll",
            ["ext-ms-win-wevtapi-eventlog-l1-1-3.dll"] = "wevtapi.dll",
            ["ext-ms-win-windowing-external-l1-1-0.dll"] = "windows.ui.dll",
            ["ext-ms-win-winrt-device-access-l1-1-0.dll"] = "deviceaccess.dll",
            ["ext-ms-win-winrt-storage-l1-1-0.dll"] = "windows.storage.dll",
            ["ext-ms-win-winrt-storage-l1-2-3.dll"] = "windows.storage.dll",
            ["ext-ms-win-winrt-storage-win32broker-l1-1-0.dll"] = "windows.storage.onecore.dll",
            ["ext-ms-win-wlan-grouppolicy-l1-1-0.dll"] = "wlgpclnt.dll",
            ["ext-ms-win-wlan-onexui-l1-1-0.dll"] = "onexui.dll",
            ["ext-ms-win-wlan-scard-l1-1-0.dll"] = "winscard.dll",
            ["ext-ms-win-wpc-webfilter-l1-1-0.dll"] = "wpcwebfilter.dll",
            ["ext-ms-win-wrp-sfc-l1-1-0.dll"] = "sfc.dll",
            ["ext-ms-win-wsclient-devlicense-l1-1-1.dll"] = "wsclient.dll",
            ["ext-ms-win-wwaext-misc-l1-1-0.dll"] = "wwaext.dll",
            ["ext-ms-win-wwaext-module-l1-1-0.dll"] = "wwaext.dll",
            ["ext-ms-win-wwan-wwapi-l1-1-3.dll"] = "wwapi.dll",
            ["ext-ms-win-xaml-controls-l1-1-0.dll"] = "windows.ui.xaml.phone.dll",
        };

        public static readonly Dictionary<ApiSetOverrideKey, string> ApiSetOverrideMap = new()
        {
            [new ApiSetOverrideKey("api-ms-win-core-appinit-l1-1-0.dll", "kernel32.dll")] = "KERNELBASE.dll",
            [new ApiSetOverrideKey("api-ms-win-core-io-l1-1-1.dll", "kernel32.dll")] = "KERNELBASE.dll",
            [new ApiSetOverrideKey("api-ms-win-core-processsecurity-l1-1-0.dll", "kernel32.dll")] = "KERNELBASE.dll",
            [new ApiSetOverrideKey("api-ms-win-core-processthreads-l1-1-8.dll", "kernel32.dll")] = "KERNELBASE.dll",
            [new ApiSetOverrideKey("api-ms-win-core-util-l1-1-1.dll", "kernel32.dll")] = "KERNELBASE.dll",
            [new ApiSetOverrideKey("ext-ms-win-kernel32-errorhandling-l1-1-0.dll", "kernel32.dll")] = "faultrep.dll",
        };

        private static IReadOnlyDictionary<uint, IWinSyscall> CachedSyscallDictionary = null;
        private static IReadOnlyDictionary<uint, IWinSyscall> CachedSyscallDictionaryx86 = null;


        /// <summary>
        /// Searches for the syscall number in the bytes.
        /// </summary>
        /// <param name="bytes">the bytes to search for the syscall in.</param>
        /// <returns>returns the syscall number if successful, otherwise zero.</returns>
        public static uint TryExtractSyscallByte(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] == 0xB8) // mov eax,
                {
                    try
                    {
                        return BitConverter.ToUInt32(bytes, i + 1);
                    }
                    catch
                    {
                        return uint.MaxValue;
                    }
                }
            }
            return 0;
        }

        /// <summary>
        /// Clear cached syscalls.
        /// </summary>
        public static void ClearCachedSyscalls()
        {
            if (CachedSyscallDictionary != null)
            {
                CachedSyscallDictionary = null;
            }

            if (CachedSyscallDictionaryx86 != null)
            {
                CachedSyscallDictionaryx86 = null;
            }
        }

        /// <summary>
        /// Build a table of export functions.
        /// </summary>
        /// <param name="Exports">Binary functions which is the exports.</param>
        /// <returns>returns a table where the key is the name of the function which points to it's own <see cref="BinaryFunction"/>.</returns>
        private static Dictionary<string, BinaryFunction> BuildExportMap(BinaryFunction[] Exports)
        {
            Dictionary<string, BinaryFunction> Map = new Dictionary<string, BinaryFunction>(StringComparer.OrdinalIgnoreCase);

            if (Exports == null || Exports.Length == 0)
                return Map;

            for (int i = 0; i < Exports.Length; i++)
            {
                BinaryFunction Export = Exports[i];
                if (string.IsNullOrEmpty(Export.FunctionName))
                    continue;

                if (!Map.ContainsKey(Export.FunctionName))
                    Map.Add(Export.FunctionName, Export);
            }

            return Map;
        }

        /// <summary>
        /// Build a dictionary with the syscalls.
        /// </summary>
        /// <param name="BinaryArch">Binary architecture to get for syscalls.</param>
        /// <returns>returns the dictionary containing the syscalls.</returns>
        public static IReadOnlyDictionary<uint, IWinSyscall> BuildWinSyscallDictionary(BinaryArchitecture BinaryArch)
        {
            if (BinaryArch == BinaryArchitecture.x64 && CachedSyscallDictionary != null)
                return CachedSyscallDictionary;
            else if (BinaryArch == BinaryArchitecture.x86 && CachedSyscallDictionaryx86 != null)
                return CachedSyscallDictionaryx86;

            string[] SupportedFunctions = WinSyscallRegistry.SupportedFunctions;
            string[] SupportedFunctionsWin32k = WinSyscallRegistry.SupportedFunctionsWin32k;

            Dictionary<uint, IWinSyscall> SyscallDictionary = new Dictionary<uint, IWinSyscall>();
            try
            {
                if (GeneralHelper.IsWindows)
                {
                    IntPtr NtdllModule = NativeWinImports.GetModuleHandleA("ntdll.dll");
                    if (NtdllModule == IntPtr.Zero)
                    {
                        Utils.LogError("[WinSyscallBuilder] ntdll.dll was not found inside the process..?");
                        Environment.Exit(0);
                    }

                    IntPtr Win32uModule = NativeWinImports.GetModuleHandleA("win32u.dll");
                    if (Win32uModule == IntPtr.Zero)
                    {
                        Win32uModule = NativeWinImports.LoadLibraryA("win32u.dll");
                        if (Win32uModule == IntPtr.Zero)
                        {
                            Utils.LogError("[WinSyscallsBuilder] Couldn't get a handle to win32u.dll");
                            Utils.PrintHighlight("[-] Couldn't get a handle to win32u.dll, expect UI-related syscalls to not work.", true);
                        }
                    }

                    if (NtdllModule != IntPtr.Zero)
                    {
                        foreach (string SupportedFunction in SupportedFunctions)
                        {
                            IntPtr hFunction = NativeWinImports.GetProcAddress(NtdllModule, SupportedFunction);
                            if (hFunction == IntPtr.Zero)
                                continue;

                            byte[] Function = new byte[40];
                            Marshal.Copy(hFunction, Function, 0, 40);
                            uint SyscallNumber = TryExtractSyscallByte(Function);
                            Array.Clear(Function, 0, Function.Length);

                            if (SyscallNumber == uint.MaxValue)
                                continue;

                            try
                            {
                                IWinSyscall Instance = WinSyscallRegistry.Create(SupportedFunction);
                                if (Instance == null)
                                    continue;

                                SyscallDictionary[SyscallNumber] = Instance;
                            }
                            catch (Exception Ex)
                            {
                                Utils.LogError($"[WinSyscallBuilder] Failed to instantiate {SupportedFunction}: {Ex.Message}");
                            }
                        }
                    }

                    if (Win32uModule != IntPtr.Zero)
                    {
                        foreach (string SupportedWin32k in SupportedFunctionsWin32k)
                        {
                            IntPtr hFunction = NativeWinImports.GetProcAddress(Win32uModule, SupportedWin32k);
                            if (hFunction == IntPtr.Zero)
                                continue;

                            byte[] Function = new byte[40];
                            Marshal.Copy(hFunction, Function, 0, 40);
                            uint SyscallNumber = TryExtractSyscallByte(Function);
                            Array.Clear(Function, 0, Function.Length);

                            if (SyscallNumber == uint.MaxValue)
                                continue;

                            try
                            {
                                IWinSyscall Instance = WinSyscallRegistry.CreateWin32k(SupportedWin32k);
                                if (Instance == null)
                                    continue;

                                SyscallDictionary[SyscallNumber] = Instance;
                            }
                            catch (Exception Ex)
                            {
                                Utils.LogError($"[WinSyscallBuilder] Failed to instantiate {SupportedWin32k}: {Ex.Message}");
                            }
                        }
                    }
                }
                else
                {
                    string NtdllPath = Path.Combine(GeneralHelper.WindowsLibsPath, "ntdll.dll");
                    string Win32uPath = Path.Combine(GeneralHelper.WindowsLibsPath, "win32u.dll");

                    if (!File.Exists(NtdllPath))
                    {
                        Utils.LogError($"[WinSyscallBuilder] Missing ntdll.dll: {NtdllPath}");
                        Utils.PrintHighlight("[-] Missing ntdll.dll in WindowsLibs. Syscalls won't work.", true);
                        return SyscallDictionary;
                    }

                    using BinaryFile Ntdll = new BinaryFile(NtdllPath, true);
                    using BinaryFile Win32u = File.Exists(Win32uPath) ? new BinaryFile(Win32uPath, true) : null;

                    if (Win32u == null)
                        Utils.PrintHighlight("[-] win32u.dll not found in WindowsLibs, UI-related syscalls may not work.", true);

                    ReadOnlySpan<byte> NtdllData = Ntdll.GetBinaryData();
                    ReadOnlySpan<byte> Win32uData = Win32u != null ? Win32u.GetBinaryData() : ReadOnlySpan<byte>.Empty;

                    Dictionary<string, BinaryFunction> NtdllExports = BuildExportMap(Ntdll.ExportFunctions);
                    Dictionary<string, BinaryFunction> Win32uExports = Win32u != null ? BuildExportMap(Win32u.ExportFunctions) : null;

                    foreach (string SupportedFunction in SupportedFunctions)
                    {
                        bool IsNtUser = SupportedFunction.StartsWith("NtUser", StringComparison.OrdinalIgnoreCase);

                        Dictionary<string, BinaryFunction> ExportMap = IsNtUser ? Win32uExports : NtdllExports;
                        if (ExportMap == null)
                            continue;

                        if (!ExportMap.TryGetValue(SupportedFunction, out BinaryFunction Export))
                            continue;

                        int Offset = unchecked((int)Export.Offset);
                        ReadOnlySpan<byte> ModuleData = IsNtUser ? Win32uData : NtdllData;

                        if ((uint)Offset >= (uint)ModuleData.Length)
                            continue;

                        int StubLen = Math.Min(40, ModuleData.Length - Offset);
                        if (StubLen < 8)
                            continue;

                        byte[] Stub = new byte[StubLen];
                        ModuleData.Slice(Offset, StubLen).CopyTo(Stub);

                        uint SyscallNumber = TryExtractSyscallByte(Stub);
                        if (SyscallNumber == uint.MaxValue)
                            continue;

                        try
                        {
                            IWinSyscall Instance = WinSyscallRegistry.Create(SupportedFunction);
                            if (Instance == null)
                                continue;

                            SyscallDictionary[SyscallNumber] = Instance;
                        }
                        catch (Exception Ex)
                        {
                            Utils.LogError($"[WinSyscallBuilder] Failed to instantiate {SupportedFunction}: {Ex.Message}");
                        }
                    }

                    if (Ntdll != null)
                    {
                        Ntdll.Dispose();
                    }

                    if (Win32u != null)
                    {
                        Win32u.Dispose();
                    }
                }

                if (SyscallDictionary.Count > 0)
                {
                    if (BinaryArch == BinaryArchitecture.x64)
                        CachedSyscallDictionary = new Dictionary<uint, IWinSyscall>(SyscallDictionary);
                    else
                        CachedSyscallDictionaryx86 = new Dictionary<uint, IWinSyscall>(SyscallDictionary);
                }

                return SyscallDictionary;
            }
            finally
            {

            }
        }
    }
}