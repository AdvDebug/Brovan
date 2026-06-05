using System.Diagnostics;
using static Brovan.Core.Helpers.BinaryHelpers;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows
{
    public struct DeviceData
    {
        public byte[] InputBuffer;
        public byte[] OutputBuffer;
        public uint InputLength;
        public uint OutputLength;
        public ulong Information;
    }

    public class WindowsSharedBuffer
    {
        private byte[] Buffer;

        public int Length => Buffer.Length;

        public WindowsSharedBuffer()
        {
            Buffer = Array.Empty<byte>();
        }

        public Span<byte> GetSpan(ulong Size)
        {
            if (Size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(Size));

            EnsureCapacity((int)Size);
            return Buffer.AsSpan(0, (int)Size);
        }

        public ReadOnlySpan<byte> GetReadOnlySpan(ulong Size)
        {
            if (Size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(Size));

            EnsureCapacity((int)Size);
            return Buffer.AsSpan(0, (int)Size);
        }

        public byte[] GetBuffer(ulong Size)
        {
            if (Size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(Size));

            EnsureCapacity((int)Size);
            return Buffer;
        }

        public void Clear(ulong Size)
        {
            if (Size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(Size));

            int Count = (int)Math.Min(Size, (ulong)Buffer.Length);
            Buffer.AsSpan(0, Count).Clear();
        }

        private void EnsureCapacity(int Size)
        {
            if (Size <= Buffer.Length)
                return;

            int NewSize = Buffer.Length == 0 ? 0x1000 : Buffer.Length;
            while (NewSize < Size)
            {
                if (NewSize > int.MaxValue / 2)
                {
                    NewSize = Size;
                    break;
                }

                NewSize *= 2;
            }

            Array.Resize(ref Buffer, NewSize);
        }
    }

    public enum NTSTATUS : uint
    {
        STATUS_SUCCESS = 0x00000000,
        STATUS_WAIT_1 = 0x00000001,
        STATUS_WAIT_2 = 0x00000002,
        STATUS_WAIT_3 = 0x00000003,
        STATUS_WAIT_63 = 0x0000003F,
        STATUS_ABANDONED = 0x00000080,
        STATUS_ABANDONED_WAIT_0 = 0x00000080,
        STATUS_USER_APC = 0x000000C0,
        STATUS_KERNEL_APC = 0x00000100,
        STATUS_ALERTED = 0x00000101,
        STATUS_TIMEOUT = 0x00000102,
        STATUS_PENDING = 0x00000103,
        STATUS_REPARSE = 0x00000104,
        STATUS_MORE_ENTRIES = 0x00000105,
        STATUS_NOT_ALL_ASSIGNED = 0x00000106,
        STATUS_SOME_NOT_MAPPED = 0x00000107,
        STATUS_OPLOCK_BREAK_IN_PROGRESS = 0x00000108,
        STATUS_INFO_LENGTH_MISMATCH = 0xC0000004,
        STATUS_INVALID_INFO_CLASS = 0xC0000003,
        STATUS_NOT_IMPLEMENTED = 0xC0000002,
        STATUS_UNSUCCESSFUL = 0xC0000001,
        STATUS_ACCESS_VIOLATION = 0xC0000005,
        STATUS_IN_PAGE_ERROR = 0xC0000006,
        STATUS_INVALID_HANDLE = 0xC0000008,
        STATUS_INVALID_PARAMETER = 0xC000000D,
        STATUS_INVALID_DEVICE_REQUEST = 0xC0000010,
        STATUS_FILE_CORRUPT_ERROR = 0xC0000102,
        STATUS_ALREADY_REGISTERED = 0xC0000718,
        STATUS_END_OF_FILE = 0xC0000011,
        STATUS_NO_MEMORY = 0xC0000017,
        STATUS_CONFLICTING_ADDRESSES = 0xC0000018,
        STATUS_UNABLE_TO_FREE_VM = 0xC000001A,
        STATUS_ILLEGAL_INSTRUCTION = 0xC000001D,
        STATUS_INVALID_LOCK_SEQUENCE = 0xC000001E,
        STATUS_INVALID_VIEW_SIZE = 0xC000001F,
        STATUS_INVALID_FILE_FOR_SECTION = 0xC0000020,
        STATUS_ACCESS_DENIED = 0xC0000022,
        STATUS_BUFFER_TOO_SMALL = 0xC0000023,
        STATUS_OBJECT_TYPE_MISMATCH = 0xC0000024,
        STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025,
        STATUS_INVALID_DISPOSITION = 0xC0000026,
        STATUS_UNWIND = 0xC0000027,
        STATUS_BAD_STACK = 0xC0000028,
        STATUS_INVALID_UNWIND_TARGET = 0xC0000029,
        STATUS_NOT_LOCKED = 0xC000002A,
        STATUS_PARITY_ERROR = 0xC000002B,
        STATUS_UNABLE_TO_DECOMMIT_VM = 0xC000002C,
        STATUS_INVALID_PORT_ATTRIBUTES = 0xC000002E,
        STATUS_PORT_MESSAGE_TOO_LONG = 0xC000002F,
        STATUS_INVALID_PARAMETER_MIX = 0xC0000030,
        STATUS_OBJECT_NAME_INVALID = 0xC0000033,
        STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034,
        STATUS_OBJECT_NAME_COLLISION = 0xC0000035,
        STATUS_OBJECT_PATH_INVALID = 0xC0000039,
        STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A,
        STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B,
        STATUS_DATA_OVERRUN = 0xC000003C,
        STATUS_DATA_LATE_ERROR = 0xC000003D,
        STATUS_DATA_ERROR = 0xC000003E,
        STATUS_CRC_ERROR = 0xC000003F,
        STATUS_SECTION_TOO_BIG = 0xC0000040,
        STATUS_PORT_CONNECTION_REFUSED = 0xC0000041,
        STATUS_INVALID_PAGE_PROTECTION = 0xC0000045,
        STATUS_THREAD_IS_TERMINATING = 0xC000004B,
        STATUS_BAD_WORKING_SET_LIMIT = 0xC000004C,
        STATUS_INSUFFICIENT_RESOURCES = 0xC000009A,
        STATUS_INVALID_IMAGE_FORMAT = 0xC000007B,
        STATUS_NO_TOKEN = 0xC000007C,
        STATUS_DLL_NOT_FOUND = 0xC0000135,
        STATUS_ORDINAL_NOT_FOUND = 0xC0000138,
        STATUS_ENTRYPOINT_NOT_FOUND = 0xC0000139,
        STATUS_STACK_OVERFLOW = 0xC00000FD,
        STATUS_CONTROL_C_EXIT = 0xC000013A,
        STATUS_INVALID_ADDRESS = 0xC0000141,
        STATUS_FILE_INVALID = 0xC0000098,
        STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096,
        STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094,
        STATUS_INTEGER_OVERFLOW = 0xC0000095,
        STATUS_MEMORY_NOT_ALLOCATED = 0xC00000A0,
        STATUS_CANT_TERMINATE_SELF = 0xC00000DB,
        STATUS_DEBUGGER_INACTIVE = 0xC0000354,
        STATUS_DATATYPE_MISALIGNMENT = 0x80000002,
        STATUS_BREAKPOINT = 0x80000003,
        STATUS_SINGLE_STEP = 0x80000004,
        STATUS_BUFFER_OVERFLOW = 0x80000005,
        STATUS_NO_MORE_ENTRIES = 0x8000001A,
        STATUS_NOT_SUPPORTED = 0xC00000BB,
        STATUS_APP_INIT_FAILURE = 0xC0000145,
        STATUS_NOT_FOUND = 0xC0000225,
        STATUS_WMI_GUID_NOT_FOUND = 0xC0000295,
        STATUS_NO_MORE_FILES = 0x80000006,
        STATUS_INVALID_CID = 0xC000000B,
        STATUS_NETWORK_UNREACHABLE = 0xC000023C,
        STATUS_HANDLE_NOT_CLOSABLE = 0xC0000235,
        STATUS_GUARD_PAGE_VIOLATION = 0x80000001,
        STATUS_IMAGE_NOT_AT_BASE = 0x40000003,
        STATUS_FILE_LOCK_CONFLICT = 0xC0000054,
        STATUS_LOCK_NOT_GRANTED = 0xC0000055,
        STATUS_NOT_SAME_OBJECT = 0xC00001AC,
        STATUS_PORT_NOT_SET = 0xC0000353,
        STATUS_RANGE_NOT_LOCKED = 0xC000007E,
        STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA,
        STATUS_NOT_SAME_DEVICE = 0xC00000D4,
        STATUS_NOT_A_DIRECTORY = 0xC0000103,
        STATUS_INVALID_LOCK_RANGE = 0xC00001A1,
        STATUS_MUTANT_NOT_OWNED = 0xC0000046,
        STATUS_SEMAPHORE_LIMIT_EXCEEDED = 0xC0000047,
        STATUS_NOT_A_REPARSE_POINT = 0xC0000275
    }

    public enum THREADINFOCLASS : int
    {
        ThreadBasicInformation = 0,
        ThreadTimes = 1,
        ThreadPriority = 2,
        ThreadBasePriority = 3,
        ThreadAffinityMask = 4,
        ThreadImpersonationToken = 5,
        ThreadDescriptorTableEntry = 6,
        ThreadEnableAlignmentFaultFixup = 7,
        ThreadEventPair = 8,
        ThreadQuerySetWin32StartAddress = 9,
        ThreadZeroTlsCell = 10,
        ThreadPerformanceCount = 11,
        ThreadAmILastThread = 12,
        ThreadIdealProcessor = 13,
        ThreadPriorityBoost = 14,
        ThreadSetTlsArrayAddress = 15,
        ThreadIsIoPending = 16,
        ThreadHideFromDebugger = 17,
        ThreadBreakOnTermination = 18,
        ThreadSwitchLegacyState = 19,
        ThreadIsTerminated = 20,
        ThreadLastSystemCall = 21,
        ThreadIoPriority = 22,
        ThreadCycleTime = 23,
        ThreadPagePriority = 24,
        ThreadActualBasePriority = 25,
        ThreadTebInformation = 26,
        ThreadCSwitchMon = 27,
        ThreadCSwitchPmu = 28,
        ThreadWow64Context = 29,
        ThreadGroupInformation = 30,
        ThreadUmsInformation = 31,
        ThreadCounterProfiling = 32,
        ThreadIdealProcessorEx = 33,
        ThreadCpuAccountingInformation = 34,
        ThreadSuspendCount = 35,
        ThreadHeterogeneousCpuPolicy = 36,
        ThreadContainerId = 37,
        ThreadNameInformation = 38,
        ThreadSelectedCpuSets = 39,
        ThreadSystemThreadInformation = 40,
        ThreadActualGroupAffinity = 41,
        ThreadDynamicCodePolicyInfo = 42,
        ThreadExplicitCaseSensitivity = 43,
        ThreadWorkOnBehalfTicket = 44,
        ThreadSubsystemInformation = 45,
        ThreadDbgkWerReportActive = 46,
        ThreadAttachContainer = 47,
        ThreadManageWritesToExecutableMemory = 48,
        ThreadPowerThrottlingState = 49,
        ThreadWorkloadClass = 50,
        ThreadCreateStateChange = 51,
        ThreadApplyStateChange = 52,
        ThreadStrongerBadHandleChecks = 53,
        ThreadEffectiveIoPriority = 54,
        ThreadEffectivePagePriority = 55,
        ThreadUpdateLockOwnership = 56,
        ThreadSchedulerSharedDataSlot = 57,
        ThreadTebInformationAtomic = 58,
        ThreadIndexInformation = 59,
        MaxThreadInfoClass = 60
    }

    public enum OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation = 0,
        ObjectNameInformation = 1,
        ObjectTypeInformation = 2,
        ObjectTypesInformation = 3,
        ObjectHandleFlagInformation = 4,
        ObjectSessionInformation = 5,
        ObjectSessionObjectInformation = 6,
        MaxObjectInfoClass = 7
    }

    internal enum FILE_INFORMATION_CLASS : uint
    {
        FileDirectoryInformation = 1,
        FileFullDirectoryInformation = 2,
        FileBothDirectoryInformation = 3,
        FileBasicInformation = 4,
        FileStandardInformation = 5,
        FileInternalInformation = 6,
        FileEaInformation = 7,
        FileAccessInformation = 8,
        FileNameInformation = 9,
        FileRenameInformation = 10,
        FileNamesInformation = 12,
        FileDispositionInformation = 13,
        FilePositionInformation = 14,
        FileModeInformation = 16,
        FileAlignmentInformation = 17,
        FileAllInformation = 18,
        FileAllocationInformation = 19,
        FileEndOfFileInformation = 20,
        FileNetworkOpenInformation = 34,
        FileAttributeTagInformation = 35,
        FileNormalizedNameInformation = 48,
        FileIsRemoteDeviceInformation = 51,
        FileIdInformation = 59,
        FileDispositionInformationEx = 64,
        FileRenameInformationEx = 65
    }

    public enum TOKEN_INFORMATION_CLASS : uint
    {
        TokenUser = 1,
        TokenGroups = 2,
        TokenPrivileges = 3,
        TokenOwner = 4,
        TokenPrimaryGroup = 5,
        TokenDefaultDacl = 6,
        TokenSource = 7,
        TokenType = 8,
        TokenImpersonationLevel = 9,
        TokenStatistics = 10,
        TokenRestrictedSids = 11,
        TokenSessionId = 12,
        TokenGroupsAndPrivileges = 13,
        TokenSessionReference = 14,
        TokenSandBoxInert = 15,
        TokenAuditPolicy = 16,
        TokenOrigin = 17,
        TokenElevationType = 18,
        TokenLinkedToken = 19,
        TokenElevation = 20,
        TokenHasRestrictions = 21,
        TokenAccessInformation = 22,
        TokenVirtualizationAllowed = 23,
        TokenVirtualizationEnabled = 24,
        TokenIntegrityLevel = 25,
        TokenUIAccess = 26,
        TokenMandatoryPolicy = 27,
        TokenLogonSid = 28,
        TokenIsAppContainer = 29,
        TokenCapabilities = 30,
        TokenAppContainerSid = 31,
        TokenAppContainerNumber = 32,
        TokenUserClaimAttributes = 33,
        TokenDeviceClaimAttributes = 34,
        TokenRestrictedUserClaimAttributes = 35,
        TokenRestrictedDeviceClaimAttributes = 36,
        TokenDeviceGroups = 37,
        TokenRestrictedDeviceGroups = 38,
        TokenSecurityAttributes = 39,
        TokenIsRestricted = 40,
        TokenProcessTrustLevel = 41,
        TokenPrivateNameSpace = 42,
        TokenSingletonAttributes = 43,
        TokenBnoIsolation = 44,
        TokenChildProcessFlags = 45,
        TokenIsLessPrivilegedAppContainer = 46,
        TokenIsSandboxed = 47,
        TokenIsAppSilo = 48,
        TokenLoggingInformation = 49
    }

    public enum SecurityImpersonationLevel : uint
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    }

    public enum MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation,
        MemoryWorkingSetInformation,
        MemoryMappedFilenameInformation,
        MemoryRegionInformation,
        MemoryWorkingSetExInformation,
        MemorySharedCommitInformation,
        MemoryImageInformation,
        MemoryRegionInformationEx,
        MemoryPrivilegedBasicInformation,
        MemoryEnclaveImageInformation,
        MemoryBasicInformationCapped,
        MemoryPhysicalContiguityInformation,
        MemoryBadInformation,
        MemoryBadInformationAllProcesses,
        MemoryImageExtensionInformation,
        MaxMemoryInfoClass
    }

    public enum SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemMirrorMemoryInformation,
        SystemPerformanceTraceInformation,
        SystemObsolete0,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeparation,
        SystemVerifierAddDriverInformation,
        SystemVerifierRemoveDriverInformation,
        SystemProcessorIdleInformation,
        SystemLegacyDriverInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation,
        SystemTimeSlipNotification,
        SystemSessionCreate,
        SystemSessionDetach,
        SystemSessionInformation,
        SystemRangeStartInformation,
        SystemVerifierInformation,
        SystemVerifierThunkExtend,
        SystemSessionProcessInformation,
        SystemLoadGdiDriverInSystemSpace,
        SystemNumaProcessorMap,
        SystemPrefetcherInformation,
        SystemExtendedProcessInformation,
        SystemRecommendedSharedDataAlignment,
        SystemComPlusPackage,
        SystemNumaAvailableMemory,
        SystemProcessorPowerInformation,
        SystemEmulationBasicInformation,
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation,
        SystemLostDelayedWriteInformation,
        SystemBigPoolInformation,
        SystemSessionPoolTagInformation,
        SystemSessionMappedViewInformation,
        SystemHotpatchInformation,
        SystemObjectSecurityMode,
        SystemWatchdogTimerHandler,
        SystemWatchdogTimerInformation,
        SystemLogicalProcessorInformation,
        SystemWow64SharedInformationObsolete,
        SystemRegisterFirmwareTableInformationHandler,
        SystemFirmwareTableInformation,
        SystemModuleInformationEx,
        SystemVerifierTriageInformation,
        SystemSuperfetchInformation,
        SystemMemoryListInformation,
        SystemFileCacheInformationEx,
        SystemThreadPriorityClientIdInformation,
        SystemProcessorIdleCycleTimeInformation,
        SystemVerifierCancellationInformation,
        SystemProcessorPowerInformationEx,
        SystemRefTraceInformation,
        SystemSpecialPoolInformation,
        SystemProcessIdInformation,
        SystemErrorPortInformation,
        SystemBootEnvironmentInformation,
        SystemHypervisorInformation,
        SystemVerifierInformationEx,
        SystemTimeZoneInformation,
        SystemImageFileExecutionOptionsInformation,
        SystemCoverageInformation,
        SystemPrefetchPatchInformation,
        SystemVerifierFaultsInformation,
        SystemSystemPartitionInformation,
        SystemSystemDiskInformation,
        SystemProcessorPerformanceDistribution,
        SystemNumaProximityNodeInformation,
        SystemDynamicTimeZoneInformation,
        SystemCodeIntegrityInformation,
        SystemProcessorMicrocodeUpdateInformation,
        SystemProcessorBrandString,
        SystemVirtualAddressInformation,
        SystemLogicalProcessorAndGroupInformation,
        SystemProcessorCycleTimeInformation,
        SystemStoreInformation,
        SystemRegistryAppendString,
        SystemAitSamplingValue,
        SystemVhdBootInformation,
        SystemCpuQuotaInformation,
        SystemNativeBasicInformation,
        SystemErrorPortTimeouts,
        SystemLowPriorityIoInformation,
        SystemTpmBootEntropyInformation,
        SystemVerifierCountersInformation,
        SystemPagedPoolInformationEx,
        SystemSystemPtesInformationEx,
        SystemNodeDistanceInformation,
        SystemAcpiAuditInformation,
        SystemBasicPerformanceInformation,
        SystemQueryPerformanceCounterInformation,
        SystemSessionBigPoolInformation,
        SystemBootGraphicsInformation,
        SystemScrubPhysicalMemoryInformation,
        SystemBadPageInformation,
        SystemProcessorProfileControlArea,
        SystemCombinePhysicalMemoryInformation,
        SystemEntropyInterruptTimingInformation,
        SystemConsoleInformation,
        SystemPlatformBinaryInformation,
        SystemPolicyInformation,
        SystemHypervisorProcessorCountInformation,
        SystemDeviceDataInformation,
        SystemDeviceDataEnumerationInformation,
        SystemMemoryTopologyInformation,
        SystemMemoryChannelInformation,
        SystemBootLogoInformation,
        SystemProcessorPerformanceInformationEx,
        SystemCriticalProcessErrorLogInformation,
        SystemSecureBootPolicyInformation,
        SystemPageFileInformationEx,
        SystemSecureBootInformation,
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation,
        SystemFullProcessInformation,
        SystemKernelDebuggerInformationEx,
        SystemBootMetadataInformation,
        SystemSoftRebootInformation,
        SystemElamCertificateInformation,
        SystemOfflineDumpConfigInformation,
        SystemProcessorFeaturesInformation,
        SystemRegistryReconciliationInformation,
        SystemEdidInformation,
        SystemManufacturingInformation,
        SystemEnergyEstimationConfigInformation,
        SystemHypervisorDetailInformation,
        SystemProcessorCycleStatsInformation,
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation,
        SystemKernelDebuggerFlags,
        SystemCodeIntegrityPolicyInformation,
        SystemIsolatedUserModeInformation,
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation,
        SystemAllowedCpuSetsInformation,
        SystemVsmProtectionInformation,
        SystemInterruptCpuSetsInformation,
        SystemSecureBootPolicyFullInformation,
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation,
        SystemRootSiloInformation,
        SystemCpuSetInformation,
        SystemCpuSetTagInformation,
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation,
        SystemCodeIntegrityPlatformManifestInformation,
        SystemInterruptSteeringInformation,
        SystemSupportedProcessorArchitectures,
        SystemMemoryUsageInformation,
        SystemCodeIntegrityCertificateInformation,
        SystemPhysicalMemoryInformation,
        SystemControlFlowTransition,
        SystemKernelDebuggingAllowed,
        SystemActivityModerationExeState,
        SystemActivityModerationUserSettings,
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation,
        SystemIntegrityQuotaInformation,
        SystemFlushInformation,
        SystemProcessorIdleMaskInformation,
        SystemSecureDumpEncryptionInformation,
        SystemWriteConstraintInformation,
        SystemKernelVaShadowInformation,
        SystemHypervisorSharedPageInformation,
        SystemFirmwareBootPerformanceInformation,
        SystemCodeIntegrityVerificationInformation,
        SystemFirmwarePartitionInformation,
        SystemSpeculationControlInformation,
        SystemDmaGuardPolicyInformation,
        SystemEnclaveLaunchControlInformation,
        SystemWorkloadAllowedCpuSetsInformation,
        SystemCodeIntegrityUnlockModeInformation,
        SystemLeapSecondInformation,
        SystemFlags2Information,
        SystemSecurityModelInformation,
        SystemCodeIntegritySyntheticCacheInformation,
        SystemFeatureConfigurationInformation,
        SystemFeatureConfigurationSectionInformation,
        SystemFeatureUsageSubscriptionInformation,
        SystemSecureSpeculationControlInformation,
        SystemSpacesBootInformation,
        SystemFwRamdiskInformation,
        SystemWheaIpmiHardwareInformation,
        SystemDifSetRuleClassInformation,
        SystemDifClearRuleClassInformation,
        SystemDifApplyPluginVerificationOnDriver,
        SystemDifRemovePluginVerificationOnDriver,
        SystemShadowStackInformation,
        SystemBuildVersionInformation,
        SystemPoolLimitInformation,
        SystemCodeIntegrityAddDynamicStore,
        SystemCodeIntegrityClearDynamicStores,
        SystemDifPoolTrackingInformation,
        SystemPoolZeroingInformation,
        SystemDpcWatchdogInformation,
        SystemDpcWatchdogInformation2,
        SystemSupportedProcessorArchitectures2,
        SystemSingleProcessorRelationshipInformation,
        SystemXfgCheckFailureInformation,
        SystemIommuStateInformation,
        SystemHypervisorMinrootInformation,
        SystemHypervisorBootPagesInformation,
        SystemPointerAuthInformation,
        SystemSecureKernelDebuggerInformation,
        SystemOriginalImageFeatureInformation,
        SystemMemoryNumaInformation,
        SystemMemoryNumaPerformanceInformation,
        SystemCodeIntegritySignedPoliciesFullInformation,
        SystemSecureCoreInformation,
        SystemTrustedAppsRuntimeInformation,
        SystemBadPageInformationEx,
        SystemResourceDeadlockTimeout,
        SystemBreakOnContextUnwindFailureInformation,
        SystemOslRamdiskInformation,
        SystemCodeIntegrityPolicyManagementInformation,
        SystemMemoryNumaCacheInformation,
        SystemProcessorFeaturesBitMapInformation,
        SystemRefTraceInformationEx,
        SystemBasicProcessInformation,
        SystemHandleCountInformation,
        SystemRuntimeAttestationReport,
        SystemPoolTagInformation2,
        MaxSystemInfoClass
    }

    public enum PROCESSINFOCLASS
    {
        ProcessBasicInformation,
        ProcessQuotaLimits,
        ProcessIoCounters,
        ProcessVmCounters,
        ProcessTimes,
        ProcessBasePriority,
        ProcessRaisePriority,
        ProcessDebugPort,
        ProcessExceptionPort,
        ProcessAccessToken,
        ProcessLdtInformation,
        ProcessLdtSize,
        ProcessDefaultHardErrorMode,
        ProcessIoPortHandlers,
        ProcessPooledUsageAndLimits,
        ProcessWorkingSetWatch,
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup,
        ProcessPriorityClass,
        ProcessWx86Information,
        ProcessHandleCount,
        ProcessAffinityMask,
        ProcessPriorityBoost,
        ProcessDeviceMap,
        ProcessSessionInformation,
        ProcessForegroundInformation,
        ProcessWow64Information,
        ProcessImageFileName,
        ProcessLUIDDeviceMapsEnabled,
        ProcessBreakOnTermination,
        ProcessDebugObjectHandle,
        ProcessDebugFlags,
        ProcessHandleTracing,
        ProcessIoPriority,
        ProcessExecuteFlags,
        ProcessTlsInformation,
        ProcessCookie,
        ProcessImageInformation,
        ProcessCycleTime,
        ProcessPagePriority,
        ProcessInstrumentationCallback,
        ProcessThreadStackAllocation,
        ProcessWorkingSetWatchEx,
        ProcessImageFileNameWin32,
        ProcessImageFileMapping,
        ProcessAffinityUpdateMode,
        ProcessMemoryAllocationMode,
        ProcessGroupInformation,
        ProcessTokenVirtualizationEnabled,
        ProcessConsoleHostProcess,
        ProcessWindowInformation,
        ProcessHandleInformation,
        ProcessMitigationPolicy,
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode,
        ProcessKeepAliveCount,
        ProcessRevokeFileHandles,
        ProcessWorkingSetControl,
        ProcessHandleTable,
        ProcessCheckStackExtentsMode,
        ProcessCommandLineInformation,
        ProcessProtectionInformation,
        ProcessMemoryExhaustion,
        ProcessFaultInformation,
        ProcessTelemetryIdInformation,
        ProcessCommitReleaseInformation,
        ProcessDefaultCpuSetsInformation,
        ProcessAllowedCpuSetsInformation,
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation,
        ProcessInPrivate,
        ProcessRaiseUMExceptionOnInvalidHandleClose,
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation,
        ProcessHighGraphicsPriorityInformation,
        ProcessSubsystemInformation,
        ProcessEnergyValues,
        ProcessPowerThrottlingState,
        ProcessActivityThrottlePolicy,
        ProcessWin32kSyscallFilterInformation,
        ProcessDisableSystemAllowedCpuSets,
        ProcessWakeInformation,
        ProcessEnergyTrackingState,
        ProcessManageWritesToExecutableMemory,
        ProcessCaptureTrustletLiveDump,
        ProcessTelemetryCoverage,
        ProcessEnclaveInformation,
        ProcessEnableReadWriteVmLogging,
        ProcessUptimeInformation,
        ProcessImageSection,
        ProcessDebugAuthInformation,
        ProcessSystemResourceManagement,
        ProcessSequenceNumber,
        ProcessLoaderDetour,
        ProcessSecurityDomainInformation,
        ProcessCombineSecurityDomainsInformation,
        ProcessEnableLogging,
        ProcessLeapSecondInformation,
        ProcessFiberShadowStackAllocation,
        ProcessFreeFiberShadowStackAllocation,
        ProcessAltSystemCallInformation,
        ProcessDynamicEHContinuationTargets,
        ProcessDynamicEnforcedCetCompatibleRanges,
        ProcessCreateStateChange,
        ProcessApplyStateChange,
        ProcessEnableOptionalXStateFeatures,
        ProcessAltPrefetchParam,
        ProcessAssignCpuPartitions,
        ProcessPriorityClassEx,
        ProcessMembershipInformation,
        ProcessEffectiveIoPriority,
        ProcessEffectivePagePriority,
        ProcessSchedulerSharedData,
        ProcessSlistRollbackInformation,
        ProcessNetworkIoCounters,
        ProcessFindFirstThreadByTebValue,
        ProcessEnclaveAddressSpaceRestriction,
        ProcessAvailableCpus,
        MaxProcessInfoClass
    }

    public enum KEY_INFORMATION_CLASS : int
    {
        KeyBasicInformation = 0,
        KeyNodeInformation = 1,
        KeyFullInformation = 2,
        KeyNameInformation = 3,
        KeyCachedInformation = 4,
        KeyFlagsInformation = 5,
        KeyVirtualizationInformation = 6,
        KeyHandleTagsInformation = 7,
    }

    public enum KEY_SET_INFORMATION_CLASS : int
    {
        KeyWriteTimeInformation = 0,
        KeyWow64FlagsInformation = 1,
        KeyControlFlagsInformation = 2,
        KeySetVirtualizationInformation = 3,
        KeySetDebugInformation = 4,
        KeySetHandleTagsInformation = 5,
    }

    public enum WORKERFACTORYINFOCLASS : int
    {
        WorkerFactoryTimeout = 0,
        WorkerFactoryRetryTimeout = 1,
        WorkerFactoryIdleTimeout = 2,
        WorkerFactoryBindingCount = 3,
        WorkerFactoryThreadMinimum = 4,
        WorkerFactoryThreadMaximum = 5,
        WorkerFactoryPaused = 6,
        WorkerFactoryBasicInformation = 7,
        WorkerFactoryAdjustThreadGoal = 8,
        WorkerFactoryCallbackType = 9,
        WorkerFactoryStackInformation = 10,
        WorkerFactoryThreadBasePriority = 11,
        WorkerFactoryTimeoutWaiters = 12,
        WorkerFactoryFlags = 13,
        WorkerFactoryThreadSoftMaximum = 14,
        WorkerFactoryThreadCpuSets = 15,
        MaxWorkerFactoryInfoClass = 16
    }

    public enum MEMORY_IMAGE_EXTENSION_TYPE : uint
    {
        MemoryImageExtensionCfgScp = 0,
        MemoryImageExtensionCfgEmulatedScp = 1,
        MemoryImageExtensionTypeMax = 2
    }

    public enum KEY_VALUE_INFORMATION_CLASS : uint
    {
        KeyValueBasicInformation = 0,
        KeyValueFullInformation = 1,
        KeyValuePartialInformation = 2,
        KeyValueFullInformationAlign64 = 3,
        KeyValuePartialInformationAlign64 = 4
    }

    [Flags]
    public enum AccessMask : uint
    {
        None = 0,
        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000,
        MaximumAllowed = 0x02000000,
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDAC = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
        StandardRightsRequired = Delete | ReadControl | WriteDAC | WriteOwner,
        StandardRightsAll = StandardRightsRequired | Synchronize,
        ProcessTerminate = 0x00000001,
        ProcessCreateThread = 0x00000002,
        ProcessSetSessionId = 0x00000004,
        ProcessVMOperation = 0x00000008,
        ProcessVMRead = 0x00000010,
        ProcessVMWrite = 0x00000020,
        ProcessDupHandle = 0x00000040,
        ProcessCreateProcess = 0x00000080,
        ProcessSetQuota = 0x00000100,
        ProcessSetInformation = 0x00000200,
        ProcessQueryInformation = 0x00000400,
        ProcessSuspendResume = 0x00000800,
        ProcessQueryLimitedInformation = 0x00001000,
        ProcessSetLimitedInformation = 0x00002000,
        ProcessAllAccess = StandardRightsRequired | Synchronize | 0xFFFF,
        ThreadTerminate = 0x00000001,
        ThreadSuspendResume = 0x00000002,
        ThreadAlert = 0x00000004,
        ThreadGetContext = 0x00000008,
        ThreadSetContext = 0x00000010,
        ThreadSetInformation = 0x00000020,
        ThreadQueryInformation = 0x00000040,
        ThreadSetThreadToken = 0x00000080,
        ThreadImpersonate = 0x00000100,
        ThreadDirectImpersonation = 0x00000200,
        ThreadSetLimitedInformation = 0x00000400,
        ThreadQueryLimitedInformation = 0x00000800,
        ThreadResume = 0x00001000,
        ThreadAllAccess = StandardRightsRequired | Synchronize | 0xFFFF,
        TokenAssignPrimary = 0x00000001,
        TokenDuplicate = 0x00000002,
        TokenImpersonate = 0x00000004,
        TokenQuery = 0x00000008,
        TokenQuerySource = 0x00000010,
        TokenAdjustPrivileges = 0x00000020,
        TokenAdjustGroups = 0x00000040,
        TokenAdjustDefault = 0x00000080,
        TokenAdjustSessionId = 0x00000100,
        TokenAllAccess = StandardRightsRequired | TokenAssignPrimary | TokenDuplicate | TokenImpersonate | TokenQuery | TokenQuerySource | TokenAdjustPrivileges | TokenAdjustGroups | TokenAdjustDefault | TokenAdjustSessionId,
        KeyQueryValue = 0x00000001,
        KeySetValue = 0x00000002,
        KeyCreateSubKey = 0x00000004,
        KeyEnumerateSubKeys = 0x00000008,
        KeyNotify = 0x00000010,
        KeyCreateLink = 0x00000020,
        KeyAllAccess = StandardRightsRequired | 0x3F,
        FileReadData = 0x00000001,
        FileWriteData = 0x00000002,
        FileAppendData = 0x00000004,
        FileReadEA = 0x00000008,
        FileWriteEA = 0x00000010,
        FileExecute = 0x00000020,
        FileDeleteChild = 0x00000040,
        FileReadAttributes = 0x00000080,
        FileWriteAttributes = 0x00000100,
        FileAllAccess = StandardRightsRequired | Synchronize | 0x1FF,
        MutantQueryState = 0x00000001,
        MutantAllAccess = StandardRightsRequired | Synchronize | MutantQueryState,
        MutexModifyState = MutantQueryState,
        MutexAllAccess = MutantAllAccess,
        SemaphoreQueryState = 0x00000001,
        SemaphoreModifyState = 0x00000002,
        SemaphoreAllAccess = StandardRightsRequired | Synchronize | SemaphoreQueryState | SemaphoreModifyState,
        SectionQuery = 0x0001,
        SectionMapWrite = 0x0002,
        SectionMapRead = 0x0004,
        SectionMapExecute = 0x0008,
        SectionExtendSize = 0x0010,
        SectionAllAccess = StandardRightsRequired | SectionQuery | SectionMapWrite | SectionMapRead | SectionMapExecute | SectionExtendSize,

        /// <summary>
        /// Tells the handle manager to give the handle temporarily
        /// </summary>
        GiveTemp = 0x12341234,
    }

    [Flags]
    public enum DuplicateFlags : uint
    {
        DUPLICATE_CLOSE_SOURCE = 0x00000001,
        DUPLICATE_SAME_ACCESS = 0x00000002,
        DUPLICATE_SAME_ATTRIBUTES = 0x00000004
    }

    public enum HandleType
    {
        ProcessHandle = 0,
        FileHandle = 1,
        MutexHandle = 2,
        RegistryKeyHandle = 3,
        EventHandle = 4,
        SectionHandle = 5,
        ThreadHandle = 6,
        TimerHandle = 7,
        TokenHandle = 8,
        PortHandle = 9,
        IoCompletionHandle = 10,
        WorkerFactoryHandle = 11,
        WaitCompletionPacketHandle = 12,
        Window = 13,
        EtwRegistrationHandle = 14,
        SemaphoreHandle = 15
    }

    public sealed class WinToken : IHandleObject
    {
        public TokenType Type;
        public uint SessionId;
        public bool IsElevated;
        public bool IsRestricted;
        public bool EffectiveOnly;
        public SecurityImpersonationLevel ImpersonationLevel = SecurityImpersonationLevel.SecurityImpersonation;
        public ulong OwningProcessId;
        public ulong OwningThreadId;
        public string ObjectId => "Token";
        public HandleType ObjectType => HandleType.TokenHandle;
    }

    public class WinHandle
    {
        public ulong Handle;
        public HandleType HandleType;
        public AccessMask Permissions;
    }

    [Flags]
    public enum ObjectHandleFlags : uint
    {
        None = 0,
        Inherit = 1,
        ProtectFromClose = 2,
    }

    public enum ProtectionStatus
    {
        None = 0,
        Light = 1,
        LightAM = 2,
        LightTCB = 3,
        LightLSA = 4,
        Full = 5,
        SecureFull = 6,
        Unaccessible = 7,
    }

    public enum User
    {
        Standard = 0,
        Admin = 1,
        System = 2,
        LocalService = 3,
        WindowManager = 4,
        FontManager = 5,
    }

    public enum TokenType
    {
        Primary,
        Impersonation
    }

    public delegate NTSTATUS WinDeviceDelegate(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance);

    public interface IWinDevice
    {
        string DeviceName { get; }

        NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler);
    }

    public interface IHandleObject
    {
        string ObjectId { get; }

        HandleType ObjectType { get; }
    }

    public class WinProcess : IHandleObject
    {
        public uint PID;
        public uint PPID;
        public string Name;
        public string Path;
        public ProtectionStatus Status;
        public User RunningUser;
        public bool Critical;
        public long CreationTime;
        public long ExitTime;
        public long KernelTime;
        public long UserTime;
        public uint ShutdownLevel = 0x280;
        public uint ShutdownFlags;
        public BinaryArchitecture Arch;
        public WinToken PrimaryToken;
        public ulong InstrumentationCallback;

        public string ObjectId => PID.ToString();
        public HandleType ObjectType => HandleType.ProcessHandle;
    }

    public sealed class WinDirectoryEntry
    {
        public string Name;
        public ulong EndOfFile;
        public ulong AllocationSize;
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
    }

    public class WinFile : IHandleObject
    {
        public class WinLockFile
        {
            public ulong Offset;
            public ulong Length;
            public ulong Key;
            public bool Exclusive;
        }

        public string Path;
        public WindowsFileStream FileStream;
        public bool Device;
        public bool Real;
        public List<WinDirectoryEntry> DirectoryEntries;
        public int DirectoryIndex;
        public string DirectoryMask;
        public bool Directory;
        public long Position;
        public uint Mode;
        public bool DeletePending;
        public bool HasBasicInformation;
        public uint BasicFileAttributes;
        public long BasicCreationTime;
        public long BasicLastAccessTime;
        public long BasicLastWriteTime;
        public long BasicChangeTime;
        public string OpenId = Guid.NewGuid().ToString("N");
        public List<WinLockFile> Locks = new List<WinLockFile>();

        public WinDeviceDelegate Handler;

        public WindowsFileStream GetFileStream(bool CreateWriteDirectories = false)
        {
            if (string.IsNullOrEmpty(Path))
                return null;

            if (FileStream == null || !string.Equals(FileStream.GuestPath, Path, StringComparison.OrdinalIgnoreCase))
                FileStream = WindowsFileStream.FromGuestPath(Path, CreateWriteDirectories);

            return FileStream;
        }

        public string ObjectId => $"FILE_{OpenId}";
        public HandleType ObjectType => HandleType.FileHandle;

        private static bool LockRangesOverlap(ulong LeftOffset, ulong LeftLength, ulong RightOffset, ulong RightLength)
        {
            if (LeftLength == 0 || RightLength == 0)
                return false;

            ulong LeftEnd = LeftOffset + LeftLength - 1;
            ulong RightEnd = RightOffset + RightLength - 1;
            return LeftOffset <= RightEnd && RightOffset <= LeftEnd;
        }

        public WinLockFile GetConflictingLock(ulong Offset, ulong Length, ulong Key, bool ExclusiveLock)
        {
            foreach (WinLockFile Existing in Locks)
            {
                if (!LockRangesOverlap(Existing.Offset, Existing.Length, Offset, Length))
                    continue;

                bool SameKey = Existing.Key == Key;

                if (Existing.Exclusive)
                {
                    if (!SameKey)
                        return Existing;

                    if (ExclusiveLock)
                        return Existing;

                    continue;
                }

                if (ExclusiveLock)
                    return Existing;
            }

            return null;
        }

        public void AddLock(ulong Offset, ulong Length, ulong Key, bool ExclusiveLock)
        {
            Locks.Add(new WinLockFile
            {
                Offset = Offset,
                Length = Length,
                Key = Key,
                Exclusive = ExclusiveLock
            });
        }

        public bool RemoveLock(ulong Offset, ulong Length, ulong Key)
        {
            for (int i = 0; i < Locks.Count; i++)
            {
                WinLockFile Existing = Locks[i];
                if (Existing.Offset != Offset)
                    continue;
                if (Existing.Length != Length)
                    continue;
                if (Existing.Key != Key)
                    continue;

                Locks.RemoveAt(i);
                return true;
            }

            return false;
        }

        public bool HasConflictingIoLock(ulong Offset, ulong Length, bool WriteOperation)
        {
            foreach (WinLockFile Existing in Locks)
            {
                if (!LockRangesOverlap(Existing.Offset, Existing.Length, Offset, Length))
                    continue;

                if (WriteOperation)
                    return true;

                if (Existing.Exclusive)
                    return true;
            }

            return false;
        }
    }

    public class WinMutex : IHandleObject
    {
        public string Name;
        public bool Signaled;
        public bool Abandoned;
        public uint OwnerThreadId;
        public int RecursionCount;

        public int SignalState => RecursionCount == 0 ? 1 : 1 - RecursionCount;

        public string ObjectId => Name;
        public HandleType ObjectType => HandleType.MutexHandle;
    }

    public class WinRegKey : IHandleObject
    {
        public string FullPath;
        public Hive Hive;
        public KeyNode Key;
        public long LastWriteTime;
        public uint Wow64Flags;
        public uint ControlFlags;
        public uint VirtualizationFlags;
        public uint DebugInformation;
        public uint HandleTags;
        public bool NotifySignaled;

        public RegistryHiveReader.HiveKey ParsedKey;
        public bool HasParsedKey;

        public string ObjectId => FullPath;
        public HandleType ObjectType => HandleType.RegistryKeyHandle;
    }

    public class WinRegistryNotification
    {
        public string KeyPath;
        public bool WatchTree;
        public uint CompletionFilter;
        public ulong EventHandle;
        public ulong KeyHandle;
        public ulong IoStatusBlock;
        public ulong ApcRoutine;
        public ulong ApcContext;
        public ulong Buffer;
        public uint BufferSize;
        public int ThreadId;
    }

    public class WinEvent : IHandleObject
    {
        public string Name;
        public bool Signaled;
        public uint EventType;

        public string ObjectId => Name;
        public HandleType ObjectType => HandleType.EventHandle;
    }

    public class WinSemaphore : IHandleObject
    {
        public string Name;
        public int CurrentCount;
        public int MaximumCount;

        public string ObjectId => Name;
        public HandleType ObjectType => HandleType.SemaphoreHandle;
    }

    public class WinSection : IHandleObject
    {
        public string Name;
        public ulong Size;
        public uint Protection;
        public uint Attributes;
        public string Path;
        public WindowsFileStream FileStream;
        public ulong BackingAddress;
        public ulong ImageSectionId;
        public bool IsImage => ((Attributes & 0x01000000) != 0);
        public bool Initialized;

        public WindowsFileStream GetFileStream(bool CreateWriteDirectories = false)
        {
            if (string.IsNullOrEmpty(Path))
                return null;

            if (FileStream == null || !string.Equals(FileStream.GuestPath, Path, StringComparison.OrdinalIgnoreCase))
                FileStream = WindowsFileStream.FromGuestPath(Path, CreateWriteDirectories);

            return FileStream;
        }

        public string MappedImageCanonicalPath;

        public string ObjectId => Name;
        public HandleType ObjectType => HandleType.SectionHandle;
    }

    public class WinWindowClass
    {
        public ushort Atom;
        public string Name;
        public string Version;
        public string MenuName;
        public ulong InstanceHandle;
        public ulong WndProc;
        public uint Style;
        public int ClassExtraBytes;
        public int WindowExtraBytes;
        public ulong IconHandle;
        public ulong CursorHandle;
        public ulong BackgroundBrush;
        public ulong SmallIconHandle;
        public uint FunctionId;
        public uint Flags;
        public bool Ansi;
    }

    public class WinWindow : IHandleObject
    {
        public ulong Hwnd;
        public ushort ClassAtom;
        public string Title;
        public string ClassName;

        public bool Visible;
        public bool Destroyed;
        public bool Minimized;
        public bool Maximized;

        public uint Style;
        public uint ExStyle;

        public int X;
        public int Y;
        public uint Width;
        public uint Height;

        public uint OwnerThreadId;
        public ulong ParentHwnd;
        public ulong OwnerHwnd;
        public ulong InstanceHandle;
        public ulong MenuHandle;
        public ulong CreateParam;
        public ulong UserData;
        public ulong ClientWindowAddress;
        public ulong ClientClassAddress;
        public ulong ClientTextAddress;
        public uint ClientTextBytes;
        public ulong UserHandleEntryAddress;

        public Dictionary<ushort, ulong> AtomProperties = new();
        public Dictionary<string, ulong> StringProperties = new(StringComparer.OrdinalIgnoreCase);

        public List<ulong> Children = new();

        public ulong WndProc;
        public bool Dirty = true;


        public string ObjectId => $"HWND_{Hwnd:X}";
        public HandleType ObjectType => HandleType.Window;
    }


    public sealed class WinIoCompletionEntry
    {
        public ulong KeyContext;
        public ulong ApcContext;
        public NTSTATUS IoStatus;
        public ulong IoStatusInformation;
        public ulong WaitCompletionPacketHandle;
    }

    public sealed class WinIoCompletion : IHandleObject
    {
        public string Name;
        public uint Count;
        public Queue<WinIoCompletionEntry> Entries = new Queue<WinIoCompletionEntry>();

        public string ObjectId => Name;

        public HandleType ObjectType => HandleType.IoCompletionHandle;
    }

    public sealed class WinWorkerFactory : IHandleObject
    {
        public string Name;
        public uint FactoryId;
        public ulong IoCompletionHandle;
        public ulong WorkerProcessHandle;
        public ulong StartRoutine;
        public ulong StartParameter;
        public uint MaxThreadCount;
        public ulong StackReserve;
        public ulong StackCommit;
        public uint ThreadMinimum;
        public uint ThreadMaximum;
        public uint ThreadSoftMaximum;
        public uint BindingCount;
        public uint Paused;
        public bool Shutdown;
        public uint Flags;
        public uint ThreadBasePriority = 8;
        public uint TimeoutWaiters;
        public long Timeout;
        public long RetryTimeout;
        public long IdleTimeout;
        public uint LastInfoClass;
        public uint LastInfoLength;
        public ulong LastInfoValue;
        public List<ulong> WorkerThreads = new List<ulong>();

        public string ObjectId => Name;

        public HandleType ObjectType => HandleType.WorkerFactoryHandle;
    }


    internal static class WorkerFactoryHelper
    {
        internal const uint WORKER_FACTORY_FLAG_LOADER_POOL = 0x1;

        internal static WinWorkerFactory GetFactory(BinaryEmulator Instance, ulong Handle)
        {
            return Instance?.WinHelper?.HandleManager?.GetObjectByHandle<WinWorkerFactory>(Handle);
        }

        internal static WinIoCompletion GetIoCompletion(BinaryEmulator Instance, ulong Handle)
        {
            return Instance?.WinHelper?.HandleManager?.GetObjectByHandle<WinIoCompletion>(Handle);
        }

        internal static uint GetThreadLimit(WinWorkerFactory Factory)
        {
            uint Limit = uint.MaxValue;

            if (Factory.MaxThreadCount != 0 && Factory.MaxThreadCount < Limit)
                Limit = Factory.MaxThreadCount;

            if (Factory.ThreadMaximum != 0 && Factory.ThreadMaximum < Limit)
                Limit = Factory.ThreadMaximum;

            if (Factory.ThreadSoftMaximum != 0 && Factory.ThreadSoftMaximum < Limit)
                Limit = Factory.ThreadSoftMaximum;

            return Limit;
        }

        internal static void PruneWorkerThreads(BinaryEmulator Instance, WinWorkerFactory Factory)
        {
            if (Instance == null || Factory == null || Factory.WorkerThreads == null)
                return;

            Factory.WorkerThreads.RemoveAll(Handle =>
            {
                EmulatedThread Thread = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(Handle);
                return Thread == null || Thread.State == EmulatedThreadState.Terminated;
            });
        }

        internal static NTSTATUS MarkWorkerReady(BinaryEmulator Instance, ulong WorkerFactoryHandle)
        {
            WinWorkerFactory Factory = GetFactory(Instance, WorkerFactoryHandle);
            if (Factory == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            EnsureWorkerThreads(Instance, Factory);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static void EnsureWorkerThreads(BinaryEmulator Instance, WinWorkerFactory Factory)
        {
            if (Instance == null || Factory == null)
                return;

            if (Factory.Shutdown || Factory.Paused != 0 || Factory.StartRoutine == 0)
                return;

            PruneWorkerThreads(Instance, Factory);

            uint Limit = GetThreadLimit(Factory);
            if (Limit == 0)
                return;

            uint Desired = Factory.ThreadMinimum;
            if (Factory.BindingCount > Desired)
                Desired = Factory.BindingCount;
            if (Desired > Limit)
                Desired = Limit;

            Brovan.Core.Emulation.Guests.WindowsGuest Guest = Instance.Guest as Brovan.Core.Emulation.Guests.WindowsGuest;
            if (Guest == null)
                return;

            while ((uint)Factory.WorkerThreads.Count < Desired)
            {
                ulong? StackOverride = Factory.StackReserve != 0 ? Factory.StackReserve : (ulong?)null;
                uint CreateFlags = 0;
                if ((Factory.Flags & WORKER_FACTORY_FLAG_LOADER_POOL) != 0)
                    CreateFlags |= Brovan.Core.Emulation.Guests.WindowsGuest.THREAD_CREATE_FLAGS_LOADER_WORKER;

                string ThreadName = (CreateFlags & Brovan.Core.Emulation.Guests.WindowsGuest.THREAD_CREATE_FLAGS_LOADER_WORKER) != 0
                    ? "loader worker"
                    : null;
                EmulatedThread Thread = Guest.CreateEmulatedThread(Instance, Factory.StartRoutine, ThreadName, Factory.StartParameter, StackOverride, (int)Factory.ThreadBasePriority, CreateFlags, false);
                if (Thread == null)
                    break;

                WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Thread, AccessMask.GiveTemp);
                Instance.WinHelper.WinHandles.Add(Handle);
                Factory.WorkerThreads.Add(Handle.Handle);
            }
        }
    }

    public sealed class WinWaitCompletionPacket : IHandleObject
    {
        public string Name;
        public ulong IoCompletionHandle;
        public ulong TargetObjectHandle;
        public ulong KeyContext;
        public ulong ApcContext;
        public NTSTATUS IoStatus;
        public ulong IoStatusInformation;
        public bool Associated;
        public bool QueuedCompletion;

        public string ObjectId => Name;

        public HandleType ObjectType => HandleType.WaitCompletionPacketHandle;
    }

    /// <summary>
    /// Represents a user-mode ETW provider registration object returned by NtTraceControl.
    /// </summary>
    public sealed class WinEtwRegistration : IHandleObject
    {
        public Guid ProviderGuid;
        public uint NotificationType;
        public ushort RegistrationIndex;
        public ulong Callback;
        public byte[] Traits;

        public string ObjectId => $"ETW_{ProviderGuid:N}_{RegistrationIndex}";

        public HandleType ObjectType => HandleType.EtwRegistrationHandle;
    }

    public class WinTimer : IHandleObject
    {
        public string Name;
        public uint TimerId;
        public uint Attributes;
        public bool Signaled;
        public bool Active;
        public long DueTick;
        public long PeriodMilliseconds;

        public string ObjectId => Name;
        public HandleType ObjectType => HandleType.TimerHandle;
    }

    public class WinSymbolicLink : IHandleObject
    {
        public string FullName;
        public string Target;

        public string ObjectId => FullName;

        public HandleType ObjectType => HandleType.FileHandle;
    }

    /// <summary>
    /// Per-port ALPC/LPC message handler.
    /// Receives the raw send-payload bytes (everything after the PORT_MESSAGE header),
    /// may mutate them, and writes the server reply into <paramref name="ReplyData"/>.
    /// Returns the NTSTATUS to surface to the caller.
    /// </summary>
    public delegate NTSTATUS PortAlpcHandler(WinPort Port, byte[] SendData, out byte[] ReplyData, BinaryEmulator Instance);

    public sealed class WinPort : IHandleObject
    {
        public string Name;

        /// <summary>
        /// Optional per-port message handler invoked by NtAlpcSendWaitReceivePort.
        /// </summary>
        public PortAlpcHandler Handler;
        public string ObjectId => Name;
        public HandleType ObjectType => HandleType.PortHandle;
    }

    /// <summary>
    /// Generic handles manager (for Processes, Files, Mutex, etc)
    /// </summary>
    internal class HandleManager
    {
        public static readonly ulong KNOWN_DLLS_DIRECTORY = 0x1111;
        public static readonly ulong KNOWN_DLLS32_DIRECTORY = 0x1112;
        public static readonly ulong BASE_NAMED_OBJECTS_DIRECTORY = 0x1113;
        public static readonly ulong RPC_CONTROL_DIRECTORY = 0x1114;
        public static readonly ulong CurrentProcess = ulong.MaxValue;
        public static readonly ulong CurrentThread = 0xFFFFFFFFFFFFFFFE;
        private ulong NextHandle = 0x40;
        private readonly Dictionary<ulong, IHandleObject> HandleToObject = new();
        private readonly Dictionary<ulong, AccessMask> HandleToPermissions = new();
        private readonly Dictionary<ulong, ObjectHandleFlags> HandleToFlags = new();
        private readonly Dictionary<string, List<ulong>> ObjectIdToHandles = new();

        public WinHandle AddHandle(IHandleObject obj, AccessMask Permissions)
        {
            ulong handle = AllocateHandleValue();

            WinHandle winHandle = new WinHandle
            {
                Handle = handle,
                HandleType = obj.ObjectType,
                Permissions = Permissions
            };

            HandleToObject[handle] = obj;
            HandleToPermissions[handle] = Permissions;
            HandleToFlags[handle] = ObjectHandleFlags.None;

            if (!ObjectIdToHandles.TryGetValue(obj.ObjectId, out List<ulong> Handles))
            {
                Handles = new List<ulong>();
                ObjectIdToHandles[obj.ObjectId] = Handles;
            }

            Handles.Add(handle);

            return winHandle;
        }

        private ulong AllocateHandleValue()
        {
            while (HandleToObject.ContainsKey(NextHandle) || IsReservedHandleValue(NextHandle))
                NextHandle += 4;

            ulong Handle = NextHandle;
            NextHandle += 4;
            return Handle;
        }

        private static bool IsReservedHandleValue(ulong Handle)
        {
            return Handle == KNOWN_DLLS_DIRECTORY ||
                Handle == KNOWN_DLLS32_DIRECTORY ||
                Handle == BASE_NAMED_OBJECTS_DIRECTORY ||
                Handle == RPC_CONTROL_DIRECTORY ||
                Handle == CurrentProcess ||
                Handle == CurrentThread ||
                Handle == 0;
        }

        public ObjectHandleFlags GetHandleFlags(ulong Handle)
        {
            if (HandleToFlags.TryGetValue(Handle, out ObjectHandleFlags Flags))
                return Flags;
            return ObjectHandleFlags.None;
        }

        public bool SetHandleFlags(ulong Handle, ObjectHandleFlags Flags)
        {
            if (!HandleToObject.ContainsKey(Handle))
                return false;

            HandleToFlags[Handle] = Flags;
            return true;
        }

        public T? GetObjectByHandle<T>(ulong Handle) where T : class, IHandleObject
        {
            if (HandleToObject.TryGetValue(Handle, out IHandleObject obj) && obj is T typedObj)
                return typedObj;
            return null;
        }

        public IHandleObject? GetObjectByHandle(ulong Handle)
        {
            if (HandleToObject.TryGetValue(Handle, out IHandleObject obj))
                return obj;
            return null;
        }

        public List<ulong> GetHandlesByObjectId(string ObjectId)
        {
            if (ObjectIdToHandles.TryGetValue(ObjectId, out List<ulong> Handles))
                return new List<ulong>(Handles);
            return new List<ulong>();
        }

        public AccessMask GetPermissionsByHandle(ulong Handle)
        {
            if (HandleToPermissions.TryGetValue(Handle, out AccessMask permissions))
                return permissions;
            return AccessMask.None;
        }

        public bool RemoveHandle(ulong Handle)
        {
            if (!HandleToObject.TryGetValue(Handle, out IHandleObject obj))
                return false;

            HandleToObject.Remove(Handle);
            HandleToPermissions.Remove(Handle);
            HandleToFlags.Remove(Handle);

            if (ObjectIdToHandles.TryGetValue(obj.ObjectId, out List<ulong> Handles))
            {
                Handles.Remove(Handle);

                if (Handles.Count == 0)
                    ObjectIdToHandles.Remove(obj.ObjectId);
            }

            return true;
        }

        public List<KeyValuePair<ulong, IHandleObject>> SnapshotHandles()
        {
            return new List<KeyValuePair<ulong, IHandleObject>>(HandleToObject);
        }

        public void SnapshotHandles(List<KeyValuePair<ulong, IHandleObject>> Destination)
        {
            if (Destination == null)
                return;

            Destination.Clear();
            foreach (KeyValuePair<ulong, IHandleObject> Pair in HandleToObject)
                Destination.Add(Pair);
        }

        public bool HandleExists(ulong Handle)
        {
            return HandleToObject.ContainsKey(Handle);
        }

        public bool HandleExists(ulong Handle, HandleType type)
        {
            if (!HandleExists(Handle))
                return false;
            return HandleToObject.TryGetValue(Handle, out var obj) && obj.ObjectType == type;
        }

        public bool CheckAccess(ulong Handle, AccessMask RequiredAccess)
        {
            if (!HandleToPermissions.TryGetValue(Handle, out AccessMask GrantedAccess))
                return false;

            if (RequiredAccess == AccessMask.GiveTemp)
                return true;

            if ((GrantedAccess & AccessMask.MaximumAllowed) != 0 || (GrantedAccess & AccessMask.GenericAll) != 0)
                return true;

            return (GrantedAccess & RequiredAccess) == RequiredAccess;
        }
    }

    public class WinModule
    {
        public BinaryArchitecture Architecture;
        public ulong MappedBase;
        public ulong EntryPoint;
        public ulong OriginalBase;
        public ulong SizeOfImage;
        public string Name;
        public string Path;
        public string CanonicalImagePath;
        public ulong ImageSectionId;
        public int ImageMapOrdinal;
        public bool IsSectionView;
        public bool Initialized;
        public Dictionary<ulong, string> Exports = new Dictionary<ulong, string>();
        public Dictionary<string, ulong> ExportsByName = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<ulong, PortableBinarySection> Sections = new Dictionary<ulong, PortableBinarySection>();
    }

    public class WinSysHelper
    {
        private static readonly Lazy<IReadOnlyDictionary<string, IWinDevice>> DeviceRegistry = new Lazy<IReadOnlyDictionary<string, IWinDevice>>(BuildDeviceRegistry);

        public WindowsSharedBuffer Shared { get; private set; }

        private Random RandomGen = new Random();
        private Dictionary<uint, bool> PIDs = new Dictionary<uint, bool>();

        private static IReadOnlyDictionary<string, IWinDevice> BuildDeviceRegistry()
        {
            Dictionary<string, IWinDevice> Devices = new Dictionary<string, IWinDevice>(StringComparer.OrdinalIgnoreCase);

            foreach (IWinDevice Device in WinDeviceRegistry.CreateAll())
            {
                string DeviceName = NormalizeDevicePath(Device.DeviceName);
                if (string.IsNullOrEmpty(DeviceName))
                    continue;

                Devices[DeviceName] = Device;
            }

            return Devices;
        }

        private static string NormalizeDevicePath(string Path)
        {
            return NormalizeDevicePath(Path, null);
        }

        private static string NormalizeDevicePath(string Path, string VolumeGuid)
        {
            if (string.IsNullOrEmpty(Path))
                return string.Empty;

            string Normalized = Path.Trim().TrimEnd('\0').Replace('/', '\\');

            if (Normalized.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Normalized = Normalized.Substring(4);

            while (Normalized.Length > "\\Device\\".Length && Normalized.EndsWith("\\", StringComparison.Ordinal))
                Normalized = Normalized.Substring(0, Normalized.Length - 1);

            if (Normalized.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) ||
                Normalized.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
            {
                Normalized = Normalized.Substring(4);
            }

            if (Normalized.Equals("MountPointManager", StringComparison.OrdinalIgnoreCase))
                Normalized = "\\Device\\MountPointManager";
            else if (Normalized.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("NUL:", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("NULL", StringComparison.OrdinalIgnoreCase))
            {
                Normalized = "\\Device\\Null";
            }
            else if (Normalized.Equals("WMIDataDevice", StringComparison.OrdinalIgnoreCase))
                Normalized = "\\Device\\WMIDataDevice";
            else if (Normalized.Equals("PhysicalDrive0", StringComparison.OrdinalIgnoreCase))
                Normalized = WindowsStorageDeviceSupport.PhysicalDiskDeviceName;
            else if (WindowsStorageDeviceSupport.IsVolumeDevicePath(Normalized, VolumeGuid))
                Normalized = WindowsStorageDeviceSupport.VolumeDeviceName;

            return Normalized;
        }

        /// <summary>
        /// Attempts to create a Windows device endpoint by resolving the device path through the generated device registry.
        /// </summary>
        /// <param name="Path">The normalized or raw NT device path.</param>
        /// <param name="EaBuffer">The extended attributes buffer supplied to NtCreateFile, if any.</param>
        /// <param name="InternalPath">The internal path to assign to the opened device handle.</param>
        /// <param name="Handler">The device I/O handler for the opened endpoint.</param>
        /// <param name="Status">The status returned by the matched device factory.</param>
        /// <returns>True if the path matched a registered device.</returns>
        public bool TryCreateDevice(string Path, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler, out NTSTATUS Status)
        {
            InternalPath = null;
            Handler = null;
            Status = NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            string DevicePath = NormalizeDevicePath(Path, SyntheticVolumeGuid);
            if (!DeviceRegistry.Value.TryGetValue(DevicePath, out IWinDevice Device))
                return false;

            Status = Device.Create(Emulator, DevicePath, EaBuffer ?? Array.Empty<byte>(), out InternalPath, out Handler);

            if (Status == NTSTATUS.STATUS_SUCCESS && (string.IsNullOrEmpty(InternalPath) || Handler == null))
                Status = NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            return true;
        }

        /// <summary>
        /// Checks whether the supplied process handle targets the current emulated process and grants the requested access.
        /// </summary>
        /// <param name="ProcessHandle">The process handle or current-process pseudo handle.</param>
        /// <param name="RequiredAccess">The access mask required for the operation.</param>
        /// <returns>True if the handle references the current process and has the requested access.</returns>
        public bool IsCurrentProcessHandle(ulong ProcessHandle, AccessMask RequiredAccess)
        {
            if (ProcessHandle == HandleManager.CurrentProcess || ProcessHandle == uint.MaxValue)
                return true;

            WinProcess Process = GetProcessByHandle(ProcessHandle, AccessMask.GiveTemp);
            if (Process == null || Process.PID != PID)
                return false;

            AccessMask Granted = HandleManager.GetPermissionsByHandle(ProcessHandle);
            return Granted == AccessMask.GiveTemp ||
                   (Granted & AccessMask.GenericAll) != 0 ||
                   (Granted & AccessMask.ProcessAllAccess) == AccessMask.ProcessAllAccess ||
                   (Granted & RequiredAccess) == RequiredAccess;
        }

        /// <summary>
        /// Returns the address of the syscall instruction that is currently being handled.
        /// </summary>
        /// <param name="Thread">The current emulated thread.</param>
        /// <param name="PreferThreadLastRip">Use the last executed RIP when it is available.</param>
        /// <returns>The syscall instruction address.</returns>
        public ulong GetSyscallRip(EmulatedThread Thread, bool PreferThreadLastRip)
        {
            if (PreferThreadLastRip && Thread != null && Thread.LastRIP != 0)
                return Thread.LastRIP;

            return Emulator.ReadRegister(Emulator.IPRegister);
        }

        /// <summary>
        /// Converts a Windows timeout pointer into an emulated deadline in milliseconds.
        /// </summary>
        /// <param name="TimeoutPtr">Pointer to a LARGE_INTEGER timeout value, or zero for an infinite wait.</param>
        /// <returns>The emulated deadline, the current tick for an immediate timeout, or -1 for an infinite wait.</returns>
        public long ParseRelativeDeadlineMs(ulong TimeoutPtr)
        {
            if (TimeoutPtr == 0)
                return -1;

            long Timeout = unchecked((long)Emulator._emulator.ReadMemoryULong(TimeoutPtr));
            if (Timeout == 0)
                return Emulator.EmulatedTickCount64;

            long Delta100Ns;
            if (Timeout < 0)
            {
                Delta100Ns = Timeout == long.MinValue ? long.MaxValue : -Timeout;
            }
            else
            {
                long NowFileTime = Emulator.GetEmulatedSystemTimeFileTimeUtc();
                if (Timeout <= NowFileTime)
                    return Emulator.EmulatedTickCount64;

                Delta100Ns = Timeout - NowFileTime;
            }

            long Ms = Delta100Ns / 10000;
            if ((Delta100Ns % 10000) != 0 && Ms < long.MaxValue)
                Ms++;

            return Emulator.CreateEmulatedDeadlineMilliseconds(Ms);
        }

        /// <summary>
        /// Clears the blocked wait state for an emulated thread.
        /// </summary>
        /// <param name="Thread">The emulated thread.</param>
        /// <param name="ClearAlertByThreadId">Also clears NtWaitForAlertByThreadId-specific state.</param>
        public void ClearWaitState(EmulatedThread Thread, bool ClearAlertByThreadId = false)
        {
            if (Thread == null)
                return;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            Thread.WaitActive = false;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = -1;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.ApcAlertable = false;

            if (ClearAlertByThreadId)
            {
                State.AlertByThreadIdWaitActive = false;
                State.AlertByThreadIdAddress = 0;
            }
        }

        /// <summary>
        /// Writes a 64-bit IO_STATUS_BLOCK to emulated memory.
        /// </summary>
        /// <param name="IoStatusBlockPtr">Address of the IO_STATUS_BLOCK.</param>
        /// <param name="Status">The operation status.</param>
        /// <param name="Information">The operation information value.</param>
        public void WriteIoStatusBlock64(ulong IoStatusBlockPtr, NTSTATUS Status, ulong Information)
        {
            Span<byte> Buffer = stackalloc byte[0x10];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), (uint)Status);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), Information);
            Emulator._emulator.WriteMemory(IoStatusBlockPtr, Buffer);
        }

        /// <summary>
        /// Writes a 32-bit IO_STATUS_BLOCK to emulated memory.
        /// </summary>
        /// <param name="IoStatusBlockPtr">Address of the IO_STATUS_BLOCK.</param>
        /// <param name="Status">The operation status.</param>
        /// <param name="Information">The operation information value.</param>
        public void WriteIoStatusBlock32(uint IoStatusBlockPtr, NTSTATUS Status, uint Information)
        {
            Span<byte> Buffer = stackalloc byte[0x08];
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), (uint)Status);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), Information);
            Emulator._emulator.WriteMemory(IoStatusBlockPtr, Buffer);
        }

        public void WriteIoStatusBlock64(BinaryEmulator Instance, ulong IoStatusBlockPtr, NTSTATUS Status, ulong Information)
        {
            Span<byte> Buffer = stackalloc byte[0x10];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), (uint)Status);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), Information);
            Instance._emulator.WriteMemory(IoStatusBlockPtr, Buffer);
        }

        public void WriteIoStatusBlock32(BinaryEmulator Instance, uint IoStatusBlockPtr, NTSTATUS Status, uint Information)
        {
            Span<byte> Buffer = stackalloc byte[0x08];
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), (uint)Status);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), Information);
            Instance._emulator.WriteMemory(IoStatusBlockPtr, Buffer);
        }

        /// <summary>
        /// Reads guest memory into the reusable Windows syscall scratch buffer.
        /// </summary>
        /// <param name="Address">The guest address to read.</param>
        /// <param name="Size">The number of bytes to read.</param>
        /// <returns>A span over the shared scratch buffer, or an empty span if the read failed.</returns>
        public Span<byte> ReadMemorySpan(ulong Address, uint Size)
        {
            if (Size == 0)
                return Span<byte>.Empty;

            Span<byte> Buffer = Shared.GetSpan(Size);
            return Emulator._emulator.ReadMemory(Address, Buffer, Size) ? Buffer.Slice(0, (int)Size) : Span<byte>.Empty;
        }

        /// <summary>
        /// Writes zero bytes from the reusable Windows syscall scratch buffer.
        /// </summary>
        /// <param name="Address">The guest address to write.</param>
        /// <param name="Size">The number of zero bytes to write.</param>
        /// <returns>True if the write succeeded.</returns>
        public bool WriteZeroMemory(ulong Address, uint Size)
        {
            if (Size == 0)
                return true;

            Span<byte> Buffer = Shared.GetSpan(Size);
            Buffer.Clear();
            return Emulator._emulator.WriteMemory(Address, Buffer, Size);
        }

        /// <summary>
        /// Writes one byte without allocating a temporary byte array.
        /// </summary>
        /// <param name="Address">The guest address to write.</param>
        /// <param name="Value">The byte value to write.</param>
        /// <returns>True if the write succeeded.</returns>
        public bool WriteByte(ulong Address, byte Value)
        {
            Span<byte> Buffer = stackalloc byte[1];
            Buffer[0] = Value;
            return Emulator._emulator.WriteMemory(Address, Buffer);
        }

        /// <summary>
        /// Writes a little-endian 32-bit integer without allocating a temporary byte array.
        /// </summary>
        public bool WriteUInt32(ulong Address, uint Value)
        {
            Span<byte> Buffer = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer, Value);
            return Emulator._emulator.WriteMemory(Address, Buffer);
        }

        /// <summary>
        /// Writes a little-endian 64-bit integer without allocating a temporary byte array.
        /// </summary>
        public bool WriteUInt64(ulong Address, ulong Value)
        {
            Span<byte> Buffer = stackalloc byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer, Value);
            return Emulator._emulator.WriteMemory(Address, Buffer);
        }

        public ulong BuildUnicodeString(string Buffer)
        {
            if (Buffer == null)
                return 0;

            ulong StructSize = (ulong)Marshal.SizeOf<UNICODE_STRING64>();
            ulong Address = Emulator.MapUniqueAddress(StructSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            int ByteLength = Buffer.Length * 2;
            int MaxByteLength = ByteLength + 2;

            ulong StringAddress = Emulator.MapUniqueAddress((ulong)MaxByteLength, MemoryProtection.ReadWrite);
            if (StringAddress == 0)
                return 0;

            Emulator._emulator.WriteMemory(StringAddress, Buffer, Encoding.Unicode);
            Emulator._emulator.WriteMemory(StringAddress + (ulong)ByteLength, (ushort)0, 2);

            Emulator._emulator.WriteMemory(Address + 0, (ushort)ByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 2, (ushort)MaxByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 8, StringAddress);

            return Address;
        }

        /// <summary>
        /// Reads a 32-bit UNICODE_STRING from guest memory and returns the status the caller should propagate on failure.
        /// </summary>
        public bool TryReadUnicodeString32(uint UnicodeStringPtr, out string Value, out NTSTATUS Status)
        {
            Value = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (UnicodeStringPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            uint UnicodeStringSize = (uint)Marshal.SizeOf<UNICODE_STRING>();
            if (!Emulator.IsRegionMapped(UnicodeStringPtr, UnicodeStringSize))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            if (!StructSerializer.ParseStruct(Emulator, UnicodeStringPtr, out UNICODE_STRING UnicodeString))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            return TryReadUnicodeString32(UnicodeString, out Value, out Status);
        }

        /// <summary>
        /// Reads a parsed 32-bit UNICODE_STRING from guest memory and returns the status the caller should propagate on failure.
        /// </summary>
        public bool TryReadUnicodeString32(UNICODE_STRING UnicodeString, out string Value, out NTSTATUS Status)
        {
            Value = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (UnicodeString.Length > UnicodeString.MaximumLength)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (UnicodeString.Length == 0)
                return true;

            if ((UnicodeString.Length & 1) != 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (UnicodeString.Buffer == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!Emulator.IsRegionMapped(UnicodeString.Buffer, UnicodeString.Length))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            Value = Emulator._emulator.ReadMemoryString(UnicodeString.Buffer, UnicodeString.Length, Encoding.Unicode).TrimEnd('\0');
            return true;
        }

        /// <summary>
        /// Reads a 64-bit UNICODE_STRING from guest memory and returns the status the caller should propagate on failure.
        /// </summary>
        public bool TryReadUnicodeString64(ulong UnicodeStringPtr, out string Value, out NTSTATUS Status)
        {
            Value = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (UnicodeStringPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            uint UnicodeStringSize = (uint)Marshal.SizeOf<UNICODE_STRING64>();
            if (!Emulator.IsRegionMapped(UnicodeStringPtr, UnicodeStringSize))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            if (!StructSerializer.ParseStruct(Emulator, UnicodeStringPtr, out UNICODE_STRING64 UnicodeString))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            return TryReadUnicodeString64(UnicodeString, out Value, out Status);
        }

        /// <summary>
        /// Reads a parsed 64-bit UNICODE_STRING from guest memory and returns the status the caller should propagate on failure.
        /// </summary>
        public bool TryReadUnicodeString64(UNICODE_STRING64 UnicodeString, out string Value, out NTSTATUS Status)
        {
            Value = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (UnicodeString.Length > UnicodeString.MaximumLength)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (UnicodeString.Length == 0)
                return true;

            if ((UnicodeString.Length & 1) != 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (UnicodeString.Buffer == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!Emulator.IsRegionMapped(UnicodeString.Buffer, UnicodeString.Length))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            Value = Emulator._emulator.ReadMemoryString(UnicodeString.Buffer, UnicodeString.Length, Encoding.Unicode).TrimEnd('\0');
            return true;
        }

        private ulong NextImageSectionId = 1;
        private readonly Dictionary<string, ulong> ImageSectionIdsByPath = new(StringComparer.OrdinalIgnoreCase);

        public ulong GetOrCreateImageSectionId(string Path)
        {
            string CanonicalPath = CanonicalizeImagePath(Path);
            if (string.IsNullOrEmpty(CanonicalPath))
                return 0;

            if (!ImageSectionIdsByPath.TryGetValue(CanonicalPath, out ulong Id))
            {
                Id = NextImageSectionId++;
                ImageSectionIdsByPath[CanonicalPath] = Id;
            }

            return Id;
        }

        public void AttachImageSectionIdentity(WinSection Section, string Path)
        {
            if (Section == null)
                return;

            string CanonicalPath = CanonicalizeImagePath(Path);
            if (string.IsNullOrEmpty(CanonicalPath))
                return;

            Section.ImageSectionId = GetOrCreateImageSectionId(CanonicalPath);
            Section.MappedImageCanonicalPath = CanonicalPath;
        }

        public void AttachImageSectionIdentity(WinModule Module, string Path)
        {
            if (Module == null)
                return;

            string CanonicalPath = CanonicalizeImagePath(Path);
            if (string.IsNullOrEmpty(CanonicalPath))
                return;

            Module.ImageSectionId = GetOrCreateImageSectionId(CanonicalPath);
            Module.CanonicalImagePath = CanonicalPath;
        }

        /// <summary>
        /// Reads a 64-bit OBJECT_ATTRIBUTES value and resolves its object name against known NT object-directory handles.
        /// </summary>
        public bool TryReadObjectAttributesName64(ulong ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes, out string Name, out string FullName, out NTSTATUS Status)
        {
            Attributes = default;
            Name = string.Empty;
            FullName = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (ObjectAttributesPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            uint ObjectAttributesSize = (uint)Marshal.SizeOf<OBJECT_ATTRIBUTES64>();
            if (!Emulator.IsRegionMapped(ObjectAttributesPtr, ObjectAttributesSize))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            if (!StructSerializer.ParseStruct(Emulator, ObjectAttributesPtr, out Attributes))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            if (Attributes.ObjectName == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!TryReadUnicodeString64(Attributes.ObjectName, out Name, out Status))
                return false;

            FullName = ResolveObjectNameWithRootDirectory(Attributes.RootDirectory, Name);
            if (string.IsNullOrEmpty(FullName))
                FullName = Name;

            return true;
        }

        /// <summary>
        /// Reads a 32-bit OBJECT_ATTRIBUTES value and resolves its object name against known NT object-directory handles.
        /// </summary>
        public bool TryReadObjectAttributesName32(uint ObjectAttributesPtr, out uint RootDirectory, out uint ObjectName, out string Name, out string FullName, out NTSTATUS Status)
        {
            RootDirectory = 0;
            ObjectName = 0;
            Name = string.Empty;
            FullName = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (ObjectAttributesPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            const uint ObjectAttributes32Size = 0x18;
            if (!Emulator.IsRegionMapped(ObjectAttributesPtr, ObjectAttributes32Size))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            RootDirectory = Emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x04);
            ObjectName = Emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x08);

            if (ObjectName == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!TryReadUnicodeString32(ObjectName, out Name, out Status))
                return false;

            FullName = ResolveObjectNameWithRootDirectory(RootDirectory, Name);
            if (string.IsNullOrEmpty(FullName))
                FullName = Name;

            return true;
        }

        /// <summary>
        /// Resolves a possibly relative NT object name against one of Brovan's synthetic object-directory handles.
        /// </summary>
        public string ResolveObjectNameWithRootDirectory(ulong RootDirectory, string Name)
        {
            if (!string.IsNullOrEmpty(Name) && Name.StartsWith("\\", StringComparison.Ordinal))
                return Name;

            string RootPath = GetKnownObjectDirectoryPath(RootDirectory);
            if (string.IsNullOrEmpty(RootPath))
                return null;

            if (string.IsNullOrEmpty(Name))
                return RootPath;

            return RootPath.TrimEnd('\\') + "\\" + Name.TrimStart('\\');
        }

        /// <summary>
        /// Returns the NT object-manager path represented by one of Brovan's synthetic object-directory handles.
        /// </summary>
        public string GetKnownObjectDirectoryPath(ulong RootDirectory)
        {
            if (RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY)
                return "\\KnownDlls";

            if (RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY)
                return "\\KnownDlls32";

            if (RootDirectory == HandleManager.BASE_NAMED_OBJECTS_DIRECTORY)
                return "\\Sessions\\1\\BaseNamedObjects";

            if (RootDirectory == HandleManager.RPC_CONTROL_DIRECTORY)
                return "\\RPC Control";

            return null;
        }

        /// <summary>
        /// Gets the synthetic handle for a supported NT object-manager directory path.
        /// </summary>
        public bool TryGetKnownObjectDirectoryHandle(string ObjectName, out ulong Handle)
        {
            Handle = 0;

            if (string.IsNullOrEmpty(ObjectName))
                return false;

            string Normalized = ObjectName.TrimEnd('\0');

            if (Normalized.Equals("\\KnownDlls", StringComparison.OrdinalIgnoreCase))
            {
                Handle = HandleManager.KNOWN_DLLS_DIRECTORY;
                return true;
            }

            if (Normalized.Equals("\\KnownDlls32", StringComparison.OrdinalIgnoreCase))
            {
                Handle = HandleManager.KNOWN_DLLS32_DIRECTORY;
                return true;
            }

            if (Normalized.Equals("\\Sessions\\1\\BaseNamedObjects", StringComparison.OrdinalIgnoreCase) ||
                Normalized.Equals("\\BaseNamedObjects", StringComparison.OrdinalIgnoreCase))
            {
                Handle = HandleManager.BASE_NAMED_OBJECTS_DIRECTORY;
                return true;
            }

            if (Normalized.Equals("\\RPC Control", StringComparison.OrdinalIgnoreCase))
            {
                Handle = HandleManager.RPC_CONTROL_DIRECTORY;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Resolves a 64-bit registry OBJECT_ATTRIBUTES value to a full NT registry path.
        /// </summary>
        public bool TryResolveRegistryObjectPath64(ulong ObjectAttributesPtr, NTSTATUS MemoryFailureStatus, NTSTATUS EmptyPathStatus, NTSTATUS InvalidRootStatus, out string KeyPath, out NTSTATUS Status)
        {
            KeyPath = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (ObjectAttributesPtr == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            uint ObjectAttributesSize = (uint)Marshal.SizeOf<OBJECT_ATTRIBUTES64>();
            if (!Emulator.IsRegionMapped(ObjectAttributesPtr, ObjectAttributesSize))
            {
                Status = MemoryFailureStatus;
                return false;
            }

            if (!StructSerializer.ParseStruct(Emulator, ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes))
            {
                Status = MemoryFailureStatus;
                return false;
            }

            if (Attributes.ObjectName == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!TryReadUnicodeString64(Attributes.ObjectName, out KeyPath, out Status))
            {
                if (Status == NTSTATUS.STATUS_ACCESS_VIOLATION)
                    Status = MemoryFailureStatus;
                return false;
            }

            if (Attributes.RootDirectory != 0)
            {
                WinRegKey ParentKey = HandleManager.GetObjectByHandle<WinRegKey>(Attributes.RootDirectory);
                if (ParentKey == null || string.IsNullOrEmpty(ParentKey.FullPath))
                {
                    Status = InvalidRootStatus;
                    return false;
                }

                if (string.IsNullOrEmpty(KeyPath))
                {
                    KeyPath = ParentKey.FullPath;
                    return true;
                }

                bool IsAbsoluteNtPath =
                    KeyPath.StartsWith("\\Registry\\", StringComparison.OrdinalIgnoreCase) ||
                    KeyPath.StartsWith("\\REGISTRY\\", StringComparison.OrdinalIgnoreCase);

                if (!IsAbsoluteNtPath)
                {
                    string ParentPath = ParentKey.FullPath.TrimEnd('\\', '\0');
                    string Relative = KeyPath.TrimStart('\\');
                    KeyPath = string.IsNullOrEmpty(Relative) ? ParentPath : ParentPath + "\\" + Relative;
                }
            }
            else if (string.IsNullOrEmpty(KeyPath))
            {
                Status = EmptyPathStatus;
                return false;
            }

            return true;
        }

        public ulong SetUnicodeString(ulong Address, string Buffer)
        {
            if (Buffer == null)
                return 0;

            ulong StructSize = (ulong)Marshal.SizeOf<UNICODE_STRING64>();
            if (!Emulator.IsRegionMapped(Address, StructSize))
                return 0;

            int ByteLength = Buffer.Length * 2;
            int MaxByteLength = ByteLength + 2;

            ulong StringAddress = Emulator.MapUniqueAddress((ulong)MaxByteLength, MemoryProtection.ReadWrite);
            if (StringAddress == 0)
                return 0;

            Emulator._emulator.WriteMemory(StringAddress, Buffer, Encoding.Unicode);
            Emulator._emulator.WriteMemory(StringAddress + (ulong)ByteLength, (ushort)0, 2);

            Emulator._emulator.WriteMemory(Address + 0, (ushort)ByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 2, (ushort)MaxByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 8, StringAddress, 8);

            return StringAddress;
        }

        public void WriteUnicodeStringRelative(BinaryEmulator Instance, ulong UnicodeStringAddress, ulong BaseAddress, string Value)
        {
            ushort Length = (ushort)(Value.Length * 2);
            ushort MaximumLength = (ushort)(Length + 2);

            ulong BufferAddress = Instance.MapUniqueAddress((ulong)MaximumLength, MemoryProtection.ReadWrite);
            Instance._emulator.WriteMemory(BufferAddress, Value, System.Text.Encoding.Unicode);
            Instance._emulator.WriteMemory(BufferAddress + (ulong)Length, (ushort)0, 2);

            Instance._emulator.WriteMemory(UnicodeStringAddress + 0, Length, 2);
            Instance._emulator.WriteMemory(UnicodeStringAddress + 2, MaximumLength, 2);

            ulong Relative = BufferAddress - BaseAddress;
            Instance._emulator.WriteMemory(UnicodeStringAddress + 8, Relative, 8);
        }

        public uint SetUnicodeString32(uint Address, string Buffer)
        {
            if (Buffer == null)
                return 0;

            ulong StructSize = (ulong)Marshal.SizeOf<UNICODE_STRING>();
            if (!Emulator.IsRegionMapped(Address, StructSize))
                return 0;

            int ByteLength = Buffer.Length * 2;
            int MaxByteLength = ByteLength + 2;

            uint StringAddress = (uint)Emulator.MapUniqueAddress((ulong)MaxByteLength, MemoryProtection.ReadWrite);
            if (StringAddress == 0)
                return 0;

            Emulator._emulator.WriteMemory(StringAddress, Buffer, Encoding.Unicode);
            Emulator._emulator.WriteMemory((ulong)StringAddress + (ulong)ByteLength, (ushort)0, 2);

            Emulator._emulator.WriteMemory(Address + 0, (ushort)ByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 2, (ushort)MaxByteLength, 2);
            Emulator._emulator.WriteMemory(Address + 4, StringAddress);

            return StringAddress;
        }

        /// <summary>
        /// Gets a x64 argument based on the index.
        /// </summary>
        /// <param name="Index">Index to read from. starting from 0.</param>
        /// <returns></returns>
        public ulong GetArg64(int Index, bool UInt = false)
        {
            if (Index == 0) return Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R10);
            if (Index == 1) return Emulator._emulator.ReadRegister(Registers.UC_X86_REG_RDX);
            if (Index == 2) return Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R8);
            if (Index == 3) return Emulator._emulator.ReadRegister(Registers.UC_X86_REG_R9);

            ulong RSP = Emulator._emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong StackArgAddress = RSP + 0x28UL + (ulong)((Index - 4) * 8);
            return UInt ? Emulator._emulator.ReadMemoryUInt(StackArgAddress) : Emulator._emulator.ReadMemoryULong(StackArgAddress);
        }

        /// <summary>
        /// Gets a x86 argument based on the index.
        /// </summary>
        /// <param name="Index">Index to read from. starting from 0.</param>
        /// <returns></returns>
        public uint GetArg32(int Index)
        {
            uint ESP = Emulator._emulator.ReadRegister32(Registers.UC_X86_REG_ESP);
            return Emulator._emulator.ReadMemoryUInt((ulong)(ESP + 4 + (Index * 4)));
        }

        public uint GenerateRandomPID()
        {
            uint PID = (uint)RandomGen.Next(500, 29999);
            if (PIDs.TryGetValue(PID, out _))
            {
                return GenerateRandomPID();
            }
            PIDs.Add(PID, true);
            return PID;
        }

        private User GenerateRandomSvchostUser()
        {
            int User = RandomGen.Next(0, 2);
            if (User == 0)
                return Windows.User.System;
            else if (User == 1)
                return Windows.User.LocalService;
            else
                return Windows.User.Standard;
        }

        public byte[] GenerateRandomData(int Length)
        {
            if (Length < 0)
                return null;
            byte[] Data = new byte[Length];
            RandomGen.NextBytes(Data);
            return Data;
        }

        public void InitializeProcessTimes(WinProcess Process, long AgeMilliseconds, bool GenerateCpuTimes)
        {
            if (Process == null)
                return;

            long Now = Emulator.GetEmulatedSystemTimeFileTimeUtc();
            long AgeTime = SaturatingMillisecondsToFileTimeDuration(AgeMilliseconds);
            Process.CreationTime = Now >= AgeTime ? Now - AgeTime : Now;
            Process.ExitTime = 0;

            if (!GenerateCpuTimes || AgeMilliseconds <= 0)
                return;

            long MaxCpuMilliseconds = Math.Max(1, AgeMilliseconds / 8);
            int CpuMilliseconds = (int)Math.Min(MaxCpuMilliseconds, int.MaxValue);
            Process.KernelTime = SaturatingMillisecondsToFileTimeDuration(RandomGen.Next(0, CpuMilliseconds));
            Process.UserTime = SaturatingMillisecondsToFileTimeDuration(RandomGen.Next(0, CpuMilliseconds));
        }

        public void UpdateProcessTimes(WinProcess Process)
        {
            if (Process == null)
                return;

            if (Process.CreationTime == 0)
                InitializeProcessTimes(Process, Process.PID == PID ? Emulator.EmulatedTickCount64 : 0, false);

            if (Process.PID == PID && Process.ExitTime == 0)
                Process.UserTime = Math.Max(Process.UserTime, SaturatingMillisecondsToFileTimeDuration(Emulator.EmulatedTickCount64));
        }

        private static long SaturatingMillisecondsToFileTimeDuration(long Milliseconds)
        {
            if (Milliseconds <= 0)
                return 0;

            if (Milliseconds > long.MaxValue / 10000)
                return long.MaxValue;

            return Milliseconds * 10000;
        }

        // Current Process
        public uint PID = 0;
        public uint PPID = 0;
        public WinHandle STD_OUT;
        public WinHandle STD_IN;
        public WinHandle ConsoleHandle;
        public uint CurrentPriority = 0x8; // Default priority (Normal), changes only if the program changed it explicitly.
        public User CurrentUser = User.Standard;
        public string CurrentUserSid = "S-1-5-21-1000-1000-1000-1001";

        // Other
        public List<WinHandle> WinHandles = new List<WinHandle>();
        public List<WinProcess> WinProcesses = new List<WinProcess>();
        public List<WinFile> WinFiles = new List<WinFile>();
        public List<WinMutex> WinMutexes = new List<WinMutex>();
        public List<WinModule> WinModules = new List<WinModule>();
        public List<WinModule> MappedImageViews = new List<WinModule>();
        private readonly Dictionary<string, int> ImageViewCountsByPath = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        internal KuserSharedDataManager KuserSharedData;
        internal HandleManager HandleManager = new HandleManager();
        private static string WinRegPath = Path.Combine(Environment.CurrentDirectory, "WinReg");
        public RegistryManager RegManager = new RegistryManager(WinRegPath);
        public Hive[] RegHives;
        public HashSet<string> TempRegistryKeys = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> DeletedRegistryKeys = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Dictionary<string, ValueNode>> TempRegistryValues = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, HashSet<string>> DeletedRegistryValues = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Hive> TempRegistryKeyHives = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> SyntheticDirectories = new(StringComparer.OrdinalIgnoreCase);
        internal string SyntheticVolumeGuid { get; private set; }
        internal string SyntheticVolumeGuidSymbolicLink { get; private set; }
        internal string SyntheticVolumeWin32GuidPath { get; private set; }
        internal byte[] SyntheticMountDevUniqueId { get; private set; }
        private BinaryEmulator Emulator;
        public List<WinEvent> WinEvents = new List<WinEvent>();
        public List<WinSemaphore> WinSemaphores = new List<WinSemaphore>();
        public List<WinRegistryNotification> RegistryNotifications = new List<WinRegistryNotification>();
        public List<WinSection> WinSections = new List<WinSection>();
        public List<WinPort> WinPorts = new List<WinPort>();
        public List<WinEtwRegistration> WinEtwRegistrations = new List<WinEtwRegistration>();
        public ulong EtwNotificationEventHandle;
        internal PebLdrTracker LdrTracker;
        public readonly Dictionary<ulong, WinWindow> WinWindows = new();
        public readonly Dictionary<ushort, WinWindowClass> WinWindowClassesByAtom = new();
        private readonly Dictionary<string, ushort> WinWindowClassAtomsByKey = new(StringComparer.OrdinalIgnoreCase);
        private ushort NextWindowClassAtom = 0xC000;
        public readonly List<ulong> TopLevelWindows = new();
        private const uint UserHandleEntryCount = 0x200;
        private const uint UserHandleEntrySize = 0x20;
        private const ulong UserWindowObjectSize = 0x200;
        private const ulong UserClassObjectSize = 0x100;
        private const ulong UserDesktopInfoSize = 0x48;
        private const byte UserHandleTypeWindow = 1;
        private ushort NextUserHandleIndex = 1;
        private ushort NextUserHandleUniq = 1;
        private ulong UserServerInfoAddress;
        private ulong UserHandleTableAddress;
        private ulong UserDesktopInfoAddress;
        private ulong UserDesktopOwnerAddress;
        private ulong UserSharedInfoMirrorAddress;
        public ulong ActiveWindow;
        public ulong FocusWindow;

        /// <summary>
        /// Initialize the environment for the helper (Processes, Console, etc).
        /// </summary>
        public WinSysHelper(BinaryEmulator Emulator)
        {
            Shared = new WindowsSharedBuffer();
            this.Emulator = Emulator;
            SyntheticVolumeGuid = Guid.NewGuid().ToString("D").ToLowerInvariant();
            SyntheticVolumeGuidSymbolicLink = $"\\??\\Volume{{{SyntheticVolumeGuid}}}";
            SyntheticVolumeWin32GuidPath = $"\\\\?\\Volume{{{SyntheticVolumeGuid}}}\\";
            SyntheticMountDevUniqueId = Guid.Parse(SyntheticVolumeGuid).ToByteArray();
            KuserSharedData = new KuserSharedDataManager(Emulator);
            PID = GenerateRandomPID();
            PPID = GenerateRandomPID();
            string FileName = null;
            BinaryFile Binary = Emulator._binary;
            if (Binary.Location != null)
            {
                try
                {
                    FileName = Path.GetFileName(Binary.Location);
                }
                catch
                {

                }
            }

            if (Binary.PE.Subsystem.HasFlag(Subsystem.WindowsCui))
            {
                WinFile STDIN = new WinFile() { Device = true, Path = "\\Device\\ConDrv" };
                WinFile STDOUT = new WinFile() { Device = true, Path = "\\Device\\ConDrv" };
                STD_IN = HandleManager.AddHandle(STDIN, AccessMask.FileReadData);
                STD_OUT = HandleManager.AddHandle(STDOUT, AccessMask.FileWriteData);
            }
            else
            {
                STD_IN = HandleManager.AddHandle(new WinFile(), AccessMask.None);
                STD_OUT = HandleManager.AddHandle(new WinFile(), AccessMask.FileWriteData);
            }
            // Generate some processes for the emulated program to work with
            uint WininitPID = GenerateRandomPID();
            uint ServicesPID = GenerateRandomPID();
            uint WinlogonPID = GenerateRandomPID();
            int MsMpRand = RandomGen.Next();
            uint FirefoxParent = GenerateRandomPID();
            WinProcesses = new List<WinProcess> {
                new WinProcess{ PID = 0, PPID = 0, Name = "System Idle Process", Path = null, Status = ProtectionStatus.Unaccessible, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = 4, PPID = 0, Name = "System", Path = "C:\\Windows\\System32\\ntoskrnl.exe", Status = ProtectionStatus.Full, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = 4, Name = "Secure System", Path = "C:\\Windows\\System32\\securekernel.exe", Status = ProtectionStatus.SecureFull, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = 4, Name = "Registry", Path = "Registry", Status = ProtectionStatus.Full, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = 4, Name = "smss.exe", Path = "C:\\Windows\\System32\\smss.exe", Status = ProtectionStatus.LightTCB, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = 4, Name = "Memory Compression", Path = "MemCompression", Status = ProtectionStatus.Full, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = PID, PPID = PPID, Name = FileName, Path = Binary.Location != null ? Binary.Location : null, Status = ProtectionStatus.None, RunningUser = CurrentUser, Critical = false, Arch = Binary.Architecture, PrimaryToken = new WinToken{SessionId = 1, IsElevated = false, IsRestricted = false, OwningProcessId = PID, OwningThreadId = 0, Type = TokenType.Primary } },
                new WinProcess{ PID = PPID, PPID = GenerateRandomPID(), Name = "explorer.exe", Path = "C:\\Windows\\explorer.exe", Status = ProtectionStatus.None, RunningUser = User.Standard, Critical = false, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = FirefoxParent, PPID = PPID, Name = "firefox.exe", Arch = BinaryArchitecture.x64, Critical = false, Path = "C:\\Program Files\\Mozilla Firefox\\firefox.exe", RunningUser = User.Standard, Status = ProtectionStatus.None},
                new WinProcess{ PID = GenerateRandomPID(), PPID = FirefoxParent, Name = "crashhelper.exe", Arch = BinaryArchitecture.x64, Critical = false, Path = "C:\\Program Files\\Mozilla Firefox\\crashhelper.exe", RunningUser = User.Standard, Status = ProtectionStatus.None},
                new WinProcess{ PID = WininitPID, PPID = GenerateRandomPID(), Name = "wininit.exe", Path = "C:\\Windows\\System32\\wininit.exe", Status = ProtectionStatus.LightTCB, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = ServicesPID, PPID = WininitPID, Name = "services.exe", Path = "C:\\Windows\\System32\\services.exe", Status = ProtectionStatus.LightTCB, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = WinlogonPID, PPID = GenerateRandomPID(), Name = "winlogon.exe", Path = "C:\\Windows\\System32\\winlogon.exe", Status = ProtectionStatus.None, RunningUser = User.System, Critical = false, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = WinlogonPID, Name = "dwm.exe", Path = "C:\\Windows\\System32\\dwm.exe", Status = ProtectionStatus.None, RunningUser = User.WindowManager, Critical = false, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = WinlogonPID, Name = "fontdrvhost.exe", Path = "C:\\Windows\\System32\\fontdrvhost.exe", Status = ProtectionStatus.None, RunningUser = User.FontManager, Critical = false, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = GenerateRandomPID(), Name = "csrss.exe", Path = "C:\\Windows\\System32\\csrss.exe", Status = ProtectionStatus.LightTCB, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = ServicesPID, Name = "MsMpEng.exe", Path = $"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.{MsMpRand.ToString()}\\MsMpEng.exe", Status = ProtectionStatus.LightAM, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
                new WinProcess{ PID = GenerateRandomPID(), PPID = ServicesPID, Name = "MpDefenderCoreService.exe", Path = $"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.{MsMpRand.ToString()}\\MpDefenderCoreService.exe", Status = ProtectionStatus.LightAM, RunningUser = User.System, Critical = true, Arch = BinaryArchitecture.x64 },
            };

            // Generate several random svchost.exe processes
            int RandomSvchostNumber = RandomGen.Next(10, 17);
            for (int i = 0; i < RandomSvchostNumber; i++)
            {
                WinProcesses.Add(new WinProcess { PID = GenerateRandomPID(), PPID = ServicesPID, Name = "svchost.exe", Path = "C:\\Windows\\System32\\svchost.exe", Status = ProtectionStatus.None, RunningUser = GenerateRandomSvchostUser(), Critical = true, Arch = BinaryArchitecture.x64 });
            }

            // Generate several firefox child processes
            int RandomFirefoxNumber = RandomGen.Next(5, 10);
            for (int i = 0; i < RandomFirefoxNumber; i++)
            {
                WinProcesses.Add(new WinProcess { PID = GenerateRandomPID(), PPID = FirefoxParent, Name = "firefox.exe", Path = "C:\\Program Files\\Mozilla Firefox\\firefox.exe", Status = ProtectionStatus.None, RunningUser = User.Standard, Critical = false, Arch = BinaryArchitecture.x64 });
            }

            foreach (WinProcess Process in WinProcesses)
            {
                if (Process.PID == PID)
                    InitializeProcessTimes(Process, Emulator.EmulatedTickCount64, false);
                else
                    InitializeProcessTimes(Process, RandomGen.Next(60 * 1000, 2 * 60 * 60 * 1000), true);
            }

            // Prepare Devices
            WinFile hConsoleHandle = new WinFile();
            hConsoleHandle.Device = true;
            hConsoleHandle.Path = "\\Device\\ConDrv";
            hConsoleHandle.Handler = ConsoleServer.Handle;
            ConsoleHandle = HandleManager.AddHandle(hConsoleHandle, AccessMask.GenericRead | AccessMask.GenericWrite);
            List<Hive> Hives = new List<Hive>();
            if (Directory.Exists(WinRegPath))
            {
                foreach (string HiveFile in Directory.GetFiles(WinRegPath))
                {
                    try
                    {
                        string Name = Path.GetFileName(HiveFile);
                        Hive Loaded = RegManager.LoadHive(Name);
                        if (Loaded == null)
                            continue;
                        Hives.Add(Loaded);
                    }
                    catch
                    {

                    }
                }
            }
            RegHives = Hives.ToArray();
            InitializeSyntheticRegistryDefaults();

            const ulong PreAllocSharedSectionSize = 0x10000;
            ulong PreAllocSharedBase = Emulator.MapUniqueAddress(PreAllocSharedSectionSize, MemoryProtection.ReadWrite);
            if (PreAllocSharedBase != 0)
            {
                WinSections.Add(new WinSection
                {
                    Name = "\\Windows\\SharedSection",
                    Size = PreAllocSharedSectionSize,
                    Protection = 0x04,
                    Attributes = 0,
                    BackingAddress = PreAllocSharedBase,
                    Initialized = false
                });
            }

            foreach (string PortName in new[]
            {
                "\\Windows\\ApiPort",
                "\\Windows\\SbApiPort",
                "\\RPC Control\\ntsvcs",
                "\\RPC Control\\lsarpc",
                "\\RPC Control\\samr",
                "\\RPC Control\\srvsvc",
                "\\RPC Control\\epmapper",
                "\\RPC Control\\svcctl",
                "\\RPC Control\\wkssvc",
                "\\RPC Control\\netlogon",
                "\\RPC Control\\winreg",
                "\\RPC Control\\atsvc",
                "\\RPC Control\\plugplay",
                "\\RPC Control\\tapsrv",
                "\\RPC Control\\keysvc",
            })
            {
                WinPorts.Add(new WinPort
                {
                    Name = PortName,
                    Handler = RPC.Ports.CsrssPortHandler.Handle
                });
            }
        }

        public enum ExceptionType
        {
            Read = 0,
            Write = 1,
            Execute = 8
        }

        public class ExceptionInformation
        {
            public ulong Address;
            public ExceptionType Type;
            public NTSTATUS Status;
            public ulong[] CustomParameters;
            public ulong[] Parameters
            {
                get
                {
                    if (CustomParameters != null && CustomParameters.Length != 0)
                        return CustomParameters;

                    if (Type != 0 || Address != 0)
                        return new[] { (ulong)Type, Address };

                    return Array.Empty<ulong>();
                }
            }
        }

        public bool UnmapViewOfSection(ulong BaseAddress)
        {
            if (BaseAddress == 0)
                return false;

            WinModule Module = FindMappedImageViewByAddress(BaseAddress);
            if (Module != null)
            {
                ulong ViewBase = Module.MappedBase;
                ulong End = ViewBase + Module.SizeOfImage;

                List<MemoryRegion> RegionsToUnmap = Emulator._memory
                    .Where(R => R.BaseAddress >= ViewBase && R.BaseAddress < End)
                    .OrderByDescending(R => R.BaseAddress)
                    .ToList();

                bool UnmappedAny = false;
                for (int i = 0; i < RegionsToUnmap.Count; i++)
                {
                    MemoryRegion Region = RegionsToUnmap[i];
                    ulong Size = Region.Size != 0 ? Region.Size : (Region.RequestedSize + 0xFFF) & ~0xFFFUL;
                    if (Size == 0)
                        continue;

                    if (Emulator._emulator.UnmapMemory(Region.BaseAddress, Size))
                    {
                        if (Emulator.TryFindMemoryRegionByBase(Region.BaseAddress, out int MemIndex, out _))
                            Emulator.RemoveMemoryRegionAt(MemIndex);

                        Emulator.AddFreedRegion(Region.BaseAddress, Size);
                        UnmappedAny = true;
                    }
                }

                if (UnmappedAny)
                {
                    UnregisterMappedImageView(Module);

                    if (!Module.IsSectionView)
                    {
                        WinModule LoadedModule = WinModules?.FirstOrDefault(M => M != null && M.MappedBase == Module.MappedBase);
                        if (LoadedModule != null)
                            LoadedModule.Initialized = false;
                    }
                }

                return UnmappedAny;
            }

            if (!Emulator.TryFindMemoryRegion(BaseAddress, out MemoryRegion ViewRegion))
                return false;

            return Emulator.UnmapMemoryRegion(ViewRegion.BaseAddress);
        }

        /// <summary>
        /// Invoke KiUserExceptionDispatcher with the specified exception.
        /// </summary>
        /// <param name="Exception">NTSTATUS exception code.</param>
        /// <param name="ExceptionInformation">Optional exception parameters (up to 15).</param>
        public void InvokeException(NTSTATUS Exception, ExceptionInformation ExceptionInformation = null)
        {
            if (Emulator == null)
                return;

            if (Emulator._binary == null || Emulator._binary.Architecture != BinaryArchitecture.x64)
            {
                Emulator.TriggerEventMessage("[-] InvokeException is only implemented for x64 right now.", LogFlags.Issues);
                return;
            }

            if (ExceptionInformation == null)
                ExceptionInformation = new ExceptionInformation { Status = Exception };
            else
                ExceptionInformation.Status = Exception;


            WinModule ntdll = WinModules.FirstOrDefault(m => m.Name != null && m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
            if (ntdll == null)
            {
                Emulator.TriggerEventMessage("[-] InvokeException failed: ntdll.dll is not loaded.", LogFlags.Issues);
                return;
            }

            ulong dispatcher = WinEmulatedThread.GetState(Emulator.CurrentThread).ExceptionFunc;
            if (dispatcher == 0)
            {
                dispatcher = GetExportAddress(ntdll, "KiUserExceptionDispatcher");
                if (dispatcher == 0 && ntdll.ExportsByName != null && ntdll.ExportsByName.TryGetValue("KiUserExceptionDispatcher", out ulong originalVa))
                {
                    dispatcher = Emulator.TranslateVirtualAddress(originalVa, "ntdll.dll");
                }
                WinEmulatedThread.GetState(Emulator.CurrentThread).ExceptionFunc = dispatcher;
            }

            if (dispatcher == 0)
            {
                Emulator.TriggerEventMessage("[-] InvokeException failed: KiUserExceptionDispatcher export was not found.", LogFlags.Issues);
                return;
            }

            DispatchExceptionX64(dispatcher, Exception, ExceptionInformation);
        }

        private static ulong AlignDown(ulong Value, ulong Align)
        {
            return Value & ~(Align - 1);
        }

        private static void WriteUInt16(Span<byte> Buffer, int Offset, ushort Value)
        {
            if (Offset < 0 || Offset + 2 > Buffer.Length)
                return;

            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(Offset, 2), Value);
        }

        private static void WriteUInt32(Span<byte> Buffer, int Offset, uint Value)
        {
            if (Offset < 0 || Offset + 4 > Buffer.Length)
                return;

            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        private static void WriteUInt64(Span<byte> Buffer, int Offset, ulong Value)
        {
            if (Offset < 0 || Offset + 8 > Buffer.Length)
                return;

            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
        }

        private uint GuessContextSizeFromDispatcher(ulong DispatcherAddress)
        {
            try
            {
                Span<byte> Code = stackalloc byte[0x80];
                if (!Emulator._emulator.ReadMemory(DispatcherAddress, Code, 0x80))
                    return 0;

                for (int i = 0; i + 8 <= Code.Length; i++)
                {
                    // lea rcx, [rsp + imm32]
                    if (Code[i] == 0x48 && Code[i + 1] == 0x8D && Code[i + 2] == 0x8C && Code[i + 3] == 0x24)
                    {
                        uint Disp = BinaryPrimitives.ReadUInt32LittleEndian(Code.Slice(i + 4, 4));

                        if (Disp >= 0x400 && Disp <= 0x600 && (Disp % 0x10) == 0)
                            return Disp;
                    }
                    // add rcx, imm32 (typically have the size according to ntdll analysis in IDA to multiple versions)
                    else if (Code[i] == 0x48 && Code[i + 1] == 0x81 && Code[i + 2] == 0xC1)
                    {
                        uint Disp = BinaryPrimitives.ReadUInt32LittleEndian(Code.Slice(i + 3, 4));

                        if (Disp >= 0x400 && Disp <= 0x600 && (Disp % 0x10) == 0)
                            return Disp;
                    }
                }
            }
            catch
            {
                // Ignore and fall back to a default.
            }

            return 0;
        }

        private void DispatchExceptionX64(ulong DispatcherAddress, NTSTATUS Exception, ExceptionInformation ExceptionInformation)
        {
            const uint ExceptionRecordSize = 0x98;
            const uint MachineFrameSize = 0x40;

            ulong InitialRsp = Emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong InitialRip = Emulator.ReadRegister(Registers.UC_X86_REG_RIP);
            ulong InitialEFlags = Emulator.ReadRegister(Registers.UC_X86_REG_EFLAGS);

            uint ContextSize = GuessContextSizeFromDispatcher(DispatcherAddress);
            if (ContextSize == 0)
                ContextSize = 0x4F0; // Common on many builds; field offsets remain fixed.
            ContextSize = (uint)BinaryEmulator.AlignUp(ContextSize, 0x10);

            ulong CombinedSize = BinaryEmulator.AlignUp((ulong)ContextSize + ExceptionRecordSize, 0x10);
            ulong AllocationSize = CombinedSize + MachineFrameSize;

            ulong NewRsp = AlignDown(InitialRsp - AllocationSize, 0x100);

            // Validate that the exception frame stays within the mapped stack.
            EmulatedThread Thread = Emulator.CurrentThread;
            if (Thread != null)
            {
                ulong StackLow = Thread.StackAddress;
                ulong StackHigh = Thread.StackAddress + Thread.StackSize;

                if (NewRsp < StackLow || (NewRsp + AllocationSize) > StackHigh)
                {
                    Emulator.TriggerEventMessage($"[-] InvokeException failed: insufficient stack space (RSP=0x{InitialRsp:X}, NewRSP=0x{NewRsp:X}, Need=0x{AllocationSize:X}).", LogFlags.Issues);
                    return;
                }
            }

            if (!Emulator.IsRegionMapped(NewRsp, AllocationSize))
            {
                // Commit stack pages in the current thread's stack reserve for the exception frame.
                if (Thread != null)
                {
                    ulong StackLow = Thread.StackAddress;
                    ulong StackHigh = Thread.StackAddress + Thread.StackSize;

                    if (NewRsp >= StackLow && (NewRsp + AllocationSize) <= StackHigh)
                    {
                        ulong PageStart = NewRsp & ~0xFFFUL;
                        ulong PageEnd = BinaryEmulator.AlignUp(NewRsp + AllocationSize, 0x1000);

                        for (ulong Page = PageStart; Page < PageEnd; Page += 0x1000)
                        {
                            if (!Emulator.IsRegionMapped(Page, 1))
                            {
                                Emulator._emulator.MapMemory(Page, 0x1000, MemoryProtection.ReadWrite);
                            }
                            else
                            {
                                Emulator._emulator.SetMemoryProtection(Page, 0x1000, MemoryProtection.ReadWrite);
                            }
                        }
                    }
                }

                if (!Emulator.IsRegionMapped(NewRsp, AllocationSize))
                {
                    Emulator.TriggerEventMessage($"[-] InvokeException failed: exception stack frame is not mapped (NewRSP=0x{NewRsp:X}, Size=0x{AllocationSize:X}).", LogFlags.Issues);
                    return;
                }
            }

            ulong ClearLen = InitialRsp > NewRsp ? (InitialRsp - NewRsp) : AllocationSize;
            if (ClearLen > 0x2000)
                ClearLen = 0x2000;

            WriteZeroMemory(NewRsp, (uint)ClearLen);

            ulong ContextAddress = NewRsp;
            ulong ExceptionRecordAddress = NewRsp + ContextSize;
            ulong MachineFrameAddress = NewRsp + CombinedSize;

            Span<byte> Context = Shared.GetSpan(ContextSize);
            Context.Clear();

            const uint CONTEXT_AMD64 = 0x00100000;
            const uint CONTEXT_CONTROL = 0x00000001;
            const uint CONTEXT_INTEGER = 0x00000002;
            const uint CONTEXT_SEGMENTS = 0x00000004;
            const uint CONTEXT_DEBUG_REGISTERS = 0x00000010;

            // Only advertise what we actually populate.
            uint Flags = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS;
            WriteUInt32(Context, 0x30, Flags);

            WriteUInt32(Context, 0x34, (uint)Emulator.ReadRegister(Registers.UC_X86_REG_MXCSR));

            WriteUInt16(Context, 0x38, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_CS));
            WriteUInt16(Context, 0x3A, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_DS));
            WriteUInt16(Context, 0x3C, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_ES));
            WriteUInt16(Context, 0x3E, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_FS));
            WriteUInt16(Context, 0x40, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_GS));
            WriteUInt16(Context, 0x42, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_SS));
            WriteUInt32(Context, 0x44, (uint)InitialEFlags);

            WriteUInt64(Context, 0x48, Emulator.ReadRegister(Registers.UC_X86_REG_DR0));
            WriteUInt64(Context, 0x50, Emulator.ReadRegister(Registers.UC_X86_REG_DR1));
            WriteUInt64(Context, 0x58, Emulator.ReadRegister(Registers.UC_X86_REG_DR2));
            WriteUInt64(Context, 0x60, Emulator.ReadRegister(Registers.UC_X86_REG_DR3));
            WriteUInt64(Context, 0x68, Emulator.ReadRegister(Registers.UC_X86_REG_DR6));
            WriteUInt64(Context, 0x70, Emulator.ReadRegister(Registers.UC_X86_REG_DR7));

            WriteUInt64(Context, 0x78, Emulator.ReadRegister(Registers.UC_X86_REG_RAX));
            WriteUInt64(Context, 0x80, Emulator.ReadRegister(Registers.UC_X86_REG_RCX));
            WriteUInt64(Context, 0x88, Emulator.ReadRegister(Registers.UC_X86_REG_RDX));
            WriteUInt64(Context, 0x90, Emulator.ReadRegister(Registers.UC_X86_REG_RBX));
            WriteUInt64(Context, 0x98, InitialRsp);
            WriteUInt64(Context, 0xA0, Emulator.ReadRegister(Registers.UC_X86_REG_RBP));
            WriteUInt64(Context, 0xA8, Emulator.ReadRegister(Registers.UC_X86_REG_RSI));
            WriteUInt64(Context, 0xB0, Emulator.ReadRegister(Registers.UC_X86_REG_RDI));
            WriteUInt64(Context, 0xB8, Emulator.ReadRegister(Registers.UC_X86_REG_R8));
            WriteUInt64(Context, 0xC0, Emulator.ReadRegister(Registers.UC_X86_REG_R9));
            WriteUInt64(Context, 0xC8, Emulator.ReadRegister(Registers.UC_X86_REG_R10));
            WriteUInt64(Context, 0xD0, Emulator.ReadRegister(Registers.UC_X86_REG_R11));
            WriteUInt64(Context, 0xD8, Emulator.ReadRegister(Registers.UC_X86_REG_R12));
            WriteUInt64(Context, 0xE0, Emulator.ReadRegister(Registers.UC_X86_REG_R13));
            WriteUInt64(Context, 0xE8, Emulator.ReadRegister(Registers.UC_X86_REG_R14));
            WriteUInt64(Context, 0xF0, Emulator.ReadRegister(Registers.UC_X86_REG_R15));
            WriteUInt64(Context, 0xF8, InitialRip);

            Emulator.WriteMemory(ContextAddress, Context);

            // Build EXCEPTION_RECORD.
            Span<byte> Record = Shared.GetSpan(ExceptionRecordSize);
            Record.Clear();
            WriteUInt32(Record, 0x00, (uint)Exception);
            WriteUInt32(Record, 0x04, 0u);   // ExceptionFlags
            WriteUInt64(Record, 0x08, 0UL);  // ExceptionRecord (chained)
            WriteUInt64(Record, 0x10, InitialRip); // ExceptionAddress

            // Generic ExceptionInformation vector (0..15 QWORDs)
            ulong[] Parameters = ExceptionInformation?.Parameters ?? Array.Empty<ulong>();
            int Count = Parameters.Length;
            if (Count > 15)
                Count = 15;

            WriteUInt32(Record, 0x18, (uint)Count); // NumberParameters
            WriteUInt32(Record, 0x1C, 0u); // __unusedAlignment

            for (int i = 0; i < Count; i++)
                WriteUInt64(Record, 0x20 + (i * 8), Parameters[i]);

            Emulator.WriteMemory(ExceptionRecordAddress, Record);

            // Build MACHINE_FRAME (as the kernel would).
            Span<byte> Frame = Shared.GetSpan(MachineFrameSize);
            Frame.Clear();
            WriteUInt64(Frame, 0x00, InitialRip);
            WriteUInt64(Frame, 0x08, (ulong)(ushort)Emulator.ReadRegister(Registers.UC_X86_REG_CS));
            WriteUInt64(Frame, 0x10, InitialEFlags);
            WriteUInt64(Frame, 0x18, InitialRsp);
            WriteUInt64(Frame, 0x20, (ulong)(ushort)Emulator.ReadRegister(Registers.UC_X86_REG_SS));

            Emulator.WriteMemory(MachineFrameAddress, Frame);

            // Enter KiUserExceptionDispatcher exactly like the kernel does: RSP points at CONTEXT, RIP = dispatcher.
            Emulator.WriteRegister(Registers.UC_X86_REG_RSP, ContextAddress);
            Emulator.WriteRegister(Registers.UC_X86_REG_RIP, DispatcherAddress);
            EmulatedThread EmuThread = Emulator.CurrentThread;
            WinEmulatedThread.GetState(EmuThread).DispatchException = true;
            WinEmulatedThread.GetState(EmuThread).IsHandlingException = true;
            if (WinEmulatedThread.GetState(EmuThread).ExceptionNesting <= 0)
                WinEmulatedThread.GetState(EmuThread).ExceptionNesting = 1;
            WinEmulatedThread.GetState(EmuThread).ExceptionInformation = ExceptionInformation;
            EmuThread.ExitCode = (int)Exception;
            Emulator.Threads[(uint)Emulator.CurrentThreadId] = EmuThread;
        }

        /// <summary>
        /// Determines whether or not the thread is in a state where it can dispatch a user APC.
        /// </summary>
        /// <param name="Thread">Thread to check.</param>
        /// <returns>returns true if the thread can dispatch an APC, otherwise false.</returns>
        public bool CanDispatchUserApc(EmulatedThread Thread)
        {
            return CanDispatchUserApc(Thread, false);
        }

        /// <summary>
        /// Determines whether or not the thread is in a state where it can dispatch a user APC.
        /// </summary>
        /// <param name="Thread">Thread to check.</param>
        /// <param name="ForceAlert">true to emulate NtTestAlert/NtContinue(TestAlert) draining the user APC queue.</param>
        /// <returns>returns true if the thread can dispatch an APC, otherwise false.</returns>
        public bool CanDispatchUserApc(EmulatedThread Thread, bool ForceAlert)
        {
            return GetDispatchableUserApcIndex(Thread, ForceAlert) >= 0;
        }

        private int GetDispatchableUserApcIndex(EmulatedThread Thread, bool ForceAlert)
        {
            if (Thread == null)
                return -1;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.PendingUserApcs == null || State.PendingUserApcs.Count == 0)
                return -1;

            if (ForceAlert || State.ApcAlertable)
                return 0;

            for (int i = 0; i < State.PendingUserApcs.Count; i++)
            {
                WinPendingUserApc Apc = State.PendingUserApcs[i];
                if (Apc != null && Apc.IsSpecial)
                    return i;
            }

            return -1;
        }

        private static void WriteInt32(Span<byte> Buffer, int Offset, int Value)
        {
            if (Offset < 0 || Offset + 4 > Buffer.Length)
                return;

            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        /// <summary>
        /// returns KiUserApcDispatcher.
        /// </summary>
        /// <param name="Thread">Thread to set the ApcFunc for.</param>
        /// <returns>returns the Dispatcher address.</returns>
        public ulong GetUserApcDispatcher(EmulatedThread Thread)
        {
            if (Thread == null)
                return 0;

            if (WinEmulatedThread.GetState(Thread).ApcFunc != 0)
                return WinEmulatedThread.GetState(Thread).ApcFunc;

            WinModule ntdll = WinModules.FirstOrDefault(m => m.Name != null && m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
            if (ntdll == null)
                return 0;

            ulong Dispatcher = GetExportAddress(ntdll, "KiUserApcDispatcher");
            if (Dispatcher == 0 && ntdll.ExportsByName != null && ntdll.ExportsByName.TryGetValue("KiUserApcDispatcher", out ulong OriginalVa))
                Dispatcher = Emulator.TranslateVirtualAddress(OriginalVa, "ntdll.dll");

            WinEmulatedThread.GetState(Thread).ApcFunc = Dispatcher;
            return Dispatcher;
        }

        private void InterruptAlertableWaitWithUserApc(EmulatedThread Thread)
        {
            if (Thread == null || !Thread.WaitActive)
                return;

            Thread.WaitActive = false;
            Thread.WaitHandles = null;
            Thread.WaitDeadline = -1;
            Thread.WaitAll = false;
            WinEmulatedThread.GetState(Thread).WaitAlertable = false;
            WinEmulatedThread.GetState(Thread).ApcAlertable = false;

            ulong ResumeRip = WinEmulatedThread.GetState(Thread).WaitReturnRIP != 0 ? WinEmulatedThread.GetState(Thread).WaitReturnRIP : (WinEmulatedThread.GetState(Thread).WaitResumeRIP != 0 ? WinEmulatedThread.GetState(Thread).WaitResumeRIP + 2 : Thread.Context.RIP);
            Thread.Context.RIP = ResumeRip;
            Thread.Context.RAX = (ulong)NTSTATUS.STATUS_USER_APC;
            WinEmulatedThread.GetState(Thread).WaitResumeRIP = 0;
            WinEmulatedThread.GetState(Thread).WaitReturnRIP = 0;
            if (Emulator.CurrentThread == Thread)
            {
                Emulator.WriteRegister(Registers.UC_X86_REG_RIP, Thread.Context.RIP);
                Emulator.WriteRegister(Registers.UC_X86_REG_RAX, Thread.Context.RAX);
            }
        }

        public bool DispatchNextUserApc(EmulatedThread Thread)
        {
            return DispatchNextUserApc(Thread, false);
        }

        /// <summary>
        /// Dispatches the next user APC for a thread.
        /// </summary>
        /// <param name="Thread">Thread to dispatch the APC on.</param>
        /// <param name="ForceAlert">true to drain a normal user APC without requiring an alertable wait.</param>
        /// <returns>returns true if an APC was dispatched, otherwise false.</returns>
        public bool DispatchNextUserApc(EmulatedThread Thread, bool ForceAlert)
        {
            if (Emulator == null || Emulator._binary == null || Emulator._binary.Architecture != BinaryArchitecture.x64)
                return false;

            int ApcIndex = GetDispatchableUserApcIndex(Thread, ForceAlert);
            if (ApcIndex < 0)
                return false;

            ulong Dispatcher = GetUserApcDispatcher(Thread);
            if (Dispatcher == 0)
            {
                Emulator.TriggerEventMessage("[-] DispatchNextUserApc failed: KiUserApcDispatcher export was not found.", LogFlags.Issues);
                WinEmulatedThread.GetState(Thread).ApcAlertable = false;
                return false;
            }

            if (Thread.WaitActive)
                InterruptAlertableWaitWithUserApc(Thread);

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            WinPendingUserApc Apc = State.PendingUserApcs[ApcIndex];
            State.ApcAlertable = false;

            const int ContinueOffset = 0x4F0;
            const int StackLayoutSize = 0x508;

            ulong InitialRsp = Emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong InitialRip = Emulator.ReadRegister(Registers.UC_X86_REG_RIP);
            ulong InitialEFlags = Emulator.ReadRegister(Registers.UC_X86_REG_EFLAGS);

            ulong NewRsp = AlignDown(InitialRsp - (ulong)StackLayoutSize, 0x100);

            ulong AllocationSize = (ulong)StackLayoutSize;
            if (Thread != null)
            {
                ulong StackLow = Thread.StackAddress;
                ulong StackHigh = Thread.StackAddress + Thread.StackSize;

                if (NewRsp < StackLow || (NewRsp + AllocationSize) > StackHigh)
                {
                    Emulator.TriggerEventMessage($"[-] DispatchNextUserApc failed: insufficient stack space (RSP=0x{InitialRsp:X}, NewRSP=0x{NewRsp:X}, Need=0x{AllocationSize:X}).", LogFlags.Issues);
                    return false;
                }
            }

            if (!Emulator.IsRegionMapped(NewRsp, AllocationSize))
            {
                ulong PageStart = NewRsp & ~0xFFFUL;
                ulong PageEnd = BinaryEmulator.AlignUp(NewRsp + AllocationSize, 0x1000);

                for (ulong Page = PageStart; Page < PageEnd; Page += 0x1000)
                {
                    if (!Emulator.IsRegionMapped(Page, 1))
                        Emulator._emulator.MapMemory(Page, 0x1000, MemoryProtection.ReadWrite);
                    else
                        Emulator._emulator.SetMemoryProtection(Page, 0x1000, MemoryProtection.ReadWrite);
                }
            }

            if (!Emulator.IsRegionMapped(NewRsp, AllocationSize))
            {
                Emulator.TriggerEventMessage($"[-] DispatchNextUserApc failed: APC stack frame is not mapped (NewRSP=0x{NewRsp:X}, Size=0x{AllocationSize:X}).", LogFlags.Issues);
                return false;
            }

            Span<byte> StackLayout = Shared.GetSpan((uint)StackLayoutSize);
            StackLayout.Clear();

            const uint ContextAmd64 = 0x00100000;
            const uint ContextControl = 0x00000001;
            const uint ContextInteger = 0x00000002;
            const uint ContextSegments = 0x00000004;
            const uint ContextDebugRegisters = 0x00000010;

            WriteUInt64(StackLayout, 0x00, Apc.ApcArgument1);
            WriteUInt64(StackLayout, 0x08, Apc.ApcArgument2);
            WriteUInt64(StackLayout, 0x10, Apc.ApcArgument3);
            WriteUInt64(StackLayout, 0x18, Apc.ApcRoutine);
            WriteUInt32(StackLayout, 0x30, ContextAmd64 | ContextControl | ContextInteger | ContextSegments | ContextDebugRegisters);
            WriteUInt32(StackLayout, 0x34, (uint)Emulator.ReadRegister(Registers.UC_X86_REG_MXCSR));
            WriteUInt16(StackLayout, 0x38, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_CS));
            WriteUInt16(StackLayout, 0x3A, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_DS));
            WriteUInt16(StackLayout, 0x3C, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_ES));
            WriteUInt16(StackLayout, 0x3E, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_FS));
            WriteUInt16(StackLayout, 0x40, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_GS));
            WriteUInt16(StackLayout, 0x42, (ushort)Emulator.ReadRegister(Registers.UC_X86_REG_SS));
            WriteUInt32(StackLayout, 0x44, (uint)InitialEFlags);
            WriteUInt64(StackLayout, 0x48, Emulator.ReadRegister(Registers.UC_X86_REG_DR0));
            WriteUInt64(StackLayout, 0x50, Emulator.ReadRegister(Registers.UC_X86_REG_DR1));
            WriteUInt64(StackLayout, 0x58, Emulator.ReadRegister(Registers.UC_X86_REG_DR2));
            WriteUInt64(StackLayout, 0x60, Emulator.ReadRegister(Registers.UC_X86_REG_DR3));
            WriteUInt64(StackLayout, 0x68, Emulator.ReadRegister(Registers.UC_X86_REG_DR6));
            WriteUInt64(StackLayout, 0x70, Emulator.ReadRegister(Registers.UC_X86_REG_DR7));
            WriteUInt64(StackLayout, 0x78, Emulator.ReadRegister(Registers.UC_X86_REG_RAX));
            WriteUInt64(StackLayout, 0x80, Emulator.ReadRegister(Registers.UC_X86_REG_RCX));
            WriteUInt64(StackLayout, 0x88, Emulator.ReadRegister(Registers.UC_X86_REG_RDX));
            WriteUInt64(StackLayout, 0x90, Emulator.ReadRegister(Registers.UC_X86_REG_RBX));
            WriteUInt64(StackLayout, 0x98, InitialRsp);
            WriteUInt64(StackLayout, 0xA0, Emulator.ReadRegister(Registers.UC_X86_REG_RBP));
            WriteUInt64(StackLayout, 0xA8, Emulator.ReadRegister(Registers.UC_X86_REG_RSI));
            WriteUInt64(StackLayout, 0xB0, Emulator.ReadRegister(Registers.UC_X86_REG_RDI));
            WriteUInt64(StackLayout, 0xB8, Emulator.ReadRegister(Registers.UC_X86_REG_R8));
            WriteUInt64(StackLayout, 0xC0, Emulator.ReadRegister(Registers.UC_X86_REG_R9));
            WriteUInt64(StackLayout, 0xC8, Emulator.ReadRegister(Registers.UC_X86_REG_R10));
            WriteUInt64(StackLayout, 0xD0, Emulator.ReadRegister(Registers.UC_X86_REG_R11));
            WriteUInt64(StackLayout, 0xD8, Emulator.ReadRegister(Registers.UC_X86_REG_R12));
            WriteUInt64(StackLayout, 0xE0, Emulator.ReadRegister(Registers.UC_X86_REG_R13));
            WriteUInt64(StackLayout, 0xE8, Emulator.ReadRegister(Registers.UC_X86_REG_R14));
            WriteUInt64(StackLayout, 0xF0, Emulator.ReadRegister(Registers.UC_X86_REG_R15));
            WriteUInt64(StackLayout, 0xF8, InitialRip);
            WriteInt32(StackLayout, ContinueOffset, 1);
            WriteInt32(StackLayout, ContinueOffset + 0x4, 1);

            Emulator.WriteMemory(NewRsp, StackLayout);
            State.PendingUserApcs.RemoveAt(ApcIndex);
            Thread.Context.RSP = NewRsp;
            Thread.Context.RIP = Dispatcher;
            Emulator.WriteRegister(Registers.UC_X86_REG_RSP, NewRsp);
            Emulator.WriteRegister(Registers.UC_X86_REG_RIP, Dispatcher);
            return true;
        }

        /// <summary>
        /// Canonicalizes an image path for section identity checks.
        /// </summary>
        /// <param name="Path">Guest or host path for the image.</param>
        /// <returns>A stable, case-insensitive identity string for the image.</returns>
        public string CanonicalizeImagePath(string Path)
        {
            string Value = NormalizeWindowsImagePath(Path);
            if (string.IsNullOrEmpty(Value))
                return string.Empty;

            string Lower = Value.ToLowerInvariant();

            int System32Index = Lower.LastIndexOf("\\windows\\system32\\", StringComparison.OrdinalIgnoreCase);
            if (System32Index >= 0)
                return "system32\\" + Lower.Substring(System32Index + "\\windows\\system32\\".Length);

            int SysWow64Index = Lower.LastIndexOf("\\windows\\syswow64\\", StringComparison.OrdinalIgnoreCase);
            if (SysWow64Index >= 0)
                return "syswow64\\" + Lower.Substring(SysWow64Index + "\\windows\\syswow64\\".Length);

            return Lower;
        }

        public string NormalizeWindowsImagePath(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return string.Empty;

            string Value = CleanWindowsPath(Path);

            if (Value.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\" + Value.Substring("\\SystemRoot\\".Length);

            if (Value.StartsWith("SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\" + Value.Substring("SystemRoot\\".Length);

            if (Value.StartsWith("\\KnownDlls32\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("KnownDlls32\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\SysWOW64\\" + FileNameOf(Value);

            if (Value.StartsWith("\\KnownDlls\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("KnownDlls\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\System32\\" + FileNameOf(Value);

            string Relative = Value.TrimStart('\\');
            if (Relative.StartsWith("System32\\", StringComparison.OrdinalIgnoreCase) ||
                Relative.Equals("System32", StringComparison.OrdinalIgnoreCase) ||
                Relative.StartsWith("SysWOW64\\", StringComparison.OrdinalIgnoreCase) ||
                Relative.Equals("SysWOW64", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\" + Relative;

            if (Relative.StartsWith("Windows\\", StringComparison.OrdinalIgnoreCase) ||
                Relative.Equals("Windows", StringComparison.OrdinalIgnoreCase))
                return "C:\\" + Relative;

            return Value;
        }

        public string ResolveWindowsFilePath(string Path, ulong RootDirectory = 0)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return string.Empty;

            string Value = CleanWindowsPath(Path);

            if (Value.StartsWith("UNC\\", StringComparison.OrdinalIgnoreCase))
                return "\\\\" + Value.Substring(4);

            if (Value.StartsWith("GLOBALROOT\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring("GLOBALROOT\\".Length);
            else if (Value.StartsWith("\\GLOBALROOT\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring("\\GLOBALROOT\\".Length);

            if (TryResolveNtDeviceFilePath(Value, out string DevicePath))
                return DevicePath;

            if (TryResolveVolumeGuidPath(Value, out string VolumeGuidPath))
                return VolumeGuidPath;

            if (Value.Length == 2 && char.IsLetter(Value[0]) && Value[1] == ':')
                return char.ToUpperInvariant(Value[0]).ToString() + ":\\";

            if (RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY ||
                Value.StartsWith("\\KnownDlls\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("KnownDlls\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\System32\\" + FileNameOf(Value);

            if (RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY ||
                Value.StartsWith("\\KnownDlls32\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("KnownDlls32\\", StringComparison.OrdinalIgnoreCase))
                return "C:\\Windows\\SysWOW64\\" + FileNameOf(Value);

            if (Value.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                Value = "C:\\Windows\\" + Value.Substring("\\SystemRoot\\".Length);
            else if (Value.StartsWith("SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                Value = "C:\\Windows\\" + Value.Substring("SystemRoot\\".Length);
            else if (Value.StartsWith("\\Windows\\", StringComparison.OrdinalIgnoreCase))
                Value = "C:\\" + Value.TrimStart('\\');
            else if (Value.Equals("\\Windows", StringComparison.OrdinalIgnoreCase))
                Value = "C:\\Windows";

            return Value.Length >= 3 && char.IsLetter(Value[0]) && Value[1] == ':' && Value[2] == '\\' ? Value : string.Empty;
        }

        private static string CleanWindowsPath(string Path)
        {
            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\');

            if (Value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) ||
                Value.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);

            while (Value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);

            while (Value.Contains("\\\\", StringComparison.Ordinal) && !Value.StartsWith("\\\\", StringComparison.Ordinal))
                Value = Value.Replace("\\\\", "\\", StringComparison.Ordinal);

            return Value;
        }

        private bool TryResolveVolumeGuidPath(string Path, out string DosPath)
        {
            DosPath = string.Empty;

            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\').TrimStart('\\');
            const string Prefix = "Volume{";
            if (!Value.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
                return false;

            int CloseBrace = Value.IndexOf('}');
            if (CloseBrace < Prefix.Length)
                return false;

            string GuidText = Value.Substring(Prefix.Length, CloseBrace - Prefix.Length);
            if (!GuidText.Equals(SyntheticVolumeGuid, StringComparison.OrdinalIgnoreCase))
                return false;

            string Rest = Value.Substring(CloseBrace + 1).TrimStart('\\');
            DosPath = string.IsNullOrEmpty(Rest) ? "C:\\" : "C:\\" + Rest;
            return true;
        }

        private static bool TryResolveNtDeviceFilePath(string Path, out string DosPath)
        {
            DosPath = string.Empty;

            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\');
            if (Value.StartsWith("Device\\", StringComparison.OrdinalIgnoreCase))
                Value = "\\" + Value;


            if (Value.StartsWith("\\Device\\Mup\\", StringComparison.OrdinalIgnoreCase))
            {
                string UncRest = Value.Substring("\\Device\\Mup\\".Length).TrimStart('\\');
                DosPath = "\\\\" + UncRest;
                return true;
            }

            const string VolumePrefix = "\\Device\\HarddiskVolume";
            if (!Value.StartsWith(VolumePrefix, StringComparison.OrdinalIgnoreCase))
                return false;

            int RestIndex = VolumePrefix.Length;
            while (RestIndex < Value.Length && char.IsDigit(Value[RestIndex]))
                RestIndex++;

            if (RestIndex >= Value.Length)
            {
                DosPath = "C:\\";
                return true;
            }

            if (Value[RestIndex] != '\\')
                return false;

            string Relative = Value.Substring(RestIndex).TrimStart('\\');
            DosPath = string.IsNullOrEmpty(Relative) ? "C:\\" : "C:\\" + Relative;
            return true;
        }

        private static string FileNameOf(string Path)
        {
            int Slash = Path.LastIndexOf('\\');
            return Slash >= 0 ? Path.Substring(Slash + 1) : Path;
        }

        /// <summary>
        /// Records a mapped image view and returns that image's mapping ordinal for its canonical path.
        /// </summary>
        /// <param name="Module">Mapped image view.</param>
        /// <param name="IsSectionView">Whether the image was mapped by NtMapViewOfSection rather than initial emulator loading.</param>
        /// <returns>One-based mapping ordinal for this canonical image path.</returns>
        public int RegisterMappedImageView(WinModule Module, bool IsSectionView)
        {
            if (Module == null)
                return 0;

            string CanonicalPath = CanonicalizeImagePath(!string.IsNullOrEmpty(Module.Path) ? Module.Path : Module.Name);
            Module.CanonicalImagePath = CanonicalPath;
            if (Module.ImageSectionId == 0 && !string.IsNullOrEmpty(CanonicalPath))
                AttachImageSectionIdentity(Module, CanonicalPath);
            Module.IsSectionView = IsSectionView;

            int Ordinal = 1;
            if (!string.IsNullOrEmpty(CanonicalPath))
            {
                ImageViewCountsByPath.TryGetValue(CanonicalPath, out int ExistingCount);
                Ordinal = ExistingCount + 1;
                ImageViewCountsByPath[CanonicalPath] = Ordinal;
            }

            Module.ImageMapOrdinal = Ordinal;
            MappedImageViews.Add(Module);
            return Ordinal;
        }

        /// <summary>
        /// Removes a mapped image view from section-view identity tracking.
        /// </summary>
        /// <param name="Module">Mapped image view to remove.</param>
        public void UnregisterMappedImageView(WinModule Module)
        {
            if (Module == null)
                return;

            MappedImageViews.RemoveAll(M => ReferenceEquals(M, Module) ||
                                            (M != null && M.MappedBase == Module.MappedBase));

            string CanonicalPath = Module.CanonicalImagePath;
            if (string.IsNullOrEmpty(CanonicalPath))
                CanonicalPath = CanonicalizeImagePath(!string.IsNullOrEmpty(Module.Path) ? Module.Path : Module.Name);

            if (!string.IsNullOrEmpty(CanonicalPath))
            {
                int ActiveCount = MappedImageViews.Count(M => M != null &&
                                                              !string.IsNullOrEmpty(M.CanonicalImagePath) &&
                                                              string.Equals(M.CanonicalImagePath, CanonicalPath, StringComparison.OrdinalIgnoreCase));

                if (ActiveCount == 0)
                    ImageViewCountsByPath.Remove(CanonicalPath);
                else
                    ImageViewCountsByPath[CanonicalPath] = ActiveCount;
            }
        }

        /// <summary>
        /// Finds the image view that contains a guest address.
        /// </summary>
        /// <param name="Address">Guest virtual address.</param>
        /// <returns>The matching mapped image view, or null when the address does not belong to a tracked image.</returns>
        public WinModule FindMappedImageViewByAddress(ulong Address)
        {
            for (int Index = MappedImageViews.Count - 1; Index >= 0; Index--)
            {
                WinModule Module = MappedImageViews[Index];
                if (Module == null || Module.MappedBase == 0 || Module.SizeOfImage == 0)
                    continue;

                ulong End = Module.MappedBase + Module.SizeOfImage;
                if (Address >= Module.MappedBase && Address < End)
                    return Module;
            }

            for (int Index = WinModules.Count - 1; Index >= 0; Index--)
            {
                WinModule Module = WinModules[Index];
                if (Module == null || Module.MappedBase == 0 || Module.SizeOfImage == 0)
                    continue;

                ulong End = Module.MappedBase + Module.SizeOfImage;
                if (Address >= Module.MappedBase && Address < End)
                    return Module;
            }

            return null;
        }

        /// <summary>
        /// Adds a module to the emulated process.
        /// </summary>
        /// <param name="Module">Module to add.</param>
        public void AddModule(WinModule Module, bool TriggerMessage)
        {
            bool Finished = false;
            try
            {
                Finished = true;
                if (TriggerMessage)
                    Emulator.TriggerEventMessage($"[+] Loaded {Module.Name} at 0x{Module.MappedBase:X}.", LogFlags.General);
            }
            finally
            {
                Module.Initialized = Finished;

                WinModule Existing = WinModules.FirstOrDefault(m => m != null && m.MappedBase == Module.MappedBase);
                if (Existing == null)
                    WinModules.Add(Module);
                else
                {
                    Existing.Architecture = Module.Architecture;
                    Existing.EntryPoint = Module.EntryPoint;
                    Existing.OriginalBase = Module.OriginalBase;
                    Existing.SizeOfImage = Module.SizeOfImage;
                    Existing.Name = Module.Name;
                    Existing.Path = Module.Path;
                    Existing.CanonicalImagePath = Module.CanonicalImagePath;
                    Existing.ImageSectionId = Module.ImageSectionId;
                    Existing.ImageMapOrdinal = Module.ImageMapOrdinal;
                    Existing.IsSectionView = Module.IsSectionView;
                    Existing.Initialized = Module.Initialized;
                    Existing.Exports = Module.Exports;
                    Existing.ExportsByName = Module.ExportsByName;
                    Existing.Sections = Module.Sections;
                }
            }
        }

        public ulong GetExportAddress(WinModule Module, string ExportName)
        {
            if (Module.Exports == null || Module.Exports.Count == 0 || string.IsNullOrEmpty(ExportName))
                return 0;

            foreach (var Exp in Module.Exports)
            {
                if (string.Equals(Exp.Value, ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    return Exp.Key - Module.OriginalBase + Module.MappedBase;
                }
            }

            return 0;
        }

        public byte[] StructureToBytes<T>(T str)
        {
            int size = Marshal.SizeOf<T>();
            byte[] arr = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(str, ptr, false);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        /// <summary>
        /// Convert windows memory protection to the internal enum.
        /// </summary>
        /// <param name="Protect">Protection to convert.</param>
        /// <returns>Internal memory protection enum with the Protect options.</returns>
        public MemoryProtection ConvertWinProtectToInternal(ulong Protect)
        {
            Protect &= 0xFF; // exclude PAGE_GUARD

            switch (Protect)
            {
                case 0x01: // PAGE_NOACCESS
                    return MemoryProtection.None;
                case 0x02: // PAGE_READONLY
                    return MemoryProtection.Read;
                case 0x04: // PAGE_READWRITE
                case 0x08: // PAGE_WRITECOPY -> treat as ReadWrite
                    return MemoryProtection.ReadWrite;
                case 0x10: // PAGE_EXECUTE
                    return MemoryProtection.Execute;
                case 0x20: // PAGE_EXECUTE_READ
                    return MemoryProtection.ReadExecute;
                case 0x40: // PAGE_EXECUTE_READWRITE
                case 0x80: // PAGE_EXECUTE_WRITECOPY -> treat as ExecuteReadWrite
                    return MemoryProtection.All;
                default:
                    return MemoryProtection.None;
            }
        }

        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        public ulong ConvertInternalToWinProtect(MemoryProtection Protection)
        {
            bool HasExec = (Protection & MemoryProtection.Execute) != 0;
            bool HasRead = (Protection & MemoryProtection.Read) != 0;
            bool HasWrite = (Protection & MemoryProtection.Write) != 0;

            if (HasExec && HasWrite)
                return PAGE_EXECUTE_READWRITE;

            if (HasExec && HasRead)
                return PAGE_EXECUTE_READ;

            if (HasExec)
                return PAGE_EXECUTE;

            if (HasWrite)
                return PAGE_READWRITE;

            if (HasRead)
                return PAGE_READONLY;

            return PAGE_NOACCESS;
        }

        /// <summary>
        /// Convert allocation type to <see cref="AllocationType"/>.
        /// </summary>
        /// <param name="AllocTypes">Allocation types.</param>
        /// <returns>returns the <see cref="AllocationType"/> enum.</returns>
        public AllocationType ConvertWinAllocType(ulong AllocTypes)
        {
            AllocationType Flags = AllocationType.None;

            if ((AllocTypes & 0x1000) != 0) // MEM_COMMIT
                Flags |= AllocationType.Commited;

            if ((AllocTypes & 0x2000) != 0) // MEM_RESERVE
                Flags |= AllocationType.Reserved;

            if ((AllocTypes & 0x1000000) != 0) // MEM_IMAGE
                Flags |= AllocationType.Image;

            return Flags;
        }

        public ulong ConvertTypeToWinAlloc(AllocationType Type)
        {
            switch (Type)
            {
                case AllocationType.Image:
                    return 0x1000000;
                case AllocationType.Commited:
                    return 0x1000;
                case AllocationType.Reserved:
                    return 0x2000;
                default:
                    return 0x00020000;
            }
        }

        public bool IsProtectedStatus(ProtectionStatus Status)
        {
            if (Status != ProtectionStatus.None) return true;
            return false;
        }

        public bool HandleExists(ulong Handle)
        {
            return HandleManager.HandleExists(Handle);
        }

        public bool HandleExists(ulong Handle, HandleType Type)
        {
            return HandleManager.HandleExists(Handle, Type);
        }

        public WinHandle OpenProcessHandle(uint PID, AccessMask Permissions)
        {
            WinProcess Process = WinProcesses.FirstOrDefault(p => p.PID == PID);
            if (Process == null)
                return new WinHandle();

            WinHandle Handle = HandleManager.AddHandle(Process, Permissions);
            WinHandles.Add(Handle);
            return Handle;
        }

        public WinProcess? GetProcessByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.ProcessHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinProcess>(Handle);
        }

        public bool ValidProcessHandle(ulong Handle)
        {
            if (HandleExists(Handle, HandleType.ProcessHandle))
            {
                WinProcess Target = HandleManager.GetObjectByHandle<WinProcess>(Handle);
                if (Target != null)
                {
                    if (WinProcesses.FirstOrDefault(p => p.PID == Target.PID) != null)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public List<WinProcess> GetProcessList()
        {
            return WinProcesses;
        }

        public ulong AllocateUserHandle()
        {
            EnsureUserSharedInfo(out _, out _, out _);

            if (NextUserHandleIndex == 0 || NextUserHandleIndex >= UserHandleEntryCount)
                return 0;

            ushort Index = NextUserHandleIndex++;
            ushort Uniq = NextUserHandleUniq++;

            if (NextUserHandleUniq == 0 || NextUserHandleUniq >= 0x7FFF)
                NextUserHandleUniq = 1;

            return ((ulong)Uniq << 16) | Index;
        }

        /// <summary>
        /// Ensures the shared USER handle metadata consumed by user32's ValidateHwnd fast path exists.
        /// </summary>
        public bool EnsureUserSharedInfo(out ulong ServerInfo, out ulong HandleTable, out uint EntrySize)
        {
            ServerInfo = EnsureUserServerInfo();
            HandleTable = EnsureUserHandleTable();
            EntrySize = UserHandleEntrySize;
            return ServerInfo != 0 && HandleTable != 0;
        }

        /// <summary>
        /// Seeds the user32 globals that cache USER shared handle-table metadata for ValidateHwnd.
        /// </summary>
        public void InitializeUser32SharedInfoGlobals(ulong ServerInfo, ulong HandleTable, uint EntrySize)
        {
            WinModule User32 = WinModules.FirstOrDefault(Module =>
                Module != null &&
                Module.MappedBase != 0 &&
                Module.SizeOfImage != 0 &&
                string.Equals(Module.Name, "user32.dll", StringComparison.OrdinalIgnoreCase));

            if (User32 == null)
                return;

            ulong Base = User32.MappedBase;
            WriteUser32Global(Base + 0xD0278, HandleTable, 8);
            WriteUser32Global(Base + 0xD0280, EntrySize, 4);

            Span<byte> SharedInfo = Shared.GetSpan(0x28);
            SharedInfo.Slice(0, 0x28).Clear();
            WriteU64(SharedInfo, 0x00, ServerInfo);
            WriteU64(SharedInfo, 0x08, HandleTable);
            WriteU32(SharedInfo, 0x10, EntrySize);
            WriteU32(SharedInfo, 0x14, 0u);
            WriteU64(SharedInfo, 0x18, 0UL);
            Emulator._emulator.WriteMemory(Base + 0xD0480, SharedInfo.Slice(0, 0x28));
        }

        private void WriteUser32Global(ulong Address, ulong Value, uint Size)
        {
            if (Size == 4)
            {
                if (Emulator.IsRegionMapped(Address, 4))
                    Emulator._emulator.WriteMemory(Address, (uint)Value, 4);
                return;
            }

            if (Emulator.IsRegionMapped(Address, 8))
                Emulator._emulator.WriteMemory(Address, Value, 8);
        }

        private ulong EnsureUserServerInfo()
        {
            if (UserServerInfoAddress != 0 && Emulator.IsRegionMapped(UserServerInfoAddress, 0x1C00))
                return UserServerInfoAddress;

            const ulong Size = 0x2000;
            ulong Address = Emulator.MapUniqueAddress(Size, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            if (!WriteZeroMemory(Address, (uint)Size))
                return 0;

            Emulator._emulator.WriteMemory(Address + 0x04, UserHandleEntryCount, 4);
            Emulator._emulator.WriteMemory(Address + 0x08, (ulong)UserHandleEntryCount, 8);

            UserServerInfoAddress = Address;
            return UserServerInfoAddress;
        }

        private ulong EnsureUserHandleTable()
        {
            ulong TableSize = UserHandleEntryCount * UserHandleEntrySize;

            if (UserHandleTableAddress != 0 && Emulator.IsRegionMapped(UserHandleTableAddress, TableSize))
                return UserHandleTableAddress;

            ulong Address = Emulator.MapUniqueAddress(TableSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            if (!WriteZeroMemory(Address, (uint)TableSize))
                return 0;

            UserHandleTableAddress = Address;
            return UserHandleTableAddress;
        }

        /// <summary>
        /// Ensures the current thread has the minimal user32 client desktop fields needed for handle validation.
        /// </summary>
        public void EnsureUserClientThreadInfo(EmulatedThread Thread, ulong ThreadInfo)
        {
            if (Thread == null || ThreadInfo == 0)
                return;

            ulong Teb = WinEmulatedThread.GetState(Thread).Teb;
            if (Teb == 0)
                return;

            ulong DesktopInfo = EnsureUserDesktopInfo();
            if (DesktopInfo == 0)
                return;

            Emulator._emulator.WriteMemory(Teb + 0x820, DesktopInfo, 8);
            Emulator._emulator.WriteMemory(Teb + 0x828, 0UL, 8);
            Emulator._emulator.WriteMemory(Teb + 0x838, 0u, 4);

            if (Emulator.IsRegionMapped(ThreadInfo + 0x840, 8))
            {
                Emulator._emulator.WriteMemory(ThreadInfo + 0x820, DesktopInfo, 8);
                Emulator._emulator.WriteMemory(ThreadInfo + 0x828, 0UL, 8);
                Emulator._emulator.WriteMemory(ThreadInfo + 0x838, 0u, 4);
            }
        }

        private ulong EnsureUserDesktopInfo()
        {
            if (UserDesktopInfoAddress != 0 && Emulator.IsRegionMapped(UserDesktopInfoAddress, UserDesktopInfoSize))
                return UserDesktopInfoAddress;

            if (UserDesktopOwnerAddress == 0 || !Emulator.IsRegionMapped(UserDesktopOwnerAddress, 8))
            {
                UserDesktopOwnerAddress = Emulator.MapUniqueAddress(0x1000, MemoryProtection.ReadWrite);
                if (UserDesktopOwnerAddress == 0)
                    return 0;

                WriteZeroMemory(UserDesktopOwnerAddress, 0x1000);
            }

            ulong DesktopInfo = Emulator.MapUniqueAddress(0x1000, MemoryProtection.ReadWrite);
            if (DesktopInfo == 0)
                return 0;

            if (!WriteZeroMemory(DesktopInfo, 0x1000))
                return 0;

            Emulator._emulator.WriteMemory(DesktopInfo + 0x00, UserDesktopOwnerAddress, 8);
            Emulator._emulator.WriteMemory(DesktopInfo + 0x10, 0u, 4);

            UserDesktopInfoAddress = DesktopInfo;
            return UserDesktopInfoAddress;
        }

        /// <summary>
        /// Creates or refreshes the shared handle-table entry and minimal client-side tagWND memory for a window.
        /// </summary>
        public bool MaterializeUserWindow(WinWindow Window)
        {
            if (Window == null || Window.Hwnd == 0)
                return false;

            if (!EnsureUserSharedInfo(out _, out ulong HandleTable, out uint EntrySize))
                return false;

            ushort Index = (ushort)(Window.Hwnd & 0xFFFF);
            ushort Uniq = (ushort)((Window.Hwnd >> 16) & 0x7FFF);
            if (Index == 0 || Index >= UserHandleEntryCount)
                return false;

            ulong ClientWindow = EnsureUserWindowObject(Window);
            ulong ThreadInfo = EnsureCurrentUserThreadInfo();
            ulong DesktopInfo = EnsureUserDesktopInfo();
            if (ClientWindow == 0 || ThreadInfo == 0 || DesktopInfo == 0)
                return false;

            ulong Entry = HandleTable + (ulong)Index * EntrySize;
            Window.UserHandleEntryAddress = Entry;

            Span<byte> Data = Shared.GetSpan(0x20);
            Data.Slice(0, 0x20).Clear();
            WriteU64(Data, 0x00, ClientWindow);
            WriteU64(Data, 0x08, ThreadInfo);
            WriteU64(Data, 0x10, UserDesktopOwnerAddress);
            Data[0x18] = UserHandleTypeWindow;
            Data[0x19] = 0;
            WriteU16(Data, 0x1A, Uniq);

            return Emulator._emulator.WriteMemory(Entry, Data.Slice(0, 0x20));
        }

        private void ClearUserWindowHandleEntry(WinWindow Window)
        {
            if (Window == null || Window.UserHandleEntryAddress == 0)
                return;

            if (Emulator.IsRegionMapped(Window.UserHandleEntryAddress, UserHandleEntrySize))
                WriteZeroMemory(Window.UserHandleEntryAddress, UserHandleEntrySize);

            Window.UserHandleEntryAddress = 0;
        }

        private ulong EnsureCurrentUserThreadInfo()
        {
            EmulatedThread Thread = Emulator.CurrentThread;
            if (Thread == null)
                return 0;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            ulong ThreadInfo = State.Win32ThreadInfo;
            ulong Teb = State.Teb;

            if (ThreadInfo == 0 && Teb != 0)
                ThreadInfo = Emulator.ReadMemoryULong(Teb + 0x78);

            if (ThreadInfo == 0 && Teb != 0)
            {
                ulong SlabSize = Emulator._binary.Architecture == BinaryArchitecture.x64 ? 0x2000UL : 0x1000UL;
                ulong Bias = Emulator._binary.Architecture == BinaryArchitecture.x64 ? 0x800UL : 0x400UL;
                ulong SlabBase = Emulator.MapUniqueAddress(SlabSize, MemoryProtection.ReadWrite);

                if (SlabBase != 0 && WriteZeroMemory(SlabBase, (uint)SlabSize))
                    ThreadInfo = SlabBase + Bias;
            }

            if (ThreadInfo != 0)
            {
                State.Win32ThreadInfo = ThreadInfo;

                if (Emulator._binary.Architecture == BinaryArchitecture.x64)
                {
                    uint Low = (uint)(ThreadInfo & 0xFFFFFFFFUL);
                    uint High = (uint)(ThreadInfo >> 32);
                    Emulator._emulator.WriteMemory(Teb + 0x78, ThreadInfo, 8);
                    Emulator._emulator.WriteMemory(Teb + 0xE8, Low, 4);
                    Emulator._emulator.WriteMemory(Teb + 0xF0, High, 4);
                }
                else
                {
                    uint ThreadInfo32 = (uint)ThreadInfo;
                    Emulator._emulator.WriteMemory(Teb + 0x40, ThreadInfo32, 4);
                    Emulator._emulator.WriteMemory(Teb + 0x78, ThreadInfo32, 4);
                    Emulator._emulator.WriteMemory(Teb + 0x7C, 0u, 4);
                }

                EnsureUserClientThreadInfo(Thread, ThreadInfo);
            }

            return ThreadInfo;
        }


        /// <summary>
        /// Returns the client-side tagWND address for a tracked window.
        /// </summary>
        public ulong GetUserWindowClientAddress(WinWindow Window)
        {
            if (Window == null)
                return 0;

            ulong Address = EnsureUserWindowObject(Window);
            MaterializeUserWindow(Window);
            return Address;
        }

        private ulong EnsureUserWindowObject(WinWindow Window)
        {
            if (Window.ClientWindowAddress != 0 && Emulator.IsRegionMapped(Window.ClientWindowAddress, UserWindowObjectSize))
            {
                RefreshUserWindowObject(Window);
                return Window.ClientWindowAddress;
            }

            ulong Address = Emulator.MapUniqueAddress(UserWindowObjectSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            if (!WriteZeroMemory(Address, (uint)UserWindowObjectSize))
                return 0;

            Window.ClientWindowAddress = Address;
            RefreshUserWindowObject(Window);
            return Window.ClientWindowAddress;
        }

        private void RefreshUserWindowObject(WinWindow Window)
        {
            ulong ClassObject = EnsureUserClassObject(Window);
            ulong TextObject = EnsureUserWindowText(Window);

            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x00, Window.Hwnd, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x08, Window.ClientWindowAddress, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x78, Window.WndProc, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0x80, ClassObject, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0xB8, Window.ClientTextBytes, 4);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0xC0, TextObject, 8);
            Emulator._emulator.WriteMemory(Window.ClientWindowAddress + 0xE0, 0UL, 8);
        }

        private ulong EnsureUserClassObject(WinWindow Window)
        {
            if (Window.ClientClassAddress != 0 && Emulator.IsRegionMapped(Window.ClientClassAddress, UserClassObjectSize))
                return Window.ClientClassAddress;

            ulong Address = Emulator.MapUniqueAddress(UserClassObjectSize, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            if (!WriteZeroMemory(Address, (uint)UserClassObjectSize))
                return 0;

            Window.ClientClassAddress = Address;
            Emulator._emulator.WriteMemory(Address + 0x00, Window.ClassAtom, 2);
            Emulator._emulator.WriteMemory(Address + 0x04, (ushort)0, 2);
            return Window.ClientClassAddress;
        }

        private ulong EnsureUserWindowText(WinWindow Window)
        {
            string Title = Window.Title ?? string.Empty;
            int TextBytes = Encoding.Unicode.GetByteCount(Title);
            uint RequiredBytes = checked((uint)TextBytes + 2);

            if (Window.ClientTextAddress == 0 || Window.ClientTextBytes + 2 < RequiredBytes ||
                !Emulator.IsRegionMapped(Window.ClientTextAddress, RequiredBytes))
            {
                ulong AllocationSize = Math.Max(RequiredBytes, 0x100u);
                ulong Address = Emulator.MapUniqueAddress(AllocationSize, MemoryProtection.ReadWrite);
                if (Address == 0)
                    return 0;

                if (!WriteZeroMemory(Address, (uint)AllocationSize))
                    return 0;

                Window.ClientTextAddress = Address;
            }

            Span<byte> Buffer = Shared.GetSpan(RequiredBytes);
            Buffer.Slice(0, (int)RequiredBytes).Clear();
            Encoding.Unicode.GetBytes(Title, Buffer.Slice(0, TextBytes));

            if (!Emulator._emulator.WriteMemory(Window.ClientTextAddress, Buffer.Slice(0, (int)RequiredBytes)))
                return 0;

            Window.ClientTextBytes = (uint)TextBytes;
            return Window.ClientTextAddress;
        }

        public void SetUserCaptureActive(bool Active)
        {
            uint Value = Active ? 1u : 0u;
            ulong ServerInfo = EnsureUserServerInfo();
            WriteUserCaptureActiveFlag(ServerInfo, Value);

            foreach (ulong Mirror in EnumerateUserSharedInfoMirrors())
                WriteUserCaptureActiveFlag(Mirror, Value);
        }

        private void WriteUserCaptureActiveFlag(ulong BaseAddress, uint Value)
        {
            if (BaseAddress != 0 && Emulator.IsRegionMapped(BaseAddress + 0x1B50, 4))
                Emulator._emulator.WriteMemory(BaseAddress + 0x1B50, Value, 4);
        }

        private IEnumerable<ulong> EnumerateUserSharedInfoMirrors()
        {
            if (UserSharedInfoMirrorAddress != 0 && Emulator.IsRegionMapped(UserSharedInfoMirrorAddress, 0x1B54))
            {
                yield return UserSharedInfoMirrorAddress;
                yield break;
            }

            if (UserServerInfoAddress == 0)
                yield break;

            WinModule User32 = WinModules.FirstOrDefault(Module =>
                Module != null &&
                Module.MappedBase != 0 &&
                Module.SizeOfImage != 0 &&
                string.Equals(Module.Name, "user32.dll", StringComparison.OrdinalIgnoreCase));

            if (User32 == null)
                yield break;

            ulong End = User32.MappedBase + User32.SizeOfImage;
            for (ulong Address = User32.MappedBase; Address + 8 <= End; Address += 8)
            {
                if (!Emulator.IsRegionMapped(Address, 8))
                    continue;

                if (Emulator.ReadMemoryULong(Address) != UserServerInfoAddress)
                    continue;

                if (!Emulator.IsRegionMapped(Address + 0x1B54, 4))
                    continue;

                UserSharedInfoMirrorAddress = Address;
                yield return Address;
                yield break;
            }
        }

        private static void WriteU16(Span<byte> Data, int Offset, ushort Value)
        {
            Data[Offset + 0] = (byte)Value;
            Data[Offset + 1] = (byte)(Value >> 8);
        }

        private static void WriteU32(Span<byte> Data, int Offset, uint Value)
        {
            for (int i = 0; i < 4; i++)
                Data[Offset + i] = (byte)(Value >> (i * 8));
        }

        private static void WriteU64(Span<byte> Data, int Offset, ulong Value)
        {
            for (int i = 0; i < 8; i++)
                Data[Offset + i] = (byte)(Value >> (i * 8));
        }

        public WinWindowClass RegisterWindowClass(WinWindowClass WindowClass)
        {
            if (WindowClass == null || string.IsNullOrEmpty(WindowClass.Name))
                return null;

            string Key = BuildWindowClassKey(WindowClass.InstanceHandle, WindowClass.Name, WindowClass.Version);
            if (WinWindowClassAtomsByKey.TryGetValue(Key, out ushort ExistingAtom))
                return WinWindowClassesByAtom.TryGetValue(ExistingAtom, out WinWindowClass ExistingClass) ? ExistingClass : null;

            ushort Atom = NextWindowClassAtom++;
            if (NextWindowClassAtom < 0xC000)
                NextWindowClassAtom = 0xC000;

            WindowClass.Atom = Atom;
            WinWindowClassesByAtom[Atom] = WindowClass;
            WinWindowClassAtomsByKey[Key] = Atom;
            return WindowClass;
        }

        public WinWindowClass GetWindowClass(ulong InstanceHandle, string Name, string Version)
        {
            if (string.IsNullOrEmpty(Name))
                return null;

            string Key = BuildWindowClassKey(InstanceHandle, Name, Version);
            if (WinWindowClassAtomsByKey.TryGetValue(Key, out ushort Atom) && WinWindowClassesByAtom.TryGetValue(Atom, out WinWindowClass WindowClass))
                return WindowClass;

            Key = BuildWindowClassKey(0, Name, Version);
            if (WinWindowClassAtomsByKey.TryGetValue(Key, out Atom) && WinWindowClassesByAtom.TryGetValue(Atom, out WindowClass))
                return WindowClass;

            foreach (WinWindowClass Candidate in WinWindowClassesByAtom.Values)
            {
                if (!string.Equals(Candidate.Name, Name, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (string.IsNullOrEmpty(Version) || string.IsNullOrEmpty(Candidate.Version) ||
                    string.Equals(Candidate.Version, Version, StringComparison.OrdinalIgnoreCase))
                    return Candidate;
            }

            return null;
        }

        public WinWindowClass GetWindowClass(ushort Atom)
        {
            return WinWindowClassesByAtom.TryGetValue(Atom, out WinWindowClass WindowClass) ? WindowClass : null;
        }

        private static string BuildWindowClassKey(ulong InstanceHandle, string Name, string Version)
        {
            return $"{InstanceHandle:X}:{Name ?? string.Empty}:{Version ?? string.Empty}";
        }

        public void UpdateTopLevelWindowZOrder(ulong Hwnd, ulong InsertAfter)
        {
            const ulong HWND_TOP = 0;
            const ulong HWND_BOTTOM = 1;
            const ulong HWND_TOPMOST = 0xFFFFFFFFFFFFFFFF;
            const ulong HWND_NOTOPMOST = 0xFFFFFFFFFFFFFFFE;

            if (!WinWindows.TryGetValue(Hwnd, out WinWindow Window))
                return;

            if (Window.ParentHwnd != 0)
                return;

            TopLevelWindows.Remove(Hwnd);

            if (InsertAfter == HWND_BOTTOM)
            {
                TopLevelWindows.Insert(0, Hwnd);
                return;
            }

            if (InsertAfter == HWND_TOP || InsertAfter == HWND_TOPMOST || InsertAfter == HWND_NOTOPMOST)
            {
                TopLevelWindows.Add(Hwnd);
                return;
            }

            int Index = TopLevelWindows.IndexOf(InsertAfter);
            if (Index == -1)
            {
                TopLevelWindows.Add(Hwnd);
                return;
            }

            TopLevelWindows.Insert(Index + 1, Hwnd);
        }

        public ulong GetForegroundWindow()
        {
            for (int i = TopLevelWindows.Count - 1; i >= 0; i--)
            {
                ulong Hwnd = TopLevelWindows[i];

                if (!WinWindows.TryGetValue(Hwnd, out WinWindow Window))
                    continue;

                if (Window.Destroyed)
                    continue;

                if (!Window.Visible)
                    continue;

                return Hwnd;
            }

            return 0;
        }

        /// <summary>
        /// Retained as a presentation boundary for future renderers. Window state is tracked in WinWindows and TopLevelWindows only.
        /// </summary>
        public void CompositeDesktop()
        {
        }

        /// <summary>
        /// Retained as a presentation boundary for future renderers. The current Win32k layer does not render windows to the host console.
        /// </summary>
        public void PresentDesktop()
        {
        }

        public WinWindow GetWindow(ulong Hwnd)
        {
            if (Hwnd == 0)
                return null;

            if (WinWindows.TryGetValue(Hwnd, out WinWindow Window))
                return Window;

            return null;
        }

        public void RegisterWindow(WinWindow Window)
        {
            MaterializeUserWindow(Window);
            WinWindows[Window.Hwnd] = Window;

            if (Window.Visible)
            {
                if (ActiveWindow == 0)
                    ActiveWindow = Window.Hwnd;

                if (FocusWindow == 0)
                    FocusWindow = Window.Hwnd;
            }

            if (Window.ParentHwnd != 0 && WinWindows.TryGetValue(Window.ParentHwnd, out WinWindow Parent))
            {
                if (!Parent.Children.Contains(Window.Hwnd))
                    Parent.Children.Add(Window.Hwnd);
            }
            else
            {
                if (!TopLevelWindows.Contains(Window.Hwnd))
                    TopLevelWindows.Add(Window.Hwnd);
            }

            Window.Dirty = true;
            MaterializeUserWindow(Window);
            PresentDesktop();
        }

        public bool DestroyWindow(ulong Hwnd)
        {
            if (!WinWindows.TryGetValue(Hwnd, out WinWindow Window))
                return false;

            if (ActiveWindow == Hwnd)
                ActiveWindow = 0;

            if (FocusWindow == Hwnd)
                FocusWindow = 0;

            foreach (ulong Child in Window.Children.ToArray())
            {
                DestroyWindow(Child);
            }

            if (Window.ParentHwnd != 0 && WinWindows.TryGetValue(Window.ParentHwnd, out WinWindow Parent))
            {
                Parent.Children.Remove(Hwnd);
            }
            else
            {
                TopLevelWindows.Remove(Hwnd);
            }

            Window.Destroyed = true;
            ClearUserWindowHandleEntry(Window);
            WinWindows.Remove(Hwnd);
            PresentDesktop();
            return true;
        }

        public WinHandle OpenFileHandle(string Path, bool FSAccess, AccessMask Permissions)
        {
            WinFile hFile = null;
            if (FSAccess)
            {
                if (File.Exists(Path))
                    hFile = new WinFile { Path = Path, Device = (Path.StartsWith("\\\\.\\") || Path.ToLower().StartsWith("\\device\\")) };
                else
                    return null;
            }
            else
            {
                hFile = WinFiles.FirstOrDefault(f => f.Path.Equals(Path, StringComparison.OrdinalIgnoreCase));
                if (hFile == null)
                {
                    hFile = new WinFile { Path = Path, Device = (Path.StartsWith("\\\\.\\") || Path.ToLower().StartsWith("\\device\\")) };
                    WinFiles.Add(hFile);
                }
            }

            WinHandle Handle = HandleManager.AddHandle(hFile, Permissions);
            WinHandles.Add(Handle);
            return Handle;
        }

        public WinFile? GetFileByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.FileHandle))
                return null;

            if (Purpose != AccessMask.GiveTemp)
            {
                if (!HandleManager.CheckAccess(Handle, Purpose))
                    return null;
            }

            return HandleManager.GetObjectByHandle<WinFile>(Handle);
        }

        public bool ValidFileHandle(ulong Handle)
        {
            if (HandleExists(Handle, HandleType.FileHandle))
            {
                WinFile Target = HandleManager.GetObjectByHandle<WinFile>(Handle);
                if (Target != null)
                {
                    if (WinFiles.FirstOrDefault(f => f.Path == Target.Path) != null)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public bool IsValidFileLockRange(ulong Offset, ulong Length)
        {
            if (Length == 0)
                return false;

            ulong End = Offset + Length - 1;
            return !(End < Offset);
        }

        /// <summary>
        /// Reads and validates a Windows file lock byte range from emulated memory.
        /// </summary>
        /// <param name="ByteOffsetPtr">Pointer to the lock offset.</param>
        /// <param name="LengthPtr">Pointer to the lock length.</param>
        /// <param name="Offset">Receives the lock offset.</param>
        /// <param name="Length">Receives the lock length.</param>
        /// <param name="Status">Receives the validation status.</param>
        /// <returns>True if the lock range was read and is valid.</returns>
        public bool TryReadFileLockRange(ulong ByteOffsetPtr, ulong LengthPtr, out ulong Offset, out ulong Length, out NTSTATUS Status)
        {
            Offset = 0;
            Length = 0;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (!Emulator.IsRegionMapped(ByteOffsetPtr, 8) || !Emulator.IsRegionMapped(LengthPtr, 8))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            long SignedOffset = unchecked((long)Emulator._emulator.ReadMemoryULong(ByteOffsetPtr));
            long SignedLength = unchecked((long)Emulator._emulator.ReadMemoryULong(LengthPtr));
            if (SignedOffset < 0 || SignedLength < 0)
            {
                Status = NTSTATUS.STATUS_INVALID_LOCK_RANGE;
                return false;
            }

            Offset = (ulong)SignedOffset;
            Length = (ulong)SignedLength;

            if (!IsValidFileLockRange(Offset, Length))
            {
                Status = NTSTATUS.STATUS_INVALID_LOCK_RANGE;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Reads an optional Windows file byte offset from emulated memory.
        /// </summary>
        /// <param name="ByteOffsetPtr">Pointer to a LARGE_INTEGER byte offset, or zero to use the current file position.</param>
        /// <param name="CurrentPosition">The current file position.</param>
        /// <returns>The requested file offset, or the current file position if no valid pointer was supplied.</returns>
        public long GetEffectiveFileOffset(ulong ByteOffsetPtr, long CurrentPosition)
        {
            if (ByteOffsetPtr == 0)
                return CurrentPosition;

            if (!Emulator.IsRegionMapped(ByteOffsetPtr, 8))
                return CurrentPosition;

            return unchecked((long)Emulator._emulator.ReadMemoryULong(ByteOffsetPtr));
        }

        public WinHandle CreateMutexHandle(string Name, AccessMask Permissions)
        {
            WinMutex Mutex = null;

            if (!string.IsNullOrEmpty(Name))
                Mutex = WinMutexes.FirstOrDefault(m => m.Name.Equals(Name, StringComparison.OrdinalIgnoreCase));

            if (Mutex == null)
            {
                Mutex = new WinMutex { Name = string.IsNullOrEmpty(Name) ? $"\\UnnamedMutant\\{WinMutexes.Count:X}" : Name, Signaled = true };
                WinMutexes.Add(Mutex);
            }

            WinHandle Handle = HandleManager.AddHandle(Mutex, Permissions);
            WinHandles.Add(Handle);
            return Handle;
        }

        public WinMutex? GetMutexByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.MutexHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinMutex>(Handle);
        }

        public void AbandonMutexesOwnedByThread(uint ThreadId)
        {
            if (ThreadId == 0)
                return;

            foreach (WinMutex Mutex in WinMutexes)
            {
                if (Mutex.OwnerThreadId != ThreadId || Mutex.RecursionCount <= 0)
                    continue;

                Mutex.OwnerThreadId = 0;
                Mutex.RecursionCount = 0;
                Mutex.Signaled = true;
                Mutex.Abandoned = true;
            }
        }

        private Hive GetHiveByNtPath(string NtPath)
        {
            return RegManager.GetHiveByNtPath(RegHives, NtPath);
        }

        private string FixupNtRegistryPath(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return NtPath;

            NtPath = NtPath.TrimEnd('\0').Trim();
            if (NtPath.Length == 0)
                return NtPath;

            NtPath = NtPath.Replace('/', '\\');

            while (NtPath.Contains("\\\\", StringComparison.Ordinal))
                NtPath = NtPath.Replace("\\\\", "\\", StringComparison.Ordinal);

            if (!NtPath.StartsWith("\\", StringComparison.Ordinal))
                NtPath = "\\" + NtPath;

            if (NtPath.Equals("\\HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase) || NtPath.Equals("\\HKLM", StringComparison.OrdinalIgnoreCase))
                NtPath = "\\Registry\\Machine";

            if (NtPath.StartsWith("\\HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase))
                NtPath = "\\Registry\\Machine\\" + NtPath.Substring("\\HKEY_LOCAL_MACHINE\\".Length);

            if (NtPath.StartsWith("\\HKLM\\", StringComparison.OrdinalIgnoreCase))
                NtPath = "\\Registry\\Machine\\" + NtPath.Substring("\\HKLM\\".Length);

            if (NtPath.Equals("\\HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) || NtPath.Equals("\\HKCU", StringComparison.OrdinalIgnoreCase))
                NtPath = $"\\Registry\\User\\{CurrentUserSid}";

            if (NtPath.StartsWith("\\HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase))
                NtPath = $"\\Registry\\User\\{CurrentUserSid}\\" + NtPath.Substring("\\HKEY_CURRENT_USER\\".Length);

            if (NtPath.StartsWith("\\HKCU\\", StringComparison.OrdinalIgnoreCase))
                NtPath = $"\\Registry\\User\\{CurrentUserSid}\\" + NtPath.Substring("\\HKCU\\".Length);

            if (NtPath.StartsWith("\\Registry\\Machine\\", StringComparison.OrdinalIgnoreCase))
            {
                string Rest = NtPath.Substring("\\Registry\\Machine\\".Length);

                if (Rest.Length == 0)
                    return NtPath;

                int Sep = Rest.IndexOf('\\');
                string First = Sep == -1 ? Rest : Rest.Substring(0, Sep);

                if (First.Equals("SOFTWARE", StringComparison.OrdinalIgnoreCase) || First.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) || First.Equals("SAM", StringComparison.OrdinalIgnoreCase) || First.Equals("SECURITY", StringComparison.OrdinalIgnoreCase) || First.Equals("HARDWARE", StringComparison.OrdinalIgnoreCase))
                {
                    return NtPath;
                }

                return "\\Registry\\Machine\\SOFTWARE\\" + Rest;
            }

            if (NtPath.Equals("\\Registry\\User", StringComparison.OrdinalIgnoreCase))
                return "\\Registry\\User";

            if (NtPath.StartsWith("\\Registry\\User\\", StringComparison.OrdinalIgnoreCase))
            {
                string Rest = NtPath.Substring("\\Registry\\User\\".Length);
                if (Rest.Length == 0)
                    return $"\\Registry\\User\\{CurrentUserSid}";

                int Sep = Rest.IndexOf('\\');
                string First = Sep == -1 ? Rest : Rest.Substring(0, Sep);
                string Tail = Sep == -1 ? string.Empty : Rest.Substring(Sep);

                if (First.Equals(".DEFAULT", StringComparison.OrdinalIgnoreCase))
                    return "\\Registry\\User\\.DEFAULT" + Tail;

                if (First.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
                    return $"\\Registry\\User\\{CurrentUserSid}{Tail}";

                return $"\\Registry\\User\\{CurrentUserSid}\\{Rest}";
            }

            if (NtPath.StartsWith("\\SOFTWARE\\", StringComparison.OrdinalIgnoreCase))
                return "\\Registry\\Machine" + NtPath;

            if (NtPath.Equals("\\SOFTWARE", StringComparison.OrdinalIgnoreCase))
                return "\\Registry\\Machine\\SOFTWARE";

            return NtPath;
        }

        private static string NormalizeKeyPath(string Path)
        {
            return RegistryManager.NormalizeKeyPath(Path);
        }

        public string NormalizeNtRegistryPath(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return null;

            NtPath = FixupNtRegistryPath(NtPath);
            return NormalizeKeyPath(NtPath);
        }

        private bool IsVirtualRegistryRoot(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return false;

            NtPath = NormalizeKeyPath(NtPath);
            return NtPath.Equals("\\Registry\\Machine", StringComparison.OrdinalIgnoreCase) ||
                   NtPath.Equals("\\Registry\\User", StringComparison.OrdinalIgnoreCase);
        }

        private void AddVirtualRegistrySubKeys(string NtPath, SortedSet<string> Names)
        {
            if (string.IsNullOrEmpty(NtPath) || Names == null)
                return;

            NtPath = NormalizeKeyPath(NtPath);

            if (NtPath.Equals("\\Registry\\Machine", StringComparison.OrdinalIgnoreCase))
            {
                Names.Add("HARDWARE");
                Names.Add("SAM");
                Names.Add("SECURITY");
                Names.Add("SOFTWARE");
                Names.Add("SYSTEM");
                return;
            }

            if (NtPath.Equals("\\Registry\\User", StringComparison.OrdinalIgnoreCase))
            {
                Names.Add(CurrentUserSid);
                Names.Add(".DEFAULT");
                return;
            }
        }

        private void InitializeSyntheticRegistryDefaults()
        {
            Dictionary<string, bool> KeyCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            Hive DefaultHive = RegHives != null && RegHives.Length != 0 ? RegHives[0] : null;
            string UserProfile = "C:\\Users\\User";
            string UserRoot = "\\Registry\\User\\" + CurrentUserSid;
            string ExplorerRoot = UserRoot + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";

            AddSyntheticRegistryKey("\\Registry\\User", KeyCache, DefaultHive);
            AddSyntheticRegistryKey(UserRoot, KeyCache, DefaultHive);
            AddSyntheticRegistryKey("\\Registry\\User\\.DEFAULT", KeyCache, DefaultHive);
            AddSyntheticRegistryKey(UserRoot + "\\" + CurrentUserSid, KeyCache, DefaultHive);
            AddSyntheticRegistryKey(ExplorerRoot + "\\SessionInfo\\0", KeyCache, DefaultHive);
            SetSyntheticRegistryString(UserRoot + "\\Volatile Environment", "USERPROFILE", 2, UserProfile, KeyCache, DefaultHive);
            SetSyntheticRegistryString(UserRoot + "\\Volatile Environment", "HOMEDRIVE", 1, "C:", KeyCache, DefaultHive);
            SetSyntheticRegistryString(UserRoot + "\\Volatile Environment", "HOMEPATH", 1, "\\Users\\User", KeyCache, DefaultHive);
            SetSyntheticRegistryString(UserRoot + "\\Volatile Environment", "APPDATA", 2, "%USERPROFILE%\\AppData\\Roaming", KeyCache, DefaultHive);
            SetSyntheticRegistryString(UserRoot + "\\Volatile Environment", "LOCALAPPDATA", 2, "%USERPROFILE%\\AppData\\Local", KeyCache, DefaultHive);

            string ProfileListKey = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + CurrentUserSid;
            AddSyntheticRegistryKey(ProfileListKey, KeyCache, DefaultHive);
            SetSyntheticRegistryString(ProfileListKey, "ProfileImagePath", 2, "%SystemDrive%\\Users\\User", KeyCache, DefaultHive);
            SetSyntheticRegistryDword(ProfileListKey, "Flags", 0, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(ProfileListKey, "State", 0, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(ProfileListKey, "RefCount", 0, KeyCache, DefaultHive);

            InitializeSyntheticWindowsVersionRegistryDefaults(KeyCache, DefaultHive);
            InitializeSyntheticKnownFolderDescriptions(UserProfile, KeyCache, DefaultHive);

            string KnownFolderSettings = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\KnownFolderSettings";
            AddSyntheticRegistryKey(KnownFolderSettings, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(KnownFolderSettings, "CacheTimeout", 0, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(KnownFolderSettings, "BackgroundRetryInterval", 0, KeyCache, DefaultHive);

            AddSyntheticDirectory(UserProfile);
            AddSyntheticDirectory(UserProfile + "\\AppData");
            AddSyntheticDirectory(UserProfile + "\\AppData\\Local");
            AddSyntheticDirectory(UserProfile + "\\AppData\\Roaming");
            AddSyntheticDirectory(UserProfile + "\\Desktop");
            AddSyntheticDirectory(UserProfile + "\\Documents");
            AddSyntheticDirectory(UserProfile + "\\Downloads");
            AddSyntheticDirectory("C:\\ProgramData");
            AddSyntheticDirectory("C:\\Users\\Public");
            AddSyntheticDirectory("C:\\Users\\Public\\Desktop");
            AddSyntheticDirectory("C:\\Users\\Public\\Documents");

            string UserShellFolders = ExplorerRoot + "\\User Shell Folders";
            string ShellFolders = ExplorerRoot + "\\Shell Folders";

            AddSyntheticRegistryKey(UserShellFolders, KeyCache, DefaultHive);
            AddSyntheticRegistryKey(ShellFolders, KeyCache, DefaultHive);

            (string Name, string ExpandValue, string ResolvedValue)[] Folders =
            {
                ("AppData", "%USERPROFILE%\\AppData\\Roaming", UserProfile + "\\AppData\\Roaming"),
                ("Local AppData", "%USERPROFILE%\\AppData\\Local", UserProfile + "\\AppData\\Local"),
                ("Desktop", "%USERPROFILE%\\Desktop", UserProfile + "\\Desktop"),
                ("Personal", "%USERPROFILE%\\Documents", UserProfile + "\\Documents"),
                ("My Pictures", "%USERPROFILE%\\Pictures", UserProfile + "\\Pictures"),
                ("My Music", "%USERPROFILE%\\Music", UserProfile + "\\Music"),
                ("My Video", "%USERPROFILE%\\Videos", UserProfile + "\\Videos"),
                ("Favorites", "%USERPROFILE%\\Favorites", UserProfile + "\\Favorites"),
                ("Start Menu", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"),
                ("Programs", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"),
                ("Startup", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                ("Recent", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent"),
                ("SendTo", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\SendTo", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\SendTo"),
                ("Templates", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Templates", UserProfile + "\\AppData\\Roaming\\Microsoft\\Windows\\Templates"),
                ("Cache", "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCache", UserProfile + "\\AppData\\Local\\Microsoft\\Windows\\INetCache"),
                ("Cookies", "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCookies", UserProfile + "\\AppData\\Local\\Microsoft\\Windows\\INetCookies"),
                ("History", "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\History", UserProfile + "\\AppData\\Local\\Microsoft\\Windows\\History")
            };

            foreach ((string Name, string ExpandValue, string ResolvedValue) in Folders)
            {
                SetSyntheticRegistryString(UserShellFolders, Name, 2, ExpandValue, KeyCache, DefaultHive);
                SetSyntheticRegistryString(ShellFolders, Name, 1, ResolvedValue, KeyCache, DefaultHive);
                AddSyntheticDirectory(ResolvedValue);
            }

            string MachineExplorerRoot = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";
            string CommonUserShellFolders = MachineExplorerRoot + "\\User Shell Folders";
            string CommonShellFolders = MachineExplorerRoot + "\\Shell Folders";
            AddSyntheticRegistryKey(CommonUserShellFolders, KeyCache, DefaultHive);
            AddSyntheticRegistryKey(CommonShellFolders, KeyCache, DefaultHive);

            SetSyntheticRegistryString(CommonUserShellFolders, "Common AppData", 2, "%ProgramData%", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonShellFolders, "Common AppData", 1, "C:\\ProgramData", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonUserShellFolders, "Common Desktop", 2, "%PUBLIC%\\Desktop", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonShellFolders, "Common Desktop", 1, "C:\\Users\\Public\\Desktop", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonUserShellFolders, "Common Documents", 2, "%PUBLIC%\\Documents", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonShellFolders, "Common Documents", 1, "C:\\Users\\Public\\Documents", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonUserShellFolders, "Common Programs", 2, "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonShellFolders, "Common Programs", 1, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonUserShellFolders, "Common Start Menu", 2, "%ProgramData%\\Microsoft\\Windows\\Start Menu", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonShellFolders, "Common Start Menu", 1, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonUserShellFolders, "Common Startup", 2, "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonShellFolders, "Common Startup", 1, "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonUserShellFolders, "Common Templates", 2, "%ProgramData%\\Microsoft\\Windows\\Templates", KeyCache, DefaultHive);
            SetSyntheticRegistryString(CommonShellFolders, "Common Templates", 1, "C:\\ProgramData\\Microsoft\\Windows\\Templates", KeyCache, DefaultHive);
        }

        private void InitializeSyntheticWindowsVersionRegistryDefaults(Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            const string CurrentVersionKey = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion";
            AddSyntheticRegistryKey(CurrentVersionKey, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "ProductName", 1, WindowsVersionInfo.ProductName, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "EditionID", 1, WindowsVersionInfo.EditionId, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "CompositionEditionID", 1, WindowsVersionInfo.EditionId, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "InstallationType", 1, WindowsVersionInfo.InstallationType, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "DisplayVersion", 1, WindowsVersionInfo.DisplayVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "ReleaseId", 1, WindowsVersionInfo.DisplayVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "CurrentVersion", 1, WindowsVersionInfo.CurrentVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "CurrentBuild", 1, WindowsVersionInfo.BuildNumber.ToString(), KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "CurrentBuildNumber", 1, WindowsVersionInfo.BuildNumber.ToString(), KeyCache, DefaultHive);
            SetSyntheticRegistryDword(CurrentVersionKey, "CurrentMajorVersionNumber", WindowsVersionInfo.MajorVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(CurrentVersionKey, "CurrentMinorVersionNumber", WindowsVersionInfo.MinorVersion, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(CurrentVersionKey, "UBR", WindowsVersionInfo.UpdateBuildRevision, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "BuildBranch", 1, WindowsVersionInfo.BuildBranch, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "BuildLab", 1, WindowsVersionInfo.BuildLab, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "BuildLabEx", 1, WindowsVersionInfo.BuildLabEx, KeyCache, DefaultHive);
            SetSyntheticRegistryString(CurrentVersionKey, "CurrentType", 1, "Multiprocessor Free", KeyCache, DefaultHive);

            const string ProductOptionsKey = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions";
            AddSyntheticRegistryKey(ProductOptionsKey, KeyCache, DefaultHive);
            SetSyntheticRegistryString(ProductOptionsKey, "ProductType", 1, WindowsVersionInfo.RegistryProductType, KeyCache, DefaultHive);
        }

        private void AddSyntheticRegistryKey(string NtPath, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return;

            string[] Parts = NtPath.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
            string Current = string.Empty;

            foreach (string Part in Parts)
            {
                Current += "\\" + Part;
                if (Current.Equals("\\Registry", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (TempRegistryKeys.Contains(Current))
                {
                    KeyCache[Current] = true;
                    continue;
                }

                if (!KeyCache.TryGetValue(Current, out bool Exists))
                {
                    Exists = RegistryKeyExists(Current, out _, out _, out _);
                    KeyCache[Current] = Exists;
                }

                if (Exists)
                    continue;

                TempRegistryKeys.Add(Current);
                DeletedRegistryKeys.Remove(Current);
                Hive Hive = GetHiveByNtPath(Current) ?? DefaultHive;
                if (Hive != null)
                    TempRegistryKeyHives[Current] = Hive;
                KeyCache[Current] = true;
            }
        }

        private void AddSyntheticDirectory(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return;

            string Normalized = Path.Replace('/', '\\').TrimEnd('\\');
            if (Normalized.Length == 2 && Normalized[1] == ':')
                Normalized += "\\";

            SyntheticDirectories.Add(Normalized);
        }

        public bool IsSyntheticDirectory(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Normalized = Path.Replace('/', '\\').TrimEnd('\\');
            if (Normalized.Length == 2 && Normalized[1] == ':')
                Normalized += "\\";

            if (SyntheticDirectories.Contains(Normalized))
                return true;

            return false;
        }

        private void SetSyntheticRegistryString(string NtPath, string ValueName, int Type, string Value, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            byte[] Data = Encoding.Unicode.GetBytes((Value ?? string.Empty) + "\0");
            SetSyntheticRegistryValue(NtPath, ValueName, Type, Data, KeyCache, DefaultHive);
        }

        private void SetSyntheticRegistryDword(string NtPath, string ValueName, uint Value, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            byte[] Data = BitConverter.GetBytes(Value);
            SetSyntheticRegistryValue(NtPath, ValueName, 4, Data, KeyCache, DefaultHive);
        }

        private void SetSyntheticRegistryValue(string NtPath, string ValueName, int Type, byte[] Data, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            AddSyntheticRegistryKey(NtPath, KeyCache, DefaultHive);

            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return;

            if (ValueName == null)
                ValueName = string.Empty;

            if (!TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values))
            {
                Values = new Dictionary<string, ValueNode>(StringComparer.OrdinalIgnoreCase);
                TempRegistryValues[NtPath] = Values;
            }

            Values[ValueName] = new ValueNode { Name = ValueName, Type = Type, Data = Data ?? Array.Empty<byte>() };

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
                DeletedValues.Remove(ValueName);
        }

        private void InitializeSyntheticKnownFolderDescriptions(string UserProfile, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            const string Root = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FolderDescriptions";
            AddSyntheticRegistryKey(Root, KeyCache, DefaultHive);

            AddSyntheticKnownFolder(Root, "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Profile", string.Empty, UserProfile, 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", "Local AppData", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "AppData\\Local", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}", "Roaming AppData", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "AppData\\Roaming", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "Documents", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Documents", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Desktop", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{374DE290-123F-4565-9164-39C4925E467B}", "Downloads", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Downloads", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{33E28130-4E1E-4676-835A-98395C3BC3BB}", "Pictures", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Pictures", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{4BD8D571-6D19-48D3-BE97-422220080E43}", "Music", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Music", 4, KeyCache, DefaultHive);
            AddSyntheticKnownFolder(Root, "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}", "Videos", "{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "Videos", 4, KeyCache, DefaultHive);
        }

        private void AddSyntheticKnownFolder(string Root, string Guid, string Name, string ParentFolder, string RelativePath, uint Category, Dictionary<string, bool> KeyCache, Hive DefaultHive)
        {
            string Key = Root + "\\" + Guid;
            AddSyntheticRegistryKey(Key, KeyCache, DefaultHive);
            SetSyntheticRegistryString(Key, "Name", 1, Name, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(Key, "Category", Category, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(Key, "Attributes", 0x10, KeyCache, DefaultHive);
            SetSyntheticRegistryDword(Key, "DefinitionFlags", 0, KeyCache, DefaultHive);
            SetSyntheticRegistryString(Key, "LocalizedName", 2, Name, KeyCache, DefaultHive);
            SetSyntheticRegistryString(Key, "Tooltip", 2, Name, KeyCache, DefaultHive);
            SetSyntheticRegistryString(Key, "Icon", 2, "%SystemRoot%\\system32\\imageres.dll,-3", KeyCache, DefaultHive);
            SetSyntheticRegistryString(Key, "Security", 1, string.Empty, KeyCache, DefaultHive);

            if (!string.IsNullOrEmpty(ParentFolder))
                SetSyntheticRegistryString(Key, "ParentFolder", 1, ParentFolder, KeyCache, DefaultHive);

            if (!string.IsNullOrEmpty(RelativePath))
                SetSyntheticRegistryString(Key, "RelativePath", 1, RelativePath, KeyCache, DefaultHive);

            string PropertyBag = Key + "\\PropertyBag";
            AddSyntheticRegistryKey(PropertyBag, KeyCache, DefaultHive);
            SetSyntheticRegistryString(PropertyBag, "ThisPCPolicy", 1, "Show", KeyCache, DefaultHive);
        }

        private bool IsRegistryPathDeleted(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return true;

            NtPath = NormalizeKeyPath(NtPath);

            foreach (string DeletedKey in DeletedRegistryKeys)
            {
                if (NtPath.Equals(DeletedKey, StringComparison.OrdinalIgnoreCase) || NtPath.StartsWith(DeletedKey + "\\", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public bool RegistryKeyExists(string NtPath, out Hive Hive, out RegistryHiveReader.HiveKey Key, out bool TempOnly)
        {
            Hive = null;
            Key = default;
            TempOnly = false;

            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            if (IsRegistryPathDeleted(NtPath))
                return false;

            if (IsVirtualRegistryRoot(NtPath))
            {
                TempOnly = true;
                return true;
            }

            bool HasTempKey = TempRegistryKeys.Contains(NtPath);
            Hive = GetHiveByNtPath(NtPath);
            if (Hive == null)
            {
                if (!HasTempKey)
                    return false;

                TempOnly = true;
                TempRegistryKeyHives.TryGetValue(NtPath, out Hive TempHive);
                Hive = TempHive ?? RegHives.FirstOrDefault();
                return true;
            }

            if (HasTempKey)
            {
                TempOnly = true;
                TempRegistryKeyHives.TryGetValue(NtPath, out Hive TempHive);
                if (TempHive != null)
                    Hive = TempHive;
            }

            if (Hive.Reader != null)
            {
                string KeyPath = RegManager.NormalizeNtRegistryPath(Hive, NtPath);
                if (string.IsNullOrEmpty(KeyPath))
                    KeyPath = "\\";

                if (Hive.Reader.TryOpenPath(KeyPath, out Key))
                    return true;
            }

            return TempOnly;
        }

        private string GetRegistryParentPath(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return null;

            NtPath = NormalizeKeyPath(NtPath);
            int Index = NtPath.LastIndexOf('\\');
            if (Index <= 0)
                return null;

            return NtPath.Substring(0, Index);
        }

        private bool TryGetRegistryValues(WinRegKey RegKey, out List<ValueNode> Values)
        {
            Values = new List<ValueNode>();

            if (RegKey == null)
                return false;

            string NtPath = NormalizeNtRegistryPath(RegKey.FullPath);
            if (string.IsNullOrEmpty(NtPath) || IsRegistryPathDeleted(NtPath))
                return false;

            Dictionary<string, ValueNode> Merged = new(StringComparer.OrdinalIgnoreCase);

            if (RegKey.Hive != null && RegKey.Hive.Reader != null && RegKey.HasParsedKey)
            {
                for (int i = 0; RegKey.Hive.Reader.TryEnumerateValueFull(RegKey.ParsedKey, i, out string Name, out int Type, out byte[] Data); i++)
                {
                    if (Name == null)
                        Name = string.Empty;

                    Merged[Name] = new ValueNode { Name = Name, Type = Type, Data = Data ?? Array.Empty<byte>() };
                }
            }

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
            {
                foreach (string Name in DeletedValues)
                    Merged.Remove(Name);
            }

            if (TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> TempValues))
            {
                foreach (var Pair in TempValues)
                {
                    ValueNode Value = Pair.Value;
                    Merged[Pair.Key] = new ValueNode { Name = Value.Name, Type = Value.Type, Data = Value.Data == null ? Array.Empty<byte>() : (byte[])Value.Data.Clone() };
                }
            }

            Values = Merged.Values.OrderBy(v => v.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase).ToList();
            return true;
        }

        public bool TryEnumerateRegistrySubKey(WinRegKey RegKey, int Index, out string Name)
        {
            Name = null;

            if (RegKey == null || Index < 0)
                return false;

            string NtPath = NormalizeNtRegistryPath(RegKey.FullPath);
            if (string.IsNullOrEmpty(NtPath) || IsRegistryPathDeleted(NtPath))
                return false;

            SortedSet<string> Names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            AddVirtualRegistrySubKeys(NtPath, Names);

            if (RegKey.Hive != null && RegKey.Hive.Reader != null && RegKey.HasParsedKey)
            {
                for (int i = 0; RegKey.Hive.Reader.TryEnumerateSubKey(RegKey.ParsedKey, i, out string SubKeyName); i++)
                {
                    string ChildFullPath = NormalizeKeyPath(NtPath + "\\" + SubKeyName);
                    if (!DeletedRegistryKeys.Contains(ChildFullPath))
                        Names.Add(SubKeyName);
                }
            }

            foreach (string TempKey in TempRegistryKeys)
            {
                if (DeletedRegistryKeys.Contains(TempKey))
                    continue;

                if (IsDirectRegistryChild(NtPath, TempKey, out string ChildName))
                    Names.Add(ChildName);
            }

            if (Index >= Names.Count)
                return false;

            Name = Names.ElementAt(Index);
            return true;
        }

        private bool IsDirectRegistryChild(string ParentPath, string ChildPath, out string ChildName)
        {
            ChildName = null;

            if (string.IsNullOrEmpty(ParentPath) || string.IsNullOrEmpty(ChildPath))
                return false;

            ParentPath = NormalizeKeyPath(ParentPath);
            ChildPath = NormalizeKeyPath(ChildPath);

            if (!ChildPath.StartsWith(ParentPath + "\\", StringComparison.OrdinalIgnoreCase))
                return false;

            string Rest = ChildPath.Substring(ParentPath.Length + 1);
            if (string.IsNullOrEmpty(Rest) || Rest.Contains("\\", StringComparison.Ordinal))
                return false;

            ChildName = Rest;
            return true;
        }

        private string GetRegistryKeyNameFromPath(string NtPath)
        {
            if (string.IsNullOrEmpty(NtPath))
                return string.Empty;

            NtPath = NormalizeKeyPath(NtPath);
            int Index = NtPath.LastIndexOf('\\');
            if (Index < 0 || Index == NtPath.Length - 1)
                return NtPath.Trim('\\');

            return NtPath.Substring(Index + 1);
        }

        public bool TryQueryRegistryKeyFullInfo(WinRegKey RegKey, out int SubKeyCount, out int ValueCount, out int MaxSubKeyNameChars, out int MaxValueNameChars, out int MaxValueDataBytes)
        {
            return TryQueryRegistryKeyFullInfo(RegKey, out SubKeyCount, out ValueCount, out MaxSubKeyNameChars, out MaxValueNameChars, out MaxValueDataBytes, out _);
        }

        public bool TryQueryRegistryKeyFullInfo(WinRegKey RegKey, out int SubKeyCount, out int ValueCount, out int MaxSubKeyNameChars, out int MaxValueNameChars, out int MaxValueDataBytes, out string Name)
        {
            SubKeyCount = 0;
            ValueCount = 0;
            MaxSubKeyNameChars = 0;
            MaxValueNameChars = 0;
            MaxValueDataBytes = 0;
            Name = null;

            if (!TryQueryRegistryKeyHeader(RegKey, out SubKeyCount, out ValueCount, out Name))
                return false;

            for (int i = 0; TryEnumerateRegistrySubKey(RegKey, i, out string SubKeyName); i++)
            {
                if (!string.IsNullOrEmpty(SubKeyName) && SubKeyName.Length > MaxSubKeyNameChars)
                    MaxSubKeyNameChars = SubKeyName.Length;
            }

            if (TryGetRegistryValues(RegKey, out List<ValueNode> Values))
            {
                foreach (ValueNode Value in Values)
                {
                    string ValueName = Value.Name ?? string.Empty;
                    int DataLength = Value.Data == null ? 0 : Value.Data.Length;
                    if (ValueName.Length > MaxValueNameChars)
                        MaxValueNameChars = ValueName.Length;
                    if (DataLength > MaxValueDataBytes)
                        MaxValueDataBytes = DataLength;
                }
            }

            return true;
        }

        public bool TryGetRegistryValue(WinRegKey RegKey, string ValueName, out ValueNode Value)
        {
            Value = null;

            if (RegKey == null)
                return false;

            string NtPath = NormalizeNtRegistryPath(RegKey.FullPath);
            if (string.IsNullOrEmpty(NtPath) || IsRegistryPathDeleted(NtPath))
                return false;

            if (ValueName == null)
                ValueName = string.Empty;

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues) && DeletedValues.Contains(ValueName))
                return false;

            if (TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values) && Values.TryGetValue(ValueName, out ValueNode TempValue))
            {
                Value = new ValueNode { Name = TempValue.Name, Type = TempValue.Type, Data = TempValue.Data == null ? Array.Empty<byte>() : (byte[])TempValue.Data.Clone() };
                return true;
            }

            if (RegKey.Hive != null && RegKey.Hive.Reader != null && RegKey.HasParsedKey)
                return RegKey.Hive.Reader.TryGetValue(RegKey.ParsedKey, ValueName, out Value);

            return false;
        }

        public bool TryQueryRegistryKeyHeader(WinRegKey RegKey, out int SubKeyCount, out int ValueCount, out string Name)
        {
            SubKeyCount = 0;
            ValueCount = 0;
            Name = null;

            if (RegKey == null)
                return false;

            string NtPath = NormalizeNtRegistryPath(RegKey.FullPath);
            if (string.IsNullOrEmpty(NtPath) || IsRegistryPathDeleted(NtPath))
                return false;

            Name = GetRegistryKeyNameFromPath(NtPath);
            if (string.IsNullOrEmpty(Name) && RegKey.Hive != null && RegKey.Hive.Reader != null && RegKey.HasParsedKey)
                RegKey.Hive.Reader.TryQueryKeyHeader(RegKey.ParsedKey, out _, out _, out Name);

            for (int i = 0; TryEnumerateRegistrySubKey(RegKey, i, out _); i++)
                SubKeyCount++;

            if (TryGetRegistryValues(RegKey, out List<ValueNode> Values))
                ValueCount = Values.Count;

            return true;
        }

        public bool TryEnumerateRegistryValueBasic(WinRegKey RegKey, int Index, out string ValueName, out int ValueType, out int DataLength)
        {
            ValueName = null;
            ValueType = 0;
            DataLength = 0;

            if (!TryGetRegistryValues(RegKey, out List<ValueNode> Values) || Index < 0 || Index >= Values.Count)
                return false;

            ValueNode Value = Values[Index];
            ValueName = Value.Name ?? string.Empty;
            ValueType = Value.Type;
            DataLength = Value.Data == null ? 0 : Value.Data.Length;
            return true;
        }

        public bool TryEnumerateRegistryValueFull(WinRegKey RegKey, int Index, out string ValueName, out int ValueType, out byte[] Data)
        {
            ValueName = null;
            ValueType = 0;
            Data = null;

            if (!TryGetRegistryValues(RegKey, out List<ValueNode> Values) || Index < 0 || Index >= Values.Count)
                return false;

            ValueNode Value = Values[Index];
            ValueName = Value.Name ?? string.Empty;
            ValueType = Value.Type;
            Data = Value.Data == null ? Array.Empty<byte>() : (byte[])Value.Data.Clone();
            return true;
        }

        public bool CreateRegistryKeyPath(string NtPath, out bool CreatedNew)
        {
            CreatedNew = false;

            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            string ParentPath = GetRegistryParentPath(NtPath);
            if (string.IsNullOrEmpty(ParentPath))
                return false;

            if (!RegistryKeyExists(ParentPath, out Hive ParentHive, out _, out _))
                return false;

            if (RegistryKeyExists(NtPath, out _, out _, out _))
                return true;

            TempRegistryKeys.Add(NtPath);
            DeletedRegistryKeys.Remove(NtPath);
            TempRegistryKeyHives[NtPath] = ParentHive;
            CreatedNew = true;
            CompleteRegistryNotifications(ParentPath, 0x00000001);
            return true;
        }

        public bool DeleteRegistryKeyPath(string NtPath)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            if (!RegistryKeyExists(NtPath, out _, out _, out _))
                return false;

            DeletedRegistryKeys.Add(NtPath);
            TempRegistryKeys.Remove(NtPath);
            TempRegistryValues.Remove(NtPath);
            DeletedRegistryValues.Remove(NtPath);
            TempRegistryKeyHives.Remove(NtPath);

            List<string> TempChildren = TempRegistryKeys.Where(x => x.StartsWith(NtPath + "\\", StringComparison.OrdinalIgnoreCase)).ToList();
            foreach (string Child in TempChildren)
            {
                TempRegistryKeys.Remove(Child);
                TempRegistryValues.Remove(Child);
                DeletedRegistryValues.Remove(Child);
                TempRegistryKeyHives.Remove(Child);
                DeletedRegistryKeys.Add(Child);
            }

            string ParentPath = GetRegistryParentPath(NtPath);
            CompleteRegistryNotifications(!string.IsNullOrEmpty(ParentPath) ? ParentPath : NtPath, 0x00000001);
            return true;
        }

        public bool SetRegistryValue(string NtPath, string ValueName, int Type, byte[] Data)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            if (!RegistryKeyExists(NtPath, out _, out _, out _))
                return false;

            if (ValueName == null)
                ValueName = string.Empty;

            if (!TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values))
            {
                Values = new Dictionary<string, ValueNode>(StringComparer.OrdinalIgnoreCase);
                TempRegistryValues[NtPath] = Values;
            }

            Values[ValueName] = new ValueNode { Name = ValueName, Type = Type, Data = Data ?? Array.Empty<byte>() };

            if (DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
                DeletedValues.Remove(ValueName);

            CompleteRegistryNotifications(NtPath, 0x00000004);
            return true;
        }

        public bool DeleteRegistryValue(string NtPath, string ValueName)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return false;

            if (!RegistryKeyExists(NtPath, out Hive Hive, out RegistryHiveReader.HiveKey Key, out bool TempOnly))
                return false;

            if (ValueName == null)
                ValueName = string.Empty;

            bool Exists = false;

            if (TempRegistryValues.TryGetValue(NtPath, out Dictionary<string, ValueNode> Values) && Values.ContainsKey(ValueName))
                Exists = true;

            if (!Exists && Hive != null && Hive.Reader != null && !TempOnly)
                Exists = Hive.Reader.TryGetValue(Key, ValueName, out _);

            if (!Exists)
                return false;

            if (TempRegistryValues.TryGetValue(NtPath, out Values))
                Values.Remove(ValueName);

            if (!DeletedRegistryValues.TryGetValue(NtPath, out HashSet<string> DeletedValues))
            {
                DeletedValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                DeletedRegistryValues[NtPath] = DeletedValues;
            }

            DeletedValues.Add(ValueName);
            CompleteRegistryNotifications(NtPath, 0x00000004);
            return true;
        }

        public void RegisterRegistryNotification(WinRegistryNotification Notification)
        {
            if (Notification == null || string.IsNullOrEmpty(Notification.KeyPath))
                return;

            Notification.KeyPath = NormalizeNtRegistryPath(Notification.KeyPath);
            RegistryNotifications.Add(Notification);
        }

        private bool RegistryNotificationMatches(WinRegistryNotification Notification, string ChangedPath, uint ChangeFilter)
        {
            if (Notification == null || string.IsNullOrEmpty(Notification.KeyPath) || string.IsNullOrEmpty(ChangedPath))
                return false;

            if ((Notification.CompletionFilter & ChangeFilter) == 0)
                return false;

            string NotifyPath = NormalizeNtRegistryPath(Notification.KeyPath);
            ChangedPath = NormalizeNtRegistryPath(ChangedPath);

            if (ChangedPath.Equals(NotifyPath, StringComparison.OrdinalIgnoreCase))
                return true;

            return Notification.WatchTree && ChangedPath.StartsWith(NotifyPath + "\\", StringComparison.OrdinalIgnoreCase);
        }

        public void CompleteRegistryNotifications(string ChangedPath, uint ChangeFilter)
        {
            if (RegistryNotifications.Count == 0)
                return;

            List<WinRegistryNotification> Completed = RegistryNotifications
                .Where(Notification => RegistryNotificationMatches(Notification, ChangedPath, ChangeFilter))
                .ToList();

            foreach (WinRegistryNotification Notification in Completed)
            {
                if (Notification.IoStatusBlock != 0 && Emulator.IsRegionMapped(Notification.IoStatusBlock, 0x10))
                    WriteIoStatusBlock64(Emulator, Notification.IoStatusBlock, NTSTATUS.STATUS_SUCCESS, 0);

                if (Notification.EventHandle != 0)
                {
                    WinEvent Event = GetEventByHandle(Notification.EventHandle, AccessMask.GiveTemp);
                    if (Event != null)
                        Event.Signaled = true;
                }
                else if (Notification.KeyHandle != 0)
                {
                    WinRegKey Key = HandleManager.GetObjectByHandle<WinRegKey>(Notification.KeyHandle);
                    if (Key != null)
                        Key.NotifySignaled = true;
                }

                RegistryNotifications.Remove(Notification);
            }
        }

        public WinHandle OpenRegistryKey(string NtPath, AccessMask Permissions)
        {
            NtPath = NormalizeNtRegistryPath(NtPath);
            if (string.IsNullOrEmpty(NtPath))
                return null;

            if (!RegistryKeyExists(NtPath, out Hive Hive, out RegistryHiveReader.HiveKey Key, out bool TempOnly))
                return null;

            WinRegKey RegKey = new WinRegKey
            {
                FullPath = NtPath,
                Hive = Hive,
                Key = null,
                ParsedKey = Key,
                HasParsedKey = !TempOnly && Hive != null && Hive.Reader != null
            };

            WinHandle Handle = HandleManager.AddHandle(RegKey, Permissions);
            WinHandles.Add(Handle);
            return Handle;
        }

        public WinHandle CreateEventHandle(string Name, uint EventType, bool InitialState, AccessMask Permissions)
        {
            if (string.IsNullOrEmpty(Name))
                Name = "Event_" + GenerateRandomPID().ToString();

            WinEvent Ev = WinEvents.FirstOrDefault(e => e.Name.Equals(Name, StringComparison.OrdinalIgnoreCase));
            if (Ev == null)
            {
                Ev = new WinEvent { Name = Name, Signaled = InitialState, EventType = EventType };
                WinEvents.Add(Ev);
            }

            WinHandle Handle = HandleManager.AddHandle(Ev, Permissions);
            WinHandles.Add(Handle);
            return Handle;
        }

        public WinEvent? GetEventByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.EventHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinEvent>(Handle);
        }

        public WinHandle CreateSemaphoreHandle(string Name, int InitialCount, int MaximumCount, AccessMask Permissions)
        {
            if (string.IsNullOrEmpty(Name))
                Name = "Semaphore_" + GenerateRandomPID().ToString();

            WinSemaphore Semaphore = WinSemaphores.FirstOrDefault(s => s.Name.Equals(Name, StringComparison.OrdinalIgnoreCase));
            if (Semaphore == null)
            {
                Semaphore = new WinSemaphore { Name = Name, CurrentCount = InitialCount, MaximumCount = MaximumCount };
                WinSemaphores.Add(Semaphore);
            }

            WinHandle Handle = HandleManager.AddHandle(Semaphore, Permissions);
            WinHandles.Add(Handle);
            return Handle;
        }

        public WinSemaphore? GetSemaphoreByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.SemaphoreHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinSemaphore>(Handle);
        }

        public WinHandle CreateSectionHandle(string Name, ulong Size, uint Protection, uint Attributes, string Path, ulong BackingAddress, AccessMask Permissions)
        {
            if (string.IsNullOrEmpty(Name))
                Name = "Section_" + GenerateRandomPID().ToString();

            WinSection Sec = new WinSection
            {
                Name = Name,
                Size = Size,
                Protection = Protection,
                Attributes = Attributes,
                Path = Path,
                FileStream = string.IsNullOrEmpty(Path) ? null : WindowsFileStream.FromGuestPath(Path),
                BackingAddress = BackingAddress
            };

            if (Sec.IsImage && !string.IsNullOrEmpty(Path))
                AttachImageSectionIdentity(Sec, Path);

            WinSections.Add(Sec);

            WinHandle Handle = HandleManager.AddHandle(Sec, Permissions);
            WinHandles.Add(Handle);
            return Handle;
        }

        public WinSection? GetSectionByHandle(ulong Handle, AccessMask Purpose)
        {
            if (!HandleManager.HandleExists(Handle, HandleType.SectionHandle))
                return null;

            if (!HandleManager.CheckAccess(Handle, Purpose))
                return null;

            return HandleManager.GetObjectByHandle<WinSection>(Handle);
        }

        public void CloseHandle(ulong Handle)
        {
            if (HandleManager.RemoveHandle(Handle))
            {
                WinHandles.RemoveAll(h => h.Handle == Handle);
            }
        }
    }

    public sealed class KuserSharedDataManager
    {
        private const ulong PageSize = 0x1000;

        private const int OffsetTickCountLowDeprecated = 0x000;
        private const int OffsetTickCountMultiplier = 0x004;
        private const int OffsetInterruptTime = 0x008;
        private const int OffsetSystemTime = 0x014;
        private const int OffsetNtSystemRoot = 0x030;
        private const int OffsetNtBuildNumber = 0x260;
        private const int OffsetNtProductType = 0x264;
        private const int OffsetProductTypeIsValid = 0x268;
        private const int OffsetNtMajorVersion = 0x26C;
        private const int OffsetNtMinorVersion = 0x270;
        private const int OffsetProcessorFeatures = 0x274;
        private const int OffsetXStateConfiguration = 0x3D8;
        private const int OffsetSystemCallX86 = 0x300;
        private const int OffsetSystemCallX64 = 0x308;
        private const int OffsetTickCountQuad = 0x320;
        private const int OffsetCookie = 0x330;

        private const ulong HundredNsPerDefaultTick = 156_250UL;

        private readonly BinaryEmulator Emulator;
        private MemoryDelegate ReadHook;
        private bool HookInstalled;

        private long LastUpdateTimestamp;

        private ulong BaseInterruptTime;

        public KuserSharedDataManager(BinaryEmulator Emulator)
        {
            this.Emulator = Emulator;
            Initialize();
        }

        public void Initialize()
        {
            if (HookInstalled)
                return;

            if (!Emulator.IsRegionMapped(Emulator.KUSER_SHARED_DATA, PageSize))
            {
                if (Emulator.MapMemoryRegion(Emulator.KUSER_SHARED_DATA, PageSize, MemoryProtection.Read) == 0)
                {
                    Utils.LogError($"[KUSER_MANAGER] Failed to map KUSER_SHARED_DATA. Last Unicorn Error: {Emulator.GetLastError()}");
                }
            }

            byte[] Page = BuildInitialPage();
            if (!Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA, Page))
            {
                Utils.LogError($"[KUSER_MANAGER] Failed write the initial page data to KUSER_SHARED_DATA. Last Unicorn Error: {Emulator.GetLastError()}");
            }

            BaseInterruptTime = ReadKsystemTimeFromBuffer(Page, OffsetInterruptTime);

            LastUpdateTimestamp = 0;

            ReadHook = OnRead;
            if (!Emulator._emulator.AddHook(Emulator.KUSER_SHARED_DATA, Emulator.KUSER_SHARED_DATA + (PageSize - 1), Hooks.UC_HOOK_MEM_READ, Marshal.GetFunctionPointerForDelegate(ReadHook)))
            {
                Utils.LogError($"[KUSER_MANAGER] Failed to add a hook for KUSER_SHARED_DATA to update dynamic fields. Last Unicorn Error: {Emulator.GetLastError()}\n- ReadHook Ptr 0x{ReadHook:X}");
            }

            HookInstalled = true;

            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)GetSystemCallOffset(), 0u, 4);
            UpdateDynamicFields(true);
        }

        private bool OnRead(IntPtr Uc, MemoryType Type, ulong Address, uint Size, ulong Value, IntPtr UserData)
        {
            UpdateDynamicFields(false);
            return true;
        }

        private void UpdateDynamicFields(bool Force)
        {
            long Now = Emulator.EmulatedTickCount64;
            if (!Force && Now == LastUpdateTimestamp)
                return;

            LastUpdateTimestamp = Now;

            ulong Elapsed100Ns = unchecked((ulong)Math.Max(0, Now)) * 10_000UL;

            ulong SystemTime = unchecked((ulong)Emulator.GetEmulatedSystemTimeFileTimeUtc());
            ulong InterruptTime = BaseInterruptTime + Elapsed100Ns;

            WriteKsystemTimeToMemory(OffsetSystemTime, SystemTime);
            WriteKsystemTimeToMemory(OffsetInterruptTime, InterruptTime);

            ulong TickCountQuad = Elapsed100Ns / HundredNsPerDefaultTick;
            WriteKsystemTimeToMemory(OffsetTickCountQuad, TickCountQuad);

            uint TickCountLow = (uint)TickCountQuad;
            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + OffsetTickCountLowDeprecated, TickCountLow, 4);

            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)GetSystemCallOffset(), 0u, 4);
        }

        private int GetSystemCallOffset()
        {
            return Emulator._binary.Architecture == BinaryArchitecture.x86 ? OffsetSystemCallX86 : OffsetSystemCallX64;
        }

        private byte[] BuildInitialPage()
        {
            byte[] Page = new byte[PageSize];
            if (GeneralHelper.IsWindows)
            {
                try
                {
                    IntPtr HostBase = new IntPtr(unchecked((int)Emulator.KUSER_SHARED_DATA));
                    for (int i = 0; i < Page.Length; i++)
                    {
                        Page[i] = Marshal.ReadByte(HostBase, i);
                    }
                }
                catch
                {
                }
                WriteUInt32(Page, OffsetNtBuildNumber, WindowsVersionInfo.BuildNumber);
                WriteUInt32(Page, OffsetNtProductType, WindowsVersionInfo.ProductTypeWinNt);
                Page[OffsetProductTypeIsValid] = 1;
                WriteUInt32(Page, OffsetNtMajorVersion, WindowsVersionInfo.MajorVersion);
                WriteUInt32(Page, OffsetNtMinorVersion, WindowsVersionInfo.MinorVersion);
                WriteUInt32(Page, OffsetCookie, (uint)RandomNumberGenerator.GetInt32(int.MaxValue));
            }
            else
            {
                void WriteByte(int Offset, byte Value)
                {
                    if ((uint)Offset >= (uint)Page.Length)
                        return;

                    Page[Offset] = Value;
                }

                Random random = new Random();

                void WriteUInt32(int Offset, uint Value)
                {
                    if (Offset < 0 || Offset + 4 > Page.Length)
                        return;

                    BinaryPrimitives.WriteUInt32LittleEndian(Page.AsSpan(Offset, 4), Value);
                }

                void WriteUInt64(int Offset, ulong Value)
                {
                    if (Offset < 0 || Offset + 8 > Page.Length)
                        return;

                    BinaryPrimitives.WriteUInt64LittleEndian(Page.AsSpan(Offset, 8), Value);
                }

                void WriteInt64(int Offset, long Value)
                {
                    if (Offset < 0 || Offset + 8 > Page.Length)
                        return;

                    BinaryPrimitives.WriteInt64LittleEndian(Page.AsSpan(Offset, 8), Value);
                }

                // TickCountLow / TickCountLowDeprecated
                WriteUInt32(OffsetTickCountLowDeprecated, unchecked((uint)Emulator.EmulatedTickCount64));

                // InterruptTime
                WriteInt64(OffsetInterruptTime, TimeSpan.FromHours(random.Next(2, 24)).Ticks);

                // SystemTime
                WriteInt64(OffsetSystemTime, Emulator.GetEmulatedSystemTimeFileTimeUtc());

                // KdDebuggerEnabled
                WriteByte(0x02D4, 0x00);

                // SafeBootMode
                WriteByte(0x02EC, 0x00);

                // NtBuildNumber
                WriteUInt32(OffsetNtBuildNumber, WindowsVersionInfo.BuildNumber);

                // NtProductType (NtProductWinNt)
                WriteUInt32(OffsetNtProductType, WindowsVersionInfo.ProductTypeWinNt);
                WriteByte(OffsetProductTypeIsValid, 1);

                // NtMajorVersion / NtMinorVersion
                WriteUInt32(OffsetNtMajorVersion, WindowsVersionInfo.MajorVersion);
                WriteUInt32(OffsetNtMinorVersion, WindowsVersionInfo.MinorVersion);

                // SystemCall flag
                WriteUInt32(OffsetSystemCallX64, 0);

                // TickCount64
                WriteUInt64(OffsetTickCountQuad, unchecked((ulong)Emulator.EmulatedTickCount64));

                // Cookie
                WriteUInt32(OffsetCookie, unchecked((uint)random.Next()));

                // ActiveProcessorCount
                WriteUInt32(0x03C0, unchecked((uint)Environment.ProcessorCount));
            }

            string SystemRoot = "C:\\Windows";
            Array.Clear(Page, OffsetNtSystemRoot, Math.Min(Page.Length - OffsetNtSystemRoot, 520));
            Span<byte> SystemRootBytes = Page.AsSpan(OffsetNtSystemRoot, Encoding.Unicode.GetByteCount(SystemRoot) + 2);
            Encoding.Unicode.GetBytes(SystemRoot.AsSpan(), SystemRootBytes);
            SystemRootBytes[SystemRootBytes.Length - 2] = 0;
            SystemRootBytes[SystemRootBytes.Length - 1] = 0;

            for (int i = 0; i < 64; i++)
                Page[OffsetProcessorFeatures + i] = 0;

            // Do not leak the host KUSER_SHARED_DATA XState configuration into the guest.
            // Brovan's CPUID surface does not advertise XSAVE/OSXSAVE, and guest ntdll will
            // enter XRSTOR-based context paths if the copied host XState bitmap remains set.
            Array.Clear(Page, OffsetXStateConfiguration, Page.Length - OffsetXStateConfiguration);

            Page[OffsetProcessorFeatures + 6] = 1;  // SSE
            Page[OffsetProcessorFeatures + 10] = 1; // SSE2
            Page[OffsetProcessorFeatures + 13] = 1; // SSE3
            Page[OffsetProcessorFeatures + 12] = 1; // NX
            Page[OffsetProcessorFeatures + 23] = 1; // FASTFAIL
            Page[OffsetProcessorFeatures + 28] = 1; // RDRAND
            Page[OffsetProcessorFeatures + 32] = 1; // RDTSCP

            return Page;
        }

        private static void WriteUInt32(byte[] Buffer, int Offset, uint Value)
        {
            Buffer[Offset + 0] = (byte)(Value & 0xFF);
            Buffer[Offset + 1] = (byte)((Value >> 8) & 0xFF);
            Buffer[Offset + 2] = (byte)((Value >> 16) & 0xFF);
            Buffer[Offset + 3] = (byte)((Value >> 24) & 0xFF);
        }

        private static ulong ReadKsystemTimeFromBuffer(byte[] Buffer, int Offset)
        {
            if (Buffer == null || Buffer.Length < Offset + 12)
                return 0;

            uint Low = BitConverter.ToUInt32(Buffer, Offset + 0);
            uint High1 = BitConverter.ToUInt32(Buffer, Offset + 4);
            return ((ulong)High1 << 32) | Low;
        }

        private void WriteKsystemTimeToMemory(int Offset, ulong Value)
        {
            uint Low = (uint)(Value & 0xFFFFFFFF);
            uint High = (uint)(Value >> 32);

            Span<byte> Tmp = stackalloc byte[12];
            BitConverter.TryWriteBytes(Tmp.Slice(0, 4), Low);
            BitConverter.TryWriteBytes(Tmp.Slice(4, 4), High);
            BitConverter.TryWriteBytes(Tmp.Slice(8, 4), High);
            Emulator._emulator.WriteMemory(Emulator.KUSER_SHARED_DATA + (ulong)Offset, Tmp);
        }
    }

    internal sealed class PebLdrTracker
    {
        private const int PebOffsetLdr = 0x18;

        private const int PebLdrSize = 0x58;
        private const int PebLdrOffsetInLoadOrder = 0x10;

        private const int ListEntryOffsetFlink = 0x0;

        private const int LdrEntryOffsetInLoadOrderLinks = 0x00;
        private const int LdrEntryOffsetDllBase = 0x30;
        private const int LdrEntryOffsetSizeOfImage = 0x40;
        private const int LdrEntryOffsetFullDllName = 0x48; // UNICODE_STRING
        private const int LdrEntryOffsetBaseDllName = 0x58; // UNICODE_STRING

        private const int UnicodeStringSize = 0x10;
        private const int UnicodeStringOffsetLength = 0x0;
        private const int UnicodeStringOffsetBuffer = 0x8;

        private const int MaxUnicodeStringBytes = 0x800; // hard cap (bytes)

        private readonly BinaryEmulator Emulator;
        private readonly WinSysHelper WinHelper;

        private MemoryDelegate PebLdrWriteHook;
        private MemoryDelegate LdrDataWriteHook;
        private BlockHookDelegate BlockHook;

        private IntPtr PebLdrWriteHookPtr;
        private IntPtr LdrDataWriteHookPtr;
        private IntPtr BlockHookPtr;

        private bool PebHookInstalled;
        private bool BlockHookInstalled;

        private readonly HashSet<ulong> HookedLdrDataBases = new HashSet<ulong>();

        private volatile bool PendingRefreshHooks;
        private volatile bool PendingSync;
        private int DelayBlocks;

        private long LastPumpTicks;

        private readonly Dictionary<ulong, ModuleInfo> LastSnapshot = new Dictionary<ulong, ModuleInfo>();

        private delegate void BlockHookDelegate(IntPtr uc, ulong address, uint size, IntPtr user_data);

        private struct ModuleInfo
        {
            public ulong DllBase;
            public uint SizeOfImage;
            public string BaseName;
            public string FullName;
        }

        internal PebLdrTracker(BinaryEmulator emulator, WinSysHelper winHelper)
        {
            Emulator = emulator;
            WinHelper = winHelper;
        }

        internal void Install()
        {
            InstallPebLdrPointerHook();
            InstallBlockHook();

            PendingRefreshHooks = true;
            PendingSync = true;
            DelayBlocks = 2;
        }

        private void InstallPebLdrPointerHook()
        {
            if (PebHookInstalled)
                return;

            ulong PebLdrPtr = Emulator.PEB + (ulong)PebOffsetLdr;

            PebLdrWriteHook = OnPebLdrPointerWrite;
            PebLdrWriteHookPtr = Marshal.GetFunctionPointerForDelegate(PebLdrWriteHook);

            if (!Emulator._emulator.AddHook(PebLdrPtr, PebLdrPtr + 7, Hooks.UC_HOOK_MEM_WRITE, PebLdrWriteHookPtr))
            {
                Utils.LogError($"[-] Failed to install PEB->Ldr MEM_WRITE hook. Last unicorn error: {Emulator.GetLastError()}");
                return;
            }

            PebHookInstalled = true;
        }

        private void InstallBlockHook()
        {
            if (BlockHookInstalled)
                return;

            BlockHook = OnBlock;
            BlockHookPtr = Marshal.GetFunctionPointerForDelegate(BlockHook);

            if (!Emulator._emulator.AddHook(1, 0, Hooks.UC_HOOK_BLOCK, BlockHookPtr))
            {
                Utils.LogError($"[-] Failed to install BLOCK hook for LDR tracker. Last unicorn error: {Emulator.GetLastError()}");
                return;
            }

            BlockHookInstalled = true;
        }

        private bool OnPebLdrPointerWrite(IntPtr uc, MemoryType type, ulong address, uint size, ulong value, IntPtr user_data)
        {
            PendingRefreshHooks = true;
            PendingSync = true;
            DelayBlocks = 2;
            return true;
        }

        private bool OnLdrDataWrite(IntPtr uc, MemoryType type, ulong address, uint size, ulong value, IntPtr user_data)
        {
            PendingSync = true;
            DelayBlocks = 2;
            return true;
        }

        private void OnBlock(IntPtr uc, ulong address, uint size, IntPtr user_data)
        {
            if (!PendingSync && !PendingRefreshHooks)
                return;

            if (DelayBlocks > 0)
            {
                DelayBlocks--;
                return;
            }

            Pump();
        }

        internal void Pump()
        {
            long Now = Stopwatch.GetTimestamp();
            long MinDelta = Stopwatch.Frequency / 2000; // ~0.5ms throttle
            if (LastPumpTicks != 0 && (Now - LastPumpTicks) < MinDelta)
                return;

            LastPumpTicks = Now;

            if (PendingRefreshHooks)
            {
                PendingRefreshHooks = false;
                RefreshLdrHooks();
            }

            if (!PendingSync)
                return;

            if (!TrySnapshotAndApply())
            {
                PendingSync = true;
                DelayBlocks = 2;
                return;
            }

            PendingSync = false;
        }

        private void RefreshLdrHooks()
        {
            ulong LdrData = SafeReadUlong(Emulator.PEB + (ulong)PebOffsetLdr);
            if (LdrData == 0)
                return;

            if (HookedLdrDataBases.Contains(LdrData))
                return;

            if (!Emulator.IsRegionMapped(LdrData, (uint)PebLdrSize))
                return;

            ulong Begin = LdrData;
            ulong End = LdrData + (ulong)PebLdrSize - 1;

            LdrDataWriteHook = OnLdrDataWrite;
            LdrDataWriteHookPtr = Marshal.GetFunctionPointerForDelegate(LdrDataWriteHook);

            if (!Emulator._emulator.AddHook(Begin, End, Hooks.UC_HOOK_MEM_WRITE, LdrDataWriteHookPtr))
            {
                Utils.LogError($"[-] Failed to install PEB_LDR_DATA MEM_WRITE hook. Last unicorn error: {Emulator.GetLastError()}");
                return;
            }

            HookedLdrDataBases.Add(LdrData);
        }

        private bool TrySnapshotAndApply()
        {
            if (!TryReadSnapshot(out var Snapshot))
                return false;

            foreach (var kv in Snapshot)
            {
                if (LastSnapshot.ContainsKey(kv.Key))
                    continue;

                var info = kv.Value;
                Emulator.TriggerEventMessage($"[+] Loaded {info.BaseName} at 0x{info.DllBase:X}.", LogFlags.General);

                var existing = WinHelper.WinModules.FirstOrDefault(m => m != null && m.MappedBase == info.DllBase);
                if (existing == null)
                {
                    WinModule MappedView = WinHelper.FindMappedImageViewByAddress(info.DllBase);
                    if (MappedView != null && MappedView.MappedBase == info.DllBase)
                        existing = MappedView;
                }

                if (existing == null)
                {
                    existing = new WinModule
                    {
                        Architecture = Emulator._binary.Architecture,
                        MappedBase = info.DllBase,
                        SizeOfImage = info.SizeOfImage,
                        Name = info.BaseName,
                        Path = string.IsNullOrEmpty(info.FullName) ? null : info.FullName,
                        Initialized = true
                    };
                }
                else
                {
                    existing.SizeOfImage = info.SizeOfImage;
                    existing.Name = info.BaseName;
                    if (!string.IsNullOrEmpty(info.FullName))
                        existing.Path = info.FullName;
                    existing.Initialized = true;
                }

                existing.IsSectionView = false;
                existing.CanonicalImagePath = WinHelper.CanonicalizeImagePath(!string.IsNullOrEmpty(existing.Path) ? existing.Path : existing.Name);
                if (existing.ImageSectionId == 0 && !string.IsNullOrEmpty(existing.CanonicalImagePath))
                    WinHelper.AttachImageSectionIdentity(existing, existing.CanonicalImagePath);

                if (!WinHelper.WinModules.Any(m => m != null && m.MappedBase == existing.MappedBase))
                    WinHelper.WinModules.Add(existing);
            }

            foreach (var kv in LastSnapshot)
            {
                if (Snapshot.ContainsKey(kv.Key))
                    continue;

                var info = kv.Value;
                Emulator.TriggerEventMessage($"[-] Unloaded {info.BaseName} at 0x{info.DllBase:X}.", LogFlags.General);

                var existing = WinHelper.WinModules.FirstOrDefault(m => m != null && m.MappedBase == info.DllBase);
                if (existing != null)
                    existing.Initialized = false;
            }

            LastSnapshot.Clear();
            foreach (var kv in Snapshot)
                LastSnapshot[kv.Key] = kv.Value;

            return true;
        }

        private bool TryReadSnapshot(out Dictionary<ulong, ModuleInfo> Snapshot)
        {
            Snapshot = new Dictionary<ulong, ModuleInfo>();

            ulong LdrData = SafeReadUlong(Emulator.PEB + (ulong)PebOffsetLdr);
            if (LdrData == 0)
                return false;

            ulong Head = LdrData + (ulong)PebLdrOffsetInLoadOrder;
            if (!Emulator.IsRegionMapped(Head, 0x10))
                return false;

            ulong Cursor = SafeReadUlong(Head + (ulong)ListEntryOffsetFlink);
            if (Cursor == 0)
                return false;

            int Guard = 0;
            while (Cursor != Head && Cursor != 0 && Guard++ < 2048)
            {
                ulong Entry = Cursor - (ulong)LdrEntryOffsetInLoadOrderLinks;

                if (!Emulator.IsRegionMapped(Entry, 0x80))
                    return false;

                ulong DllBase = SafeReadUlong(Entry + (ulong)LdrEntryOffsetDllBase);
                uint SizeOfImage = SafeReadUInt(Entry + (ulong)LdrEntryOffsetSizeOfImage);

                if (!TryReadUnicodeString(Entry + (ulong)LdrEntryOffsetBaseDllName, out string BaseName))
                    return false;

                TryReadUnicodeString(Entry + (ulong)LdrEntryOffsetFullDllName, out string FullName);

                if (DllBase != 0 && SizeOfImage != 0 && !string.IsNullOrEmpty(BaseName))
                {
                    BaseName = BaseName.TrimEnd('\0');
                    FullName = FullName?.TrimEnd('\0');

                    Snapshot[DllBase] = new ModuleInfo
                    {
                        DllBase = DllBase,
                        SizeOfImage = SizeOfImage,
                        BaseName = BaseName,
                        FullName = FullName
                    };
                }

                Cursor = SafeReadUlong(Cursor + (ulong)ListEntryOffsetFlink);
            }

            return true;
        }

        private bool TryReadUnicodeString(ulong unicodeStringAddress, out string Value)
        {
            Value = null;

            try
            {
                if (!Emulator.IsRegionMapped(unicodeStringAddress, (uint)UnicodeStringSize))
                    return false;

                ushort Length = Emulator._emulator.ReadMemoryUShort(unicodeStringAddress + (ulong)UnicodeStringOffsetLength);
                ulong Buffer = Emulator.ReadMemoryULong(unicodeStringAddress + (ulong)UnicodeStringOffsetBuffer);

                if (Length == 0 || Buffer == 0)
                {
                    Value = string.Empty;
                    return true;
                }

                if ((Length & 1) != 0)
                    return false;

                if (Length > MaxUnicodeStringBytes)
                    return false;

                if (!Emulator.IsRegionMapped(Buffer, Length))
                    return false;

                byte[] Data = Emulator.ReadMemory(Buffer, Length);
                Value = Encoding.Unicode.GetString(Data);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private ulong SafeReadUlong(ulong address)
        {
            try
            {
                if (address == 0 || !Emulator.IsRegionMapped(address, 8))
                    return 0;
                return Emulator.ReadMemoryULong(address);
            }
            catch
            {
                return 0;
            }
        }

        private uint SafeReadUInt(ulong address)
        {
            try
            {
                if (address == 0 || !Emulator.IsRegionMapped(address, 4))
                    return 0;
                return Emulator.ReadMemoryUInt(address);
            }
            catch
            {
                return 0;
            }
        }
    }
}
