using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

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

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct UserSharedDisplayInfo
    {
        [FieldOffset(0x00)]
        public uint Type;

        [FieldOffset(0x08)]
        public ulong PrimaryMonitor;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct UserPrimaryMonitorInfo
    {
        public const int Size = 0x40;

        [FieldOffset(0x00)]
        public ulong Header;

        [FieldOffset(0x08)]
        public ulong Reserved1;

        [FieldOffset(0x10)]
        public ulong Reserved2;

        [FieldOffset(0x18)]
        public uint Padding18;

        [FieldOffset(0x1C)]
        public int MonitorLeft;

        [FieldOffset(0x20)]
        public int MonitorTop;

        [FieldOffset(0x24)]
        public int MonitorRight;

        [FieldOffset(0x28)]
        public int MonitorBottom;

        [FieldOffset(0x2C)]
        public int WorkLeft;

        [FieldOffset(0x30)]
        public int WorkTop;

        [FieldOffset(0x34)]
        public int WorkRight;

        [FieldOffset(0x38)]
        public int WorkBottom;

        [FieldOffset(0x3C)]
        public ushort DpiX;

        [FieldOffset(0x3E)]
        public ushort DpiY;
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
        STATUS_NOT_A_REPARSE_POINT = 0xC0000275,
        STATUS_PROCESS_IN_JOB = 0x00000124,
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

    public enum JOBOBJECTINFOCLASS : uint
    {
        JobObjectBasicAccountingInformation = 1,
        JobObjectBasicLimitInformation = 2,
        JobObjectBasicProcessIdList = 3,
        JobObjectBasicUIRestrictions = 4,
        JobObjectEndOfJobTimeInformation = 6,
        JobObjectAssociateCompletionPortInformation = 7,
        JobObjectBasicAndIoAccountingInformation = 8,
        JobObjectExtendedLimitInformation = 9,
        JobObjectGroupInformation = 11,
        JobObjectNotificationLimitInformation = 12,
        JobObjectLimitViolationInformation = 13,
        JobObjectGroupInformationEx = 14,
        JobObjectCpuRateControlInformation = 15,
        JobObjectNetRateControlInformation = 32,
        JobObjectNotificationLimitInformation2 = 33,
        JobObjectLimitViolationInformation2 = 34,
        JobObjectReserved1Information = 35
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
        TimerQueryState = 0x00000001,
        TimerModifyState = 0x00000002,
        TimerAllAccess = StandardRightsRequired | Synchronize | TimerQueryState | TimerModifyState,
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
        SemaphoreHandle = 15,
        JobHandle = 16
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

    public enum TIMER_TYPE
    {
        NotificationTimer = 0,
        SynchronizationTimer = 1,
    }

    public enum TIMER_SET_INFORMATION_CLASS
    {
        TimerSetCoalescableTimer = 0,
        MaxTimerInfoClass = 1,
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
        public ulong JobObjectHandle;

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
        public ulong WorkerFactoryHandle;
        public bool WorkerFactoryRelease;
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
        public uint PendingReleaseCount;
        public bool ReleasePending;
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

        internal static bool EnqueueReleaseCompletion(BinaryEmulator Instance, ulong WorkerFactoryHandle)
        {
            if (Instance == null || WorkerFactoryHandle == 0)
                return false;

            WinWorkerFactory Factory = GetFactory(Instance, WorkerFactoryHandle);
            if (Factory == null)
                return false;

            WinIoCompletion Completion = GetIoCompletion(Instance, Factory.IoCompletionHandle);
            if (Completion == null)
                return false;

            Completion.Entries.Enqueue(new WinIoCompletionEntry
            {
                IoStatus = NTSTATUS.STATUS_SUCCESS,
                IoStatusInformation = 0,
                WorkerFactoryHandle = WorkerFactoryHandle,
                WorkerFactoryRelease = true
            });

            return true;
        }

        internal static void OnIoCompletionEntryDequeued(BinaryEmulator Instance, WinIoCompletionEntry Entry)
        {
            if (Instance == null || Entry == null || !Entry.WorkerFactoryRelease)
                return;

            WinWorkerFactory Factory = GetFactory(Instance, Entry.WorkerFactoryHandle);
            if (Factory == null)
                return;

            if (Factory.PendingReleaseCount > 0)
                Factory.PendingReleaseCount--;

            if (Factory.Shutdown || Factory.PendingReleaseCount == 0)
            {
                Factory.ReleasePending = false;
                return;
            }

            EnqueueReleaseCompletion(Instance, Entry.WorkerFactoryHandle);
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
            if (Factory.ReleasePending || Factory.PendingReleaseCount != 0)
                Desired = Math.Max(Desired, 1u);
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
                Instance.WinHelper.AddWinHandle(Handle);
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
        public TIMER_TYPE TimerType = TIMER_TYPE.SynchronizationTimer;
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

    public sealed class WinJob : IHandleObject
    {
        public string Name;
        public bool IsTerminated;
        public List<uint> ProcessIds = new List<uint>();

        public ulong PerProcessUserTimeLimit;
        public ulong PerJobUserTimeLimit;
        public uint LimitFlags;
        public ulong MinimumWorkingSetSize;
        public ulong MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public ulong Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;

        public uint UiRestrictionsClass;
        public uint EndOfJobTimeAction;

        public ulong CompletionPort;
        public ulong CompletionKey;

        public ulong ProcessMemoryLimit;
        public ulong JobMemoryLimit;
        public ulong PeakProcessMemoryUsed;
        public ulong PeakJobMemoryUsed;

        public ulong IoReadBytesLimit;
        public ulong IoWriteBytesLimit;
        public ulong NotificationPerJobUserTimeLimit;
        public ulong NotificationJobMemoryLimit;
        public uint NotificationRateControlTolerance;
        public uint NotificationRateControlToleranceInterval;
        public uint NotificationLimitFlags;

        public uint CpuRateControlFlags;
        public uint CpuRateControlValue;
        public uint CpuRateControlWeight;
        public ushort CpuRateControlMinRate;
        public ushort CpuRateControlMaxRate;

        public ulong NetRateControlMaxBandwidth;
        public uint NetRateControlFlags;
        public byte NetRateControlDscpTag;

        public string ObjectId => Name;
        public HandleType ObjectType => HandleType.JobHandle;
    }
}
