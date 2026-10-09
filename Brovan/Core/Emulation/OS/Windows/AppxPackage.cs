using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // NT: PackageOrigin.
    internal enum AppxPackageOrigin : uint
    {
        Unknown = 0,
        Unsigned = 1,
        Inbox = 2,
        Store = 3,
        DeveloperUnsigned = 4,
        DeveloperSigned = 5,
        LineOfBusiness = 6,
    }

    internal sealed class AppxApplication
    {
        public string Id;
        public string Executable;
        public string EntryPoint;
        public string TrustLevel;
        public string DisplayName;
        public string Description;
        public string Square150x150Logo;
        public string Square44x44Logo;
        public string ForegroundText;
        public string BackgroundColor;
        public bool SupportsMultipleInstances;

        public bool IsFullTrust =>
            string.Equals(EntryPoint, "Windows.FullTrustApplication", StringComparison.OrdinalIgnoreCase)
            || string.Equals(TrustLevel, "mediumIL", StringComparison.OrdinalIgnoreCase);
    }

    internal struct AppxDependency
    {
        public string Name;
        public string Publisher;
        public ulong MinVersion;
    }

    internal sealed class AppxPackage
    {
        public string Name;
        public string Publisher;
        public string PublisherId;
        public string ResourceId = string.Empty;
        public ulong Version;
        public string ArchitectureName = "neutral";
        public ushort Architecture = AppxPackageModel.ArchitectureNeutral;
        public string FullName;
        public string FamilyName;
        public string InstallPath;
        public string SourceBundle;
        public bool IsFramework;
        public bool IsResource;
        public AppxPackageOrigin Origin;
        public uint TargetPlatform;
        public ulong MinVersion;
        public ulong MaxVersionTested;
        public string DisplayName;
        public string PublisherDisplayName;
        public string Description;
        public string Logo;
        public readonly List<AppxApplication> Applications = new();
        public readonly List<string> Capabilities = new();
        public readonly List<AppxDependency> Dependencies = new();
    }

    internal sealed class AppxProcessIdentity
    {
        public AppxPackage Package;
        public AppxApplication Application;
        public List<AppxPackage> Graph;
        public bool IsAppContainer;
        public byte[] AppContainerSid;
        public byte[][] CapabilitySids;
        public string LoaderSearchPath;
        public byte[] DependencyMiniRepository;
        public WinTokenSecurityAttribute[] SecurityAttributes;
    }

    internal static class AppxPackageModel
    {
        internal const string ManifestName = "AppxManifest.xml";
        internal const string BundleManifestName = "AppxBundleManifest.xml";
        internal const string SignatureName = "AppxSignature.p7x";
        internal const string PackageStore = "C:\\Program Files\\WindowsApps";
        private const string AppxRoot = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx";
        private const string AppxAllUserStore = AppxRoot + "\\AppxAllUserStore";
        private const string WindowsDirectoryPrefix = "C:\\Windows\\";
        private const string BundleResourceId = "~";

        // NT: PROCESSOR_ARCHITECTURE_*.
        internal const ushort ArchitectureIntel = 0;
        internal const ushort ArchitectureArm = 5;
        internal const ushort ArchitectureAmd64 = 9;
        internal const ushort ArchitectureNeutral = 11;
        internal const ushort ArchitectureArm64 = 12;

        // NT: PACKAGE_PROPERTY_* and PACKAGE_FILTER_*.
        private const uint PackageFramework = 0x1;
        private const uint PackageResource = 0x2;
        private const uint PackageHead = 0x10;
        private const uint PackageDirect = 0x20;
        private const uint PackageOriginBase = 0x40;

        // NT: PSM_ACTIVATION_TOKEN_* claims in WIN://PKG.
        private const ulong ClaimPackagedApplication = 0x1;
        private const ulong ClaimFullTrust = 0x4;
        private const ulong ClaimAppContainer = 0x10;
        private const ulong PackageHostIdBase = 0x1000000000000000;

        private const uint TargetPlatformUniversal = 0;
        private const uint TargetPlatformDesktop = 3;

        private const int MaxManifestBytes = 0x400000;
        private const int MaxManifestSearchDepth = 8;
        private const int MaxDependencies = 128;
        private const int MaxApplications = 100;
        private const int MaxCapabilities = 1000;
        // NT: dependency graph section limit.
        private const int MaxGraphNodes = 640;
        private const int MaxInstalledPackages = 0x10000;
        private const int MaxRecordKeys = 0x4000;
        private const int MaxSignatureBytes = 0x100000;

        // NT: the State Repository service fills this volatile tree when it starts.
        private const string StateRepositoryCache = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache";

        // NT: the State Repository PackageType column.
        private const uint RepositoryMain = 0x1;
        private const uint RepositoryFramework = 0x2;
        private const uint RepositoryResource = 0x4;

        // NT: Package.Flags and Package.Flags2.
        private const uint RepositoryRegistered = 0x8;
        private const uint RepositoryFamilyHead = 0x400;
        private const uint RepositoryElevatedInstall = 0x800;
        private const uint RepositoryMachineRegistration = 0x1000;

        // NT: PackageUser.Flags and DeploymentState.
        private const uint PackageUserExplicit = 0x1;
        private const uint DeploymentStateRegistered = 2;

        private const uint DependencyFramework = 1;
        private const uint DependencyResource = 2;
        private const uint SystemVolume = 1;
        private const ulong GuestUserId = 1;

        // NT: a subset of CacheManagement::_Initialize_Structure.
        private static readonly (string Table, string[] Indexes)[] StateRepositoryTables =
        {
            ("User", new[] { "UserSid" }),
            ("PackageFamily", new[] { "PackageFamilyName", "PackageSID" }),
            ("Package", new[] { "PackageFamily", "PackageFullName" }),
            ("PackageUser", new[] { "User", "UserAndPackage" }),
            ("PackageFamilyUser", new[] { "PackageFamily", "User", "UserAndPackageFamily" }),
            ("DependencyGraph", new[] { "UserAndDependentPackageAndDependencyType" }),
            ("PackageExternalLocation", new[] { "UserAndPackage" }),
        };

        private const string PublisherIdAlphabet = "0123456789abcdefghjkmnpqrstvwxyz";
        private const string StoreSigningEku = "1.3.6.1.4.1.311.76.3.1";
        private const string ExtendedKeyUsageOid = "2.5.29.37";

        // NT: the capabilities with a SECURITY_CAPABILITY_* RID of their own.
        private static readonly string[] WellKnownCapabilities =
        {
            "internetClient", "internetClientServer", "privateNetworkClientServer", "picturesLibrary",
            "videosLibrary", "musicLibrary", "documentsLibrary", "enterpriseAuthentication",
            "sharedUserCertificates", "removableStorage", "appointments", "contacts",
        };

        // NT: the dependency mini repository security section carries only these, in this order.
        private static readonly string[] SecurityContextCapabilities =
        {
            "internetClient", "internetClientServer", "privateNetworkClientServer", "documentsLibrary",
            "picturesLibrary", "videosLibrary", "musicLibrary", "enterpriseAuthentication",
            "sharedUserCertificates", "removableStorage",
        };

        private static long PackageHostSequence;

        internal static AppxProcessIdentity TryCreate(BinaryEmulator Instance, WinSysHelper Helper, string GuestImagePath)
        {
            if (string.IsNullOrEmpty(GuestImagePath))
                return null;

            string ImagePath = GuestImagePath.Replace('/', '\\');
            string PackageRoot = GeneralHelper.IO.GetWindowsDirectoryName(ImagePath);
            AppxPackage Package = null;
            AppxApplication Application = null;

            for (int Depth = 0; Depth < MaxManifestSearchDepth && !string.IsNullOrEmpty(PackageRoot); Depth++)
            {
                string ManifestPath = CombineWindowsPath(PackageRoot, ManifestName);
                if (TryReadHostFile(ManifestPath, MaxManifestBytes, out byte[] Manifest))
                {
                    Package = ParseManifest(Instance, Manifest, ManifestPath);
                    if (Package == null)
                        return null;

                    string Relative = ImagePath.Substring(PackageRoot.TrimEnd('\\').Length).TrimStart('\\');
                    Application = Package.Applications.Find(App =>
                        string.Equals(App.Executable?.Replace('/', '\\'), Relative, StringComparison.OrdinalIgnoreCase));
                    break;
                }

                string Parent = GeneralHelper.IO.GetWindowsDirectoryName(PackageRoot.TrimEnd('\\'));
                if (string.IsNullOrEmpty(Parent) || string.Equals(Parent, PackageRoot, StringComparison.OrdinalIgnoreCase))
                    break;

                PackageRoot = Parent;
            }

            if (Package == null)
                return null;

            if (Application == null)
            {
                Instance.TriggerEventMessage($"[-] AppX: {Package.FullName} declares no application for \"{ImagePath}\", running without package identity.", LogFlags.Issues);
                return null;
            }

            if (Package.IsFramework || Package.IsResource)
            {
                Instance.TriggerEventMessage($"[-] AppX: {Package.FullName} is not a main package.", LogFlags.Issues);
                return null;
            }

            List<InstalledPackage> Installed = EnumerateInstalledPackages(Helper);
            Package.InstallPath = PackageRoot.TrimEnd('\\');
            Package.Origin = DetermineOrigin(Instance, Package.InstallPath);

            string ProcessArchitecture = Instance._binary.Architecture == BinaryArchitecture.x64 ? "x64" : "x86";
            List<AppxPackage> Graph = ResolveGraph(Instance, Package, ProcessArchitecture, Installed);
            if (Graph == null)
                return null;

            AppxProcessIdentity Identity = new AppxProcessIdentity
            {
                Package = Package,
                Application = Application,
                Graph = Graph,
                IsAppContainer = !Application.IsFullTrust,
                AppContainerSid = DeriveAppContainerSid(Package.FamilyName),
            };

            List<uint> Flags = new List<uint>(Graph.Count);
            for (int Index = 0; Index < Graph.Count; Index++)
                Flags.Add(GetGraphFlags(Graph[Index], Index == 0));

            Identity.LoaderSearchPath = BuildLoaderSearchPath(Graph, Flags, Graph.Count);
            Identity.CapabilitySids = Identity.IsAppContainer ? BuildCapabilitySids(Package, Identity.AppContainerSid) : Array.Empty<byte[]>();
            Identity.SecurityAttributes = BuildSecurityAttributes(Package, Application, Identity.IsAppContainer);
            Identity.DependencyMiniRepository = BuildDependencyMiniRepository(Identity, Flags);

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] AppX: {Package.FamilyName}!{Application.Id}, {Graph.Count} package(s) in the graph, {(Identity.IsAppContainer ? "AppContainer" : "full trust")}, origin {Package.Origin}.", LogFlags.General);

            return Identity;
        }

        internal static void PublishRegistration(BinaryEmulator Instance, WinSysHelper Helper, AppxProcessIdentity Identity)
        {
            PublishStateRepositoryCache(Helper, Identity);
            PublishUserDependencyMiniRepository(Instance, Helper, Identity);
        }

        // NT: OpenPackageInfoByFullName reads this file.
        private static void PublishUserDependencyMiniRepository(BinaryEmulator Instance, WinSysHelper Helper, AppxProcessIdentity Identity)
        {
            WinRegKey Appx = Helper.ResolveRegistryKey(AppxRoot);
            if (Appx == null || !Helper.TryGetRegistryValue(Appx, "PackageRepositoryRoot", out ValueNode Root) || Root.Data == null)
            {
                Instance.TriggerEventMessage("[-] AppX: PackageRepositoryRoot is not set, the package has no dependency mini repository for the user.", LogFlags.Issues);
                return;
            }

            string Repository = Encoding.Unicode.GetString(Root.Data).TrimEnd('\0').TrimEnd('\\');
            string GuestPath = $"{Repository}\\Packages\\{Identity.Package.FullName}\\{Helper.CurrentUserSid}.pckgdep";

            try
            {
                using WindowsFileStream Store = WindowsFileStream.FromGuestPath(GuestPath, CreateWriteDirectories: true);
                if (Store.TryReadAllBytes(out byte[] Existing) && Existing.AsSpan().SequenceEqual(Identity.DependencyMiniRepository))
                    return;

                Store.WriteAllBytes(Identity.DependencyMiniRepository);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[-] AppX: {GuestPath} cannot be written: {Error.Message}");
            }
        }

        private static void PublishStateRepositoryCache(WinSysHelper Helper, AppxProcessIdentity Identity)
        {
            bool Written = true;
            foreach ((string Table, string[] Indexes) in StateRepositoryTables)
            {
                Written &= CreateCacheKey(Helper, Table + "\\Data");
                foreach (string Index in Indexes)
                    Written &= CreateCacheKey(Helper, Table + "\\Index\\" + Index);
            }

            string UserSid = Helper.CurrentUserSid;
            string UserKey = FormatCacheId(GuestUserId);
            string UserRow = "User\\Data\\" + UserKey;
            Written &= CreateCacheKey(Helper, UserRow);
            Written &= SetCacheString(Helper, UserRow, "UserSid", UserSid);
            Written &= AddCacheIndex(Helper, "User\\Index\\UserSid\\" + EscapeCacheKey(UserSid), UserKey);

            List<AppxPackage> Graph = Identity.Graph;
            Dictionary<string, ulong> Families = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, ulong> Bundles = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
            string MainKey = FormatCacheId(1);

            for (int Index = 0; Index < Graph.Count; Index++)
            {
                AppxPackage Package = Graph[Index];
                string PackageKey = FormatCacheId((ulong)Index + 1);

                if (!Families.TryGetValue(Package.FamilyName, out ulong FamilyId))
                {
                    FamilyId = (ulong)Families.Count + 1;
                    Families[Package.FamilyName] = FamilyId;

                    string NewFamilyKey = FormatCacheId(FamilyId);
                    string PackageSid = FormatSid(DeriveAppContainerSid(Package.FamilyName));
                    string FamilyRow = "PackageFamily\\Data\\" + NewFamilyKey;
                    Written &= CreateCacheKey(Helper, FamilyRow);
                    Written &= SetCacheString(Helper, FamilyRow, "PackageFamilyName", Package.FamilyName);
                    Written &= SetCacheString(Helper, FamilyRow, "PackageSID", PackageSid);
                    Written &= SetCacheString(Helper, FamilyRow, "Publisher", Package.Publisher);
                    Written &= AddCacheIndex(Helper, "PackageFamily\\Index\\PackageFamilyName\\" + EscapeCacheKey(Package.FamilyName), NewFamilyKey);
                    Written &= AddCacheIndex(Helper, "PackageFamily\\Index\\PackageSID\\" + EscapeCacheKey(PackageSid), NewFamilyKey);

                    string FamilyUserRow = "PackageFamilyUser\\Data\\" + NewFamilyKey;
                    Written &= CreateCacheKey(Helper, FamilyUserRow);
                    Written &= SetCacheDword(Helper, FamilyUserRow, "PackageFamily", (uint)FamilyId);
                    Written &= SetCacheDword(Helper, FamilyUserRow, "User", (uint)GuestUserId);
                    Written &= AddCacheIndex(Helper, "PackageFamilyUser\\Index\\PackageFamily\\" + NewFamilyKey, NewFamilyKey);
                    Written &= AddCacheIndex(Helper, "PackageFamilyUser\\Index\\User\\" + UserKey, NewFamilyKey);
                    Written &= AddCacheIndex(Helper, "PackageFamilyUser\\Index\\UserAndPackageFamily\\" + UserKey + "^" + NewFamilyKey, NewFamilyKey);
                }

                uint BundleId = 0;
                if (Package.SourceBundle != null)
                {
                    if (!Bundles.TryGetValue(Package.SourceBundle, out ulong Bundle))
                    {
                        Bundle = (ulong)Bundles.Count + 1;
                        Bundles[Package.SourceBundle] = Bundle;
                    }

                    BundleId = (uint)Bundle;
                }

                uint Type = Package.IsFramework ? RepositoryFramework : Package.IsResource ? RepositoryResource : RepositoryMain;
                uint Flags = RepositoryRegistered | (Type == RepositoryMain && BundleId == 0 ? RepositoryFamilyHead : 0);
                uint Flags2 = Package.Origin == AppxPackageOrigin.Inbox ? RepositoryElevatedInstall | RepositoryMachineRegistration
                    : Package.Origin == AppxPackageOrigin.Store ? RepositoryElevatedInstall : 0;

                string FamilyKey = FormatCacheId(FamilyId);
                string PackageRow = "Package\\Data\\" + PackageKey;
                Written &= CreateCacheKey(Helper, PackageRow);
                Written &= SetCacheString(Helper, PackageRow, "PackageFullName", Package.FullName);
                Written &= SetCacheDword(Helper, PackageRow, "PackageFamily", (uint)FamilyId);
                Written &= SetCacheDword(Helper, PackageRow, "PackageType", Type);
                Written &= SetCacheDword(Helper, PackageRow, "Flags", Flags);
                Written &= SetCacheDword(Helper, PackageRow, "Flags2", Flags2);
                Written &= SetCacheDword(Helper, PackageRow, "PackageOrigin", (uint)Package.Origin);
                Written &= SetCacheDword(Helper, PackageRow, "Volume", SystemVolume);
                Written &= SetCacheQword(Helper, PackageRow, "OSMaxVersionTested", Package.MaxVersionTested);
                Written &= SetCacheString(Helper, PackageRow, "InstalledLocation", Package.InstallPath);
                Written &= SetCacheString(Helper, PackageRow, "MutableLink", null);
                Written &= SetCacheString(Helper, PackageRow, "MutableLocation", null);
                Written &= SetCacheDword(Helper, PackageRow, "TargetDeviceFamilyName", Package.TargetPlatform);
                Written &= SetCacheString(Helper, PackageRow, "DisplayName", Package.DisplayName);
                Written &= SetCacheDword(Helper, PackageRow, "SourceBundle", BundleId);
                Written &= AddCacheIndex(Helper, "Package\\Index\\PackageFamily\\" + FamilyKey, PackageKey);
                Written &= AddCacheIndex(Helper, "Package\\Index\\PackageFullName\\" + EscapeCacheKey(Package.FullName), PackageKey);

                bool Explicit = Package.Origin != AppxPackageOrigin.Inbox && !Package.IsResource;
                string PackageUserRow = "PackageUser\\Data\\" + PackageKey;
                Written &= CreateCacheKey(Helper, PackageUserRow);
                Written &= SetCacheDword(Helper, PackageUserRow, "Package", (uint)Index + 1);
                Written &= SetCacheDword(Helper, PackageUserRow, "User", (uint)GuestUserId);
                Written &= SetCacheQword(Helper, PackageUserRow, "InstallTime", GetInstallTime(Package.InstallPath));
                Written &= SetCacheDword(Helper, PackageUserRow, "Flags", Explicit ? PackageUserExplicit : 0);
                Written &= SetCacheDword(Helper, PackageUserRow, "DeploymentState", DeploymentStateRegistered);
                Written &= AddCacheIndex(Helper, "PackageUser\\Index\\User\\" + UserKey, PackageKey);
                Written &= AddCacheIndex(Helper, "PackageUser\\Index\\UserAndPackage\\" + UserKey + "^" + PackageKey, PackageKey);

                if (Index == 0)
                    continue;

                string DependencyKey = FormatCacheId((ulong)Index);
                uint DependencyType = Package.IsResource ? DependencyResource : DependencyFramework;
                string DependencyRow = "DependencyGraph\\Data\\" + DependencyKey;
                Written &= CreateCacheKey(Helper, DependencyRow);
                Written &= SetCacheDword(Helper, DependencyRow, "User", (uint)GuestUserId);
                Written &= SetCacheDword(Helper, DependencyRow, "SupplierPackage", (uint)Index + 1);
                Written &= SetCacheDword(Helper, DependencyRow, "Index", (uint)Index - 1);
                Written &= AddCacheIndex(Helper, "DependencyGraph\\Index\\UserAndDependentPackageAndDependencyType\\" + UserKey + "^" + MainKey + "^" + FormatCacheId(DependencyType), DependencyKey);
            }

            Written &= CreateCacheKey(Helper, "Metadata");
            Written &= Helper.SetRegistryValue(StateRepositoryCache + "\\Metadata", "Revision", WinSysHelper.RegDword, BitConverter.GetBytes(1u));
            Written &= Helper.SetRegistryValue(StateRepositoryCache + "\\Metadata", "LastChangeId", WinSysHelper.RegQword, BitConverter.GetBytes(0ul));

            if (!Written)
                Utils.LogError($"[-] AppX: the State Repository cache for {Identity.Package.FullName} could not be written completely.");
        }

        private static bool CreateCacheKey(WinSysHelper Helper, string RelativePath)
        {
            return Helper.CreateRegistryKeyPath(StateRepositoryCache + "\\" + RelativePath, true, out _);
        }

        private static bool AddCacheIndex(WinSysHelper Helper, string IndexPath, string RowKey)
        {
            return CreateCacheKey(Helper, IndexPath + "\\" + RowKey);
        }

        private static bool SetCacheString(WinSysHelper Helper, string RowPath, string Name, string Value)
        {
            byte[] Data = Value == null ? Array.Empty<byte>() : Encoding.Unicode.GetBytes(Value + "\0");
            return Helper.SetRegistryValue(StateRepositoryCache + "\\" + RowPath, Name, Value == null ? WinSysHelper.RegNone : WinSysHelper.RegSz, Data);
        }

        private static bool SetCacheDword(WinSysHelper Helper, string RowPath, string Name, uint Value)
        {
            return Helper.SetRegistryValue(StateRepositoryCache + "\\" + RowPath, Name, WinSysHelper.RegDword, BitConverter.GetBytes(Value));
        }

        private static bool SetCacheQword(WinSysHelper Helper, string RowPath, string Name, ulong Value)
        {
            return Helper.SetRegistryValue(StateRepositoryCache + "\\" + RowPath, Name, WinSysHelper.RegQword, BitConverter.GetBytes(Value));
        }

        private static string FormatCacheId(ulong Id)
        {
            return Id.ToString("x");
        }

        // NT: '^' separates the parts of a composite key.
        private static string EscapeCacheKey(string Value)
        {
            return Value.Replace("^", "^^", StringComparison.Ordinal);
        }

        // The folder creation time stands in for the NT registration time.
        private static ulong GetInstallTime(string GuestDirectory)
        {
            string HostPath = GeneralHelper.IO.ResolveHostPath(GuestDirectory, BinaryFormat.PE);
            if (string.IsNullOrEmpty(HostPath))
                return 0;

            try
            {
                return Directory.Exists(HostPath) ? (ulong)Directory.GetCreationTimeUtc(HostPath).ToFileTimeUtc() : 0;
            }
            catch (IOException)
            {
                return 0;
            }
            catch (UnauthorizedAccessException)
            {
                return 0;
            }
        }

        internal static string FormatSid(byte[] Sid)
        {
            ulong Authority = 0;
            for (int Index = 2; Index < 8; Index++)
                Authority = (Authority << 8) | Sid[Index];

            StringBuilder Builder = new StringBuilder("S-").Append(Sid[0]).Append('-').Append(Authority);
            for (int Index = 0; Index < Sid[1]; Index++)
                Builder.Append('-').Append(BinaryPrimitives.ReadUInt32LittleEndian(Sid.AsSpan(8 + Index * 4, 4)));

            return Builder.ToString();
        }

        private struct InstalledPackage
        {
            public string FullName;
            public string Name;
            public ulong Version;
            public string Architecture;
            public string ResourceId;
            public string PublisherId;
            public string ManifestPath;
            public string BundleManifestPath;
            public string SourceBundle;
        }

        private static List<AppxPackage> ResolveGraph(BinaryEmulator Instance, AppxPackage Package, string ProcessArchitecture, List<InstalledPackage> Installed)
        {
            List<AppxPackage> Graph = new List<AppxPackage> { Package };

            foreach (AppxDependency Dependency in Package.Dependencies)
            {
                string PublisherId = DerivePublisherId(Dependency.Publisher);
                int Best = -1;
                bool BestExact = false;

                for (int Index = 0; Index < Installed.Count; Index++)
                {
                    InstalledPackage Candidate = Installed[Index];
                    if (!string.Equals(Candidate.Name, Dependency.Name, StringComparison.OrdinalIgnoreCase)
                        || !string.Equals(Candidate.PublisherId, PublisherId, StringComparison.OrdinalIgnoreCase)
                        || Candidate.ResourceId.Length != 0
                        || Candidate.Version < Dependency.MinVersion)
                    {
                        continue;
                    }

                    bool Exact = string.Equals(Candidate.Architecture, ProcessArchitecture, StringComparison.OrdinalIgnoreCase);
                    if (!Exact && !string.Equals(Candidate.Architecture, "neutral", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (Best < 0 || (Exact && !BestExact) || (Exact == BestExact && Candidate.Version > Installed[Best].Version))
                    {
                        Best = Index;
                        BestExact = Exact;
                    }
                }

                AppxPackage Resolved = Best >= 0 ? LoadInstalledPackage(Instance, Installed[Best]) : null;
                if (Resolved == null)
                {
                    Instance.TriggerEventMessage($"[-] AppX: {Package.FullName} depends on {Dependency.Name}_{PublisherId}, which is not installed.", LogFlags.Issues);
                    return null;
                }

                Graph.Add(Resolved);
            }

            AddBundleResources(Instance, Package, Installed);

            List<InstalledPackage> Resources = new();
            foreach (InstalledPackage Candidate in Installed)
            {
                if (Candidate.ResourceId.Length != 0
                    && Candidate.ResourceId != BundleResourceId
                    && Candidate.Version == Package.Version
                    && string.Equals(Candidate.Name, Package.Name, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(Candidate.PublisherId, Package.PublisherId, StringComparison.OrdinalIgnoreCase))
                {
                    Resources.Add(Candidate);
                }
            }

            Resources.Sort((A, B) => string.Compare(A.ResourceId, B.ResourceId, StringComparison.OrdinalIgnoreCase));
            foreach (InstalledPackage Resource in Resources)
            {
                AppxPackage Loaded = LoadInstalledPackage(Instance, Resource);
                if (Loaded != null && Loaded.IsResource)
                    Graph.Add(Loaded);
            }

            if (Graph.Count > MaxGraphNodes)
            {
                Instance.TriggerEventMessage($"[-] AppX: {Package.FullName} has {Graph.Count} packages in its graph.", LogFlags.Issues);
                return null;
            }

            return Graph;
        }

        // A store folder with no AppxAllUserStore record counts as a development registration.
        private static List<InstalledPackage> EnumerateInstalledPackages(WinSysHelper Helper)
        {
            Dictionary<string, InstalledPackage> Packages = new Dictionary<string, InstalledPackage>(StringComparer.OrdinalIgnoreCase);
            WinRegKey Store = Helper.ResolveRegistryKey(AppxAllUserStore);

            for (int Position = 0; Store != null && Position < MaxRecordKeys && Helper.TryEnumerateRegistrySubKey(Store, Position, out string Section); Position++)
            {
                string SectionPath = AppxAllUserStore + "\\" + Section;
                bool Provisioned = string.Equals(Section, "Applications", StringComparison.OrdinalIgnoreCase);
                bool Inbox = string.Equals(Section, "InboxApplications", StringComparison.OrdinalIgnoreCase);
                bool User = Section.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase);
                if (!Provisioned && !Inbox && !User)
                    continue;

                WinRegKey SectionKey = Helper.ResolveRegistryKey(SectionPath);
                for (int Entry = 0; SectionKey != null && Entry < MaxRecordKeys && Helper.TryEnumerateRegistrySubKey(SectionKey, Entry, out string FullName); Entry++)
                {
                    string EntryPath = SectionPath + "\\" + FullName;
                    AddRecord(Helper, Packages, FullName, EntryPath);

                    if (!Provisioned)
                        continue;

                    WinRegKey Components = Helper.ResolveRegistryKey(EntryPath);
                    for (int Child = 0; Components != null && Child < MaxRecordKeys && Helper.TryEnumerateRegistrySubKey(Components, Child, out string ComponentName); Child++)
                        AddRecord(Helper, Packages, ComponentName, EntryPath + "\\" + ComponentName);
                }
            }

            string HostStore = GeneralHelper.IO.ResolveHostPath(PackageStore, BinaryFormat.PE);
            if (!string.IsNullOrEmpty(HostStore))
            {
                try
                {
                    foreach (string Entry in Directory.EnumerateDirectories(HostStore))
                    {
                        if (Packages.Count >= MaxInstalledPackages)
                            break;

                        string Leaf = Path.GetFileName(Entry);
                        if (!Packages.ContainsKey(Leaf) && TryParseFullName(Leaf, null, out InstalledPackage Package))
                            Packages[Leaf] = Package;
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                    // NT: a standard user may open a package folder by name but not list the store.
                }
            }

            return new List<InstalledPackage>(Packages.Values);
        }

        private static void AddRecord(WinSysHelper Helper, Dictionary<string, InstalledPackage> Packages, string FullName, string KeyPath)
        {
            if (Packages.Count >= MaxInstalledPackages || Packages.ContainsKey(FullName))
                return;

            string ManifestPath = null;
            WinRegKey Key = Helper.ResolveRegistryKey(KeyPath);
            if (Key != null && Helper.TryGetRegistryValue(Key, "Path", out ValueNode PathValue) && PathValue.Data != null)
                ManifestPath = Encoding.Unicode.GetString(PathValue.Data).TrimEnd('\0');

            if (TryParseFullName(FullName, ManifestPath, out InstalledPackage Package))
                Packages[FullName] = Package;
        }

        private static bool TryParseFullName(string FullName, string? ManifestPath, out InstalledPackage Package)
        {
            Package = default;
            string[] Parts = FullName.Split('_');
            if (Parts.Length != 5 || !TryParseVersion(Parts[1], out ulong Version))
                return false;

            string BundleManifestPath = null;
            if (ManifestPath != null && ManifestPath.EndsWith("\\" + BundleManifestName, StringComparison.OrdinalIgnoreCase))
                BundleManifestPath = ManifestPath;

            if (string.IsNullOrEmpty(ManifestPath) || !ManifestPath.EndsWith("\\" + ManifestName, StringComparison.OrdinalIgnoreCase))
                ManifestPath = PackageStore + "\\" + FullName + "\\" + ManifestName;

            Package = new InstalledPackage
            {
                FullName = FullName,
                Name = Parts[0],
                Version = Version,
                Architecture = Parts[2],
                ResourceId = Parts[3],
                PublisherId = Parts[4],
                ManifestPath = ManifestPath,
                BundleManifestPath = BundleManifestPath,
            };
            return true;
        }

        // NT: a bundle manifest names its resource packages. An installed one has a folder in the package store.
        private static void AddBundleResources(BinaryEmulator Instance, AppxPackage Package, List<InstalledPackage> Installed)
        {
            Dictionary<string, int> Known = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            List<InstalledPackage> Bundles = new();
            for (int Index = 0; Index < Installed.Count; Index++)
            {
                InstalledPackage Candidate = Installed[Index];
                Known[Candidate.FullName] = Index;
                if (Candidate.BundleManifestPath != null
                    && string.Equals(Candidate.Name, Package.Name, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(Candidate.PublisherId, Package.PublisherId, StringComparison.OrdinalIgnoreCase))
                {
                    Bundles.Add(Candidate);
                }
            }

            foreach (InstalledPackage Bundle in Bundles)
            {
                if (!TryReadHostFile(Bundle.BundleManifestPath, MaxManifestBytes, out byte[] Manifest))
                    continue;

                try
                {
                    using XmlReader Reader = WinSxS.CreateManifestReader(Manifest);
                    while (Reader.Read() && Installed.Count < MaxInstalledPackages)
                    {
                        if (Reader.NodeType != XmlNodeType.Element || Reader.LocalName != "Package"
                            || !TryParseVersion(Reader.GetAttribute("Version"), out ulong Version) || Version != Package.Version)
                        {
                            continue;
                        }

                        string Type = Reader.GetAttribute("Type");
                        string Architecture = (Reader.GetAttribute("Architecture") ?? "neutral").ToLowerInvariant();
                        if (string.Equals(Type, "application", StringComparison.OrdinalIgnoreCase))
                        {
                            if (Architecture == Package.ArchitectureName)
                                Package.SourceBundle = Bundle.FullName;

                            continue;
                        }

                        string ResourceId = Reader.GetAttribute("ResourceId");
                        if (!string.Equals(Type, "resource", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(ResourceId))
                            continue;

                        string FullName = $"{Package.Name}_{FormatVersion(Version)}_{Architecture}_{ResourceId}_{Package.PublisherId}";
                        if (Known.TryGetValue(FullName, out int Existing))
                        {
                            InstalledPackage Listed = Installed[Existing];
                            Listed.SourceBundle = Bundle.FullName;
                            Installed[Existing] = Listed;
                        }
                        else if (TryParseFullName(FullName, null, out InstalledPackage Resource))
                        {
                            Resource.SourceBundle = Bundle.FullName;
                            Known[FullName] = Installed.Count;
                            Installed.Add(Resource);
                        }
                    }
                }
                catch (XmlException Error)
                {
                    Instance.TriggerEventMessage($"[-] AppX: {Bundle.BundleManifestPath} is not a valid bundle manifest: {Error.Message}", LogFlags.Issues);
                }
            }
        }

        private static AppxPackage LoadInstalledPackage(BinaryEmulator Instance, InstalledPackage Installed)
        {
            if (!TryReadHostFile(Installed.ManifestPath, MaxManifestBytes, out byte[] Manifest))
                return null;

            AppxPackage Package = ParseManifest(Instance, Manifest, Installed.ManifestPath);
            if (Package == null)
                return null;

            Package.InstallPath = GeneralHelper.IO.GetWindowsDirectoryName(Installed.ManifestPath);
            Package.Origin = DetermineOrigin(Instance, Package.InstallPath);
            Package.SourceBundle = Installed.SourceBundle;
            return Package;
        }

        private static AppxPackageOrigin DetermineOrigin(BinaryEmulator Instance, string GuestDirectory)
        {
            if (GuestDirectory.StartsWith(WindowsDirectoryPrefix, StringComparison.OrdinalIgnoreCase))
                return AppxPackageOrigin.Inbox;

            if (!TryReadHostFile(CombineWindowsPath(GuestDirectory, SignatureName), MaxSignatureBytes, out byte[] Signature))
                return AppxPackageOrigin.DeveloperUnsigned;

            try
            {
                return SignerHasEku(Signature, StoreSigningEku) ? AppxPackageOrigin.Store : AppxPackageOrigin.DeveloperSigned;
            }
            catch (AsnContentException Error)
            {
                Instance.TriggerEventMessage($"[-] AppX: the signature of {GuestDirectory} cannot be read: {Error.Message}", LogFlags.Issues);
                return AppxPackageOrigin.DeveloperSigned;
            }
        }

        // AppxSignature.p7x is "PKCX" followed by a DER ContentInfo that holds PKCS #7 SignedData.
        private static bool SignerHasEku(byte[] Signature, string Eku)
        {
            if (Signature.Length < 4 || Signature[0] != (byte)'P' || Signature[1] != (byte)'K' || Signature[2] != (byte)'C' || Signature[3] != (byte)'X')
                throw new AsnContentException("missing PKCX header");

            AsnReader ContentInfo = new AsnReader(Signature.AsMemory(4), AsnEncodingRules.BER).ReadSequence();
            ContentInfo.ReadObjectIdentifier();
            AsnReader SignedData = ContentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
            SignedData.ReadInteger();
            SignedData.ReadSetOf();
            SignedData.ReadSequence();

            List<ReadOnlyMemory<byte>> Certificates = new();
            Asn1Tag CertificatesTag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
            if (SignedData.HasData && SignedData.PeekTag().HasSameClassAndValue(CertificatesTag))
            {
                AsnReader CertificateSet = SignedData.ReadSetOf(CertificatesTag);
                while (CertificateSet.HasData)
                    Certificates.Add(CertificateSet.ReadEncodedValue());
            }

            if (SignedData.HasData && SignedData.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                SignedData.ReadEncodedValue();

            AsnReader SignerInfos = SignedData.ReadSetOf();
            if (!SignerInfos.HasData)
                return false;

            AsnReader SignerInfo = SignerInfos.ReadSequence();
            SignerInfo.ReadInteger();
            AsnReader IssuerAndSerial = SignerInfo.ReadSequence();
            ReadOnlyMemory<byte> SignerIssuer = IssuerAndSerial.ReadEncodedValue();
            ReadOnlyMemory<byte> SignerSerial = IssuerAndSerial.ReadIntegerBytes();

            foreach (ReadOnlyMemory<byte> Certificate in Certificates)
            {
                AsnReader Tbs = new AsnReader(Certificate, AsnEncodingRules.DER).ReadSequence().ReadSequence();
                if (Tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    Tbs.ReadEncodedValue();

                ReadOnlyMemory<byte> Serial = Tbs.ReadIntegerBytes();
                Tbs.ReadSequence();
                ReadOnlyMemory<byte> Issuer = Tbs.ReadEncodedValue();
                if (!Serial.Span.SequenceEqual(SignerSerial.Span) || !Issuer.Span.SequenceEqual(SignerIssuer.Span))
                    continue;

                Tbs.ReadSequence();
                Tbs.ReadSequence();
                Tbs.ReadSequence();
                Asn1Tag ExtensionsTag = new Asn1Tag(TagClass.ContextSpecific, 3, true);
                while (Tbs.HasData)
                {
                    if (!Tbs.PeekTag().HasSameClassAndValue(ExtensionsTag))
                    {
                        Tbs.ReadEncodedValue();
                        continue;
                    }

                    AsnReader Extensions = Tbs.ReadSequence(ExtensionsTag).ReadSequence();
                    while (Extensions.HasData)
                    {
                        AsnReader Extension = Extensions.ReadSequence();
                        string Oid = Extension.ReadObjectIdentifier();
                        if (Extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                            Extension.ReadBoolean();

                        byte[] Value = Extension.ReadOctetString();
                        if (Oid != ExtendedKeyUsageOid)
                            continue;

                        AsnReader Usages = new AsnReader(Value, AsnEncodingRules.DER).ReadSequence();
                        while (Usages.HasData)
                        {
                            if (Usages.ReadObjectIdentifier() == Eku)
                                return true;
                        }
                    }
                }

                return false;
            }

            return false;
        }

        private static AppxPackage ParseManifest(BinaryEmulator Instance, byte[] Manifest, string ManifestPath)
        {
            AppxPackage Package = new AppxPackage();
            AppxApplication Current = null;
            string Section = null;
            string PropertyName = null;
            List<(string Name, ulong Min, ulong Max)> Families = new();

            try
            {
                using XmlReader Reader = WinSxS.CreateManifestReader(Manifest);

                while (Reader.Read())
                {
                    if (Reader.NodeType == XmlNodeType.EndElement)
                    {
                        if (Reader.LocalName == "Application")
                            Current = null;
                        else if (Reader.LocalName == "Properties" || Reader.LocalName == "Dependencies" || Reader.LocalName == "Capabilities")
                            Section = null;

                        PropertyName = null;
                        continue;
                    }

                    if (Reader.NodeType == XmlNodeType.Text && Section == "Properties" && PropertyName != null && Reader.Depth == 3)
                    {
                        string Value = Reader.Value.Trim();
                        switch (PropertyName)
                        {
                            case "DisplayName": Package.DisplayName = Value; break;
                            case "PublisherDisplayName": Package.PublisherDisplayName = Value; break;
                            case "Description": Package.Description = Value; break;
                            case "Logo": Package.Logo = Value; break;
                            case "Framework": Package.IsFramework = string.Equals(Value, "true", StringComparison.OrdinalIgnoreCase); break;
                            case "ResourcePackage": Package.IsResource = string.Equals(Value, "true", StringComparison.OrdinalIgnoreCase); break;
                        }

                        continue;
                    }

                    if (Reader.NodeType != XmlNodeType.Element)
                        continue;

                    switch (Reader.LocalName)
                    {
                        case "Identity" when Reader.Depth == 1:
                            Package.Name = Reader.GetAttribute("Name");
                            Package.Publisher = Reader.GetAttribute("Publisher");
                            Package.ResourceId = Reader.GetAttribute("ResourceId") ?? string.Empty;
                            Package.ArchitectureName = (Reader.GetAttribute("ProcessorArchitecture") ?? "neutral").ToLowerInvariant();
                            if (!TryParseVersion(Reader.GetAttribute("Version"), out Package.Version))
                                throw new FormatException("bad Identity Version");
                            break;

                        case "Properties" when Reader.Depth == 1:
                        case "Dependencies" when Reader.Depth == 1:
                        case "Capabilities" when Reader.Depth == 1:
                            Section = Reader.LocalName;
                            break;

                        case "TargetDeviceFamily" when Section == "Dependencies":
                            TryParseVersion(Reader.GetAttribute("MinVersion"), out ulong FamilyMin);
                            TryParseVersion(Reader.GetAttribute("MaxVersionTested"), out ulong FamilyMax);
                            Families.Add((Reader.GetAttribute("Name"), FamilyMin, FamilyMax));
                            break;

                        case "PackageDependency" when Section == "Dependencies":
                            if (Package.Dependencies.Count >= MaxDependencies)
                                throw new FormatException("too many PackageDependency elements");

                            TryParseVersion(Reader.GetAttribute("MinVersion"), out ulong DependencyMin);
                            Package.Dependencies.Add(new AppxDependency { Name = Reader.GetAttribute("Name"), Publisher = Reader.GetAttribute("Publisher"), MinVersion = DependencyMin });
                            break;

                        case "Capability" when Section == "Capabilities":
                        case "DeviceCapability" when Section == "Capabilities":
                            string Capability = Reader.GetAttribute("Name");
                            if (!string.IsNullOrEmpty(Capability) && Package.Capabilities.Count < MaxCapabilities)
                                Package.Capabilities.Add(Capability);
                            break;

                        case "Application":
                            if (Package.Applications.Count >= MaxApplications)
                                throw new FormatException("too many Application elements");

                            Current = new AppxApplication
                            {
                                Id = Reader.GetAttribute("Id"),
                                Executable = Reader.GetAttribute("Executable"),
                                EntryPoint = Reader.GetAttribute("EntryPoint"),
                                TrustLevel = GetPrefixedAttribute(Reader, "TrustLevel"),
                                SupportsMultipleInstances = string.Equals(GetPrefixedAttribute(Reader, "SupportsMultipleInstances"), "true", StringComparison.OrdinalIgnoreCase),
                            };

                            Package.Applications.Add(Current);
                            if (Reader.IsEmptyElement)
                                Current = null;
                            break;

                        case "VisualElements" when Current != null:
                            Current.DisplayName = Reader.GetAttribute("DisplayName");
                            Current.Description = Reader.GetAttribute("Description");
                            Current.Square150x150Logo = Reader.GetAttribute("Square150x150Logo");
                            Current.Square44x44Logo = Reader.GetAttribute("Square44x44Logo");
                            Current.ForegroundText = Reader.GetAttribute("ForegroundText");
                            Current.BackgroundColor = Reader.GetAttribute("BackgroundColor");
                            break;

                        default:
                            if (Section == "Properties" && Reader.Depth == 2)
                                PropertyName = Reader.IsEmptyElement ? null : Reader.LocalName;
                            break;
                    }
                }
            }
            catch (Exception Error) when (Error is XmlException || Error is FormatException)
            {
                Instance.TriggerEventMessage($"[-] AppX: {ManifestPath} is not a valid package manifest: {Error.Message}", LogFlags.Issues);
                return null;
            }

            if (string.IsNullOrEmpty(Package.Name) || string.IsNullOrEmpty(Package.Publisher) || !TryMapArchitecture(Package.ArchitectureName, out Package.Architecture))
            {
                Instance.TriggerEventMessage($"[-] AppX: {ManifestPath} has no usable package identity.", LogFlags.Issues);
                return null;
            }

            Package.PublisherId = DerivePublisherId(Package.Publisher);
            Package.FamilyName = Package.Name + "_" + Package.PublisherId;
            Package.FullName = $"{Package.Name}_{FormatVersion(Package.Version)}_{Package.ArchitectureName}_{Package.ResourceId}_{Package.PublisherId}";
            SelectTargetPlatform(Package, Families);
            return Package;
        }

        private static string GetPrefixedAttribute(XmlReader Reader, string LocalName)
        {
            if (!Reader.MoveToFirstAttribute())
                return null;

            try
            {
                do
                {
                    if (Reader.LocalName == LocalName)
                        return Reader.Value;
                }
                while (Reader.MoveToNextAttribute());
            }
            finally
            {
                Reader.MoveToElement();
            }

            return null;
        }

        // NT: a desktop device picks the Windows.Desktop family over Windows.Universal.
        private static void SelectTargetPlatform(AppxPackage Package, List<(string Name, ulong Min, ulong Max)> Families)
        {
            bool Found = false;
            foreach (var Family in Families)
            {
                if (string.Equals(Family.Name, "Windows.Desktop", StringComparison.OrdinalIgnoreCase))
                {
                    Package.TargetPlatform = TargetPlatformDesktop;
                    Package.MinVersion = Family.Min;
                    Package.MaxVersionTested = Family.Max;
                    return;
                }

                if (!Found && string.Equals(Family.Name, "Windows.Universal", StringComparison.OrdinalIgnoreCase))
                {
                    Package.TargetPlatform = TargetPlatformUniversal;
                    Package.MinVersion = Family.Min;
                    Package.MaxVersionTested = Family.Max;
                    Found = true;
                }
            }
        }

        private static uint GetGraphFlags(AppxPackage Package, bool IsMain)
        {
            if (IsMain)
            {
                uint Flags = PackageHead | (Package.IsFramework ? PackageFramework : Package.IsResource ? PackageResource : 0);
                return Flags | (PackageOriginBase << (int)Package.Origin);
            }

            if (Package.IsFramework)
                return PackageFramework | PackageDirect;

            return Package.IsResource ? PackageResource : 0;
        }

        private static bool IsLoaderPathNode(uint Flags)
        {
            return (Flags & 0xF) == 0 || (Flags & 7) == PackageFramework;
        }

        private static string BuildLoaderSearchPath(List<AppxPackage> Graph, List<uint> Flags, int Count)
        {
            StringBuilder Builder = new StringBuilder();
            HashSet<string> Seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int Index = 0; Index < Count; Index++)
            {
                if (!IsLoaderPathNode(Flags[Index]) || !Seen.Add(Graph[Index].InstallPath))
                    continue;

                Builder.Append(Graph[Index].InstallPath).Append(';');
            }

            return Builder.ToString();
        }

        private static byte[][] BuildCapabilitySids(AppxPackage Package, byte[] AppContainerSid)
        {
            List<byte[]> Sids = new List<byte[]>(Package.Capabilities.Count + 1);
            HashSet<string> Seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string Capability in Package.Capabilities)
            {
                if (Seen.Add(Capability))
                    Sids.Add(DeriveCapabilitySid(Capability));
            }

            uint[] PackageRids = new uint[(AppContainerSid[1]) - 1];
            for (int Index = 0; Index < PackageRids.Length; Index++)
                PackageRids[Index] = BinaryPrimitives.ReadUInt32LittleEndian(AppContainerSid.AsSpan(12 + Index * 4, 4));

            uint[] CapabilityRids = new uint[PackageRids.Length + 1];
            CapabilityRids[0] = 3;
            PackageRids.CopyTo(CapabilityRids, 1);
            Sids.Add(NtQueryInformationToken.BuildSid(1, 15, CapabilityRids));
            return Sids.ToArray();
        }

        private static WinTokenSecurityAttribute[] BuildSecurityAttributes(AppxPackage Package, AppxApplication Application, bool IsAppContainer)
        {
            List<string> AppIdentity = new List<string> { Package.FullName, Application.Id, Package.FamilyName };
            if (Application.SupportsMultipleInstances)
                AppIdentity.Add(Guid.NewGuid().ToString("B"));

            ulong Claims = ((ulong)Package.Origin << 32) | ClaimPackagedApplication | (IsAppContainer ? ClaimAppContainer : ClaimFullTrust);
            ulong HostId = PackageHostIdBase | (ulong)System.Threading.Interlocked.Increment(ref PackageHostSequence);

            return new[]
            {
                new WinTokenSecurityAttribute { Name = WinTokenSecurityAttribute.SysAppIdName, ValueType = WinTokenSecurityAttribute.TypeString, StringValues = AppIdentity.ToArray() },
                new WinTokenSecurityAttribute { Name = WinTokenSecurityAttribute.PackageClaimsName, ValueType = WinTokenSecurityAttribute.TypeUInt64, UInt64Values = new[] { Claims } },
                new WinTokenSecurityAttribute { Name = WinTokenSecurityAttribute.PackageHostIdName, ValueType = WinTokenSecurityAttribute.TypeUInt64, UInt64Values = new[] { HostId } },
            };
        }

        internal static string DerivePublisherId(string Publisher)
        {
            byte[] Hash = SHA256.HashData(Encoding.Unicode.GetBytes(Publisher ?? string.Empty));
            ulong Bits = BinaryPrimitives.ReadUInt64BigEndian(Hash);
            Span<char> Id = stackalloc char[13];
            for (int Index = 0; Index < Id.Length; Index++)
            {
                int Shift = 64 - 5 * (Index + 1);
                ulong Group = Shift >= 0 ? Bits >> Shift : Bits << -Shift;
                Id[Index] = PublisherIdAlphabet[(int)(Group & 31)];
            }

            return new string(Id);
        }

        internal static byte[] DeriveAppContainerSid(string FamilyName)
        {
            byte[] Hash = SHA256.HashData(Encoding.Unicode.GetBytes(FamilyName.ToLowerInvariant()));
            uint[] Rids = new uint[8];
            Rids[0] = 2;
            for (int Index = 0; Index < 7; Index++)
                Rids[Index + 1] = BinaryPrimitives.ReadUInt32LittleEndian(Hash.AsSpan(Index * 4, 4));

            return NtQueryInformationToken.BuildSid(1, 15, Rids);
        }

        internal static byte[] DeriveCapabilitySid(string Capability)
        {
            int WellKnown = Array.FindIndex(WellKnownCapabilities, Name => string.Equals(Name, Capability, StringComparison.OrdinalIgnoreCase));
            if (WellKnown >= 0)
                return NtQueryInformationToken.BuildSid(1, 15, 3, (uint)WellKnown + 1);

            byte[] Hash = SHA256.HashData(Encoding.Unicode.GetBytes(Capability.ToUpperInvariant()));
            uint[] Rids = new uint[10];
            Rids[0] = 3;
            Rids[1] = 1024;
            for (int Index = 0; Index < 8; Index++)
                Rids[Index + 2] = BinaryPrimitives.ReadUInt32LittleEndian(Hash.AsSpan(Index * 4, 4));

            return NtQueryInformationToken.BuildSid(1, 15, Rids);
        }

        private static bool TryMapArchitecture(string Name, out ushort Architecture)
        {
            switch (Name)
            {
                case "x86": Architecture = ArchitectureIntel; return true;
                case "arm": Architecture = ArchitectureArm; return true;
                case "x64": Architecture = ArchitectureAmd64; return true;
                case "neutral": Architecture = ArchitectureNeutral; return true;
                case "arm64": Architecture = ArchitectureArm64; return true;
                default: Architecture = 0; return false;
            }
        }

        private static bool TryParseVersion(string? Text, out ulong Version)
        {
            Version = 0;
            if (string.IsNullOrEmpty(Text))
                return false;

            string[] Parts = Text.Split('.');
            if (Parts.Length != 4)
                return false;

            for (int Index = 0; Index < 4; Index++)
            {
                if (!ushort.TryParse(Parts[Index], out ushort Part))
                    return false;

                Version |= (ulong)Part << (16 * (3 - Index));
            }

            return true;
        }

        private static string FormatVersion(ulong Version)
        {
            return $"{(ushort)(Version >> 48)}.{(ushort)(Version >> 32)}.{(ushort)(Version >> 16)}.{(ushort)Version}";
        }

        private static string CombineWindowsPath(string Directory, string Leaf)
        {
            return Directory.TrimEnd('\\') + "\\" + Leaf;
        }

        private static bool TryReadHostFile(string GuestPath, int MaxBytes, out byte[] Data)
        {
            Data = null;
            string HostPath = GeneralHelper.IO.ResolveHostPath(GuestPath, BinaryFormat.PE);
            return !string.IsNullOrEmpty(HostPath) && GeneralHelper.IO.TryReadHostFile(HostPath, MaxBytes, out Data);
        }

        private static uint ParseBackgroundColor(string Color)
        {
            if (string.IsNullOrEmpty(Color) || string.Equals(Color, "transparent", StringComparison.OrdinalIgnoreCase))
                return 0;

            if (Color.Length == 7 && Color[0] == '#' && uint.TryParse(Color.AsSpan(1), System.Globalization.NumberStyles.HexNumber, null, out uint Rgb))
                return 0xFF000000 | Rgb;

            return 0;
        }

        private static uint ParseForegroundText(string Text)
        {
            return string.Equals(Text, "dark", StringComparison.OrdinalIgnoreCase) ? 2u : 1u;
        }

        private static byte[] BuildDependencyMiniRepository(AppxProcessIdentity Identity, List<uint> Flags)
        {
            AppxPackage Package = Identity.Package;
            List<(string Signature, byte[] Body)> Sections = new();

            Sections.Add(("SECU", BuildSecurityContext(Package, Identity.AppContainerSid)));
            Sections.Add(("ALTP", BuildAlternatePath(Identity.LoaderSearchPath)));

            int FirstFamily = 1;
            while (FirstFamily < Identity.Graph.Count
                && string.Equals(Identity.Graph[FirstFamily].Name, Package.Name, StringComparison.OrdinalIgnoreCase)
                && string.Equals(Identity.Graph[FirstFamily].PublisherId, Package.PublisherId, StringComparison.OrdinalIgnoreCase))
            {
                FirstFamily++;
            }

            if (FirstFamily < Identity.Graph.Count)
                Sections.Add(("ALTF", BuildAlternatePathForFirstFamily(BuildLoaderSearchPath(Identity.Graph, Flags, FirstFamily))));

            List<byte[]> Nodes = new List<byte[]>(Identity.Graph.Count);
            for (int Index = 0; Index < Identity.Graph.Count; Index++)
                Nodes.Add(BuildGraphNode(Identity.Graph[Index], Flags[Index]));

            Sections.Add(("DEPG", BuildContainer("DEPG", Nodes)));
            Sections.Add(("TPLT", BuildTargetPlatform(Package)));

            List<byte[]> MutablePaths = new List<byte[]>(Identity.Graph.Count);
            for (int Index = 0; Index < Identity.Graph.Count; Index++)
                MutablePaths.Add(BuildMutablePath());

            Sections.Add(("PKMP", BuildContainer("PKMP", MutablePaths)));

            List<byte[]> Applications = new List<byte[]>(Package.Applications.Count);
            bool EnterpriseAuthentication = Package.Capabilities.Exists(Name => string.Equals(Name, "enterpriseAuthentication", StringComparison.OrdinalIgnoreCase));
            foreach (AppxApplication Application in Package.Applications)
            {
                Sections.Add(("GLOB", BuildGlobalization(Application)));
                Applications.Add(BuildApplication(Package, Application, EnterpriseAuthentication));
            }

            Sections.Add(("APPS", BuildContainer("APPS", Applications)));
            Sections.Add(("JHN8", Signature("JHN8", 8)));

            uint TocSize = (uint)(8 * Sections.Count + 12);
            uint Total = 16 + TocSize;
            foreach (var Section in Sections)
                Total += (uint)Section.Body.Length;

            byte[] Data = new byte[Total];
            Span<byte> Span = Data;
            WriteSignature(Span, "ARI8");
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(8), Total);
            WriteSignature(Span.Slice(16), "TOC8");
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(20), TocSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(24), (uint)Sections.Count);

            uint Offset = 16 + TocSize;
            for (int Index = 0; Index < Sections.Count; Index++)
            {
                WriteSignature(Span.Slice(28 + Index * 8), Sections[Index].Signature);
                BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(32 + Index * 8), Offset);
                Sections[Index].Body.CopyTo(Span.Slice((int)Offset));
                Offset += (uint)Sections[Index].Body.Length;
            }

            return Data;
        }

        private static byte[] BuildSecurityContext(AppxPackage Package, byte[] AppContainerSid)
        {
            List<byte[]> Capabilities = new();
            foreach (string Name in SecurityContextCapabilities)
            {
                if (Package.Capabilities.Exists(Declared => string.Equals(Declared, Name, StringComparison.OrdinalIgnoreCase)))
                    Capabilities.Add(DeriveCapabilitySid(Name));
            }

            int CapabilityBytes = 0;
            foreach (byte[] Sid in Capabilities)
                CapabilityBytes += Sid.Length;

            int Actual = 20 + AppContainerSid.Length + CapabilityBytes;
            byte[] Body = Signature("SECU", Actual);
            Span<byte> Span = Body;
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(4), (uint)Actual);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(8), Package.Origin == AppxPackageOrigin.Inbox ? 1u : 0u);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(12), (ushort)AppContainerSid.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(14), (ushort)Capabilities.Count);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(16), (ushort)CapabilityBytes);

            int Cursor = 20;
            AppContainerSid.CopyTo(Span.Slice(Cursor));
            Cursor += AppContainerSid.Length;
            foreach (byte[] Sid in Capabilities)
            {
                Sid.CopyTo(Span.Slice(Cursor));
                Cursor += Sid.Length;
            }

            return Body;
        }

        private static byte[] BuildAlternatePath(string Path)
        {
            byte[] Text = Utf16z(Path);
            byte[] Body = Signature("ALTP", 8 + Text.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Body.AsSpan(4), (uint)(8 + Text.Length));
            Text.CopyTo(Body, 8);
            return Body;
        }

        private static byte[] BuildAlternatePathForFirstFamily(string Path)
        {
            byte[] Text = Utf16z(Path);
            byte[] Body = Signature("ALTF", 16 + Text.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Body.AsSpan(4), (uint)(16 + Text.Length));
            BinaryPrimitives.WriteUInt32LittleEndian(Body.AsSpan(12), (uint)Text.Length);
            Text.CopyTo(Body, 16);
            return Body;
        }

        private static byte[] BuildGraphNode(AppxPackage Package, uint Flags)
        {
            byte[] Name = Utf16z(Package.Name);
            byte[] PublisherId = Utf16z(Package.PublisherId);
            byte[] Publisher = Utf16z(Package.Publisher);
            byte[] ResourceId = Utf16z(Package.ResourceId);
            byte[] FullName = Utf16z(Package.FullName);
            byte[] Path = Utf16z(Package.InstallPath);

            int Base = 40 + Name.Length + PublisherId.Length + Publisher.Length + ResourceId.Length + FullName.Length + Path.Length;
            byte[] DisplayName = Utf16z(Package.DisplayName);
            byte[] PublisherDisplayName = Utf16z(Package.PublisherDisplayName);
            byte[] Description = Utf16z(Package.Description);
            byte[] Logo = Utf16z(Package.Logo);

            bool HasProperties = DisplayName.Length != 0;
            int PropertiesOffset = HasProperties ? Align4(Base) : 0;
            int PropertiesSize = HasProperties ? 32 + DisplayName.Length + PublisherDisplayName.Length + Description.Length + Logo.Length : 0;
            int Actual = HasProperties ? PropertiesOffset + PropertiesSize : Base;

            byte[] Body = new byte[Align4(Actual)];
            Span<byte> Span = Body;
            BinaryPrimitives.WriteUInt32LittleEndian(Span, (uint)Actual);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(4), (ushort)Path.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(6), (ushort)PropertiesOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(8), (uint)(32 + Name.Length + PublisherId.Length + Publisher.Length + ResourceId.Length + FullName.Length));
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(12), Flags);
            BinaryPrimitives.WriteUInt64LittleEndian(Span.Slice(16), Package.Version);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(24), Package.Architecture);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(28), (ushort)Name.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(30), (ushort)PublisherId.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(32), (uint)Publisher.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(36), (ushort)ResourceId.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(38), (ushort)FullName.Length);

            int Cursor = 40;
            foreach (byte[] Part in new[] { Name, PublisherId, Publisher, ResourceId, FullName, Path })
            {
                Part.CopyTo(Span.Slice(Cursor));
                Cursor += Part.Length;
            }

            if (HasProperties)
            {
                Span<byte> Properties = Span.Slice(PropertiesOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(Properties, (uint)PropertiesSize);
                BinaryPrimitives.WriteUInt64LittleEndian(Properties.Slice(8), Package.MinVersion);
                BinaryPrimitives.WriteUInt64LittleEndian(Properties.Slice(16), Package.MaxVersionTested);
                BinaryPrimitives.WriteUInt16LittleEndian(Properties.Slice(24), (ushort)DisplayName.Length);
                BinaryPrimitives.WriteUInt16LittleEndian(Properties.Slice(26), (ushort)PublisherDisplayName.Length);
                BinaryPrimitives.WriteUInt16LittleEndian(Properties.Slice(28), (ushort)Description.Length);
                BinaryPrimitives.WriteUInt16LittleEndian(Properties.Slice(30), (ushort)Logo.Length);

                Cursor = 32;
                foreach (byte[] Part in new[] { DisplayName, PublisherDisplayName, Description, Logo })
                {
                    Part.CopyTo(Properties.Slice(Cursor));
                    Cursor += Part.Length;
                }
            }

            return Body;
        }

        private static byte[] BuildTargetPlatform(AppxPackage Package)
        {
            byte[] Body = Signature("TPLT", 32);
            BinaryPrimitives.WriteUInt32LittleEndian(Body.AsSpan(12), Package.TargetPlatform);
            BinaryPrimitives.WriteUInt64LittleEndian(Body.AsSpan(16), Package.MinVersion);
            BinaryPrimitives.WriteUInt64LittleEndian(Body.AsSpan(24), Package.MaxVersionTested);
            return Body;
        }

        private static byte[] BuildMutablePath()
        {
            byte[] Body = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(Body, 4);
            return Body;
        }

        private static byte[] BuildGlobalization(AppxApplication Application)
        {
            byte[] Id = Utf16z(Application.Id);
            byte[] Body = Signature("GLOB", 20 + Id.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Body.AsSpan(4), (uint)(20 + Id.Length));
            BinaryPrimitives.WriteUInt32LittleEndian(Body.AsSpan(12), (uint)Id.Length);
            Id.CopyTo(Body, 20);
            return Body;
        }

        private static byte[] BuildApplication(AppxPackage Package, AppxApplication Application, bool EnterpriseAuthentication)
        {
            string AppUserModelId = Package.FamilyName + "!" + Application.Id;
            byte[] Aumid = Utf16z(AppUserModelId);
            byte[] DisplayName = Utf16z(Application.DisplayName);
            byte[] Description = Utf16z(Application.Description);
            byte[] Square150 = Utf16z(Application.Square150x150Logo);
            byte[] Square44 = Utf16z(Application.Square44x44Logo);

            int Actual = 36 + Aumid.Length + DisplayName.Length + Description.Length + Square150.Length + Square44.Length;
            byte[] Body = new byte[Align4(Actual)];
            Span<byte> Span = Body;
            BinaryPrimitives.WriteUInt32LittleEndian(Span, (uint)Actual);
            Span[7] = EnterpriseAuthentication ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(8), (ushort)Aumid.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(10), (ushort)(2 * (Package.FamilyName.Length + 1)));
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(12), (ushort)DisplayName.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(14), (ushort)Description.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(16), (ushort)Square150.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(18), (ushort)Square44.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(20), ParseForegroundText(Application.ForegroundText));
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(24), ParseBackgroundColor(Application.BackgroundColor));

            int Cursor = 36;
            foreach (byte[] Part in new[] { Aumid, DisplayName, Description, Square150, Square44 })
            {
                Part.CopyTo(Span.Slice(Cursor));
                Cursor += Part.Length;
            }

            return Body;
        }

        private static byte[] BuildContainer(string Name, List<byte[]> Children)
        {
            int Actual = 16;
            foreach (byte[] Child in Children)
                Actual += Child.Length;

            byte[] Body = Signature(Name, Actual);
            BinaryPrimitives.WriteUInt32LittleEndian(Body.AsSpan(4), (uint)Actual);
            BinaryPrimitives.WriteUInt32LittleEndian(Body.AsSpan(12), (uint)Children.Count);

            int Cursor = 16;
            foreach (byte[] Child in Children)
            {
                Child.CopyTo(Body, Cursor);
                Cursor += Child.Length;
            }

            return Body;
        }

        private static byte[] Signature(string Name, int Size)
        {
            byte[] Body = new byte[Align4(Size)];
            WriteSignature(Body, Name);
            return Body;
        }

        private static void WriteSignature(Span<byte> Destination, string Name)
        {
            for (int Index = 0; Index < 4; Index++)
                Destination[Index] = (byte)Name[Index];
        }

        private static byte[] Utf16z(string Text)
        {
            return string.IsNullOrEmpty(Text) ? Array.Empty<byte>() : Encoding.Unicode.GetBytes(Text + "\0");
        }

        private static int Align4(int Value)
        {
            return (Value + 3) & ~3;
        }
    }
}
