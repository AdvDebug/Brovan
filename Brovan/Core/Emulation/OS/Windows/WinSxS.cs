using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class WinSxS
    {
        private const uint ActivationContextMagic = 0x78746341;
        private const uint StringSectionMagic = 0x64487353;
        private const uint GuidSectionMagic = 0x64487347;

        private const int HeaderSize = 0x20;
        private const int TocOffset = 0x20;
        private const int TocHeaderSize = 0x10;
        private const int TocEntriesOffset = 0x30;
        private const int TocEntrySize = 0x10;
        private const int AssemblyRosterOffset = 0xC0;
        private const int FirstSectionOffset = 0xD8;

        private const int StringSectionHeaderSize = 0x2C;
        private const int GuidSectionHeaderSize = 0x28;
        private const int StringEntrySize = 0x18;
        private const int DllRedirectionSize = 0x14;
        private const int PathSegmentSize = 0x08;
        private const int WindowClassRedirectionSize = 0x18;

        private const uint SectionCaseInsensitive = 1;
        private const uint HashAlgorithmNone = 0xFFFFFFFF;
        private const uint DllRedirectionSectionId = 2;
        private const uint WindowClassRedirectionSectionId = 3;

        // Roster entry 1 is the root manifest.
        private const int FirstDependencyRosterIndex = 2;

        internal const ulong PebActivationContextData64 = 0x2F8;
        internal const ulong PebActivationContextData32 = 0x1F8;

        private const uint ResourceIdCreateProcessManifest = 1;
        private const string StoreGuestPath = @"C:\Windows\WinSxS";
        private const string StoreManifestsGuestPath = @"C:\Windows\WinSxS\Manifests\";

        // BASE_MSG_SXS_STREAM handle types.
        private const byte StreamHandleProcess = 1;
        private const byte StreamHandleSection = 3;

        private const ushort ProcessorArchitectureIntel = 0;
        private const ushort ProcessorArchitectureAmd64 = 9;
        private const ushort ProcessorArchitectureIa32OnWin64 = 10;

        private static readonly XmlReaderSettings ManifestReaderSettings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            IgnoreComments = true,
            IgnoreWhitespace = true,
            IgnoreProcessingInstructions = true,
            XmlResolver = null,
            CloseInput = true,
        };

        internal static XmlReader CreateManifestReader(byte[] Manifest)
            => XmlReader.Create(new MemoryStream(Manifest, 0, Manifest.Length, false), ManifestReaderSettings);

        private static readonly uint[] SectionIds =
        {
            2u,  // ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION.
            3u,  // ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION.
            4u,  // ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION.
            5u,  // ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION.
            6u,  // ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION.
            7u,  // ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION.
            9u,  // ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES.
            10u, // ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS.
            12u  // ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES.
        };

        private const string AssemblyNamespace = "urn:schemas-microsoft-com:asm.v1";
        private const string CompatibilityNamespace = "urn:schemas-microsoft-com:compatibility.v1";

        // NT: SbSupportedOsList in kernel32 and sxs.
        private static readonly (Guid Id, string Name, ushort Major, ushort Minor)[] SupportedOsList =
        {
            (new Guid("e2011457-1546-43c5-a5fe-008deee3d3f0"), "windows vista", 6, 0),
            (new Guid("35138b9a-5d96-4fbd-8e2d-a2440225f93a"), "windows seven", 6, 1),
            (new Guid("4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38"), "windows eight", 6, 2),
            (new Guid("1f676c76-80e1-4239-95bb-83d0f6d0da78"), "windows blue", 6, 3),
            (new Guid("8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"), "windows threshold", 10, 0),
        };

        private struct AssemblyIdentity
        {
            public string Name;
            public string Version;
            public string PublicKeyToken;
            public string ProcessorArchitecture;
            public string Language;
            public bool Optional;
        }

        private sealed class AssemblyManifest
        {
            public string Version;
            public string GuestDirectory;
            public readonly List<AssemblyIdentity> Dependencies = new();
            public readonly List<string> Files = new();
            public readonly List<(string Name, bool Versioned, string Dll)> WindowClasses = new();
        }

        internal readonly record struct ActivationContextRequest(byte HandleType, ulong FileHandle, ulong Handle, ulong Offset, ulong Size,
            ushort ProcessorArchitecture, ulong OutputPointer);

        internal static NTSTATUS CreateActivationContext(BinaryEmulator Instance, in ActivationContextRequest Request, out ulong Data)
        {
            Data = 0;
            if (Request.OutputPointer == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!TryGetArchitecture(Request.ProcessorArchitecture, out BinaryArchitecture Architecture)
                || !TryReadRequestManifest(Instance, Request, out byte[] Manifest)
                || !TryResolveDependencies(Instance, Manifest, Architecture, true, out List<AssemblyManifest> Assemblies)
                || !TryWriteActivationContext(Assemblies, out ReadOnlySpan<byte> Context))
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[!] Side by side: no activation context from a manifest of 0x{Request.Size:X} bytes.", LogFlags.Issues);
                return NTSTATUS.STATUS_SXS_CANT_GEN_ACTCTX;
            }

            ulong Mapped = Instance.WinHelper.MapUnnamedSectionView(Context, MemoryProtection.Read);
            if (Mapped == 0)
                return NTSTATUS.STATUS_NO_MEMORY;

            if (!Instance.WinHelper.WritePointer(Request.OutputPointer, Mapped))
            {
                Instance.WinHelper.UnmapViewOfSection(Mapped);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Data = Mapped;
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static ulong BuildProcessActivationContext(BinaryEmulator Instance, WinModule Module)
        {
            if (Instance == null || Module == null || Instance._binary?.FileFormat != BinaryFormat.PE)
                return 0;

            byte[] Manifest = ReadImageManifest(Instance, Module);
            if (Manifest == null)
                return 0;

            // Process startup tolerates missing assemblies that NT would reject.
            if (!TryResolveDependencies(Instance, Manifest, Instance._binary.Architecture, false, out List<AssemblyManifest> Assemblies)
                || Assemblies.Count == 0 || !TryWriteActivationContext(Assemblies, out ReadOnlySpan<byte> Data))
                return 0;

            ulong Address = Instance.WinHelper.MapUnnamedSectionView(Data, MemoryProtection.Read);

            if (Address != 0 && (Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] Side by side: {Assemblies.Count} assembly(ies) for {Module.Name}.", LogFlags.General);

            return Address;
        }

        private static bool TryGetArchitecture(ushort ProcessorArchitecture, out BinaryArchitecture Architecture)
        {
            Architecture = ProcessorArchitecture == ProcessorArchitectureAmd64 ? BinaryArchitecture.x64 : BinaryArchitecture.x86;
            return ProcessorArchitecture == ProcessorArchitectureAmd64 || ProcessorArchitecture == ProcessorArchitectureIntel
                || ProcessorArchitecture == ProcessorArchitectureIa32OnWin64;
        }

        private static bool TryReadRequestManifest(BinaryEmulator Instance, in ActivationContextRequest Request, out byte[] Manifest)
        {
            Manifest = null;
            if (Request.Size == 0 || Request.Size > (ulong)MemoryBudget.SideBySideManifestBytes)
                return false;

            byte[] Bytes = new byte[Request.Size];
            switch (Request.HandleType)
            {
                case StreamHandleProcess:
                    if (!HandleManager.IsCurrentProcessPseudoHandle(Request.Handle) || !Instance.ReadMemory(Request.Offset, Bytes))
                        return false;
                    break;

                case StreamHandleSection:
                {
                    WindowsFileStream Stream = Instance.WinHelper.GetFileByHandle(Request.FileHandle, AccessMask.FileReadData)?.GetFileStream();
                    if (Stream == null || Request.Offset > long.MaxValue || Stream.ReadAt((long)Request.Offset, Bytes) != Bytes.Length)
                        return false;
                    break;
                }

                default:
                    return false;
            }

            Manifest = Bytes;
            return true;
        }

        internal static byte[] ReadImageManifest(BinaryEmulator Instance, WinModule Module)
        {
            if (Module == null)
                return null;

            return ReadEmbeddedManifest(new MappedImage(Instance, Module.MappedBase)) ?? ReadExternalManifest(Module.Path);
        }

        internal static byte[] ReadImageManifest(BinaryFile Image, string HostPath)
        {
            if (Image == null || Image.FileFormat != BinaryFormat.PE)
                return null;

            return ReadEmbeddedManifest(new ImageFile(Image)) ?? ReadExternalManifest(HostPath);
        }

        private static byte[] ReadExternalManifest(string ImagePath)
        {
            if (string.IsNullOrEmpty(ImagePath))
                return null;

            return GeneralHelper.IO.TryReadHostFile(ImagePath + ".manifest", MemoryBudget.SideBySideManifestBytes, out byte[] Manifest) ? Manifest : null;
        }

        private static byte[] ReadEmbeddedManifest<TImage>(TImage Image) where TImage : struct, IImageReader
        {
            if (!ImageResources.TryFindResource(Image, ImageResources.TypeManifest, ResourceIdCreateProcessManifest, out uint DataRva, out uint DataSize)
                || DataSize > MemoryBudget.SideBySideManifestBytes)
                return null;

            byte[] Manifest = new byte[DataSize];
            return Image.TryRead(DataRva, Manifest) ? Manifest : null;
        }

        private static bool TryResolveDependencies(BinaryEmulator Instance, byte[] Manifest, BinaryArchitecture Architecture,
            bool RequireAll, out List<AssemblyManifest> Assemblies)
        {
            Assemblies = new List<AssemblyManifest>();

            AssemblyManifest Root = new AssemblyManifest();
            if (!TryParseManifest(Manifest, Root))
                return false;

            foreach (AssemblyIdentity Identity in Root.Dependencies)
            {
                if (Assemblies.Count >= MemoryBudget.ActivationContextAssemblies)
                    return false;

                if (TryResolveAssembly(Instance, Identity, Architecture, out AssemblyManifest Assembly, out bool NoStore))
                    Assemblies.Add(Assembly);
                else if (RequireAll && !NoStore && !Identity.Optional)
                    return false;
            }

            return true;
        }

        // Manifest resources can contain padding after the root element.
        private static bool TryParseManifest(byte[] Manifest, AssemblyManifest Content)
        {
            try
            {
                using XmlReader Reader = CreateManifestReader(Manifest);

                bool InDependency = false;
                bool Optional = false;
                string File = null;

                while (!Reader.EOF)
                {
                    if (Reader.NodeType == XmlNodeType.EndElement)
                    {
                        if (Reader.Depth == 0)
                            return true;

                        if (Reader.LocalName == "dependency")
                            InDependency = false;
                        else if (Reader.LocalName == "file")
                            File = null;
                    }
                    else if (Reader.NodeType == XmlNodeType.Element)
                    {
                        if (Reader.Depth == 0 && Reader.IsEmptyElement)
                            return true;

                        switch (Reader.LocalName)
                        {
                            case "dependency":
                                InDependency = !Reader.IsEmptyElement;
                                Optional = string.Equals(Reader.GetAttribute("optional"), "yes", StringComparison.OrdinalIgnoreCase);
                                break;

                            case "assemblyIdentity" when InDependency:
                            {
                                AssemblyIdentity Identity = new AssemblyIdentity
                                {
                                    Name = Reader.GetAttribute("name"),
                                    Version = Reader.GetAttribute("version"),
                                    PublicKeyToken = Reader.GetAttribute("publicKeyToken"),
                                    ProcessorArchitecture = Reader.GetAttribute("processorArchitecture"),
                                    Language = Reader.GetAttribute("language"),
                                    Optional = Optional,
                                };

                                if (!string.IsNullOrEmpty(Identity.Name))
                                    Content.Dependencies.Add(Identity);
                                break;
                            }

                            case "file" when Reader.Depth == 1:
                            {
                                string Name = Reader.GetAttribute("name");
                                if (!string.IsNullOrEmpty(Name))
                                    Content.Files.Add(Name);
                                File = Reader.IsEmptyElement ? null : Name;
                                break;
                            }

                            case "windowClass" when File != null:
                            {
                                bool Versioned = !string.Equals(Reader.GetAttribute("versioned"), "no", StringComparison.OrdinalIgnoreCase);
                                string Class = Reader.ReadElementContentAsString().Trim();
                                if (Class.Length != 0)
                                    Content.WindowClasses.Add((Class, Versioned, File));
                                continue;
                            }
                        }
                    }

                    Reader.Read();
                }
            }
            catch (XmlException)
            {
                return false;
            }

            return false;
        }

        private static bool TryResolveAssembly(BinaryEmulator Instance, AssemblyIdentity Identity, BinaryArchitecture Architecture,
            out AssemblyManifest Assembly, out bool NoStore)
        {
            Assembly = null;

            string ArchitectureName = Architecture == BinaryArchitecture.x64 ? "amd64" : "x86";
            if (!string.IsNullOrEmpty(Identity.ProcessorArchitecture) && Identity.ProcessorArchitecture != "*")
                ArchitectureName = Identity.ProcessorArchitecture.ToLowerInvariant();

            string Language = string.IsNullOrEmpty(Identity.Language) || Identity.Language == "*"
                ? "none"
                : Identity.Language.ToLowerInvariant();

            string Token = (Identity.PublicKeyToken ?? string.Empty).ToLowerInvariant();
            string Prefix = $"{ArchitectureName}_{Identity.Name.ToLowerInvariant()}_{Token}_";
            string LanguagePart = $"_{Language}_";

            List<WinDirectoryEntry> Candidates = NtQueryDirectoryFileCommon.ListDirectory(StoreGuestPath, Prefix + "*", null);
            NoStore = Candidates == null;
            if (NoStore)
                return false;

            string Best = null;
            string BestVersionText = null;
            Version BestVersion = null;
            Version Wanted = ParseVersion(Identity.Version);

            foreach (WinDirectoryEntry Candidate in Candidates)
            {
                if ((Candidate.FileAttributes & (uint)FileAttributes.Directory) == 0)
                    continue;

                string Leaf = Candidate.Name;
                int VersionStart = Prefix.Length;
                int LanguageStart = Leaf.IndexOf(LanguagePart, VersionStart, StringComparison.OrdinalIgnoreCase);
                if (LanguageStart <= VersionStart)
                    continue;

                string VersionText = Leaf.Substring(VersionStart, LanguageStart - VersionStart);
                Version Found = ParseVersion(VersionText);
                if (Found == null)
                    continue;

                // Servicing can change the store version's build and revision.
                if (Wanted != null && (Found.Major != Wanted.Major || Found.Minor != Wanted.Minor))
                    continue;

                if (BestVersion == null || Found > BestVersion)
                {
                    BestVersion = Found;
                    BestVersionText = VersionText;
                    Best = Leaf;
                }
            }

            if (Best == null)
                return false;

            Assembly = new AssemblyManifest
            {
                Version = BestVersionText,
                GuestDirectory = StoreGuestPath + "\\" + Best + "\\",
            };

            string ManifestPath = GeneralHelper.IO.ResolveHostPath(StoreManifestsGuestPath + Best + ".manifest", BinaryFormat.PE);
            if (GeneralHelper.IO.TryReadHostFile(ManifestPath, MemoryBudget.SideBySideManifestBytes, out byte[] Manifest)
                && TryParseManifest(Manifest, Assembly))
                return true;

            // Compressed manifests require a DLL directory scan.
            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[!] Side by side: manifest of {Best} not readable, its window classes are missing.", LogFlags.Issues);

            Assembly.Files.Clear();
            Assembly.WindowClasses.Clear();

            List<WinDirectoryEntry> Dlls = NtQueryDirectoryFileCommon.ListDirectory(StoreGuestPath + "\\" + Best, "*.dll", null);
            if (Dlls != null)
            {
                foreach (WinDirectoryEntry Dll in Dlls)
                    Assembly.Files.Add(Dll.Name);
            }

            return true;
        }

        private static bool TryWriteActivationContext(List<AssemblyManifest> Assemblies, out ReadOnlySpan<byte> Context)
        {
            Context = default;
            ContextWriter Writer = new ContextWriter(MemoryBudget.ActivationContextBytes);

            if (!Writer.TryReserve(FirstSectionOffset, out _))
                return false;

            Writer.Write32(0x00, ActivationContextMagic);
            Writer.Write32(0x04, HeaderSize);
            Writer.Write32(0x08, 1u);
            Writer.Write32(0x10, TocOffset);
            Writer.Write32(0x18, AssemblyRosterOffset);

            Writer.Write32(TocOffset + 0x00, TocHeaderSize);
            Writer.Write32(TocOffset + 0x04, (uint)SectionIds.Length);
            Writer.Write32(TocOffset + 0x08, TocEntriesOffset);

            Writer.Write32(AssemblyRosterOffset + 0x00, 0x14u);
            Writer.Write32(AssemblyRosterOffset + 0x08, 1u);

            for (int Index = 0; Index < SectionIds.Length; Index++)
            {
                uint Id = SectionIds[Index];
                int Base = Writer.Length;
                bool Written = Id switch
                {
                    DllRedirectionSectionId => TryWriteDllRedirectionSection(Writer, Assemblies),
                    WindowClassRedirectionSectionId => TryWriteWindowClassSection(Writer, Assemblies),
                    _ => TryWriteEmptySection(Writer, Id == 4u || Id == 5u || Id == 6u || Id == 9u),
                };

                if (!Written)
                    return false;

                int Entry = TocEntriesOffset + Index * TocEntrySize;
                Writer.Write32(Entry + 0x00, Id);
                Writer.Write32(Entry + 0x04, (uint)Base);
                Writer.Write32(Entry + 0x08, (uint)(Writer.Length - Base));
            }

            Writer.Write32(0x0C, (uint)Writer.Length);
            Context = Writer.Written;
            return true;
        }

        private static bool TryWriteEmptySection(ContextWriter Writer, bool GuidSection)
        {
            if (!Writer.TryReserve(GuidSection ? GuidSectionHeaderSize : StringSectionHeaderSize, out int Base))
                return false;

            Writer.Write32(Base, GuidSection ? GuidSectionMagic : StringSectionMagic);
            return true;
        }

        private static bool TryWriteDllRedirectionSection(ContextWriter Writer, List<AssemblyManifest> Assemblies)
        {
            List<(string Key, string Path, int Roster)> Entries = new();
            HashSet<string> Seen = new(StringComparer.OrdinalIgnoreCase);
            for (int Assembly = 0; Assembly < Assemblies.Count; Assembly++)
            {
                foreach (string File in Assemblies[Assembly].Files)
                {
                    if (Seen.Add(File))
                        Entries.Add((File, Assemblies[Assembly].GuestDirectory, FirstDependencyRosterIndex + Assembly));
                }
            }

            if (!TryBeginStringSection(Writer, Entries.Count, out int Base))
                return false;

            for (int Index = 0; Index < Entries.Count; Index++)
            {
                if (!Writer.TryWriteString(Entries[Index].Key, out int KeyOffset, out int KeyBytes)
                    || !Writer.TryReserve(DllRedirectionSize + PathSegmentSize, out int Redirection)
                    || !Writer.TryWriteString(Entries[Index].Path, out int PathOffset, out int PathBytes))
                    return false;

                Writer.Write32(Redirection + 0x00, DllRedirectionSize);
                Writer.Write32(Redirection + 0x08, (uint)PathBytes);
                Writer.Write32(Redirection + 0x0C, 1u);
                Writer.Write32(Redirection + 0x10, (uint)(Redirection + DllRedirectionSize - Base));
                Writer.Write32(Redirection + DllRedirectionSize + 0x00, (uint)PathBytes);
                Writer.Write32(Redirection + DllRedirectionSize + 0x04, (uint)(PathOffset - Base));

                WriteStringEntry(Writer, Base, Index, KeyOffset, KeyBytes, Redirection, DllRedirectionSize, Entries[Index].Roster);
            }

            return true;
        }

        // Versioned-name offsets use the entry data. DLL-name offsets use the section.
        private static bool TryWriteWindowClassSection(ContextWriter Writer, List<AssemblyManifest> Assemblies)
        {
            List<(string Key, string Versioned, string Dll, int Roster)> Entries = new();
            HashSet<string> Seen = new(StringComparer.OrdinalIgnoreCase);
            for (int Assembly = 0; Assembly < Assemblies.Count; Assembly++)
            {
                string Version = Assemblies[Assembly].Version;
                foreach ((string Name, bool Versioned, string Dll) in Assemblies[Assembly].WindowClasses)
                {
                    if (Seen.Add(Name))
                        Entries.Add((Name, Versioned ? Version + "!" + Name : Name, Dll, FirstDependencyRosterIndex + Assembly));
                }
            }

            if (!TryBeginStringSection(Writer, Entries.Count, out int Base))
                return false;

            for (int Index = 0; Index < Entries.Count; Index++)
            {
                if (!Writer.TryWriteString(Entries[Index].Key, out int KeyOffset, out int KeyBytes)
                    || !Writer.TryReserve(WindowClassRedirectionSize, out int Data)
                    || !Writer.TryWriteString(Entries[Index].Versioned, out int VersionedOffset, out int VersionedBytes)
                    || !Writer.TryWriteString(Entries[Index].Dll, out int DllOffset, out int DllBytes))
                    return false;

                Writer.Write32(Data + 0x00, WindowClassRedirectionSize);
                Writer.Write32(Data + 0x08, (uint)VersionedBytes);
                Writer.Write32(Data + 0x0C, (uint)(VersionedOffset - Data));
                Writer.Write32(Data + 0x10, (uint)DllBytes);
                Writer.Write32(Data + 0x14, (uint)(DllOffset - Base));

                WriteStringEntry(Writer, Base, Index, KeyOffset, KeyBytes, Data, Writer.Length - Data, Entries[Index].Roster);
            }

            return true;
        }

        private static bool TryBeginStringSection(ContextWriter Writer, int Count, out int Base)
        {
            if (!Writer.TryReserve(StringSectionHeaderSize, out Base) || !Writer.TryReserve(Count * StringEntrySize, out _))
                return false;

            Writer.Write32(Base + 0x00, StringSectionMagic);
            Writer.Write32(Base + 0x04, StringSectionHeaderSize);
            Writer.Write32(Base + 0x08, 1u);
            Writer.Write32(Base + 0x0C, 1u);
            Writer.Write32(Base + 0x10, SectionCaseInsensitive);
            Writer.Write32(Base + 0x14, (uint)Count);
            Writer.Write32(Base + 0x18, StringSectionHeaderSize);
            Writer.Write32(Base + 0x1C, HashAlgorithmNone);
            return true;
        }

        private static void WriteStringEntry(ContextWriter Writer, int Base, int Index, int KeyOffset, int KeyBytes, int DataOffset, int DataBytes,
            int RosterIndex)
        {
            int Entry = Base + StringSectionHeaderSize + Index * StringEntrySize;
            Writer.Write32(Entry + 0x04, (uint)(KeyOffset - Base));
            Writer.Write32(Entry + 0x08, (uint)KeyBytes);
            Writer.Write32(Entry + 0x0C, (uint)(DataOffset - Base));
            Writer.Write32(Entry + 0x10, (uint)DataBytes);
            Writer.Write32(Entry + 0x14, (uint)RosterIndex);
        }

        private sealed class ContextWriter
        {
            private readonly int Limit;
            private byte[] Data = new byte[0x1000];

            public int Length { get; private set; }

            public ContextWriter(int Limit)
            {
                this.Limit = Limit;
            }

            public bool TryReserve(int Count, out int Offset)
            {
                Offset = Length;
                if (Count < 0 || Count > Limit - Length)
                    return false;

                int Aligned = (Count + 3) & ~3;
                if (Aligned > Limit - Length)
                    return false;

                if (Length + Aligned > Data.Length)
                    Array.Resize(ref Data, Math.Min(Limit, Math.Max(Data.Length * 2, Length + Aligned)));

                Length += Aligned;
                return true;
            }

            public bool TryWriteString(string Text, out int Offset, out int Bytes)
            {
                Bytes = Text.Length * 2;
                if (!TryReserve(Bytes + 2, out Offset))
                    return false;

                Encoding.Unicode.GetBytes(Text, Data.AsSpan(Offset));
                return true;
            }

            public void Write32(int Offset, uint Value) => BinaryPrimitives.WriteUInt32LittleEndian(Data.AsSpan(Offset), Value);

            public ReadOnlySpan<byte> Written => Data.AsSpan(0, Length);
        }

        // NT: sxs reports the highest supportedOS and maxversiontested not above the running version.
        // SupportedOs holds the major version in its low word, MaxVersionTested in its highest word.
        internal static void ReadCompatibility(byte[] Manifest, out uint SupportedOs, out ulong MaxVersionTested)
        {
            SupportedOs = 0;
            MaxVersionTested = 0;

            uint RunningOs = (WindowsVersionInfo.MajorVersion << 16) | WindowsVersionInfo.MinorVersion;
            ulong RunningVersion = ((ulong)WindowsVersionInfo.MajorVersion << 48) | ((ulong)WindowsVersionInfo.MinorVersion << 32) |
                ((ulong)WindowsVersionInfo.BuildNumber << 16);
            uint BestOs = 0;

            // NT: only assembly, compatibility and application lead to these elements.
            Span<bool> OnPath = stackalloc bool[3];

            try
            {
                using XmlReader Reader = CreateManifestReader(Manifest);

                while (Reader.Read())
                {
                    if (Reader.NodeType != XmlNodeType.Element)
                        continue;

                    int Depth = Reader.Depth;
                    if (Depth < 3)
                    {
                        OnPath[Depth] = Depth switch
                        {
                            0 => Reader.LocalName == "assembly" && Reader.NamespaceURI == AssemblyNamespace,
                            1 => OnPath[0] && Reader.LocalName == "compatibility" && Reader.NamespaceURI == CompatibilityNamespace,
                            _ => OnPath[1] && Reader.LocalName == "application" && Reader.NamespaceURI == CompatibilityNamespace,
                        };
                        continue;
                    }

                    if (Depth != 3 || !OnPath[2] || Reader.NamespaceURI != CompatibilityNamespace)
                        continue;

                    string Id = Reader.GetAttribute("Id");
                    if (Id == null)
                        continue;

                    if (Reader.LocalName == "supportedOS")
                    {
                        if (TryFindSupportedOs(Id, out uint Os) && Os <= RunningOs && Os > BestOs)
                            BestOs = Os;
                    }
                    else if (Reader.LocalName == "maxversiontested")
                    {
                        if (TryParseVersionQword(Id, out ulong Tested) && Tested <= RunningVersion && Tested > MaxVersionTested)
                            MaxVersionTested = Tested;
                    }
                }
            }
            catch (XmlException Ex)
            {
                Utils.LogError($"[WinSxS] Manifest compatibility section not read: {Ex.Message}");
                MaxVersionTested = 0;
                return;
            }

            SupportedOs = (BestOs >> 16) | ((BestOs & 0xFFFF) << 16);
        }

        // NT: an Id is a braced GUID or one of the names in SbSupportedOsList, compared without case.
        private static bool TryFindSupportedOs(string Id, out uint Os)
        {
            bool IsGuid = Guid.TryParseExact(Id, "B", out Guid Parsed);

            foreach ((Guid Guid, string Name, ushort Major, ushort Minor) in SupportedOsList)
            {
                if ((IsGuid && Guid == Parsed) || (!IsGuid && string.Equals(Id, Name, StringComparison.OrdinalIgnoreCase)))
                {
                    Os = ((uint)Major << 16) | Minor;
                    return true;
                }
            }

            Os = 0;
            return false;
        }

        // NT: sxs VersionToQword.
        private static bool TryParseVersionQword(string Text, out ulong Version)
        {
            Version = 0;
            if (string.IsNullOrEmpty(Text))
                return false;

            string[] Parts = Text.Split('.');
            if (Parts.Length > 4)
                return false;

            for (int Index = 0; Index < Parts.Length; Index++)
            {
                string Part = Parts[Index];
                if (Part.Length == 0)
                    return false;

                uint Value = 0;
                foreach (char Digit in Part)
                {
                    if (Digit < '0' || Digit > '9')
                        return false;

                    Value = Value * 10 + (uint)(Digit - '0');
                    if (Value >= 0xFFFF)
                        return false;
                }

                Version |= (ulong)Value << (16 * (3 - Index));
            }

            return true;
        }

        private static Version ParseVersion(string Text)
        {
            return Version.TryParse(Text, out Version Parsed) ? Parsed : null;
        }
    }
}
