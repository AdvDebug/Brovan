using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Brovan.Core.Emulation.OS.Windows.Win32k;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Side by side assembly redirection for the process image.
    /// </summary>
    internal static class WinSxS
    {
        private const uint ActivationContextMagic = 0x78746341;
        private const uint StringSectionMagic = 0x64487353;
        private const uint GuidSectionMagic = 0x64487347;

        private const uint HeaderSize = 0x20;
        private const uint TocOffset = 0x20;
        private const uint TocHeaderSize = 0x10;
        private const uint TocEntriesOffset = 0x30;
        private const uint TocEntrySize = 0x10;
        private const uint AssemblyRosterOffset = 0xC0;
        private const uint FirstSectionOffset = 0xD8;

        private const uint StringSectionHeaderSize = 0x2C;
        private const uint GuidSectionHeaderSize = 0x28;
        private const uint StringEntrySize = 0x18;
        private const uint RedirectionSize = 0x14;
        private const uint PathSegmentSize = 0x08;

        private const uint SectionCaseInsensitive = 1;
        private const uint HashAlgorithmNone = 0xFFFFFFFF;
        private const uint DllRedirectionSectionId = 2;

        private const int MaxRedirectedDlls = 512;

        internal const ulong PebActivationContextData64 = 0x2F8;
        internal const ulong PebActivationContextData32 = 0x1F8;

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
        }

        internal static ulong BuildProcessActivationContext(BinaryEmulator Instance, WinModule Module)
        {
            if (Instance == null || Module == null || Instance._binary?.FileFormat != BinaryFormat.PE)
                return 0;

            byte[] Manifest = Win32kDpi.ReadImageManifest(Instance, Module);
            if (Manifest == null)
                return 0;

            List<AssemblyIdentity> Dependencies = ParseDependencies(Manifest);
            if (Dependencies.Count == 0)
                return 0;

            Dictionary<string, string> Redirects = new(StringComparer.OrdinalIgnoreCase);
            foreach (AssemblyIdentity Identity in Dependencies)
            {
                string Directory = ResolveAssemblyDirectory(Identity, Instance._binary.Architecture);
                if (string.IsNullOrEmpty(Directory))
                    continue;

                CollectAssemblyDlls(Directory, Redirects);
            }

            if (Redirects.Count == 0)
                return 0;

            byte[] Data = BuildActivationContextData(Redirects);
            ulong Address = Instance.MapUniqueAddress((ulong)Data.Length, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            Instance._emulator.WriteMemory(Address, Data);

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] Side by side: redirected {Redirects.Count} DLL(s) for {Module.Name}.", LogFlags.General);

            return Address;
        }

        private static List<AssemblyIdentity> ParseDependencies(byte[] Manifest)
        {
            List<AssemblyIdentity> Dependencies = new();

            try
            {
                using XmlReader Reader = CreateManifestReader(Manifest);

                bool InDependency = false;

                while (Reader.Read())
                {
                    if (Reader.NodeType == XmlNodeType.EndElement && Reader.LocalName == "dependency")
                    {
                        InDependency = false;
                        continue;
                    }

                    if (Reader.NodeType != XmlNodeType.Element)
                        continue;

                    if (Reader.LocalName == "dependency")
                    {
                        InDependency = !Reader.IsEmptyElement;
                        continue;
                    }

                    if (!InDependency || Reader.LocalName != "assemblyIdentity")
                        continue;

                    AssemblyIdentity Identity = new AssemblyIdentity
                    {
                        Name = Reader.GetAttribute("name"),
                        Version = Reader.GetAttribute("version"),
                        PublicKeyToken = Reader.GetAttribute("publicKeyToken"),
                        ProcessorArchitecture = Reader.GetAttribute("processorArchitecture"),
                        Language = Reader.GetAttribute("language"),
                    };

                    if (!string.IsNullOrEmpty(Identity.Name))
                        Dependencies.Add(Identity);
                }
            }
            catch (XmlException)
            {
            }

            return Dependencies;
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

        private static string GetSideBySideRoot()
        {
            if (GeneralHelper.IsWindows)
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS");

            return Path.Combine(GeneralHelper.WindowsLibsPath, "WinSxS");
        }

        private static string ResolveAssemblyDirectory(AssemblyIdentity Identity, BinaryArchitecture Architecture)
        {
            string Root = GetSideBySideRoot();
            if (!Directory.Exists(Root))
                return null;

            string ArchitectureName = Architecture == BinaryArchitecture.x64 ? "amd64" : "x86";
            if (!string.IsNullOrEmpty(Identity.ProcessorArchitecture) && Identity.ProcessorArchitecture != "*")
                ArchitectureName = Identity.ProcessorArchitecture.ToLowerInvariant();

            string Language = string.IsNullOrEmpty(Identity.Language) || Identity.Language == "*"
                ? "none"
                : Identity.Language.ToLowerInvariant();

            string Token = (Identity.PublicKeyToken ?? string.Empty).ToLowerInvariant();
            string Prefix = $"{ArchitectureName}_{Identity.Name.ToLowerInvariant()}_{Token}_";
            string LanguagePart = $"_{Language}_";

            string Best = null;
            Version BestVersion = null;
            Version Wanted = ParseVersion(Identity.Version);

            foreach (string Candidate in Directory.EnumerateDirectories(Root, Prefix + "*"))
            {
                string Leaf = Path.GetFileName(Candidate);
                int VersionStart = Prefix.Length;
                int LanguageStart = Leaf.IndexOf(LanguagePart, VersionStart, StringComparison.Ordinal);
                if (LanguageStart <= VersionStart)
                    continue;

                Version Found = ParseVersion(Leaf.Substring(VersionStart, LanguageStart - VersionStart));
                if (Found == null)
                    continue;

                // Manifests name a binding version, the store holds the serviced build.
                if (Wanted != null && (Found.Major != Wanted.Major || Found.Minor != Wanted.Minor))
                    continue;

                if (BestVersion == null || Found > BestVersion)
                {
                    BestVersion = Found;
                    Best = Candidate;
                }
            }

            return Best;
        }

        private static Version ParseVersion(string Text)
        {
            return Version.TryParse(Text, out Version Parsed) ? Parsed : null;
        }

        private static void CollectAssemblyDlls(string AssemblyDirectory, Dictionary<string, string> Redirects)
        {
            string Prefix = AssemblyDirectory.EndsWith('\\') ? AssemblyDirectory : AssemblyDirectory + "\\";

            foreach (string Entry in Directory.EnumerateFiles(AssemblyDirectory, "*.dll"))
            {
                if (Redirects.Count >= MaxRedirectedDlls)
                    return;

                string Leaf = Path.GetFileName(Entry);
                if (!string.IsNullOrEmpty(Leaf))
                    Redirects[Leaf] = Prefix;
            }
        }

        private static byte[] BuildActivationContextData(Dictionary<string, string> Redirects)
        {
            int Count = Redirects.Count;

            uint EntriesOffset = StringSectionHeaderSize;
            uint RedirectionsOffset = EntriesOffset + (uint)Count * StringEntrySize;
            uint SegmentsOffset = RedirectionsOffset + (uint)Count * RedirectionSize;
            uint StringsOffset = SegmentsOffset + (uint)Count * PathSegmentSize;

            List<byte[]> Keys = new(Count);
            List<byte[]> Paths = new(Count);
            uint StringBytes = 0;

            foreach (KeyValuePair<string, string> Redirect in Redirects)
            {
                byte[] Key = Encoding.Unicode.GetBytes(Redirect.Key + "\0");
                byte[] PathText = Encoding.Unicode.GetBytes(Redirect.Value + "\0");
                Keys.Add(Key);
                Paths.Add(PathText);
                StringBytes += (uint)(Key.Length + PathText.Length);
            }

            uint DllSectionSize = StringsOffset + StringBytes;

            uint TotalSize = FirstSectionOffset;
            uint[] SectionOffsets = new uint[SectionIds.Length];
            uint[] SectionSizes = new uint[SectionIds.Length];

            for (int Index = 0; Index < SectionIds.Length; Index++)
            {
                uint Id = SectionIds[Index];
                bool GuidSection = Id == 4u || Id == 5u || Id == 6u || Id == 9u;
                uint Size = Id == DllRedirectionSectionId
                    ? DllSectionSize
                    : (GuidSection ? GuidSectionHeaderSize : StringSectionHeaderSize);

                SectionOffsets[Index] = TotalSize;
                SectionSizes[Index] = Size;
                TotalSize += (Size + 3u) & ~3u;
            }

            byte[] Data = new byte[TotalSize];

            Write32(Data, 0x00, ActivationContextMagic);
            Write32(Data, 0x04, HeaderSize);
            Write32(Data, 0x08, 1u);
            Write32(Data, 0x0C, TotalSize);
            Write32(Data, 0x10, TocOffset);
            Write32(Data, 0x18, AssemblyRosterOffset);

            Write32(Data, (int)TocOffset + 0x00, TocHeaderSize);
            Write32(Data, (int)TocOffset + 0x04, (uint)SectionIds.Length);
            Write32(Data, (int)TocOffset + 0x08, TocEntriesOffset);

            for (int Index = 0; Index < SectionIds.Length; Index++)
            {
                int Entry = (int)(TocEntriesOffset + (uint)Index * TocEntrySize);
                Write32(Data, Entry + 0x00, SectionIds[Index]);
                Write32(Data, Entry + 0x04, SectionOffsets[Index]);
                Write32(Data, Entry + 0x08, SectionSizes[Index]);

                uint Id = SectionIds[Index];
                bool GuidSection = Id == 4u || Id == 5u || Id == 6u || Id == 9u;
                int Section = (int)SectionOffsets[Index];
                Write32(Data, Section, GuidSection ? GuidSectionMagic : StringSectionMagic);

                if (Id != DllRedirectionSectionId)
                    Write32(Data, Section + 0x14, 0u);
            }

            Write32(Data, (int)AssemblyRosterOffset + 0x00, 0x14u);
            Write32(Data, (int)AssemblyRosterOffset + 0x08, 1u);

            int Base = (int)SectionOffsets[Array.IndexOf(SectionIds, DllRedirectionSectionId)];

            Write32(Data, Base + 0x04, StringSectionHeaderSize);
            Write32(Data, Base + 0x08, 1u);
            Write32(Data, Base + 0x0C, 1u);
            Write32(Data, Base + 0x10, SectionCaseInsensitive);
            Write32(Data, Base + 0x14, (uint)Count);
            Write32(Data, Base + 0x18, EntriesOffset);
            Write32(Data, Base + 0x1C, HashAlgorithmNone);

            uint StringCursor = StringsOffset;

            for (int Index = 0; Index < Count; Index++)
            {
                byte[] Key = Keys[Index];
                byte[] PathText = Paths[Index];

                uint KeyOffset = StringCursor;
                Buffer.BlockCopy(Key, 0, Data, Base + (int)KeyOffset, Key.Length);
                StringCursor += (uint)Key.Length;

                uint PathOffset = StringCursor;
                Buffer.BlockCopy(PathText, 0, Data, Base + (int)PathOffset, PathText.Length);
                StringCursor += (uint)PathText.Length;

                uint RedirectionOffset = RedirectionsOffset + (uint)Index * RedirectionSize;
                uint SegmentOffset = SegmentsOffset + (uint)Index * PathSegmentSize;
                uint PathLength = (uint)PathText.Length - 2;

                int Entry = Base + (int)(EntriesOffset + (uint)Index * StringEntrySize);
                Write32(Data, Entry + 0x04, KeyOffset);
                Write32(Data, Entry + 0x08, (uint)Key.Length - 2);
                Write32(Data, Entry + 0x0C, RedirectionOffset);
                Write32(Data, Entry + 0x10, RedirectionSize);
                Write32(Data, Entry + 0x14, 1u);

                int Redirection = Base + (int)RedirectionOffset;
                Write32(Data, Redirection + 0x00, RedirectionSize);
                Write32(Data, Redirection + 0x08, PathLength);
                Write32(Data, Redirection + 0x0C, 1u);
                Write32(Data, Redirection + 0x10, SegmentOffset);

                int Segment = Base + (int)SegmentOffset;
                Write32(Data, Segment + 0x00, PathLength);
                Write32(Data, Segment + 0x04, PathOffset);
            }

            return Data;
        }

        private static void Write32(byte[] Data, int Offset, uint Value)
        {
            Data[Offset + 0] = (byte)Value;
            Data[Offset + 1] = (byte)(Value >> 8);
            Data[Offset + 2] = (byte)(Value >> 16);
            Data[Offset + 3] = (byte)(Value >> 24);
        }
    }
}
