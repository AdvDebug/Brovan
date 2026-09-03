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

            XmlReaderSettings Settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                IgnoreComments = true,
                IgnoreWhitespace = true,
                IgnoreProcessingInstructions = true,
                XmlResolver = null,
                CloseInput = true,
            };

            try
            {
                using MemoryStream Stream = new MemoryStream(Manifest, 0, Manifest.Length, false);
                using XmlReader Reader = XmlReader.Create(Stream, Settings);

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
