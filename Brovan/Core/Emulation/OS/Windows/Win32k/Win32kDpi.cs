using System.Runtime.CompilerServices;
using System.Xml;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal static class Win32kDpi
    {
        internal const uint ContextUnaware = 0x00006010;
        internal const uint ContextUnawareGdiScaled = 0x40006010;
        internal const uint ContextPerMonitorV2 = 0x00000022;

        internal const uint AwarenessUnaware = 0;
        internal const uint AwarenessSystem = 1;
        internal const uint AwarenessPerMonitor = 2;

        internal const uint MonitorDpiTypeEffective = 0;

        private const uint SystemAwareFlags = 0x11;
        private const uint AwarenessMask = 0xF;
        private const uint DpiFieldMask = 0x1FF;
        private const int DpiFieldShift = 8;

        private const ulong TebContextOffset = 0x8E8;

        private const ulong WindowContextOffset = 0x120;
        private const ulong WindowDpiOffset = 0x11C;
        private const ulong WindowDpiAlternateOffset = 0x11E;

        private const int ResourceDataDirectoryIndex = 2;
        private const uint ResourceTypeManifest = 24;
        private const uint ResourceIdCreateProcessManifest = 1;
        private const int ResourceDirectoryHeaderSize = 0x10;
        private const int ResourceDirectoryEntrySize = 8;
        private const int ResourceDataEntrySize = 0x10;
        private const int MaxResourceDirectoryEntries = 0x1000;
        private const int MaxManifestBytes = 0x100000;

        private static readonly ConditionalWeakTable<BinaryEmulator, DpiState> States = new();

        private sealed class DpiState
        {
            public uint ProcessContext = ContextUnaware;
            public bool Locked;
        }

        private static DpiState GetState(BinaryEmulator Instance)
        {
            return States.GetValue(Instance, static _ => new DpiState());
        }

        internal static uint GetProcessContext(BinaryEmulator Instance)
        {
            return GetState(Instance).ProcessContext;
        }

        internal static uint GetAwareness(BinaryEmulator Instance)
        {
            return GetState(Instance).ProcessContext & AwarenessMask;
        }

        internal static DpiAwareness GetHostAwareness(BinaryEmulator Instance)
        {
            return GetAwareness(Instance) switch
            {
                AwarenessPerMonitor => DpiAwareness.PerMonitor,
                AwarenessSystem => DpiAwareness.System,
                _ => DpiAwareness.Unaware,
            };
        }

        internal static uint GetEffectiveDpi(BinaryEmulator Instance)
        {
            return GetAwareness(Instance) == AwarenessUnaware ? HostDisplayMetrics.DefaultDpi : HostDisplayMetrics.SystemDpi;
        }

        internal static uint GetMonitorDpi(BinaryEmulator Instance, uint DpiType)
        {
            return DpiType == MonitorDpiTypeEffective ? GetEffectiveDpi(Instance) : HostDisplayMetrics.RawDpi;
        }

        internal static int GetScreenWidth(BinaryEmulator Instance)
        {
            return ScaleToProcess(Instance, HostDisplayMetrics.ScreenWidth);
        }

        internal static int GetScreenHeight(BinaryEmulator Instance)
        {
            return ScaleToProcess(Instance, HostDisplayMetrics.ScreenHeight);
        }

        private static int ScaleToProcess(BinaryEmulator Instance, int PhysicalPixels)
        {
            if (!HostDisplayMetrics.VirtualizesUnawareWindows)
                return PhysicalPixels;

            uint Dpi = GetEffectiveDpi(Instance);
            uint SystemDpi = HostDisplayMetrics.SystemDpi;
            if (Dpi == SystemDpi || SystemDpi == 0)
                return PhysicalPixels;

            return Math.Max((int)((long)PhysicalPixels * Dpi / SystemDpi), 1);
        }

        internal static uint BuildContext(uint Awareness, bool GdiScaled = false)
        {
            return Awareness switch
            {
                AwarenessSystem => ((HostDisplayMetrics.SystemDpi & DpiFieldMask) << DpiFieldShift) | SystemAwareFlags,
                AwarenessPerMonitor => ContextPerMonitorV2,
                _ => GdiScaled ? ContextUnawareGdiScaled : ContextUnaware,
            };
        }

        internal static bool IsValidContext(uint Context)
        {
            return (Context & AwarenessMask) <= AwarenessPerMonitor;
        }

        internal static bool TrySetProcessContext(BinaryEmulator Instance, uint Context)
        {
            if (!IsValidContext(Context))
                return false;

            DpiState State = GetState(Instance);
            if (State.Locked)
                return false;

            State.ProcessContext = (Context & AwarenessMask) == AwarenessSystem
                ? BuildContext(AwarenessSystem)
                : Context;

            State.Locked = true;
            PublishContext(Instance);
            return true;
        }

        private static void PublishContext(BinaryEmulator Instance)
        {
            foreach (EmulatedThread Thread in Instance.GetThreadsSnapshot())
            {
                WindowsThreadState ThreadState = WinEmulatedThread.TryGetState(Thread);
                if (ThreadState != null)
                    ApplyThreadContext(Instance, ThreadState.NativeTeb != 0 ? ThreadState.NativeTeb : ThreadState.Teb);
            }

            Instance.WinHelper?.RefreshDisplayDependentState();
        }

        internal static void ApplyThreadContext(BinaryEmulator Instance, ulong Teb)
        {
            if (Teb == 0)
                return;

            Instance._emulator.WriteMemory(Teb + TebContextOffset, GetProcessContext(Instance), 4);
        }

        internal static void ApplyWindowContext(BinaryEmulator Instance, ulong ClientWindowAddress)
        {
            if (ClientWindowAddress == 0)
                return;

            uint Context = GetProcessContext(Instance);
            Instance._emulator.WriteMemory(ClientWindowAddress + WindowContextOffset, Context, 4);
            Instance._emulator.WriteMemory(ClientWindowAddress + WindowDpiOffset, (ushort)GetEffectiveDpi(Instance), 2);
            Instance._emulator.WriteMemory(ClientWindowAddress + WindowDpiAlternateOffset, (ushort)0, 2);
        }

        internal static void DrainHostDpiChange(BinaryEmulator Instance)
        {
            uint NewDpi = HostEventQueue.ConsumeDpiChange();
            if (NewDpi == 0)
                return;

            Instance.WinHelper?.RefreshDisplayDependentState();

            if (GetAwareness(Instance) != AwarenessPerMonitor)
                return;

            ulong Hwnd = Instance.WinHelper?.GetForegroundWindow() ?? 0;
            WinWindow Window = Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return;

            ulong Rect = Instance.WinHelper.EnsureDpiChangeRect();
            if (Rect == 0)
                return;

            int Left = Window.X == unchecked((int)0x80000000) ? 0 : Window.X;
            int Top = Window.Y == unchecked((int)0x80000000) ? 0 : Window.Y;
            Instance._emulator.WriteMemory(Rect + 0x00, (uint)Left, 4);
            Instance._emulator.WriteMemory(Rect + 0x04, (uint)Top, 4);
            Instance._emulator.WriteMemory(Rect + 0x08, (uint)(Left + (int)Window.Width), 4);
            Instance._emulator.WriteMemory(Rect + 0x0C, (uint)(Top + (int)Window.Height), 4);

            Win32kHelper.PostMessage(Instance, Hwnd, Win32kHelper.WM_DPICHANGED, (NewDpi << 16) | NewDpi, Rect);
        }

        internal static void SeedFromImage(BinaryEmulator Instance, WinModule Module)
        {
            if (Module == null || Instance._binary?.FileFormat != BinaryFormat.PE)
                return;

            byte[] Manifest = ReadExternalManifest(Module) ?? ReadEmbeddedManifest(Instance, Module);
            if (Manifest == null)
                return;

            try
            {
                if (TryParseManifestAwareness(Manifest, out uint Awareness, out bool GdiScaled))
                {
                    DpiState State = GetState(Instance);
                    State.ProcessContext = BuildContext(Awareness, GdiScaled);
                    State.Locked = true;
                }
            }
            catch (XmlException)
            {
            }
            catch (InvalidOperationException)
            {
            }
        }

        private static byte[] ReadExternalManifest(WinModule Module)
        {
            if (string.IsNullOrEmpty(Module.Path))
                return null;

            try
            {
                string Path = Module.Path + ".manifest";
                if (!File.Exists(Path))
                    return null;

                using FileStream Stream = File.OpenRead(Path);
                if (Stream.Length == 0 || Stream.Length > MaxManifestBytes)
                    return null;

                byte[] Buffer = new byte[Stream.Length];
                return Stream.ReadAtLeast(Buffer, Buffer.Length, false) == Buffer.Length ? Buffer : null;
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }

        private static byte[] ReadEmbeddedManifest(BinaryEmulator Instance, WinModule Module)
        {
            if (!TryFindManifestResource(Instance, Module, out ulong Address, out uint Size))
                return null;

            byte[] Buffer = new byte[Size];
            return Instance.ReadMemory(Address, Buffer, Size) ? Buffer : null;
        }

        private static bool TryFindManifestResource(BinaryEmulator Instance, WinModule Module, out ulong Address, out uint Size)
        {
            Address = 0;
            Size = 0;

            uint DirectoryRva = Instance._binary.Architecture == BinaryArchitecture.x64
                ? Instance._binary.PE.OptionalHeader64.DataDirectory[ResourceDataDirectoryIndex].VirtualAddress
                : Instance._binary.PE.OptionalHeader32.DataDirectory[ResourceDataDirectoryIndex].VirtualAddress;

            if (DirectoryRva == 0)
                return false;

            ulong Root = Module.MappedBase + DirectoryRva;
            if (!TryFindDirectoryEntry(Instance, Root, Root, ResourceTypeManifest, out ulong TypeDirectory, out bool IsDirectory) || !IsDirectory)
                return false;

            if (!TryFindDirectoryEntry(Instance, Root, TypeDirectory, ResourceIdCreateProcessManifest, out ulong NameDirectory, out IsDirectory) || !IsDirectory)
                return false;

            if (!TryFindDirectoryEntry(Instance, Root, NameDirectory, uint.MaxValue, out ulong DataEntry, out IsDirectory) || IsDirectory)
                return false;

            if (!Instance.IsRegionMapped(DataEntry, ResourceDataEntrySize))
                return false;

            uint DataRva = Instance.ReadMemoryUInt(DataEntry + 0x00);
            uint DataSize = Instance.ReadMemoryUInt(DataEntry + 0x04);
            if (DataRva == 0 || DataSize == 0 || DataSize > MaxManifestBytes)
                return false;

            Address = Module.MappedBase + DataRva;
            Size = DataSize;
            return Instance.IsRegionMapped(Address, DataSize);
        }

        private static bool TryFindDirectoryEntry(BinaryEmulator Instance, ulong Root, ulong Directory, uint Id, out ulong Target, out bool IsDirectory)
        {
            Target = 0;
            IsDirectory = false;

            if (!Instance.IsRegionMapped(Directory, ResourceDirectoryHeaderSize))
                return false;

            int NamedEntries = Instance._emulator.ReadMemoryUShort(Directory + 0x0C);
            int IdEntries = Instance._emulator.ReadMemoryUShort(Directory + 0x0E);
            int TotalEntries = NamedEntries + IdEntries;
            if (TotalEntries <= 0 || TotalEntries > MaxResourceDirectoryEntries)
                return false;

            ulong EntryBase = Directory + ResourceDirectoryHeaderSize;
            if (!Instance.IsRegionMapped(EntryBase, (ulong)(TotalEntries * ResourceDirectoryEntrySize)))
                return false;

            for (int i = NamedEntries; i < TotalEntries; i++)
            {
                ulong Entry = EntryBase + (ulong)(i * ResourceDirectoryEntrySize);
                uint EntryId = Instance.ReadMemoryUInt(Entry + 0x00);
                if (Id != uint.MaxValue && EntryId != Id)
                    continue;

                uint OffsetToData = Instance.ReadMemoryUInt(Entry + 0x04);
                IsDirectory = (OffsetToData & 0x80000000u) != 0;
                Target = Root + (OffsetToData & 0x7FFFFFFFu);
                return true;
            }

            return false;
        }

        private static bool TryParseManifestAwareness(byte[] Manifest, out uint Awareness, out bool GdiScaled)
        {
            Awareness = AwarenessUnaware;
            GdiScaled = false;

            string DpiAwarenessValue = null;
            string DpiAwareValue = null;
            string GdiScalingValue = null;

            XmlReaderSettings Settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                IgnoreComments = true,
                IgnoreWhitespace = true,
                IgnoreProcessingInstructions = true,
                XmlResolver = null,
                CloseInput = true,
            };

            using MemoryStream Stream = new MemoryStream(Manifest, 0, Manifest.Length, false);
            using XmlReader Reader = XmlReader.Create(Stream, Settings);

            while (!Reader.EOF)
            {
                if (Reader.NodeType != XmlNodeType.Element)
                {
                    Reader.Read();
                    continue;
                }

                string Name = Reader.LocalName;
                if (Name != "dpiAwareness" && Name != "dpiAware" && Name != "gdiScaling")
                {
                    Reader.Read();
                    continue;
                }

                string Value = Reader.ReadElementContentAsString();
                switch (Name)
                {
                    case "dpiAwareness":
                        DpiAwarenessValue ??= Value;
                        break;
                    case "dpiAware":
                        DpiAwareValue ??= Value;
                        break;
                    default:
                        GdiScalingValue ??= Value;
                        break;
                }
            }

            GdiScaled = string.Equals(GdiScalingValue?.Trim(), "true", StringComparison.OrdinalIgnoreCase);

            if (DpiAwarenessValue != null)
            {
                foreach (string Token in DpiAwarenessValue.Split(','))
                {
                    switch (Token.Trim().ToLowerInvariant())
                    {
                        case "permonitorv2":
                        case "permonitor":
                            Awareness = AwarenessPerMonitor;
                            return true;
                        case "system":
                            Awareness = AwarenessSystem;
                            return true;
                        case "unaware":
                            Awareness = AwarenessUnaware;
                            return true;
                    }
                }
            }

            if (DpiAwareValue == null)
                return GdiScaled;

            switch (DpiAwareValue.Trim().ToLowerInvariant())
            {
                case "true/pm":
                case "per monitor":
                case "permonitor":
                    Awareness = AwarenessPerMonitor;
                    return true;
                case "true":
                    Awareness = AwarenessSystem;
                    return true;
                case "false":
                    Awareness = AwarenessUnaware;
                    return true;
                default:
                    return GdiScaled;
            }
        }
    }
}
