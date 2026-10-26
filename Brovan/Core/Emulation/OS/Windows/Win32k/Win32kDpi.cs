using System.Buffers.Binary;
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

        internal const int DpiInformationSize = 0x60;
        private const int DpiInfoUnscaledOffset = 0x00;
        private const int DpiInfoScaleOffset = 0x08;
        private const int DpiInfoPhysicalSizeOffset = 0x18;
        private const int DpiInfoResolutionOffset = 0x20;
        private const int DpiInfoRawDpiOffset = 0x28;
        private const int DpiInfoOverrideDpiOffset = 0x30;
        private const uint UnscaledPercent = 100;
        private const uint TenthsOfMillimetrePerInch = 254;

        private const uint SystemAwareFlags = 0x11;
        private const uint AwarenessMask = 0xF;
        private const uint DpiFieldMask = 0x1FF;
        private const int DpiFieldShift = 8;

        private const ulong TebContextOffset = 0x8E8;

        private const ulong WindowContextOffset = 0x120;
        private const ulong WindowDpiOffset = 0x11C;
        private const ulong WindowDpiAlternateOffset = 0x11E;

        private const uint ResourceIdCreateProcessManifest = 1;
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

        internal static void GetWorkArea(BinaryEmulator Instance, out int Left, out int Top, out int Right, out int Bottom)
        {
            HostDisplayMetrics.GetWorkArea(out int HostLeft, out int HostTop, out int HostRight, out int HostBottom);
            Left = ScalePositionToProcess(Instance, HostLeft);
            Top = ScalePositionToProcess(Instance, HostTop);
            Right = ScalePositionToProcess(Instance, HostRight);
            Bottom = ScalePositionToProcess(Instance, HostBottom);
        }

        // NT _DPI_INFORMATION. The view distance and the override range stay zero.
        internal static void FillDpiInformation(Span<byte> Info)
        {
            Info.Slice(0, DpiInformationSize).Clear();

            uint Scale = (UnscaledPercent * HostDisplayMetrics.SystemDpi + HostDisplayMetrics.DefaultDpi / 2) / HostDisplayMetrics.DefaultDpi;
            uint RawDpi = HostDisplayMetrics.RawDpi;
            uint Width = (uint)Math.Max(HostDisplayMetrics.ScreenWidth, 0);
            uint Height = (uint)Math.Max(HostDisplayMetrics.ScreenHeight, 0);

            WritePair(Info, DpiInfoUnscaledOffset, UnscaledPercent, UnscaledPercent);
            WritePair(Info, DpiInfoScaleOffset, Scale, Scale);
            WritePair(Info, DpiInfoPhysicalSizeOffset, MillimetresAt(Width, RawDpi), MillimetresAt(Height, RawDpi));
            WritePair(Info, DpiInfoResolutionOffset, Width, Height);
            WritePair(Info, DpiInfoRawDpiOffset, RawDpi, RawDpi);
            WritePair(Info, DpiInfoOverrideDpiOffset, RawDpi, RawDpi);
        }

        private static uint MillimetresAt(uint Pixels, uint Dpi)
        {
            return Dpi == 0 ? 0 : (Pixels * TenthsOfMillimetrePerInch + Dpi * 5) / (Dpi * 10);
        }

        private static void WritePair(Span<byte> Info, int Offset, uint First, uint Second)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(Offset), First);
            BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(Offset + 4), Second);
        }

        internal static bool TryGetHostCursorPosition(BinaryEmulator Instance, out int X, out int Y)
        {
            X = 0;
            Y = 0;
            if (!HostDisplayMetrics.TryGetCursorPosition(out int HostX, out int HostY))
                return false;

            X = ScalePositionToProcess(Instance, HostX);
            Y = ScalePositionToProcess(Instance, HostY);
            return true;
        }

        private static int ScalePositionToProcess(BinaryEmulator Instance, int PhysicalPixels)
        {
            return ScaleToProcess(Instance, PhysicalPixels, int.MinValue);
        }

        private static int ScaleToProcess(BinaryEmulator Instance, int PhysicalPixels, int Minimum = 1)
        {
            if (!HostDisplayMetrics.VirtualizesUnawareWindows)
                return PhysicalPixels;

            uint Dpi = GetEffectiveDpi(Instance);
            uint SystemDpi = HostDisplayMetrics.SystemDpi;
            if (Dpi == SystemDpi || SystemDpi == 0)
                return PhysicalPixels;

            return Math.Max((int)((long)PhysicalPixels * Dpi / SystemDpi), Minimum);
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
            Instance.WinHelper.PublishUserDisplayDpi();
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

            byte[] Manifest = ReadImageManifest(Instance, Module);
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

        internal static byte[] ReadImageManifest(BinaryEmulator Instance, WinModule Module)
        {
            if (Module == null)
                return null;

            // NT: an embedded manifest wins over image.manifest.
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

            return GeneralHelper.IO.TryReadHostFile(ImagePath + ".manifest", MaxManifestBytes, out byte[] Manifest) ? Manifest : null;
        }

        private static byte[] ReadEmbeddedManifest<TImage>(TImage Image) where TImage : struct, IImageReader
        {
            if (!ImageResources.TryFindResource(Image, ImageResources.TypeManifest, ResourceIdCreateProcessManifest, out uint DataRva, out uint DataSize)
                || DataSize > MaxManifestBytes)
                return null;

            byte[] Manifest = new byte[DataSize];
            return Image.TryRead(DataRva, Manifest) ? Manifest : null;
        }

        private static bool TryParseManifestAwareness(byte[] Manifest, out uint Awareness, out bool GdiScaled)
        {
            Awareness = AwarenessUnaware;
            GdiScaled = false;

            string DpiAwarenessValue = null;
            string DpiAwareValue = null;
            string GdiScalingValue = null;

            using XmlReader Reader = WinSxS.CreateManifestReader(Manifest);

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
