using System;
using System.Collections.Generic;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed unsafe class BrovVulkWsi
    {
        internal readonly struct SwapchainPlan
        {
            public readonly IntPtr Surface;
            public readonly uint GuestFormat;
            public readonly uint HostFormat;
            public readonly bool HiddenTransform;

            public SwapchainPlan(IntPtr surface, uint guestFormat, uint hostFormat, bool hiddenTransform)
            {
                Surface = surface;
                GuestFormat = guestFormat;
                HostFormat = hostFormat;
                HiddenTransform = hiddenTransform;
            }

            public bool Substituted => GuestFormat != HostFormat;
        }

        private sealed class SurfaceState
        {
            public IntPtr PhysicalDevice;
            public uint[] Formats = Array.Empty<uint>();
            public uint[] PresentModes = Array.Empty<uint>();
            public bool HiddenTransform;
        }

        private readonly struct ImageFormat
        {
            public readonly IntPtr Swapchain;
            public readonly uint GuestFormat;
            public readonly uint HostFormat;

            public ImageFormat(IntPtr swapchain, uint guestFormat, uint hostFormat)
            {
                Swapchain = swapchain;
                GuestFormat = guestFormat;
                HostFormat = hostFormat;
            }
        }

        private const uint TransformIdentity = 0x1u;
        private const uint CompositeOpaque = 0x1u;
        private const uint CompositePreMultiplied = 0x2u;
        private const uint CompositePostMultiplied = 0x4u;
        private const uint CompositeInherit = 0x8u;
        private const uint UsageColorAttachment = 0x10u;
        private const uint PresentModeImmediate = 0u;
        private const uint PresentModeMailbox = 1u;
        private const uint PresentModeFifo = 2u;
        private const uint PresentModeFifoRelaxed = 3u;
        private const uint LayoutPresentSrc = 1000001002u;
        private const uint StructureTypeImageFormatList = 1000147000u;
        private const int Suboptimal = 1000001003;

        private const int MaxSurfaceFormats = 64;
        private const int MaxPresentModes = 16;

        private static readonly int CapsSize = BrovVulkLayout.StructSize["VkSurfaceCapabilitiesKHR"];
        private static readonly int CapsMinImageCount = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.minImageCount"];
        private static readonly int CapsMaxImageCount = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.maxImageCount"];
        private static readonly int CapsMinImageExtent = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.minImageExtent"];
        private static readonly int CapsMaxImageExtent = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.maxImageExtent"];
        private static readonly int CapsMaxArrayLayers = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.maxImageArrayLayers"];
        private static readonly int CapsSupportedTransforms = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.supportedTransforms"];
        private static readonly int CapsCurrentTransform = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.currentTransform"];
        private static readonly int CapsSupportedAlpha = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.supportedCompositeAlpha"];
        private static readonly int CapsSupportedUsage = BrovVulkLayout.MemberOffset["VkSurfaceCapabilitiesKHR.supportedUsageFlags"];

        private static readonly int ExtentWidth = BrovVulkLayout.MemberOffset["VkExtent2D.width"];
        private static readonly int ExtentHeight = BrovVulkLayout.MemberOffset["VkExtent2D.height"];

        private static readonly int SurfaceFormatSize = BrovVulkLayout.StructSize["VkSurfaceFormatKHR"];
        private static readonly int SurfaceFormatFormat = BrovVulkLayout.MemberOffset["VkSurfaceFormatKHR.format"];
        private static readonly int SurfaceFormatColorSpace = BrovVulkLayout.MemberOffset["VkSurfaceFormatKHR.colorSpace"];

        private static readonly int Caps2Inner = BrovVulkLayout.MemberOffset["VkSurfaceCapabilities2KHR.surfaceCapabilities"];
        private static readonly int SurfaceInfo2Surface = BrovVulkLayout.MemberOffset["VkPhysicalDeviceSurfaceInfo2KHR.surface"];

        private static readonly int SwapPNext = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.pNext"];
        private static readonly int SwapSurface = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.surface"];
        private static readonly int SwapMinImageCount = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.minImageCount"];
        private static readonly int SwapImageFormat = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.imageFormat"];
        private static readonly int SwapColorSpace = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.imageColorSpace"];
        private static readonly int SwapImageExtent = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.imageExtent"];
        private static readonly int SwapArrayLayers = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.imageArrayLayers"];
        private static readonly int SwapImageUsage = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.imageUsage"];
        private static readonly int SwapPreTransform = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.preTransform"];
        private static readonly int SwapCompositeAlpha = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.compositeAlpha"];
        private static readonly int SwapPresentMode = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.presentMode"];

        private static readonly int ViewImage = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.image"];
        private static readonly int ViewFormat = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.format"];

        private static readonly int PassAttachmentCount = BrovVulkLayout.MemberOffset["VkRenderPassCreateInfo.attachmentCount"];
        private static readonly int PassAttachments = BrovVulkLayout.MemberOffset["VkRenderPassCreateInfo.pAttachments"];
        private static readonly int Pass2AttachmentCount = BrovVulkLayout.MemberOffset["VkRenderPassCreateInfo2.attachmentCount"];
        private static readonly int Pass2Attachments = BrovVulkLayout.MemberOffset["VkRenderPassCreateInfo2.pAttachments"];

        private static readonly int AttachmentSize = BrovVulkLayout.StructSize["VkAttachmentDescription"];
        private static readonly int AttachmentFormat = BrovVulkLayout.MemberOffset["VkAttachmentDescription.format"];
        private static readonly int AttachmentInitialLayout = BrovVulkLayout.MemberOffset["VkAttachmentDescription.initialLayout"];
        private static readonly int AttachmentFinalLayout = BrovVulkLayout.MemberOffset["VkAttachmentDescription.finalLayout"];
        private static readonly int Attachment2Size = BrovVulkLayout.StructSize["VkAttachmentDescription2"];
        private static readonly int Attachment2Format = BrovVulkLayout.MemberOffset["VkAttachmentDescription2.format"];
        private static readonly int Attachment2InitialLayout = BrovVulkLayout.MemberOffset["VkAttachmentDescription2.initialLayout"];
        private static readonly int Attachment2FinalLayout = BrovVulkLayout.MemberOffset["VkAttachmentDescription2.finalLayout"];

        private static readonly int FormatListCount = BrovVulkLayout.MemberOffset["VkImageFormatListCreateInfo.viewFormatCount"];
        private static readonly int FormatListFormats = BrovVulkLayout.MemberOffset["VkImageFormatListCreateInfo.pViewFormats"];

        private static readonly int PresentSwapchainCount = BrovVulkLayout.MemberOffset["VkPresentInfoKHR.swapchainCount"];
        private static readonly int PresentSwapchains = BrovVulkLayout.MemberOffset["VkPresentInfoKHR.pSwapchains"];

        private readonly Dictionary<IntPtr, SurfaceState> _surfaces = new Dictionary<IntPtr, SurfaceState>();
        private readonly Dictionary<IntPtr, SwapchainPlan> _swapchains = new Dictionary<IntPtr, SwapchainPlan>();
        private readonly Dictionary<IntPtr, List<IntPtr>> _swapchainImages = new Dictionary<IntPtr, List<IntPtr>>();
        private readonly Dictionary<IntPtr, ImageFormat> _imageFormats = new Dictionary<IntPtr, ImageFormat>();
        private int _hiddenTransforms;

        public void NoteSurface(IntPtr physicalDevice, IntPtr surface) => Describe(physicalDevice, surface);

        public void NormalizeCapabilities(IntPtr physicalDevice, IntPtr surface, IntPtr capabilities)
        {
            if (capabilities == IntPtr.Zero)
                return;

            SurfaceState state = Describe(physicalDevice, surface);
            if (state == null)
                return;

            byte* caps = (byte*)capabilities;
            uint supported = *(uint*)(caps + CapsSupportedTransforms);
            uint current = *(uint*)(caps + CapsCurrentTransform);
            if (current == TransformIdentity || (supported & TransformIdentity) == 0)
            {
                state.HiddenTransform = false;
                return;
            }

            // A Win32 surface is never pre-rotated, so a guest copies currentTransform straight into
            // preTransform and still renders unrotated. Report identity and let the compositor rotate.
            *(uint*)(caps + CapsCurrentTransform) = TransformIdentity;
            state.HiddenTransform = true;
        }

        public void NormalizeCapabilities2(IntPtr physicalDevice, IntPtr surfaceInfo, IntPtr capabilities2)
        {
            if (surfaceInfo == IntPtr.Zero || capabilities2 == IntPtr.Zero)
                return;

            NormalizeCapabilities(physicalDevice, *(IntPtr*)((byte*)surfaceInfo + SurfaceInfo2Surface), capabilities2 + Caps2Inner);
        }

        public SwapchainPlan ReconcileSwapchain(IntPtr device, IntPtr createInfo, GenState state, BinaryEmulator instance)
        {
            if (createInfo == IntPtr.Zero)
                return default;

            byte* info = (byte*)createInfo;
            IntPtr surface = *(IntPtr*)(info + SwapSurface);
            if (surface == IntPtr.Zero)
                return default;

            if (!_surfaces.TryGetValue(surface, out SurfaceState described))
            {
                if (!state.TryGetDevicePhysical(device, out IntPtr physicalDevice))
                    return default;
                described = Describe(physicalDevice, surface);
                if (described == null)
                    return default;
            }

            uint guestFormat = *(uint*)(info + SwapImageFormat);

            byte* caps = stackalloc byte[CapsSize];
            new Span<byte>(caps, CapsSize).Clear();
            if (BrovVulkApi.vkGetPhysicalDeviceSurfaceCapabilitiesKHR(described.PhysicalDevice, surface, (IntPtr)caps) >= 0)
            {
                ClampImageCount(info, caps);
                ClampImageExtent(info, caps);
                ClampArrayLayers(info, caps);
                ReconcileUsage(info, caps);
                ReconcileCompositeAlpha(info, caps);
                ReconcilePreTransform(info, caps);
            }

            ReconcileFormat(info, described, instance);
            ReconcilePresentMode(info, described);

            return new SwapchainPlan(surface, guestFormat, *(uint*)(info + SwapImageFormat), described.HiddenTransform);
        }

        public void NoteSwapchain(IntPtr swapchain, in SwapchainPlan plan)
        {
            if (swapchain == IntPtr.Zero || plan.Surface == IntPtr.Zero)
                return;

            ForgetSwapchain(swapchain);
            _swapchains[swapchain] = plan;
            if (plan.HiddenTransform)
                _hiddenTransforms++;
        }

        public void NoteSwapchainImages(IntPtr swapchain, IntPtr images, uint count)
        {
            if (images == IntPtr.Zero || count == 0
                || !_swapchains.TryGetValue(swapchain, out SwapchainPlan plan) || !plan.Substituted)
                return;

            if (!_swapchainImages.TryGetValue(swapchain, out List<IntPtr> owned))
            {
                owned = new List<IntPtr>((int)count);
                _swapchainImages[swapchain] = owned;
            }

            ImageFormat fix = new ImageFormat(swapchain, plan.GuestFormat, plan.HostFormat);
            for (uint k = 0; k < count; k++)
            {
                IntPtr image = *(IntPtr*)((byte*)images + k * 8);
                if (image == IntPtr.Zero)
                    continue;
                if (!_imageFormats.TryGetValue(image, out ImageFormat held) || held.Swapchain != swapchain)
                    owned.Add(image);
                _imageFormats[image] = fix;
            }
        }

        // The swapchain images carry the format the surface could allocate, not the one the guest named,
        // and the view is what decides how that memory is read and written.
        public void ReconcileImageView(IntPtr createInfo)
        {
            if (createInfo == IntPtr.Zero || _imageFormats.Count == 0)
                return;

            byte* info = (byte*)createInfo;
            IntPtr image = *(IntPtr*)(info + ViewImage);
            if (image == IntPtr.Zero || !_imageFormats.TryGetValue(image, out ImageFormat fix))
                return;

            if (*(uint*)(info + ViewFormat) == fix.GuestFormat)
                *(uint*)(info + ViewFormat) = fix.HostFormat;
        }

        // An attachment that begins or ends in PRESENT_SRC is a swapchain image, so its format has to be
        // one the surface offers even when the render pass is built before any swapchain exists.
        public void ReconcileRenderPass(IntPtr createInfo, bool version2)
        {
            if (createInfo == IntPtr.Zero || _surfaces.Count == 0)
                return;

            byte* info = (byte*)createInfo;
            uint count = *(uint*)(info + (version2 ? Pass2AttachmentCount : PassAttachmentCount));
            byte* attachments = (byte*)*(IntPtr*)(info + (version2 ? Pass2Attachments : PassAttachments));
            if (count == 0 || attachments == null)
                return;

            int stride = version2 ? Attachment2Size : AttachmentSize;
            int formatOffset = version2 ? Attachment2Format : AttachmentFormat;
            int initialOffset = version2 ? Attachment2InitialLayout : AttachmentInitialLayout;
            int finalOffset = version2 ? Attachment2FinalLayout : AttachmentFinalLayout;

            for (uint k = 0; k < count; k++)
            {
                byte* attachment = attachments + k * (uint)stride;
                if (*(uint*)(attachment + initialOffset) != LayoutPresentSrc && *(uint*)(attachment + finalOffset) != LayoutPresentSrc)
                    continue;

                if (TryResolvePresentableFormat(*(uint*)(attachment + formatOffset), out uint host))
                    *(uint*)(attachment + formatOffset) = host;
            }
        }

        // Reporting identity for a rotated surface leaves the swapchain permanently disagreeing with it,
        // so a guest that rebuilds on VK_SUBOPTIMAL_KHR would never stop. A real geometry change still
        // reaches the guest as VK_ERROR_OUT_OF_DATE_KHR.
        public int FilterAcquireResult(int result, IntPtr swapchain)
        {
            if (result != Suboptimal || _hiddenTransforms == 0)
                return result;

            return _swapchains.TryGetValue(swapchain, out SwapchainPlan plan) && plan.HiddenTransform ? 0 : result;
        }

        public int FilterPresentResult(int result, IntPtr presentInfo)
        {
            if (result != Suboptimal || _hiddenTransforms == 0 || presentInfo == IntPtr.Zero)
                return result;

            byte* info = (byte*)presentInfo;
            uint count = *(uint*)(info + PresentSwapchainCount);
            byte* swapchains = (byte*)*(IntPtr*)(info + PresentSwapchains);
            if (count == 0 || swapchains == null)
                return result;

            for (uint k = 0; k < count; k++)
            {
                IntPtr swapchain = *(IntPtr*)(swapchains + k * 8);
                if (!_swapchains.TryGetValue(swapchain, out SwapchainPlan plan) || !plan.HiddenTransform)
                    return result;
            }

            return 0;
        }

        public void Forget(IntPtr handle, string type)
        {
            if (type == "VkSwapchainKHR")
                ForgetSwapchain(handle);
            else if (type == "VkSurfaceKHR")
                _surfaces.Remove(handle);
        }

        private void ForgetSwapchain(IntPtr swapchain)
        {
            if (_swapchains.TryGetValue(swapchain, out SwapchainPlan plan))
            {
                if (plan.HiddenTransform)
                    _hiddenTransforms--;
                _swapchains.Remove(swapchain);
            }

            if (!_swapchainImages.TryGetValue(swapchain, out List<IntPtr> owned))
                return;

            // A recreated swapchain can be handed the same images before the old one is destroyed, so
            // only the entries this swapchain still owns may go.
            for (int k = 0; k < owned.Count; k++)
                if (_imageFormats.TryGetValue(owned[k], out ImageFormat fix) && fix.Swapchain == swapchain)
                    _imageFormats.Remove(owned[k]);

            _swapchainImages.Remove(swapchain);
        }

        private SurfaceState Describe(IntPtr physicalDevice, IntPtr surface)
        {
            if (surface == IntPtr.Zero || physicalDevice == IntPtr.Zero)
                return null;

            if (_surfaces.TryGetValue(surface, out SurfaceState state) && state.PhysicalDevice == physicalDevice)
                return state;

            state ??= new SurfaceState();
            state.PhysicalDevice = physicalDevice;
            state.Formats = QueryFormats(physicalDevice, surface);
            state.PresentModes = QueryPresentModes(physicalDevice, surface);
            _surfaces[surface] = state;
            return state;
        }

        private static uint[] QueryFormats(IntPtr physicalDevice, IntPtr surface)
        {
            uint count = MaxSurfaceFormats;
            byte* buffer = stackalloc byte[MaxSurfaceFormats * SurfaceFormatSize];
            if (BrovVulkApi.vkGetPhysicalDeviceSurfaceFormatsKHR(physicalDevice, surface, (IntPtr)(&count), (IntPtr)buffer) < 0)
                return Array.Empty<uint>();

            if (count > MaxSurfaceFormats)
                count = MaxSurfaceFormats;
            if (count == 0)
                return Array.Empty<uint>();

            uint[] pairs = new uint[count * 2];
            for (uint k = 0; k < count; k++)
            {
                byte* entry = buffer + k * (uint)SurfaceFormatSize;
                pairs[k * 2] = *(uint*)(entry + SurfaceFormatFormat);
                pairs[k * 2 + 1] = *(uint*)(entry + SurfaceFormatColorSpace);
            }
            return pairs;
        }

        private static uint[] QueryPresentModes(IntPtr physicalDevice, IntPtr surface)
        {
            uint count = MaxPresentModes;
            uint* buffer = stackalloc uint[MaxPresentModes];
            if (BrovVulkApi.vkGetPhysicalDeviceSurfacePresentModesKHR(physicalDevice, surface, (IntPtr)(&count), (IntPtr)buffer) < 0)
                return Array.Empty<uint>();

            if (count > MaxPresentModes)
                count = MaxPresentModes;
            if (count == 0)
                return Array.Empty<uint>();

            uint[] modes = new uint[count];
            for (uint k = 0; k < count; k++)
                modes[k] = buffer[k];
            return modes;
        }

        private static void ClampImageCount(byte* info, byte* caps)
        {
            uint want = *(uint*)(info + SwapMinImageCount);
            uint min = *(uint*)(caps + CapsMinImageCount);
            uint max = *(uint*)(caps + CapsMaxImageCount);
            uint use = want < min ? min : want;
            if (max != 0 && use > max)
                use = max;
            if (use != want)
                *(uint*)(info + SwapMinImageCount) = use;
        }

        private static void ClampImageExtent(byte* info, byte* caps)
        {
            uint maxWidth = *(uint*)(caps + CapsMaxImageExtent + ExtentWidth);
            uint maxHeight = *(uint*)(caps + CapsMaxImageExtent + ExtentHeight);
            if (maxWidth == 0 || maxHeight == 0)
                return;

            uint width = *(uint*)(info + SwapImageExtent + ExtentWidth);
            uint height = *(uint*)(info + SwapImageExtent + ExtentHeight);
            // An empty extent means the surface has no area, which the host has to reject as it would
            // natively. Growing it to the minimum would hide that behind a swapchain nobody can see.
            if (width == 0 || height == 0)
                return;

            uint minWidth = *(uint*)(caps + CapsMinImageExtent + ExtentWidth);
            uint minHeight = *(uint*)(caps + CapsMinImageExtent + ExtentHeight);

            uint useWidth = width < minWidth ? minWidth : width > maxWidth ? maxWidth : width;
            uint useHeight = height < minHeight ? minHeight : height > maxHeight ? maxHeight : height;

            if (useWidth != width)
                *(uint*)(info + SwapImageExtent + ExtentWidth) = useWidth;
            if (useHeight != height)
                *(uint*)(info + SwapImageExtent + ExtentHeight) = useHeight;
        }

        private static void ClampArrayLayers(byte* info, byte* caps)
        {
            uint want = *(uint*)(info + SwapArrayLayers);
            uint max = *(uint*)(caps + CapsMaxArrayLayers);
            uint use = want == 0 ? 1u : want;
            if (max != 0 && use > max)
                use = max;
            if (use != want)
                *(uint*)(info + SwapArrayLayers) = use;
        }

        private static void ReconcileUsage(byte* info, byte* caps)
        {
            uint want = *(uint*)(info + SwapImageUsage);
            uint supported = *(uint*)(caps + CapsSupportedUsage);
            if (supported == 0 || (want & ~supported) == 0)
                return;

            uint use = want & supported;
            if (use == 0)
                use = supported & UsageColorAttachment;
            if (use != 0)
                *(uint*)(info + SwapImageUsage) = use;
        }

        private static void ReconcileCompositeAlpha(byte* info, byte* caps)
        {
            uint want = *(uint*)(info + SwapCompositeAlpha);
            uint supported = *(uint*)(caps + CapsSupportedAlpha);
            if (supported == 0 || IsSupportedBit(want, supported))
                return;

            *(uint*)(info + SwapCompositeAlpha) = Prefer(supported, CompositeInherit, CompositeOpaque, CompositePreMultiplied, CompositePostMultiplied);
        }

        private static void ReconcilePreTransform(byte* info, byte* caps)
        {
            uint want = *(uint*)(info + SwapPreTransform);
            uint supported = *(uint*)(caps + CapsSupportedTransforms);
            if (supported == 0 || IsSupportedBit(want, supported))
                return;

            uint current = *(uint*)(caps + CapsCurrentTransform);
            *(uint*)(info + SwapPreTransform) = (supported & TransformIdentity) != 0 ? TransformIdentity
                : IsSupportedBit(current, supported) ? current
                : LowestBit(supported);
        }

        private static void ReconcilePresentMode(byte* info, SurfaceState state)
        {
            uint[] modes = state.PresentModes;
            if (modes.Length == 0)
                return;

            uint want = *(uint*)(info + SwapPresentMode);
            for (int k = 0; k < modes.Length; k++)
                if (modes[k] == want)
                    return;

            uint use = PreferMode(modes, PresentModeFifo, PresentModeFifoRelaxed, PresentModeMailbox, PresentModeImmediate);
            *(uint*)(info + SwapPresentMode) = use == uint.MaxValue ? modes[0] : use;
        }

        private static void ReconcileFormat(byte* info, SurfaceState state, BinaryEmulator instance)
        {
            uint[] offered = state.Formats;
            if (offered.Length == 0)
                return;

            uint wantFormat = *(uint*)(info + SwapImageFormat);
            uint wantSpace = *(uint*)(info + SwapColorSpace);

            for (int k = 0; k < offered.Length; k += 2)
                if (offered[k] == wantFormat && offered[k + 1] == wantSpace)
                    return;

            PickPair(offered, wantFormat, wantSpace, out uint useFormat, out uint useSpace);
            *(uint*)(info + SwapImageFormat) = useFormat;
            *(uint*)(info + SwapColorSpace) = useSpace;
            RewriteViewFormatList(info, wantFormat, useFormat);

            if (instance != null && (instance.Settings.Flags & LogFlags.Issues) != 0)
                instance.TriggerEventMessage($"[BrovVulk] surface does not offer swapchain format {wantFormat}/{wantSpace}; using {useFormat}/{useSpace}.", LogFlags.Issues);
        }

        private static void RewriteViewFormatList(byte* info, uint guestFormat, uint hostFormat)
        {
            for (byte* node = (byte*)*(IntPtr*)(info + SwapPNext); node != null; node = (byte*)*(IntPtr*)(node + 8))
            {
                if (*(uint*)node != StructureTypeImageFormatList)
                    continue;

                uint count = *(uint*)(node + FormatListCount);
                uint* formats = (uint*)*(IntPtr*)(node + FormatListFormats);
                if (formats == null)
                    continue;

                for (uint k = 0; k < count; k++)
                    if (formats[k] == guestFormat)
                        formats[k] = hostFormat;
            }
        }

        private bool TryResolvePresentableFormat(uint format, out uint host)
        {
            host = 0;
            bool resolved = false;
            foreach (KeyValuePair<IntPtr, SurfaceState> entry in _surfaces)
            {
                uint[] offered = entry.Value.Formats;
                if (offered.Length == 0)
                    continue;

                for (int k = 0; k < offered.Length; k += 2)
                    if (offered[k] == format)
                        return false;

                PickPair(offered, format, uint.MaxValue, out uint candidate, out _);
                if (resolved && candidate != host)
                    return false;

                host = candidate;
                resolved = true;
            }

            return resolved && host != format;
        }

        private static void PickPair(uint[] offered, uint wantFormat, uint wantSpace, out uint format, out uint space)
        {
            uint sibling = SwapChannelOrder(wantFormat);
            uint alias = ByteIdenticalFormat(wantFormat);
            uint siblingAlias = sibling == 0 ? 0 : ByteIdenticalFormat(sibling);

            if (TryFindPair(offered, wantFormat, wantSpace, out format, out space)
                || TryFindPair(offered, sibling, wantSpace, out format, out space)
                || TryFindPair(offered, alias, wantSpace, out format, out space)
                || TryFindPair(offered, siblingAlias, wantSpace, out format, out space)
                || TryFindPair(offered, wantFormat, uint.MaxValue, out format, out space)
                || TryFindPair(offered, sibling, uint.MaxValue, out format, out space)
                || TryFindPair(offered, alias, uint.MaxValue, out format, out space)
                || TryFindPair(offered, siblingAlias, uint.MaxValue, out format, out space))
                return;

            // Encoding survives ahead of layout: an sRGB target would gamma-encode output the guest has
            // already encoded, and the colours come out washed.
            bool srgb = IsSrgb(wantFormat);
            for (int k = 0; k < offered.Length; k += 2)
            {
                if (IsSrgb(offered[k]) != srgb)
                    continue;
                format = offered[k];
                space = offered[k + 1];
                return;
            }

            format = offered[0];
            space = offered[1];
        }

        private static bool TryFindPair(uint[] offered, uint format, uint space, out uint gotFormat, out uint gotSpace)
        {
            if (format != 0)
            {
                for (int k = 0; k < offered.Length; k += 2)
                {
                    if (offered[k] != format || (space != uint.MaxValue && offered[k + 1] != space))
                        continue;
                    gotFormat = offered[k];
                    gotSpace = offered[k + 1];
                    return true;
                }
            }

            gotFormat = 0;
            gotSpace = 0;
            return false;
        }

        // VkFormat keeps the channel-swapped pairs in fixed runs, so the sibling holds the numeric type
        // and the bit layout and only reverses the channel order. A shader writes the same components to
        // either one, which is what keeps the colours as the guest meant them.
        private static uint SwapChannelOrder(uint format)
        {
            if (format >= 2 && format <= 7) return format ^ 1u;
            if (format >= 23 && format <= 29) return format + 7;
            if (format >= 30 && format <= 36) return format - 7;
            if (format >= 37 && format <= 43) return format + 7;
            if (format >= 44 && format <= 50) return format - 7;
            if (format >= 58 && format <= 63) return format + 6;
            if (format >= 64 && format <= 69) return format - 6;
            return 0;
        }

        // A8B8G8R8_*_PACK32 holds the same bytes as R8G8B8A8_* on a little-endian host.
        private static uint ByteIdenticalFormat(uint format)
        {
            if (format >= 37 && format <= 43) return format + 14;
            if (format >= 51 && format <= 57) return format - 14;
            return 0;
        }

        private static bool IsSrgb(uint format) =>
            format == 15 || format == 22 || format == 29 || format == 36 || format == 43 || format == 50 || format == 57;

        private static bool IsSupportedBit(uint value, uint supported) =>
            value != 0 && (value & (value - 1)) == 0 && (value & supported) != 0;

        private static uint LowestBit(uint value) => value & (uint)(-(int)value);

        private static uint Prefer(uint supported, uint first, uint second, uint third, uint fourth)
        {
            if ((supported & first) != 0) return first;
            if ((supported & second) != 0) return second;
            if ((supported & third) != 0) return third;
            if ((supported & fourth) != 0) return fourth;
            return LowestBit(supported);
        }

        private static uint PreferMode(uint[] modes, uint first, uint second, uint third, uint fourth)
        {
            for (int k = 0; k < modes.Length; k++)
                if (modes[k] == first) return first;
            for (int k = 0; k < modes.Length; k++)
                if (modes[k] == second) return second;
            for (int k = 0; k < modes.Length; k++)
                if (modes[k] == third) return third;
            for (int k = 0; k < modes.Length; k++)
                if (modes[k] == fourth) return fourth;
            return uint.MaxValue;
        }
    }
}
