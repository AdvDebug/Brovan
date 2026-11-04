using System;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static unsafe class BrovVulkGenStruct
    {
        private const uint MaxElems = 1u << 20;
        private const long MaxBytes = 256L << 20;

        private static readonly int SamplerCreateInfoSid = Array.IndexOf(BrovVulkStructMeta.STypes, (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO);
        private static readonly int SamplerAddressModeU = BrovVulkLayout.MemberOffset["VkSamplerCreateInfo.addressModeU"];
        private static readonly int SamplerAddressModeV = BrovVulkLayout.MemberOffset["VkSamplerCreateInfo.addressModeV"];
        private static readonly int SamplerAddressModeW = BrovVulkLayout.MemberOffset["VkSamplerCreateInfo.addressModeW"];
        private static readonly int SamplerBorderColor = BrovVulkLayout.MemberOffset["VkSamplerCreateInfo.borderColor"];
        private static readonly int ImageCreateInfoSid = Array.IndexOf(BrovVulkStructMeta.STypes, (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO);
        private static readonly int BufferViewCreateInfoSid = Array.IndexOf(BrovVulkStructMeta.STypes, (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_BUFFER_VIEW_CREATE_INFO);
        private static readonly int BufferViewBuffer = BrovVulkLayout.MemberOffset["VkBufferViewCreateInfo.buffer"];
        private static readonly int BufferViewOffset = BrovVulkLayout.MemberOffset["VkBufferViewCreateInfo.offset"];
        private static readonly int BufferViewRange = BrovVulkLayout.MemberOffset["VkBufferViewCreateInfo.range"];
        private static readonly int ImageViewCreateInfoSid = Array.IndexOf(BrovVulkStructMeta.STypes, (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO);
        private static readonly int PipelineLayoutSid = Array.IndexOf(BrovVulkStructMeta.STypes, (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO);
        private static readonly Dictionary<int, int> ColorCounts = ColorCountMembers(
            (BrovVulkConstants.VK_STRUCTURE_TYPE_PIPELINE_RENDERING_CREATE_INFO, "VkPipelineRenderingCreateInfo.colorAttachmentCount"),
            (BrovVulkConstants.VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO, "VkPipelineColorBlendStateCreateInfo.attachmentCount"),
            (BrovVulkConstants.VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_LOCATION_INFO, "VkRenderingAttachmentLocationInfo.colorAttachmentCount"),
            (BrovVulkConstants.VK_STRUCTURE_TYPE_RENDERING_INPUT_ATTACHMENT_INDEX_INFO, "VkRenderingInputAttachmentIndexInfo.colorAttachmentCount"),
            (BrovVulkConstants.VK_STRUCTURE_TYPE_PIPELINE_COLOR_WRITE_CREATE_INFO_EXT, "VkPipelineColorWriteCreateInfoEXT.attachmentCount"),
            (BrovVulkConstants.VK_STRUCTURE_TYPE_ATTACHMENT_SAMPLE_COUNT_INFO_AMD, "VkAttachmentSampleCountInfoAMD.colorAttachmentCount"));
        private static readonly int GraphicsPipelineSid = Array.IndexOf(BrovVulkStructMeta.STypes, (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO);
        private static readonly int GraphicsPipelinePass = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.renderPass"];
        private static readonly int GraphicsPipelineSubpass = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.subpass"];
        private static readonly int PipelineRobustnessSid = Array.IndexOf(BrovVulkStructMeta.STypes, (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_PIPELINE_ROBUSTNESS_CREATE_INFO);
        private static readonly int PipelineRobustnessBehaviours = BrovVulkLayout.MemberOffset["VkPipelineRobustnessCreateInfo.storageBuffers"];
        private static readonly int PipelineRobustnessBehavioursEnd = BrovVulkLayout.MemberOffset["VkPipelineRobustnessCreateInfo.images"] + 4;

        // The slot is sized from the descriptor id, so a node whose sType names a different struct would let
        // a reader of the chain write outside the slot.
        internal static uint CheckedSType(uint sType, int sid)
        {
            uint want = BrovVulkStructMeta.STypes[sid];
            if (want != 0 && sType != want)
                throw new InvalidOperationException($"BrovVulk generic: sType {sType} does not match the chain node type.");

            return sType;
        }

        internal static int CheckedBytes(uint n, int elem)
        {
            if (elem <= 0)
                throw new InvalidOperationException("BrovVulk generic: non-positive element size.");
            if (n == 0)
                return 0;
            if (n > MaxElems)
                throw new InvalidOperationException($"BrovVulk generic: array count {n} exceeds cap.");
            long total = (long)n * elem;
            if (total > MaxBytes)
                throw new InvalidOperationException($"BrovVulk generic: allocation {total} bytes exceeds cap.");
            return (int)total;
        }

        private static void VerifyArrayLen(IntPtr dst, in BvkM d, uint n)
        {
            uint Declared = *(uint*)(dst + d.LenOffset);
            if (d.LenSamples)
                Declared = (Declared + 31) / 32;
            if (n != 0 && n != Declared)
                throw new InvalidOperationException("BrovVulk generic: array length mismatch.");

            if (n == 0 && Declared != 0 && !d.Optional)
                throw new InvalidOperationException("BrovVulk generic: required array is null but its count is non-zero.");
        }

        // The loader ends the process on a NULL pointer the spec marks required.
        public static IntPtr RebuildRequired(int sid, GenReader r, GenState st, string type)
        {
            if (r.ReadU32() == 0)
                throw new InvalidOperationException($"BrovVulk generic: null pointer where {type} is required.");
            return Rebuild(sid, r, st);
        }

        public static IntPtr Rebuild(int sid, GenReader r, GenState st)
        {
            IntPtr p = st.Alloc(BrovVulkStructMeta.Sizes[sid]);
            RebuildAt(sid, r, st, p);
            return p;
        }

        public static void RebuildAt(int sid, GenReader r, GenState st, IntPtr dst)
        {
            // BvkM is wide enough that a by-value foreach copies it on every member of every array element.
            BvkM[] Members = BrovVulkStructMeta.Members[sid];
            for (int mi = 0; mi < Members.Length; mi++)
            {
                ref readonly BvkM d = ref Members[mi];
                IntPtr fp = dst + d.Offset;
                switch (d.Kind)
                {
                    case BvkMK.Scalar:
                        r.CopyInto(fp, (uint)d.Size);
                        break;
                    case BvkMK.Handle:
                        *(IntPtr*)fp = d.Optional
                            ? st.Lookup(r.ReadU32(), d.HandleType)
                            : st.LookupRequired(r.ReadU32(), d.HandleType);
                        break;
                    case BvkMK.StructValue:
                        RebuildAt(d.Sub, r, st, fp);
                        break;
                    case BvkMK.StructPtr:
                    {
                        uint has = r.ReadU32();
                        if (has == 0 && !d.Optional)
                            throw new InvalidOperationException($"BrovVulk generic: null pointer where struct {d.Sub} is required.");
                        *(IntPtr*)fp = has != 0 ? Rebuild(d.Sub, r, st) : IntPtr.Zero;
                        break;
                    }
                    case BvkMK.StructArray:
                    {
                        uint n = r.ReadU32();
                        VerifyArrayLen(dst, d, n);
                        if (n > 0)
                        {
                            int esz = BrovVulkStructMeta.Sizes[d.Sub];
                            int bytes = CheckedBytes(n, esz);
                            IntPtr arr = st.Alloc(bytes);
                            for (uint k = 0; k < n; k++)
                                RebuildAt(d.Sub, r, st, arr + (int)(k * (uint)esz));
                            *(IntPtr*)fp = arr;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.HandleArray:
                    {
                        uint n = r.ReadU32();
                        VerifyArrayLen(dst, d, n);
                        if (n > 0)
                        {
                            IntPtr arr = st.Alloc(CheckedBytes(n, 8));
                            for (uint k = 0; k < n; k++)
                            {
                                IntPtr h = st.Lookup(r.ReadU32(), d.HandleType);

                                if (h == IntPtr.Zero && !d.OptionalElements)
                                    throw new InvalidOperationException($"BrovVulk generic: null {d.HandleType} in a required array.");

                                *(IntPtr*)(arr + (int)(k * 8)) = h;
                            }
                            *(IntPtr*)fp = arr;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.ScalarArray:
                    {
                        uint n = r.ReadU32();
                        VerifyArrayLen(dst, d, n);
                        if (n > 0)
                        {
                            int bytes = CheckedBytes(n, d.Size);
                            IntPtr arr = st.Alloc(bytes);
                            r.CopyInto(arr, (uint)bytes);
                            *(IntPtr*)fp = arr;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.StringZ:
                    {
                        uint l = r.ReadU32();
                        if (l > 0)
                        {
                            IntPtr s = st.Alloc(CheckedBytes(l, 1) + 1);
                            r.CopyInto(s, l);
                            *(IntPtr*)fp = s;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.StringArray:
                    {
                        uint n = r.ReadU32();
                        VerifyArrayLen(dst, d, n);
                        if (n > 0)
                        {
                            IntPtr arr = st.Alloc(CheckedBytes(n, 8));
                            for (uint k = 0; k < n; k++)
                            {
                                uint l = r.ReadU32();
                                IntPtr s = st.Alloc(CheckedBytes(l, 1) + 1);
                                if (l > 0) r.CopyInto(s, l);
                                *(IntPtr*)(arr + (int)(k * 8)) = s;
                            }
                            *(IntPtr*)fp = arr;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.BlobPtr:
                    {
                        uint n = r.ReadU32();
                        ulong declared = d.Size == 8 ? *(ulong*)(dst + d.LenOffset) : *(uint*)(dst + d.LenOffset);
                        if (n != 0 && n != declared)
                            throw new InvalidOperationException("BrovVulk generic: blob length mismatch.");
                        if (n > 0)
                        {
                            IntPtr s = st.Alloc(CheckedBytes(n, 1));
                            r.CopyInto(s, n);
                            *(IntPtr*)fp = s;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.SelectArray:
                    {
                        uint dt = *(uint*)(dst + d.SelOffset);
                        if (dt < 32 && (d.SelMask & (1u << (int)dt)) != 0)
                        {
                            uint n = r.ReadU32();
                            if (n != *(uint*)(dst + d.LenOffset))
                                throw new InvalidOperationException("BrovVulk generic: descriptor array length mismatch.");
                            if (n > 0 && d.Sub >= 0)
                            {
                                int esz = BrovVulkStructMeta.Sizes[d.Sub];
                                IntPtr arr = st.Alloc(CheckedBytes(n, esz));
                                for (uint k = 0; k < n; k++)
                                    RebuildAt(d.Sub, r, st, arr + (int)(k * (uint)esz));
                                *(IntPtr*)fp = arr;
                            }
                            else if (n > 0)
                            {
                                IntPtr arr = st.Alloc(CheckedBytes(n, 8));
                                for (uint k = 0; k < n; k++)
                                    *(IntPtr*)(arr + (int)(k * 8)) = st.Lookup(r.ReadU32(), d.HandleType);
                                *(IntPtr*)fp = arr;
                            }
                            else *(IntPtr*)fp = IntPtr.Zero;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.PNext:
                    {
                        uint has = r.ReadU32();
                        if (has != 0)
                        {
                            int psid = (int)r.ReadU32();
                            if (psid < 0 || psid >= BrovVulkStructMeta.PNext.Length || !BrovVulkStructMeta.PNext[psid])
                                throw new InvalidOperationException("BrovVulk generic: pNext sid not allowed.");
                            st.EnterChain();
                            IntPtr node = Rebuild(psid, r, st);
                            st.LeaveChain();
                            CheckedSType(*(uint*)node, psid);
                            if (!BrovVulkStructMeta.Repeatable[psid])
                            {
                                for (byte* later = *(byte**)((byte*)node + 8); later != null; later = *(byte**)(later + 8))
                                {
                                    if (*(uint*)later == *(uint*)node)
                                        throw new InvalidOperationException("BrovVulk generic: a pNext chain repeats a structure.");
                                }
                            }
                            *(IntPtr*)fp = node;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.Ignore:
                        break;
                }
            }

            if (sid == BrovVulkStructMeta.DescriptorBufferInfoSid)
                st.CheckBufferRange(*(IntPtr*)(dst + BrovVulkStructMeta.DescriptorBufferInfoBuffer),
                                    *(ulong*)(dst + BrovVulkStructMeta.DescriptorBufferInfoOffset),
                                    *(ulong*)(dst + BrovVulkStructMeta.DescriptorBufferInfoRange));
            else if (sid == SamplerCreateInfoSid)
                CheckSamplerBorderColor(dst);
            else if (sid == ImageCreateInfoSid)
                CheckImageCreateInfo(st, dst);
            else if (sid == ImageViewCreateInfoSid)
                st.CheckImageView(dst);
            else if (sid == PipelineLayoutSid)
                st.CheckPipelineLayout(dst);
            else if (ColorCounts.TryGetValue(sid, out int colorCount))
                st.CheckColorCount(*(uint*)(dst + colorCount));
            else if (sid == GraphicsPipelineSid)
                st.CheckSubpass(*(IntPtr*)(dst + GraphicsPipelinePass), *(uint*)(dst + GraphicsPipelineSubpass));
            else if (sid == BufferViewCreateInfoSid)
                st.CheckBufferSpanOrRest(*(IntPtr*)(dst + BufferViewBuffer), *(ulong*)(dst + BufferViewOffset), *(ulong*)(dst + BufferViewRange));
            // Zero selects the device's forced robustness settings.
            else if (sid == PipelineRobustnessSid && (st.DeviceStandIns(st.CallDevice) & VulkanStandIns.HostCpuDeviceBit) != 0)
                new Span<byte>((void*)(dst + PipelineRobustnessBehaviours), PipelineRobustnessBehavioursEnd - PipelineRobustnessBehaviours).Clear();
        }

        private static Dictionary<int, int> ColorCountMembers(params (int SType, string Member)[] members)
        {
            Dictionary<int, int> counts = new Dictionary<int, int>();
            foreach ((int sType, string member) in members)
            {
                int sid = Array.IndexOf(BrovVulkStructMeta.STypes, (uint)sType);
                if (sid >= 0 && BrovVulkLayout.MemberOffset.TryGetValue(member, out int offset))
                    counts[sid] = offset;
            }
            return counts;
        }

        // VUID-VkImageCreateInfo-mipLevels-00947 and -00958.
        private static void CheckImageCreateInfo(GenState st, IntPtr info)
        {
            uint largest = Math.Max(*(uint*)(info + VkOffsets.ImageWidth), Math.Max(*(uint*)(info + VkOffsets.ImageHeight), *(uint*)(info + VkOffsets.ImageDepth)));
            uint levels = *(uint*)(info + VkOffsets.ImageMipLevels);
            if (levels == 0 || levels > 32 - (uint)BitOperations.LeadingZeroCount(largest))
                throw new InvalidOperationException($"BrovVulk generic: {levels} mip levels do not fit the image extent.");

            if (!st.TryGetDevicePhysical(st.CallDevice, out IntPtr physicalDevice) || !VulkanStandIns.ImageExtentFits(physicalDevice, info))
                throw new InvalidOperationException("BrovVulk generic: the image extent is past what the device creates.");
        }

        // Some drivers read borderColor even when no address mode uses it.
        private static void CheckSamplerBorderColor(IntPtr info)
        {
            int color = *(int*)(info + SamplerBorderColor);
            if (color is >= BrovVulkConstants.VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK and <= BrovVulkConstants.VK_BORDER_COLOR_INT_OPAQUE_WHITE
                or BrovVulkConstants.VK_BORDER_COLOR_FLOAT_CUSTOM_EXT or BrovVulkConstants.VK_BORDER_COLOR_INT_CUSTOM_EXT)
                return;

            const int ClampToBorder = BrovVulkConstants.VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER;
            if (*(int*)(info + SamplerAddressModeU) == ClampToBorder || *(int*)(info + SamplerAddressModeV) == ClampToBorder
                || *(int*)(info + SamplerAddressModeW) == ClampToBorder)
                throw new InvalidOperationException($"BrovVulk generic: border color {color} is not a VkBorderColor.");

            *(int*)(info + SamplerBorderColor) = BrovVulkConstants.VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK;
        }

        public static void WritebackBody(int sid, GenBuf w, IntPtr src)
        {
            int[] Padding = BrovVulkStructMeta.Padding[sid];
            if (Padding != null)
            {
                for (int pi = 0; pi < Padding.Length; pi += 2)
                    new Span<byte>((void*)(src + Padding[pi]), Padding[pi + 1]).Clear();
            }

            BvkM[] Members = BrovVulkStructMeta.Members[sid];
            for (int mi = 0; mi < Members.Length; mi++)
            {
                ref readonly BvkM d = ref Members[mi];
                switch (d.Kind)
                {
                    case BvkMK.Scalar:
                        w.WriteBytesFrom(src + d.Offset, (uint)d.Size);
                        break;
                    case BvkMK.StructValue:
                        WritebackBody(d.Sub, w, src + d.Offset);
                        break;
                }
            }
        }
    }
}
