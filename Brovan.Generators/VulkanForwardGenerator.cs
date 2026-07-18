#nullable disable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Brovan.Generators
{
    [Generator(LanguageNames.CSharp)]
    public sealed class VulkanForwardGenerator : IIncrementalGenerator
    {
        public void Initialize(IncrementalGeneratorInitializationContext context)
        {
            IncrementalValuesProvider<(string Path, string Text)> Xml = context.AdditionalTextsProvider
                .Where(t => t.Path.EndsWith("vk.xml", StringComparison.OrdinalIgnoreCase))
                .Select((t, ct) => (t.Path, t.GetText(ct)?.ToString()))
                .Where(x => x.Item2 != null);

            context.RegisterSourceOutput(Xml, (spc, x) => Emit(spc, x.Path, x.Text));
        }

        private static void WriteIfChanged(string path, string content)
        {
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                if (File.Exists(path) && File.ReadAllText(path) == content)
                    return;
                File.WriteAllText(path, content);
            }
            catch
            {
            }
        }

        private static string GuestGenDir(string vkXmlPath)
        {
            string genProj = Path.GetDirectoryName(vkXmlPath);
            string repo = Path.GetDirectoryName(genProj);
            return Path.Combine(repo, "Brovan.Graphics", "brovvulk-icd", "obj", "generated");
        }

        private sealed class Member
        {
            public string Name;
            public string Type;
            public int PtrDepth;
            public bool IsConst;
            public string Length;
            public string AltLength;
            public int ArrayLen = 1;
            public string Values;
        }

        private sealed class VkStruct
        {
            public string Name;
            public bool IsUnion;
            public string[] Extends = Array.Empty<string>();
            public readonly List<Member> Members = new List<Member>();
        }

        private sealed class VkExtension
        {
            public string Name;
            public string Type;
            public uint SpecVersion;
            public readonly HashSet<string> Commands = new HashSet<string>();
            public readonly HashSet<string> Types = new HashSet<string>();
        }

        private sealed class Param
        {
            public string Name;
            public string Type;
            public int PtrDepth;
            public bool IsConst;
            public string Length;
            public int ArrayLen = 1;
            public bool Optional;
        }

        private sealed class Command
        {
            public string Name;
            public string Ret;
            public readonly List<Param> Params = new List<Param>();
            public string Alias;
        }

        private sealed class Model
        {
            public readonly Dictionary<string, bool> Handles = new Dictionary<string, bool>();
            public readonly Dictionary<string, VkStruct> Structs = new Dictionary<string, VkStruct>();
            public readonly Dictionary<string, Command> Commands = new Dictionary<string, Command>();
            public readonly HashSet<string> Enums = new HashSet<string>();
            public readonly Dictionary<string, int> BitmaskWidth = new Dictionary<string, int>();
            public readonly HashSet<string> BaseTypes = new HashSet<string>();
            public readonly HashSet<string> FuncPointers = new HashSet<string>();
            public readonly Dictionary<string, int> Constants = new Dictionary<string, int>();
            public readonly Dictionary<string, string> TypeAlias = new Dictionary<string, string>();
            public readonly Dictionary<string, VkExtension> Extensions = new Dictionary<string, VkExtension>();
            public readonly Dictionary<string, double> CoreTypeVersion = new Dictionary<string, double>();
            public readonly Dictionary<string, HashSet<string>> TypeExtensions = new Dictionary<string, HashSet<string>>();
        }

        private static readonly string[] SkipPlatform =
        {
            "Android", "ANDROID", "Xlib", "Xcb", "Wayland", "DirectFB", "Metal", "MacOS", "IOS",
            "Screen", "ViSurface", "OHOS", "Fuchsia", "GGP", "QNX", "Winrt", "Stream",
        };

        private static readonly Dictionary<string, string> ScalarCs = new Dictionary<string, string>
        {
            ["uint32_t"] = "uint",
            ["int32_t"] = "int",
            ["uint64_t"] = "ulong",
            ["int64_t"] = "long",
            ["float"] = "float",
            ["double"] = "double",
            ["size_t"] = "UIntPtr",
            ["int"] = "int",
            ["VkBool32"] = "uint",
            ["VkDeviceSize"] = "ulong",
            ["VkDeviceAddress"] = "ulong",
            ["uint8_t"] = "byte",
            ["VkSampleMask"] = "uint",
            ["VkFlags"] = "uint",
            ["VkFlags64"] = "ulong",
            ["char"] = "byte",
        };

        private static string RawText(XElement e)
        {
            StringBuilder sb = new StringBuilder();
            foreach (XNode n in e.Nodes())
            {
                if (n is XText t)
                    sb.Append(t.Value);
                else if (n is XElement el)
                    sb.Append(el.Value);
            }
            return sb.ToString();
        }

        private static void ParseTyped(XElement node, out string type, out string name, out int ptrDepth, out bool isConst)
        {
            XElement typeNode = node.Element("type");
            XElement nameNode = node.Element("name");
            type = typeNode?.Value;
            name = nameNode?.Value;
            string full = RawText(node);
            isConst = full.Contains("const");
            ptrDepth = 0;
            if (type != null && name != null)
            {
                int ti = full.IndexOf(type, StringComparison.Ordinal);
                int ni = full.LastIndexOf(name, StringComparison.Ordinal);
                if (ti >= 0 && ni > ti)
                {
                    string between = full.Substring(ti + type.Length, ni - (ti + type.Length));
                    ptrDepth = between.Count(ch => ch == '*');
                }
            }
        }

        private static bool TryParseIntLiteral(string s, out int value)
        {
            value = 0;
            if (s == null) return false;
            s = s.Trim().TrimEnd('U', 'u', 'L', 'l').Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return int.TryParse(s.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out value);
            return int.TryParse(s, out value);
        }

        private static int ResolveArrayLen(XElement mem, Dictionary<string, int> consts)
        {
            string raw = RawText(mem);
            int total = 1;
            int i = 0;
            while ((i = raw.IndexOf('[', i)) >= 0)
            {
                int j = raw.IndexOf(']', i);
                if (j < 0) break;
                string inner = raw.Substring(i + 1, j - i - 1).Trim();
                i = j + 1;
                if (inner.Length == 0) continue;
                if (TryParseIntLiteral(inner, out int lit)) total *= lit;
                else if (consts.TryGetValue(inner, out int cv)) total *= cv;
            }
            return total;
        }

        private static Model Parse(string xml)
        {
            Model m = new Model();
            XDocument doc = XDocument.Parse(xml);
            XElement root = doc.Root;

            foreach (XElement e in root.Descendants("enum"))
            {
                string name = (string)e.Attribute("name");
                string val = (string)e.Attribute("value");
                if (name != null && val != null && !m.Constants.ContainsKey(name) && TryParseIntLiteral(val, out int cv))
                    m.Constants[name] = cv;
            }

            foreach (XElement t in root.Descendants("type"))
            {
                string cat = (string)t.Attribute("category");
                if (cat == null)
                    continue;
                string name = (string)t.Attribute("name") ?? t.Element("name")?.Value;
                if (name == null)
                    continue;
                string typeAlias = (string)t.Attribute("alias");
                if (typeAlias != null)
                {
                    m.TypeAlias[name] = typeAlias;
                    continue;
                }

                if (cat == "handle")
                {
                    string txt = RawText(t);
                    bool dispatch = txt.Contains("VK_DEFINE_HANDLE") && !txt.Contains("NON_DISPATCHABLE");
                    m.Handles[name] = dispatch;
                }
                else if (cat == "struct" || cat == "union")
                {
                    string extends = (string)t.Attribute("structextends");
                    VkStruct s = new VkStruct
                    {
                        Name = name,
                        IsUnion = cat == "union",
                        Extends = extends == null ? Array.Empty<string>() : extends.Split(','),
                    };
                    foreach (XElement mem in t.Elements("member"))
                    {
                        if ((string)mem.Attribute("api") == "vulkansc")
                            continue;
                        ParseTyped(mem, out string ty, out string nm, out int pd, out bool isc);
                        int alen = pd == 0 ? ResolveArrayLen(mem, m.Constants) : 1;
                        s.Members.Add(new Member { Name = nm, Type = ty, PtrDepth = pd, IsConst = isc, Length = (string)mem.Attribute("len"), AltLength = (string)mem.Attribute("altlen"), ArrayLen = alen, Values = (string)mem.Attribute("values") });
                    }
                    m.Structs[name] = s;
                }
                else if (cat == "basetype") m.BaseTypes.Add(name);
                else if (cat == "enum") m.Enums.Add(name);
                else if (cat == "funcpointer") m.FuncPointers.Add(name);
                else if (cat == "bitmask")
                {
                    string inner = t.Element("type")?.Value ?? "VkFlags";
                    m.BitmaskWidth[name] = inner.Contains("64") ? 64 : 32;
                }
            }

            foreach (XElement c in root.Descendants("command"))
            {
                string aliasName = (string)c.Attribute("name");
                string aliasTarget = (string)c.Attribute("alias");
                if (aliasName != null && aliasTarget != null)
                {
                    m.Commands[aliasName] = new Command { Name = aliasName, Alias = aliasTarget };
                    continue;
                }
                XElement proto = c.Element("proto");
                if (proto == null)
                    continue;
                Command cmd = new Command { Name = proto.Element("name")?.Value, Ret = proto.Element("type")?.Value };
                foreach (XElement p in c.Elements("param"))
                {
                    if ((string)p.Attribute("api") == "vulkansc")
                        continue;
                    ParseTyped(p, out string ty, out string nm, out int pd, out bool isc);
                    int palen = pd == 0 ? ResolveArrayLen(p, m.Constants) : 1;
                    cmd.Params.Add(new Param { Name = nm, Type = ty, PtrDepth = pd, IsConst = isc, Length = (string)p.Attribute("len"), ArrayLen = palen, Optional = ((string)p.Attribute("optional") ?? "").StartsWith("true", StringComparison.Ordinal) });
                }
                if (cmd.Name != null)
                    m.Commands[cmd.Name] = cmd;
            }

            string Canonical(string ty) => m.TypeAlias.TryGetValue(ty, out string tgt) ? tgt : ty;

            foreach (XElement f in root.Elements("feature"))
            {
                string api = (string)f.Attribute("api") ?? "";
                if (!api.Split(',').Contains("vulkan"))
                    continue;
                if (!double.TryParse((string)f.Attribute("number"), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double ver))
                    continue;
                foreach (XElement req in f.Elements("require"))
                {
                    foreach (XElement ty in req.Elements("type"))
                    {
                        string tn = Canonical((string)ty.Attribute("name") ?? "");
                        if (tn.Length == 0)
                            continue;
                        if (!m.CoreTypeVersion.TryGetValue(tn, out double cur) || ver < cur)
                            m.CoreTypeVersion[tn] = ver;
                    }
                }
            }

            XElement exts = root.Element("extensions");
            if (exts != null)
            {
                foreach (XElement e in exts.Elements("extension"))
                {
                    string name = (string)e.Attribute("name");
                    string supported = (string)e.Attribute("supported") ?? "";
                    if (name == null || !supported.Split(',').Contains("vulkan"))
                        continue;
                    string platform = (string)e.Attribute("platform");
                    if (platform != null && platform != "win32")
                        continue;
                    VkExtension ext = new VkExtension { Name = name, Type = (string)e.Attribute("type") };
                    foreach (XElement req in e.Elements("require"))
                    {
                        bool gated = req.Attribute("depends") != null;
                        foreach (XElement en in req.Elements("enum"))
                        {
                            string enName = (string)en.Attribute("name");
                            if (enName != null && enName.EndsWith("_SPEC_VERSION", StringComparison.Ordinal)
                                && TryParseIntLiteral((string)en.Attribute("value"), out int sv))
                                ext.SpecVersion = (uint)sv;
                        }
                        if (gated)
                            continue;
                        foreach (XElement cn in req.Elements("command"))
                        {
                            string cname = (string)cn.Attribute("name");
                            if (cname == null)
                                continue;
                            if (m.Commands.TryGetValue(cname, out Command cc) && cc.Alias != null)
                                cname = cc.Alias;
                            ext.Commands.Add(cname);
                        }
                        foreach (XElement tn in req.Elements("type"))
                        {
                            string ty = Canonical((string)tn.Attribute("name") ?? "");
                            if (ty.Length == 0)
                                continue;
                            ext.Types.Add(ty);
                            if (!m.TypeExtensions.TryGetValue(ty, out HashSet<string> owners))
                                m.TypeExtensions[ty] = owners = new HashSet<string>();
                            owners.Add(name);
                        }
                    }
                    m.Extensions[name] = ext;
                }
            }

            return m;
        }

        private static string CsType(Model m, string ty, int ptrDepth)
        {
            if (ptrDepth > 0) return "IntPtr";
            if (m.Handles.ContainsKey(ty)) return "IntPtr";
            if (m.FuncPointers.Contains(ty)) return "IntPtr";
            if (ScalarCs.TryGetValue(ty, out string cs)) return cs;
            if (m.Enums.Contains(ty)) return "int";
            if (m.BitmaskWidth.TryGetValue(ty, out int w)) return w == 64 ? "ulong" : "uint";
            return "IntPtr";
        }

        private static string CsRet(Model m, string ty) => ty == "void" ? "void" : CsType(m, ty, 0);

        private sealed class Layout
        {
            public int Size;
            public int Align;
            public readonly Dictionary<string, int> Offsets = new Dictionary<string, int>();
        }

        private static int AlignUp(int x, int a) => a <= 1 ? x : ((x + a - 1) / a) * a;

        private static void SizeAlign(Model m, string ty, int ptrDepth, Dictionary<string, Layout> cache, out int size, out int align)
        {
            if (ptrDepth > 0 || m.Handles.ContainsKey(ty) || m.FuncPointers.Contains(ty)) { size = 8; align = 8; return; }
            switch (ty)
            {
                case "uint8_t": case "int8_t": case "char": size = 1; align = 1; return;
                case "uint16_t": case "int16_t": size = 2; align = 2; return;
                case "uint32_t":
                case "int32_t":
                case "int":
                case "float":
                case "VkBool32":
                case "VkFlags":
                case "VkSampleMask": size = 4; align = 4; return;
                case "uint64_t":
                case "int64_t":
                case "double":
                case "size_t":
                case "VkDeviceSize":
                case "VkDeviceAddress":
                case "VkFlags64": size = 8; align = 8; return;
                case "HINSTANCE": case "HWND": case "HANDLE": case "HMONITOR": case "HDC": case "LPCWSTR": size = 8; align = 8; return;
                case "DWORD": case "BOOL": case "LONG": case "UINT": size = 4; align = 4; return;
            }
            if (m.Enums.Contains(ty)) { size = 4; align = 4; return; }
            if (m.BitmaskWidth.TryGetValue(ty, out int w)) { size = w == 64 ? 8 : 4; align = size; return; }
            if (m.Structs.ContainsKey(ty)) { Layout la = ComputeLayout(m, ty, cache); size = la.Size; align = la.Align; return; }
            size = 4; align = 4;
        }

        private static Layout ComputeLayout(Model m, string name, Dictionary<string, Layout> cache)
        {
            if (cache.TryGetValue(name, out Layout v)) return v;
            Layout lay = new Layout { Size = 0, Align = 1 };
            cache[name] = lay;
            VkStruct s = m.Structs[name];
            int cursor = 0, maxAlign = 1;
            foreach (Member mem in s.Members)
            {
                SizeAlign(m, mem.Type, mem.PtrDepth, cache, out int esz, out int eal);
                int total = esz * (mem.ArrayLen <= 0 ? 1 : mem.ArrayLen);
                if (eal > maxAlign) maxAlign = eal;
                int off = s.IsUnion ? 0 : AlignUp(cursor, eal);
                if (mem.Name != null && !lay.Offsets.ContainsKey(mem.Name))
                    lay.Offsets[mem.Name] = off;
                if (s.IsUnion) { if (total > cursor) cursor = total; }
                else cursor = off + total;
            }
            lay.Size = AlignUp(cursor, maxAlign);
            lay.Align = maxAlign;
            return lay;
        }

        private static bool Keep(Command c)
        {
            if (c.Alias != null) return false;
            foreach (string s in SkipPlatform)
                if (c.Name.IndexOf(s, StringComparison.Ordinal) >= 0)
                    return false;
            return true;
        }

        private static readonly HashSet<string> GenAllowlist = new HashSet<string>
        {
            "vkEnumerateInstanceVersion",
            "vkCreateInstance",
            "vkDestroyInstance",
            "vkEnumeratePhysicalDevices",
            "vkGetPhysicalDeviceProperties",
            "vkGetPhysicalDeviceQueueFamilyProperties",
            "vkCreateDevice",
            "vkGetDeviceQueue",
            "vkCreateCommandPool",
            "vkDestroyCommandPool",
            "vkAllocateCommandBuffers",
            "vkBeginCommandBuffer",
            "vkEndCommandBuffer",
            "vkQueueSubmit",
            "vkQueueWaitIdle",
            "vkDestroyDevice",
            "vkCreateWin32SurfaceKHR",
            "vkDestroySurfaceKHR",
            "vkGetPhysicalDeviceSurfaceSupportKHR",
            "vkGetPhysicalDeviceSurfaceCapabilitiesKHR",
            "vkGetPhysicalDeviceSurfaceFormatsKHR",
            "vkGetPhysicalDeviceSurfacePresentModesKHR",
            "vkCreateSwapchainKHR",
            "vkDestroySwapchainKHR",
            "vkGetSwapchainImagesKHR",
            "vkCreateSemaphore",
            "vkDestroySemaphore",
            "vkCreateFence",
            "vkDestroyFence",
            "vkResetFences",
            "vkWaitForFences",
            "vkGetFenceStatus",
            "vkAcquireNextImageKHR",
            "vkCmdPipelineBarrier",
            "vkCmdClearColorImage",
            "vkQueuePresentKHR",
            "vkCreateImageView",
            "vkDestroyImageView",
            "vkCreateRenderPass",
            "vkDestroyRenderPass",
            "vkCreateFramebuffer",
            "vkDestroyFramebuffer",
            "vkCreateShaderModule",
            "vkDestroyShaderModule",
            "vkCreatePipelineLayout",
            "vkDestroyPipelineLayout",
            "vkCreateGraphicsPipelines",
            "vkDestroyPipeline",
            "vkCmdBeginRenderPass",
            "vkCmdEndRenderPass",
            "vkCmdBindPipeline",
            "vkCmdSetViewport",
            "vkCmdSetScissor",
            "vkCmdPushConstants",
            "vkCmdDraw",
            "vkCmdDrawIndexed",
            "vkGetPhysicalDeviceMemoryProperties",
            "vkAllocateMemory",
            "vkFreeMemory",
            "vkMapMemory",
            "vkUnmapMemory",
            "vkFlushMappedMemoryRanges",
            "vkInvalidateMappedMemoryRanges",
            "vkCreateBuffer",
            "vkDestroyBuffer",
            "vkGetBufferMemoryRequirements",
            "vkBindBufferMemory",
            "vkCreateImage",
            "vkDestroyImage",
            "vkGetImageMemoryRequirements",
            "vkBindImageMemory",
            "vkCmdCopyBuffer",
            "vkCmdCopyBufferToImage",
            "vkCmdBindVertexBuffers",
            "vkCmdBindIndexBuffer",
            "vkDeviceWaitIdle",
            "vkGetPhysicalDeviceFeatures",
            "vkGetPhysicalDeviceFormatProperties",
            "vkGetPhysicalDeviceImageFormatProperties",
            "vkCreateSampler",
            "vkDestroySampler",
            "vkCreateDescriptorSetLayout",
            "vkDestroyDescriptorSetLayout",
            "vkCreateDescriptorPool",
            "vkDestroyDescriptorPool",
            "vkResetDescriptorPool",
            "vkAllocateDescriptorSets",
            "vkFreeDescriptorSets",
            "vkUpdateDescriptorSets",
            "vkCmdBindDescriptorSets",
            "vkCmdCopyImage",
            "vkCmdBlitImage",
            "vkCmdCopyImageToBuffer",
            "vkCmdResolveImage",
            "vkCmdClearDepthStencilImage",
            "vkCmdClearAttachments",
            "vkCmdUpdateBuffer",
            "vkCmdFillBuffer",
            "vkCmdSetLineWidth",
            "vkCmdSetDepthBias",
            "vkCmdSetBlendConstants",
            "vkCmdSetDepthBounds",
            "vkCmdSetStencilCompareMask",
            "vkCmdSetStencilWriteMask",
            "vkCmdSetStencilReference",
            "vkCmdDrawIndirect",
            "vkCmdDrawIndexedIndirect",
            "vkGetPhysicalDeviceFeatures2",
            "vkGetPhysicalDeviceProperties2",
            "vkGetPhysicalDeviceMemoryProperties2",
            "vkGetBufferMemoryRequirements2",
            "vkGetImageMemoryRequirements2",
            "vkCreateComputePipelines",
            "vkCmdDispatch",
            "vkCmdDispatchIndirect",
            "vkCreateQueryPool",
            "vkDestroyQueryPool",
            "vkCmdBeginQuery",
            "vkCmdEndQuery",
            "vkCmdResetQueryPool",
            "vkCmdWriteTimestamp",
            "vkCmdCopyQueryPoolResults",
            "vkGetQueryPoolResults",
            "vkResetQueryPool",
            "vkCreateEvent",
            "vkDestroyEvent",
            "vkCmdSetEvent",
            "vkCmdResetEvent",
            "vkCmdWaitEvents",
            "vkSetEvent",
            "vkResetEvent",
            "vkGetEventStatus",
            "vkCmdExecuteCommands",
            "vkFreeCommandBuffers",
            "vkResetCommandPool",
            "vkResetCommandBuffer",
            "vkCmdNextSubpass",
            "vkCreatePipelineCache",
            "vkDestroyPipelineCache",
            "vkMergePipelineCaches",
            "vkWaitSemaphores",
            "vkSignalSemaphore",
            "vkGetSemaphoreCounterValue",
            "vkEnumerateInstanceExtensionProperties",
            "vkEnumerateDeviceExtensionProperties",
            "vkQueueSubmit2",
            "vkCmdPipelineBarrier2",
            "vkCmdSetEvent2",
            "vkCmdResetEvent2",
            "vkCmdWaitEvents2",
            "vkCmdWriteTimestamp2",
            "vkCmdBeginRendering",
            "vkCmdEndRendering",
            "vkCmdSetCullMode",
            "vkCmdSetFrontFace",
            "vkCmdSetPrimitiveTopology",
            "vkCmdSetViewportWithCount",
            "vkCmdSetScissorWithCount",
            "vkCmdBindVertexBuffers2",
            "vkCmdSetDepthTestEnable",
            "vkCmdSetDepthWriteEnable",
            "vkCmdSetDepthCompareOp",
            "vkCmdSetDepthBoundsTestEnable",
            "vkCmdSetStencilTestEnable",
            "vkCmdSetStencilOp",
            "vkCmdSetRasterizerDiscardEnable",
            "vkCmdSetDepthBiasEnable",
            "vkCmdSetPrimitiveRestartEnable",
            "vkCmdCopyBuffer2",
            "vkCmdCopyImage2",
            "vkCmdCopyBufferToImage2",
            "vkCmdCopyImageToBuffer2",
            "vkCmdBlitImage2",
            "vkCmdResolveImage2",
            "vkCreateRenderPass2",
            "vkCmdBeginRenderPass2",
            "vkCmdNextSubpass2",
            "vkCmdEndRenderPass2",
            "vkGetBufferDeviceAddress",
            "vkGetBufferOpaqueCaptureAddress",
            "vkGetDeviceMemoryOpaqueCaptureAddress",
            "vkCmdBindTransformFeedbackBuffersEXT",
            "vkCmdBeginTransformFeedbackEXT",
            "vkCmdEndTransformFeedbackEXT",
            "vkCmdBeginQueryIndexedEXT",
            "vkCmdEndQueryIndexedEXT",
            "vkCmdDrawIndirectByteCountEXT",
            "vkGetPhysicalDeviceFormatProperties2",
            "vkGetPhysicalDeviceImageFormatProperties2",
            "vkGetPhysicalDeviceQueueFamilyProperties2",
            "vkGetPhysicalDeviceSurfaceCapabilities2KHR",
            "vkGetPhysicalDeviceSurfaceFormats2KHR",
            "vkGetPhysicalDeviceToolProperties",
            "vkGetPhysicalDeviceWin32PresentationSupportKHR",
            "vkGetDeviceQueue2",
            "vkGetImageSubresourceLayout",
            "vkGetRenderAreaGranularity",
            "vkTrimCommandPool",
            "vkGetDescriptorSetLayoutSupport",
            "vkGetDeviceBufferMemoryRequirements",
            "vkGetDeviceImageMemoryRequirements",
            "vkGetPipelineCacheData",
            "vkCmdBindIndexBuffer2",
            "vkGetRenderingAreaGranularity",
            "vkGetDeviceImageSubresourceLayout",
            "vkGetImageSubresourceLayout2",
        };

        private static readonly HashSet<string> ExtAllowlist = new HashSet<string>
        {
            "VK_KHR_surface",
            "VK_KHR_win32_surface",
            "VK_KHR_get_surface_capabilities2",
            "VK_KHR_swapchain",
            "VK_KHR_image_format_list",
            "VK_KHR_swapchain_mutable_format",
            "VK_EXT_robustness2",
            "VK_KHR_robustness2",
            "VK_EXT_transform_feedback",
            "VK_EXT_custom_border_color",
            "VK_EXT_depth_clip_enable",
            "VK_EXT_vertex_attribute_divisor",
            "VK_KHR_vertex_attribute_divisor",
            "VK_EXT_memory_budget",
            "VK_EXT_memory_priority",
            "VK_EXT_4444_formats",
            "VK_EXT_non_seamless_cube_map",
            "VK_KHR_maintenance5",
            "VK_KHR_pipeline_library",
        };

        private const double MaxCoreVersion = 1.3;

        private static bool IsWaitTimeoutParam(Model m, Param p)
            => p.Name == "timeout" && ParamKind(m, p) == "ScalarIn" && ScalarWidth(m, p.Type) == 8;

        private static HashSet<string> PNextSet = new HashSet<string>();

        private static string StructSType(VkStruct s)
        {
            foreach (Member mem in s.Members)
                if (mem.Name == "sType" && mem.Values != null)
                    return mem.Values;
            return null;
        }

        private static int ScalarWidth(Model m, string ty)
        {
            SizeAlign(m, ty, 0, new Dictionary<string, Layout>(), out int sz, out _);
            return sz;
        }

        private static string CSig(Param p)
        {
            if (p.PtrDepth == 0 && p.ArrayLen > 1)
                return (p.IsConst ? "const " : "") + p.Type + " " + p.Name + "[" + p.ArrayLen + "]";
            string stars = new string('*', p.PtrDepth);
            return (p.IsConst ? "const " : "") + p.Type + " " + stars + p.Name;
        }

        private static string GuestSig(Command c)
        {
            StringBuilder sig = new StringBuilder();
            for (int i = 0; i < c.Params.Count; i++)
            {
                if (i > 0) sig.Append(", ");
                sig.Append(CSig(c.Params[i]));
            }
            return sig.ToString();
        }

        private static Dictionary<string, int> StructId = new Dictionary<string, int>();

        private static readonly DiagnosticDescriptor ExtGuard = new DiagnosticDescriptor(
            "BVK001", "BrovVulk extension allowlist drift",
            "Extension {0}: {1}", "BrovVulk", DiagnosticSeverity.Error, true);

        private sealed class MDesc
        {
            public string Kind = "Ignore";
            public int Offset;
            public int Size = -1;
            public string SubName;
            public int LenOffset = -1;
            public string HandleType = "";
            public int SelOffset = -1;
            public uint SelMask;
        }

        private static readonly Dictionary<string, byte> KindNum = new Dictionary<string, byte>
        {
            ["Scalar"] = 0,
            ["Handle"] = 1,
            ["StructValue"] = 2,
            ["StructPtr"] = 3,
            ["StructArray"] = 4,
            ["HandleArray"] = 5,
            ["ScalarArray"] = 6,
            ["StringZ"] = 7,
            ["StringArray"] = 8,
            ["PNext"] = 9,
            ["Ignore"] = 10,
            ["BlobPtr"] = 11,
            ["SelectArray"] = 12,
        };

        private static bool StructIsFlat(Model m, string name, HashSet<string> seen)
        {
            if (!seen.Add(name)) return true;
            if (!m.Structs.TryGetValue(name, out VkStruct s)) return false;
            if (s.IsUnion) return false;
            foreach (Member mem in s.Members)
            {
                if (mem.PtrDepth > 0) return false;
                if (m.Handles.ContainsKey(mem.Type) || m.FuncPointers.Contains(mem.Type)) return false;
                if (m.Structs.ContainsKey(mem.Type) && !StructIsFlat(m, mem.Type, seen)) return false;
            }
            return true;
        }

        private static int ResolveLen(Member mem, Dictionary<string, int> offsets)
        {
            string len = mem.Length;
            if (len == null || len == "null-terminated") return -1;
            int comma = len.IndexOf(',');
            if (comma >= 0) len = len.Substring(0, comma);
            if (len.IndexOfAny(new[] { '/', '*', '-', '>', '(', ' ', '+' }) >= 0) return -1;
            return offsets.TryGetValue(len, out int o) ? o : -1;
        }

        private static MDesc ClassifyMember(Model m, VkStruct owner, Member mem, Dictionary<string, int> offsets, Dictionary<string, Layout> cache)
        {
            MDesc d = new MDesc { Offset = offsets.TryGetValue(mem.Name, out int mo) ? mo : 0 };
            if (mem.Name == "pNext") { d.Kind = "PNext"; d.Size = 8; return d; }
            if (owner.Name == "VkWriteDescriptorSet" && (mem.Name == "pImageInfo" || mem.Name == "pBufferInfo" || mem.Name == "pTexelBufferView"))
            {
                d.Kind = "SelectArray";
                d.SelOffset = offsets["descriptorType"];
                d.LenOffset = offsets["descriptorCount"];
                if (mem.Name == "pImageInfo") { d.SubName = "VkDescriptorImageInfo"; d.SelMask = (1u << 0) | (1u << 1) | (1u << 2) | (1u << 3) | (1u << 10); }
                else if (mem.Name == "pBufferInfo") { d.SubName = "VkDescriptorBufferInfo"; d.SelMask = (1u << 6) | (1u << 7) | (1u << 8) | (1u << 9); }
                else { d.HandleType = "VkBufferView"; d.SelMask = (1u << 4) | (1u << 5); }
                return d;
            }
            if (mem.PtrDepth == 0)
            {
                if (mem.ArrayLen > 1)
                {
                    SizeAlign(m, mem.Type, 0, cache, out int esz, out _);
                    d.Kind = "Scalar"; d.Size = esz * mem.ArrayLen; return d;
                }
                if (m.Handles.ContainsKey(mem.Type)) { d.Kind = "Handle"; d.Size = 8; d.HandleType = mem.Type; return d; }
                if (m.Structs.ContainsKey(mem.Type))
                {
                    if (StructIsFlat(m, mem.Type, new HashSet<string>())) { d.Kind = "Scalar"; d.Size = ComputeLayout(m, mem.Type, cache).Size; return d; }
                    d.Kind = "StructValue"; d.SubName = mem.Type; return d;
                }
                SizeAlign(m, mem.Type, 0, cache, out int w, out _); d.Kind = "Scalar"; d.Size = w; return d;
            }
            if (mem.Type == "char")
            {
                if (mem.PtrDepth >= 2) { int lo = ResolveLen(mem, offsets); if (lo >= 0) { d.Kind = "StringArray"; d.LenOffset = lo; } else d.Kind = "Ignore"; return d; }
                d.Kind = "StringZ"; return d;
            }
            string blobLen = mem.AltLength != null && mem.AltLength.Contains("/") ? mem.AltLength
                           : mem.Length != null && mem.Length.Contains("/") ? mem.Length : null;
            if (blobLen == null && mem.Type == "void" && mem.Length != null)
                blobLen = mem.Length;
            if (blobLen != null)
            {
                string num = blobLen.Split('/')[0].Split(',')[0].Trim();
                if (offsets.TryGetValue(num, out int blo))
                {
                    Member lenMem = owner.Members.FirstOrDefault(x => x.Name == num);
                    d.Kind = "BlobPtr"; d.LenOffset = blo; d.Size = lenMem != null ? ScalarWidth(m, lenMem.Type) : 8;
                    return d;
                }
            }
            if (mem.Type == "void") { d.Kind = "Ignore"; return d; }
            int len = ResolveLen(mem, offsets);
            if (len >= 0)
            {
                if (m.Handles.ContainsKey(mem.Type)) { d.Kind = "HandleArray"; d.LenOffset = len; d.HandleType = mem.Type; return d; }
                if (m.Structs.ContainsKey(mem.Type)) { d.Kind = "StructArray"; d.SubName = mem.Type; d.LenOffset = len; return d; }
                SizeAlign(m, mem.Type, 0, cache, out int ew, out _); d.Kind = "ScalarArray"; d.Size = ew; d.LenOffset = len; return d;
            }
            if (m.Structs.ContainsKey(mem.Type)) { d.Kind = "StructPtr"; d.SubName = mem.Type; return d; }
            d.Kind = "Ignore"; return d;
        }

        private static List<string> ComputeNeededStructs(Model m, List<Command> allowed, Dictionary<string, Layout> cache)
        {
            HashSet<string> need = new HashSet<string>();
            Queue<string> q = new Queue<string>();
            foreach (Command c in allowed)
                foreach (Param p in c.Params)
                {
                    string k = ParamKind(m, p);
                    if ((k == "StructIn" || k == "ArrayIn" || k == "ChainOut") && m.Structs.ContainsKey(p.Type) && need.Add(p.Type))
                        q.Enqueue(p.Type);
                }
            foreach (string pn in PNextSet)
                if (m.Structs.ContainsKey(pn) && need.Add(pn))
                    q.Enqueue(pn);
            while (q.Count > 0)
            {
                string name = q.Dequeue();
                VkStruct s = m.Structs[name];
                Layout lay = ComputeLayout(m, name, cache);
                foreach (Member mem in s.Members)
                {
                    MDesc d = ClassifyMember(m, s, mem, lay.Offsets, cache);
                    if (d.SubName != null && need.Add(d.SubName))
                        q.Enqueue(d.SubName);
                }
            }
            List<string> list = need.ToList();
            list.Sort(StringComparer.Ordinal);
            return list;
        }

        private static bool StructHasPNext(Model m, string type)
        {
            return m.Structs.TryGetValue(type, out VkStruct s) && s.Members.Any(x => x.Name == "pNext");
        }

        private static bool StructMarshallable(Model m, string name, HashSet<string> seen, Dictionary<string, Layout> cache)
        {
            if (!m.Structs.TryGetValue(name, out VkStruct s))
                return false;
            if (!seen.Add(name))
                return true;
            if (s.IsUnion)
                return true;
            Layout lay = ComputeLayout(m, name, cache);
            foreach (Member mem in s.Members)
            {
                if (mem.Name == "pNext")
                    continue;
                if (m.FuncPointers.Contains(mem.Type))
                    return false;
                MDesc d = ClassifyMember(m, s, mem, lay.Offsets, cache);
                if (d.Kind == "Ignore")
                    return false;
                if (d.SubName != null && !StructMarshallable(m, d.SubName, seen, cache))
                    return false;
            }
            return true;
        }

        private static bool PNextOwnerAllowed(Model m, string name)
        {
            if (m.CoreTypeVersion.TryGetValue(name, out double ver) && ver <= MaxCoreVersion)
                return true;
            return m.TypeExtensions.TryGetValue(name, out HashSet<string> owners) && owners.Overlaps(ExtAllowlist);
        }

        private static HashSet<string> ComputePNextSet(Model m, List<Command> allowed, Dictionary<string, Layout> cache)
        {
            HashSet<string> closure = new HashSet<string>();
            Queue<string> q = new Queue<string>();
            foreach (Command c in allowed)
                foreach (Param p in c.Params)
                {
                    string k = ParamKind(m, p);
                    if ((k == "StructIn" || k == "ArrayIn" || k == "ChainOut") && m.Structs.ContainsKey(p.Type) && closure.Add(p.Type))
                        q.Enqueue(p.Type);
                }
            HashSet<string> pnext = new HashSet<string>();
            while (true)
            {
                while (q.Count > 0)
                {
                    string name = q.Dequeue();
                    VkStruct s = m.Structs[name];
                    Layout lay = ComputeLayout(m, name, cache);
                    if (s.IsUnion)
                        continue;
                    foreach (Member mem in s.Members)
                    {
                        MDesc d = ClassifyMember(m, s, mem, lay.Offsets, cache);
                        if (d.SubName != null && closure.Add(d.SubName))
                            q.Enqueue(d.SubName);
                    }
                }
                bool grew = false;
                foreach (VkStruct s in m.Structs.Values)
                {
                    if (pnext.Contains(s.Name) || s.Extends.Length == 0)
                        continue;
                    if (StructSType(s) == null)
                        continue;
                    if (!s.Extends.Any(x => closure.Contains(m.TypeAlias.TryGetValue(x, out string cx) ? cx : x)))
                        continue;
                    if (!PNextOwnerAllowed(m, s.Name))
                        continue;
                    if (!StructMarshallable(m, s.Name, new HashSet<string>(), cache))
                        continue;
                    pnext.Add(s.Name);
                    if (closure.Add(s.Name))
                        q.Enqueue(s.Name);
                    grew = true;
                }
                if (!grew)
                    return pnext;
            }
        }

        private static bool IsCountArrayPair(Model m, Command c, int i)
        {
            if (i + 1 >= c.Params.Count) return false;
            Param p = c.Params[i], n = c.Params[i + 1];
            return p.Type == "uint32_t" && p.PtrDepth == 1 && !p.IsConst
                   && n.PtrDepth >= 1 && !n.IsConst && n.Length == p.Name;
        }

        private static int DestroyedHandleIndex(Model m, Command c)
        {
            if (!c.Name.StartsWith("vkDestroy") && !c.Name.StartsWith("vkFree"))
                return -1;
            foreach (Param p in c.Params)
                if (p.PtrDepth == 1 && p.IsConst && m.Handles.ContainsKey(p.Type))
                    return -1;
            int idx = -1;
            for (int i = 0; i < c.Params.Count; i++)
            {
                Param p = c.Params[i];
                if (p.PtrDepth == 0 && m.Handles.ContainsKey(p.Type))
                    idx = i;
            }
            return idx;
        }

        private static int ParamLenIndex(Command c, Param p, int i)
        {
            if (p.Length == null)
                return -1;
            for (int j = 0; j < i; j++)
                if (c.Params[j].Name == p.Length && c.Params[j].PtrDepth == 0 && c.Params[j].Type == "uint32_t")
                    return j;
            return -1;
        }

        private static bool Ret64(Command c)
        {
            return c.Ret == "VkDeviceAddress" || c.Ret == "uint64_t";
        }

        private static bool IsStructLenHandleArrayOut(Model m, Param p)
        {
            return !p.IsConst && p.PtrDepth == 1 && m.Handles.ContainsKey(p.Type)
                && p.Length != null && p.Length.Contains("->");
        }

        private static string StructLenGuestExpr(string len)
        {
            int i = len.IndexOf("->", StringComparison.Ordinal);
            string sp = len.Substring(0, i);
            string fld = len.Substring(i + 2);
            return "(" + sp + " ? (uint32_t)" + sp + "->" + fld + " : 0)";
        }

        private static string EmitHostCase(Model m, Command c, int id)
        {
            if (c.Name == "vkMapMemory")
                return "            case " + id + ":\n                return BrovVulkGenMemory.MapMemory(r, st, inst);\n";
            if (c.Name == "vkUnmapMemory")
                return "            case " + id + ":\n                return BrovVulkGenMemory.UnmapMemory(r, st, inst);\n";
            if (c.Name == "vkAllocateMemory")
                return "            case " + id + ":\n                return BrovVulkGenMemory.AllocateMemory(r, w, st, inst, " + StructId["VkMemoryAllocateInfo"] + ");\n";
            if (c.Name == "vkFreeMemory")
                return "            case " + id + ":\n                return BrovVulkGenMemory.FreeMemory(r, st);\n";
            if (c.Name == "vkCreateDevice")
                return "            case " + id + ":\n                return BrovVulkGenMemory.CreateDevice(r, w, st, " + StructId["VkDeviceCreateInfo"] + ");\n";
            if (c.Name == "vkFlushMappedMemoryRanges")
                return "            case " + id + ":\n                return BrovVulkGenMemory.FlushMappedMemoryRanges(r, st, inst);\n";
            if (c.Name == "vkInvalidateMappedMemoryRanges")
                return "            case " + id + ":\n                return BrovVulkGenMemory.InvalidateMappedMemoryRanges(r, st, inst);\n";
            if (c.Name == "vkCreateInstance")
                return "            case " + id + ":\n            {\n" +
                    "                uint hasCi = r.ReadU32();\n" +
                    "                System.IntPtr ci = System.IntPtr.Zero;\n" +
                    "                if (hasCi != 0) ci = BrovVulkGenStruct.Rebuild(" + StructId["VkInstanceCreateInfo"] + ", r, st);\n" +
                    "                if (Brovan.GeneralHelper.IsLinux && ci != System.IntPtr.Zero)\n" +
                    "                {\n" +
                    "                    System.IntPtr extPtr = *(System.IntPtr*)(ci + 56);\n" +
                    "                    uint extCount = *(uint*)(ci + 48);\n" +
                    "                    // ppEnabledExtensionNames is counted by enabledExtensionCount, not NULL-terminated;\n" +
                    "                    // scanning for a null entry runs off the end of the guest's array.\n" +
                    "                    if (extPtr != System.IntPtr.Zero && extCount != 0)\n" +
                    "                    {\n" +
                    "                        System.IntPtr newArr = st.Alloc(BrovVulkGenStruct.CheckedBytes(extCount + 1, 8));\n" +
                    "                        uint newCount = 0;\n" +
                    "                        bool sawWin32 = false;\n" +
                    "                        for (uint k = 0; k < extCount; k++)\n" +
                    "                        {\n" +
                    "                            System.IntPtr p = System.Runtime.InteropServices.Marshal.ReadIntPtr(extPtr, (int)(k * 8));\n" +
                    "                            if (p == System.IntPtr.Zero) continue;\n" +
                    "                            string name = System.Runtime.InteropServices.Marshal.PtrToStringAnsi(p);\n" +
                    "                            if (name == \"VK_KHR_win32_surface\") { sawWin32 = true; continue; }\n" +
                    "                            System.Runtime.InteropServices.Marshal.WriteIntPtr(newArr, (int)(newCount * 8), p);\n" +
                    "                            newCount++;\n" +
                    "                        }\n" +
                    "                        if (sawWin32)\n" +
                    "                        {\n" +
                    "                            System.IntPtr xcbName = System.Runtime.InteropServices.Marshal.StringToHGlobalAnsi(\"VK_KHR_xcb_surface\");\n" +
                    "                            System.Runtime.InteropServices.Marshal.WriteIntPtr(newArr, (int)(newCount * 8), xcbName);\n" +
                    "                            newCount++;\n" +
                    "                            *(uint*)(ci + 48) = newCount;\n" +
                    "                            *(System.IntPtr*)(ci + 56) = newArr;\n" +
                    "                        }\n" +
                    "                    }\n" +
                    "                }\n" +
                    "                System.IntPtr vki = System.IntPtr.Zero;\n" +
                    "                int rr = (int)BrovVulkApi.vkCreateInstance(ci, System.IntPtr.Zero, (System.IntPtr)(&vki));\n" +
                    "                if (rr >= 0 && vki == System.IntPtr.Zero) rr = -3;\n" +
                    "                w.WriteU32(rr >= 0 ? st.Register(vki, \"VkInstance\") : 0u);\n" +
                    "                return rr;\n            }\n";
            if (c.Name == "vkCreateWin32SurfaceKHR")
                return "            case " + id + ":\n            {\n" +
                    "                System.IntPtr vi = st.Lookup(r.ReadU32(), \"VkInstance\");\n" +
                    "                System.IntPtr surf = System.IntPtr.Zero;\n" +
                    "                int rr;\n" +
                    "                if (Brovan.GeneralHelper.IsLinux)\n" +
                    "                {\n" +
                    "                    System.IntPtr xdpy; System.IntPtr xwin;\n" +
                    "                    inst.WinHelper.EnsureHostXlibSurfaceHandles(out xdpy, out xwin);\n" +
                    "                    byte* ci = stackalloc byte[40];\n" +
                    "                    for (int z = 0; z < 40; z++) ci[z] = 0;\n" +
                    "                    *(int*)(ci + 0) = 1000005000;\n" +
                    "                    *(void**)(ci + 24) = (void*)xdpy;\n" +
                    "                    *(uint*)(ci + 32) = (uint)xwin;\n" +
                    "                    rr = (int)BrovVulkLinuxWsi.vkCreateXcbSurfaceKHR(vi, (System.IntPtr)ci, System.IntPtr.Zero, (System.IntPtr)(&surf));\n" +
                    "                }\n" +
                    "                else\n" +
                    "                {\n" +
                    "                    System.IntPtr hwnd = inst.WinHelper.EnsureHostWindowHandle();\n" +
                    "                    System.IntPtr hinst = BrovVulkGenNative.GetModuleHandleW(System.IntPtr.Zero);\n" +
                    "                    byte* ci = stackalloc byte[40];\n" +
                    "                    for (int z = 0; z < 40; z++) ci[z] = 0;\n" +
                    "                    *(int*)(ci + 0) = 1000009000;\n" +
                    "                    *(void**)(ci + 24) = (void*)hinst;\n" +
                    "                    *(void**)(ci + 32) = (void*)hwnd;\n" +
                    "                    rr = (int)BrovVulkApi.vkCreateWin32SurfaceKHR(vi, (System.IntPtr)ci, System.IntPtr.Zero, (System.IntPtr)(&surf));\n" +
                    "                }\n" +
                    "                if (rr >= 0 && surf == System.IntPtr.Zero) rr = -3;\n" +
                    "                w.WriteU32(rr >= 0 ? st.Register(surf, \"VkSurfaceKHR\") : 0u);\n" +
                    "                return rr;\n            }\n";
            if (c.Name == "vkEnumerateInstanceExtensionProperties")
                return "            case " + id + ":\n                return BrovVulkGenExt.Instance(w);\n";
            if (c.Name == "vkEnumerateDeviceExtensionProperties")
                return "            case " + id + ":\n                return BrovVulkGenExt.Device(st.Lookup(r.ReadU32(), \"VkPhysicalDevice\"), w);\n";
            if (c.Name == "vkGetPhysicalDeviceWin32PresentationSupportKHR")
                return "            case " + id + ":\n            {\n" +
                    "                System.IntPtr pd = st.Lookup(r.ReadU32(), \"VkPhysicalDevice\");\n" +
                    "                uint qf = r.ReadU32();\n" +
                    "                return Brovan.GeneralHelper.IsLinux ? 1 : (int)BrovVulkApi.vkGetPhysicalDeviceWin32PresentationSupportKHR(pd, qf);\n" +
                    "            }\n";
            if (c.Name == "vkGetPipelineCacheData")
                return "            case " + id + ":\n            {\n" +
                    "                System.IntPtr dev = st.Lookup(r.ReadU32(), \"VkDevice\");\n" +
                    "                System.IntPtr pc = st.Lookup(r.ReadU32(), \"VkPipelineCache\");\n" +
                    "                uint want = r.ReadU32();\n" +
                    "                ulong req = r.ReadU64();\n" +
                    "                ulong total = 0;\n" +
                    "                int rr = (int)BrovVulkApi.vkGetPipelineCacheData(dev, pc, (System.IntPtr)(&total), System.IntPtr.Zero);\n" +
                    "                if (rr < 0) return rr;\n" +
                    "                if (want == 0)\n" +
                    "                {\n" +
                    "                    w.WriteU64(total);\n" +
                    "                    return rr;\n" +
                    "                }\n" +
                    "                ulong take = req < total ? req : total;\n" +
                    "                if (take > (1ul << 26)) take = 1ul << 26;\n" +
                    "                System.IntPtr buf = System.IntPtr.Zero;\n" +
                    "                if (take > 0) buf = st.Alloc(BrovVulkGenStruct.CheckedBytes((uint)((take + 63) / 64), 64));\n" +
                    "                ulong got = take;\n" +
                    "                rr = (int)BrovVulkApi.vkGetPipelineCacheData(dev, pc, (System.IntPtr)(&got), buf);\n" +
                    "                if (rr < 0) return rr;\n" +
                    "                w.WriteU64(got);\n" +
                    "                if (got > 0) w.WriteBytesFrom(buf, (uint)got);\n" +
                    "                return rr;\n            }\n";

            StringBuilder b = new StringBuilder();
            List<string> callArgs = new List<string>();
            List<string> check = new List<string>();
            List<string> post = new List<string>();
            bool vkRes = c.Ret == "VkResult";
            string gate = vkRes ? "rr >= 0 && " : "";
            int forgetIdx = DestroyedHandleIndex(m, c);
            for (int i = 0; i < c.Params.Count; i++)
            {
                Param p = c.Params[i];
                string local = "p" + i;
                if (IsCountArrayPair(m, c, i))
                {
                    Param a = c.Params[i + 1];
                    bool elemHandle = m.Handles.ContainsKey(a.Type);
                    bool elemStruct = m.Structs.ContainsKey(a.Type);
                    bool elemChain = elemStruct && StructHasPNext(m, a.Type);
                    string esz = elemHandle ? "8" : elemStruct ? "BrovVulkLayout.StructSize[\"" + a.Type + "\"]" : ScalarWidth(m, a.Type).ToString();
                    b.Append("                uint ").Append(local).Append("c = r.ReadU32();\n");
                    b.Append("                uint ").Append(local).Append("pr = r.ReadU32();\n");
                    b.Append("                System.IntPtr ").Append(local).Append("a = ").Append(local).Append("pr != 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("c, ").Append(esz).Append(")) : System.IntPtr.Zero;\n");
                    if (elemChain)
                        b.Append("                if (").Append(local).Append("pr != 0) for (uint k = 0; k < ").Append(local).Append("c; k++) *(uint*)(").Append(local).Append("a + (int)(k * (uint)(").Append(esz).Append("))) = r.ReadU32();\n");
                    callArgs.Add("(System.IntPtr)(&" + local + "c)");
                    callArgs.Add(local + "a");
                    if (vkRes && elemHandle)
                        check.Add("                if (rr >= 0 && " + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) if (System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + "a, (int)k * 8) == System.IntPtr.Zero) { rr = -3; break; }");
                    post.Add("                w.WriteU32(" + local + "c);");
                    if (elemHandle)
                        post.Add("                if (" + gate + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) w.WriteU32(st.Register(System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + "a, (int)k * 8), \"" + a.Type + "\"));");
                    else if (elemChain)
                        post.Add("                if (" + gate + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) w.WriteBytesFrom(" + local + "a + (int)(k * (uint)(" + esz + ")) + 16, (uint)(" + esz + " - 16));");
                    else
                        post.Add("                if (" + gate + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) w.WriteBytesFrom(" + local + "a + (int)k * (" + esz + "), (uint)(" + esz + "));");
                    i++;
                    continue;
                }
                string kind = ParamKind(m, p);
                if (kind == "ChainOut" && StructId.ContainsKey(p.Type))
                {
                    int baseSid = StructId[p.Type];
                    b.Append("                uint ").Append(local).Append("bst = r.ReadU32();\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = st.Alloc(BrovVulkStructMeta.Sizes[").Append(baseSid).Append("]);\n");
                    b.Append("                *(uint*)").Append(local).Append(" = ").Append(local).Append("bst;\n");
                    b.Append("                System.IntPtr ").Append(local).Append("tail = ").Append(local).Append(";\n");
                    b.Append("                var ").Append(local).Append("ch = new System.Collections.Generic.List<(System.IntPtr, int)>();\n");
                    b.Append("                ").Append(local).Append("ch.Add((").Append(local).Append(", ").Append(baseSid).Append("));\n");
                    b.Append("                while (r.ReadU32() == 1) { uint ").Append(local).Append("st = r.ReadU32(); int ").Append(local).Append("sd = (int)r.ReadU32(); if (").Append(local).Append("sd < 0 || ").Append(local).Append("sd >= BrovVulkStructMeta.PNext.Length || !BrovVulkStructMeta.PNext[").Append(local).Append("sd]) throw new System.InvalidOperationException(\"BrovVulk generic: pNext sid not allowed.\"); System.IntPtr ").Append(local).Append("nd = st.Alloc(BrovVulkStructMeta.Sizes[").Append(local).Append("sd]); *(uint*)").Append(local).Append("nd = ").Append(local).Append("st; *(System.IntPtr*)(").Append(local).Append("tail + 8) = ").Append(local).Append("nd; ").Append(local).Append("tail = ").Append(local).Append("nd; ").Append(local).Append("ch.Add((").Append(local).Append("nd, ").Append(local).Append("sd)); }\n");
                    b.Append("                *(System.IntPtr*)(").Append(local).Append("tail + 8) = System.IntPtr.Zero;\n");
                    callArgs.Add(local);
                    post.Add("                foreach (var e in " + local + "ch) w.WriteBytesFrom(e.Item1 + 16, (uint)(BrovVulkStructMeta.Sizes[e.Item2] - 16));");
                }
                else if (kind == "ScalarIn")
                {
                    string ct = CsType(m, p.Type, 0);
                    int w = ScalarWidth(m, p.Type);
                    b.Append("                ").Append(ct).Append(" ").Append(local).Append(" = (").Append(ct).Append(")r.Read").Append(w == 8 ? "U64" : "U32").Append("();\n");
                    if (IsWaitTimeoutParam(m, p))
                        b.Append("                ").Append(local).Append(" = 0;\n");
                    callArgs.Add(local);
                }
                else if (kind == "ScalarOut")
                {
                    string ct = CsType(m, p.Type, 0);
                    int w = ScalarWidth(m, p.Type);
                    b.Append("                ").Append(ct).Append(" ").Append(local).Append(" = default;\n");
                    callArgs.Add("(System.IntPtr)(&" + local + ")");
                    post.Add("                w.Write" + (w == 8 ? "U64" : "U32") + "((" + (w == 8 ? "ulong" : "uint") + ")" + local + ");");
                }
                else if (kind == "HandleIn")
                {
                    if (i == forgetIdx)
                    {
                        b.Append("                uint ").Append(local).Append("Id = r.ReadU32();\n");
                        b.Append("                System.IntPtr ").Append(local).Append(" = st.Lookup(").Append(local).Append("Id, \"").Append(p.Type).Append("\");\n");
                        post.Add("                st.Forget(" + local + "Id);");
                    }
                    else
                    {
                        b.Append("                System.IntPtr ").Append(local).Append(" = st.Lookup(r.ReadU32(), \"").Append(p.Type).Append("\");\n");
                    }
                    callArgs.Add(local);
                }
                else if (kind == "HandleOut")
                {
                    b.Append("                System.IntPtr ").Append(local).Append(" = System.IntPtr.Zero;\n");
                    callArgs.Add("(System.IntPtr)(&" + local + ")");
                    if (vkRes)
                    {
                        check.Add("                if (rr >= 0 && " + local + " == System.IntPtr.Zero) rr = -3;");
                        post.Add("                w.WriteU32(rr >= 0 ? st.Register(" + local + ", \"" + p.Type + "\") : 0u);");
                    }
                    else
                        post.Add("                w.WriteU32(st.Register(" + local + ", \"" + p.Type + "\"));");
                }
                else if (kind == "AllocatorIn")
                {
                    callArgs.Add("System.IntPtr.Zero");
                }
                else if (kind == "FixedArrayIn")
                {
                    int bytes = p.ArrayLen * ScalarWidth(m, p.Type);
                    b.Append("                System.IntPtr ").Append(local).Append(" = st.Alloc(").Append(bytes).Append(");\n");
                    b.Append("                r.CopyInto(").Append(local).Append(", ").Append(bytes).Append(");\n");
                    callArgs.Add(local);
                }
                else if (kind == "StructIn" && StructId.ContainsKey(p.Type))
                {
                    b.Append("                System.IntPtr ").Append(local).Append(" = r.ReadU32() != 0 ? BrovVulkGenStruct.Rebuild(").Append(StructId[p.Type]).Append(", r, st) : System.IntPtr.Zero;\n");
                    callArgs.Add(local);
                }
                else if (kind == "StructOut")
                {
                    b.Append("                int sz").Append(i).Append(" = BrovVulkLayout.StructSize[\"").Append(p.Type).Append("\"];\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = st.Alloc(sz").Append(i).Append(");\n");
                    callArgs.Add(local);
                    post.Add("                w.WriteBytesFrom(" + local + ", (uint)sz" + i + ");");
                }
                else if (kind == "ArrayIn" && (!m.Structs.ContainsKey(p.Type) || StructId.ContainsKey(p.Type))
                         && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("                uint ").Append(local).Append("n = r.ReadU32();\n");
                    int liIn = ParamLenIndex(c, p, i);
                    if (liIn >= 0)
                        b.Append("                if (").Append(p.Optional ? local + "n != 0 && " : "").Append(local).Append("n != p").Append(liIn).Append(") throw new System.InvalidOperationException(\"BrovVulk generic: array count mismatch.\");\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = System.IntPtr.Zero;\n");
                    if (m.Structs.ContainsKey(p.Type))
                    {
                        int sid = StructId[p.Type];
                        b.Append("                if (").Append(local).Append("n > 0) { int esz").Append(i).Append(" = BrovVulkStructMeta.Sizes[").Append(sid).Append("]; ").Append(local).Append(" = st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, esz").Append(i).Append(")); for (uint k = 0; k < ").Append(local).Append("n; k++) BrovVulkGenStruct.RebuildAt(").Append(sid).Append(", r, st, ").Append(local).Append(" + (int)(k * (uint)esz").Append(i).Append(")); }\n");
                    }
                    else if (m.Handles.ContainsKey(p.Type))
                    {
                        bool freeArr = c.Name.StartsWith("vkFree", StringComparison.Ordinal);
                        if (freeArr)
                        {
                            b.Append("                System.IntPtr ").Append(local).Append("ids = System.IntPtr.Zero;\n");
                            b.Append("                if (").Append(local).Append("n > 0) { ").Append(local).Append(" = st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 8)); ").Append(local).Append("ids = st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 4)); for (uint k = 0; k < ").Append(local).Append("n; k++) { uint gid = r.ReadU32(); *(uint*)(").Append(local).Append("ids + (int)(k * 4)) = gid; *(System.IntPtr*)(").Append(local).Append(" + (int)(k * 8)) = st.Lookup(gid, \"").Append(p.Type).Append("\"); } }\n");
                            post.Add("                for (uint k = 0; k < " + local + "n; k++) st.Forget(*(uint*)(" + local + "ids + (int)(k * 4)));");
                        }
                        else
                        {
                            b.Append("                if (").Append(local).Append("n > 0) { ").Append(local).Append(" = st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 8)); for (uint k = 0; k < ").Append(local).Append("n; k++) *(System.IntPtr*)(").Append(local).Append(" + (int)(k * 8)) = st.Lookup(r.ReadU32(), \"").Append(p.Type).Append("\"); }\n");
                        }
                    }
                    else
                    {
                        int w = ScalarWidth(m, p.Type);
                        b.Append("                if (").Append(local).Append("n > 0) { int bytes").Append(i).Append(" = BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, ").Append(w).Append("); ").Append(local).Append(" = st.Alloc(bytes").Append(i).Append("); r.CopyInto(").Append(local).Append(", (uint)bytes").Append(i).Append("); }\n");
                    }
                    callArgs.Add(local);
                }
                else if (kind == "ArrayOut" && IsStructLenHandleArrayOut(m, p))
                {
                    int arrow = p.Length.IndexOf("->", StringComparison.Ordinal);
                    string spName = p.Length.Substring(0, arrow);
                    string fld = p.Length.Substring(arrow + 2);
                    int spi = -1;
                    for (int j = 0; j < i; j++)
                        if (c.Params[j].Name == spName && ParamKind(m, c.Params[j]) == "StructIn" && StructId.ContainsKey(c.Params[j].Type))
                            spi = j;
                    if (spi < 0)
                        return null;
                    b.Append("                uint ").Append(local).Append("n = r.ReadU32();\n");
                    b.Append("                if (p").Append(spi).Append(" != System.IntPtr.Zero) *(uint*)(p").Append(spi).Append(" + BrovVulkLayout.MemberOffset[\"").Append(c.Params[spi].Type).Append(".").Append(fld).Append("\"]) = ").Append(local).Append("n;\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = ").Append(local).Append("n > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 8)) : System.IntPtr.Zero;\n");
                    callArgs.Add(local);
                    if (vkRes)
                        check.Add("                if (rr >= 0) for (uint k = 0; k < " + local + "n; k++) if (System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + ", (int)k * 8) == System.IntPtr.Zero) { rr = -3; break; }");
                    post.Add("                " + (vkRes ? "if (rr >= 0) " : "") + "for (uint k = 0; k < " + local + "n; k++) w.WriteU32(st.Register(System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + ", (int)k * 8), \"" + p.Type + "\"));");
                }
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(p.Type) && ParamLenIndex(c, p, i) >= 0)
                {
                    int liOut = ParamLenIndex(c, p, i);
                    b.Append("                System.IntPtr ").Append(local).Append(" = p").Append(liOut).Append(" > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(p").Append(liOut).Append(", 8)) : System.IntPtr.Zero;\n");
                    callArgs.Add(local);
                    if (vkRes)
                        check.Add("                if (rr >= 0) for (uint k = 0; k < p" + liOut + "; k++) if (System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + ", (int)k * 8) == System.IntPtr.Zero) { rr = -3; break; }");
                    post.Add("                " + (vkRes ? "if (rr >= 0) " : "") + "for (uint k = 0; k < p" + liOut + "; k++) w.WriteU32(st.Register(System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + ", (int)k * 8), \"" + p.Type + "\"));");
                }
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(p.Type))
                {
                    b.Append("                System.IntPtr ").Append(local).Append(" = System.IntPtr.Zero;\n");
                    callArgs.Add("(System.IntPtr)(&" + local + ")");
                    if (vkRes)
                    {
                        check.Add("                if (rr >= 0 && " + local + " == System.IntPtr.Zero) rr = -3;");
                        post.Add("                w.WriteU32(rr >= 0 ? st.Register(" + local + ", \"" + p.Type + "\") : 0u);");
                    }
                    else
                        post.Add("                w.WriteU32(st.Register(" + local + ", \"" + p.Type + "\"));");
                }
                else if (kind == "VoidIn" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("                uint ").Append(local).Append("n = r.ReadU32();\n");
                    int lvIn = ParamLenIndex(c, p, i);
                    if (lvIn >= 0)
                        b.Append("                if (").Append(local).Append("n != p").Append(lvIn).Append(") throw new System.InvalidOperationException(\"BrovVulk generic: blob length mismatch.\");\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = ").Append(local).Append("n > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 1)) : System.IntPtr.Zero;\n");
                    b.Append("                if (").Append(local).Append("n > 0) r.CopyInto(").Append(local).Append(", ").Append(local).Append("n);\n");
                    callArgs.Add(local);
                }
                else if (kind == "VoidOut" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("                uint ").Append(local).Append("n = r.ReadU32();\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = ").Append(local).Append("n > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 1)) : System.IntPtr.Zero;\n");
                    callArgs.Add(local);
                    post.Add("                if (" + local + "n > 0) w.WriteBytesFrom(" + local + ", " + local + "n);");
                }
                else
                {
                    return null;
                }
            }

            if (c.Name == "vkDestroyDevice" || c.Name == "vkDestroyInstance")
                post.Add("                st.ClearMappings();");
            StringBuilder head = new StringBuilder();
            head.Append("            case ").Append(id).Append(":\n            {\n");
            if (c.Name == "vkQueueSubmit" || c.Name == "vkQueueSubmit2")
                head.Append("                BrovVulkGenMemory.SyncAllMappingsToHost(st, inst);\n");
            head.Append(b);
            string call = "BrovVulkApi." + c.Name + "(" + string.Join(", ", callArgs) + ")";
            if (c.Ret == "void")
            {
                head.Append("                ").Append(call).Append(";\n");
                foreach (string s in post) head.Append(s).Append("\n");
                head.Append("                return 0;\n            }\n");
            }
            else if (Ret64(c))
            {
                head.Append("                ulong rv = (ulong)").Append(call).Append(";\n");
                foreach (string s in post) head.Append(s).Append("\n");
                head.Append("                w.WriteU64(rv);\n");
                head.Append("                return 0;\n            }\n");
            }
            else
            {
                head.Append("                int rr = (int)").Append(call).Append(";\n");
                foreach (string s in check) head.Append(s).Append("\n");
                foreach (string s in post) head.Append(s).Append("\n");
                head.Append("                return rr;\n            }\n");
            }
            return head.ToString();
        }

        private static string EmitGuestTrampoline(Model m, Command c)
        {
            if (c.Name == "vkAllocateMemory")
                return "VKAPI_ATTR VkResult VKAPI_CALL vkAllocateMemory(" + GuestSig(c) + ")\n" +
                    "{\n" +
                    "    (void)pAllocator;\n" +
                    "    void *bvk_bounce = NULL;\n" +
                    "    uint64_t bvk_bsize = 0;\n" +
                    "    if (pAllocateInfo && pAllocateInfo->memoryTypeIndex < 32 && (bvk_hostvis_types >> pAllocateInfo->memoryTypeIndex) & 1)\n" +
                    "    {\n" +
                    "        bvk_bsize = (pAllocateInfo->allocationSize + 0xFFFull) & ~0xFFFull;\n" +
                    "        bvk_bounce = VirtualAlloc(NULL, (SIZE_T)bvk_bsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n" +
                    "        if (!bvk_bounce) bvk_bsize = 0;\n" +
                    "    }\n" +
                    "    bvk_rq_reset();\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)device);\n" +
                    "    if (pAllocateInfo) { bvk_w_u32(1); bvk_ser_struct(" + StructId["VkMemoryAllocateInfo"] + ", (const unsigned char*)pAllocateInfo); } else bvk_w_u32(0);\n" +
                    "    bvk_w_u64((uint64_t)(uintptr_t)bvk_bounce);\n" +
                    "    bvk_w_u64(bvk_bsize);\n" +
                    "    unsigned char bvk_out[32]; unsigned int bvk_outLen = 0;\n" +
                    "    int bvk_r = bvk_rq_send(BVK_vkAllocateMemory, bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "    if (bvk_r == 0 && pMemory && bvk_outLen >= 8)\n" +
                    "    {\n" +
                    "        uint32_t bvk_id; memcpy(&bvk_id, bvk_out + 4, 4);\n" +
                    "        *pMemory = (VkDeviceMemory)(uintptr_t)bvk_id;\n" +
                    "        if (pAllocateInfo) bvk_mem_add(bvk_id, pAllocateInfo->allocationSize, bvk_bounce);\n" +
                    "    }\n" +
                    "    else if (bvk_bounce)\n" +
                    "        VirtualFree(bvk_bounce, 0, MEM_RELEASE);\n" +
                    "    return (VkResult)bvk_r;\n" +
                    "}\n";
            if (c.Name == "vkFreeMemory")
                return "VKAPI_ATTR void VKAPI_CALL vkFreeMemory(" + GuestSig(c) + ")\n" +
                    "{\n" +
                    "    (void)pAllocator;\n" +
                    "    bvk_rq_reset();\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)device);\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)memory);\n" +
                    "    unsigned char bvk_out[32]; unsigned int bvk_outLen = 0;\n" +
                    "    bvk_rq_send(BVK_vkFreeMemory, bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "    bvk_mem_remove((uint32_t)(uintptr_t)memory);\n" +
                    "}\n";
            if (c.Name == "vkMapMemory")
                return "VKAPI_ATTR VkResult VKAPI_CALL vkMapMemory(" + GuestSig(c) + ")\n" +
                    "{\n" +
                    "    uint32_t bvk_id = (uint32_t)(uintptr_t)memory;\n" +
                    "    uint64_t bvk_total = 0;\n" +
                    "    if (!ppData) return VK_ERROR_MEMORY_MAP_FAILED;\n" +
                    "    *ppData = NULL;\n" +
                    "    if (!bvk_mem_size(bvk_id, &bvk_total)) return VK_ERROR_MEMORY_MAP_FAILED;\n" +
                    "    if (bvk_mem_mapped(bvk_id)) return VK_ERROR_MEMORY_MAP_FAILED;\n" +
                    "    if ((uint64_t)offset >= bvk_total) return VK_ERROR_MEMORY_MAP_FAILED;\n" +
                    "    uint64_t bvk_span = (size == VK_WHOLE_SIZE) ? bvk_total - offset : (uint64_t)size;\n" +
                    "    if (bvk_span == 0 || bvk_span > bvk_total - offset) return VK_ERROR_MEMORY_MAP_FAILED;\n" +
                    "    void *bvk_bounce = bvk_mem_bounce(bvk_id);\n" +
                    "    void *bvk_map;\n" +
                    "    if (bvk_bounce)\n" +
                    "        bvk_map = (char *)bvk_bounce + offset;\n" +
                    "    else\n" +
                    "    {\n" +
                    "        bvk_map = VirtualAlloc(NULL, (SIZE_T)bvk_span, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n" +
                    "        if (!bvk_map) return VK_ERROR_OUT_OF_HOST_MEMORY;\n" +
                    "    }\n" +
                    "    bvk_rq_reset();\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)device);\n" +
                    "    bvk_w_u32(bvk_id);\n" +
                    "    bvk_w_u64((uint64_t)offset);\n" +
                    "    bvk_w_u64(bvk_span);\n" +
                    "    bvk_w_u32((uint32_t)flags);\n" +
                    "    bvk_w_u64((uint64_t)(uintptr_t)bvk_map);\n" +
                    "    unsigned char bvk_out[32]; unsigned int bvk_outLen = 0;\n" +
                    "    int bvk_r = bvk_rq_send(BVK_vkMapMemory, bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "    if (bvk_r != 0) { if (!bvk_bounce) VirtualFree(bvk_map, 0, MEM_RELEASE); return (VkResult)bvk_r; }\n" +
                    "    bvk_mem_setmap(bvk_id, bvk_bounce ? NULL : bvk_map);\n" +
                    "    *ppData = bvk_map;\n" +
                    "    return VK_SUCCESS;\n" +
                    "}\n";
            if (c.Name == "vkUnmapMemory")
                return "VKAPI_ATTR void VKAPI_CALL vkUnmapMemory(" + GuestSig(c) + ")\n" +
                    "{\n" +
                    "    bvk_rq_reset();\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)device);\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)memory);\n" +
                    "    unsigned char bvk_out[32]; unsigned int bvk_outLen = 0;\n" +
                    "    bvk_rq_send(BVK_vkUnmapMemory, bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "    bvk_mem_clearmap((uint32_t)(uintptr_t)memory);\n" +
                    "}\n";
            if (c.Name == "vkFlushMappedMemoryRanges" || c.Name == "vkInvalidateMappedMemoryRanges")
                return "VKAPI_ATTR VkResult VKAPI_CALL " + c.Name + "(" + GuestSig(c) + ")\n" +
                    "{\n" +
                    "    bvk_rq_reset();\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)device);\n" +
                    "    bvk_w_u32(pMemoryRanges ? memoryRangeCount : 0);\n" +
                    "    if (pMemoryRanges)\n" +
                    "        for (uint32_t bvk_k = 0; bvk_k < memoryRangeCount; bvk_k++)\n" +
                    "        {\n" +
                    "            bvk_w_u32((uint32_t)(uintptr_t)pMemoryRanges[bvk_k].memory);\n" +
                    "            bvk_w_u64((uint64_t)pMemoryRanges[bvk_k].offset);\n" +
                    "            bvk_w_u64((uint64_t)pMemoryRanges[bvk_k].size);\n" +
                    "        }\n" +
                    "    unsigned char bvk_out[32]; unsigned int bvk_outLen = 0;\n" +
                    "    int bvk_r = bvk_rq_send(BVK_" + c.Name + ", bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "    return (VkResult)bvk_r;\n" +
                    "}\n";
            if (c.Name == "vkCreateWin32SurfaceKHR")
                return "VKAPI_ATTR VkResult VKAPI_CALL vkCreateWin32SurfaceKHR(VkInstance instance, const VkWin32SurfaceCreateInfoKHR *pCreateInfo, const VkAllocationCallbacks *pAllocator, VkSurfaceKHR *pSurface)\n" +
                    "{\n" +
                    "    (void)pCreateInfo; (void)pAllocator;\n" +
                    "    bvk_rq_reset();\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)instance);\n" +
                    "    unsigned char bvk_out[64]; unsigned int bvk_outLen = 0;\n" +
                    "    int bvk_r = bvk_rq_send(BVK_vkCreateWin32SurfaceKHR, bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "    if (bvk_r == 0 && pSurface && bvk_outLen >= 8) { uint32_t id; memcpy(&id, bvk_out + 4, 4); *pSurface = (VkSurfaceKHR)(uintptr_t)id; }\n" +
                    "    return (VkResult)bvk_r;\n" +
                    "}\n";
            if (c.Name == "vkEnumerateInstanceExtensionProperties" || c.Name == "vkEnumerateDeviceExtensionProperties")
            {
                bool dev = c.Name == "vkEnumerateDeviceExtensionProperties";
                return "VKAPI_ATTR VkResult VKAPI_CALL " + c.Name + "(" + GuestSig(c) + ")\n" +
                    "{\n" +
                    "    if (pLayerName) { if (pPropertyCount) *pPropertyCount = 0; return VK_SUCCESS; }\n" +
                    "    if (!pPropertyCount) return VK_ERROR_INITIALIZATION_FAILED;\n" +
                    "    bvk_rq_reset();\n" +
                    (dev ? "    bvk_w_u32((uint32_t)(uintptr_t)physicalDevice);\n" : "") +
                    "    unsigned char bvk_out[65536]; unsigned int bvk_outLen = 0;\n" +
                    "    int bvk_r = bvk_rq_send(BVK_" + c.Name + ", bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "    if (bvk_r < 0) return (VkResult)bvk_r;\n" +
                    "    uint32_t bvk_n = 0;\n" +
                    "    if (bvk_outLen >= 8) memcpy(&bvk_n, bvk_out + 4, 4);\n" +
                    "    if (bvk_n > (bvk_outLen - 8) / sizeof(VkExtensionProperties)) bvk_n = (bvk_outLen - 8) / (unsigned int)sizeof(VkExtensionProperties);\n" +
                    "    if (!pProperties) { *pPropertyCount = bvk_n; return VK_SUCCESS; }\n" +
                    "    uint32_t bvk_copy = *pPropertyCount < bvk_n ? *pPropertyCount : bvk_n;\n" +
                    "    if (bvk_copy) memcpy(pProperties, bvk_out + 8, bvk_copy * sizeof(VkExtensionProperties));\n" +
                    "    *pPropertyCount = bvk_copy;\n" +
                    "    return bvk_copy < bvk_n ? VK_INCOMPLETE : VK_SUCCESS;\n" +
                    "}\n";
            }
            if (c.Name == "vkGetPipelineCacheData")
                return "VKAPI_ATTR VkResult VKAPI_CALL vkGetPipelineCacheData(" + GuestSig(c) + ")\n" +
                    "{\n" +
                    "    if (!pDataSize) return VK_ERROR_INITIALIZATION_FAILED;\n" +
                    "    bvk_rq_reset();\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)device);\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)pipelineCache);\n" +
                    "    bvk_w_u32(pData ? 1u : 0u);\n" +
                    "    bvk_w_u64(pData ? (uint64_t)*pDataSize : 0);\n" +
                    "    if (!pData)\n" +
                    "    {\n" +
                    "        unsigned char bvk_out[32]; unsigned int bvk_outLen = 0;\n" +
                    "        int bvk_r = bvk_rq_send(BVK_vkGetPipelineCacheData, bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "        if (bvk_r == 0 && bvk_outLen >= 12) { uint64_t n; memcpy(&n, bvk_out + 4, 8); *pDataSize = (size_t)n; }\n" +
                    "        return (VkResult)bvk_r;\n" +
                    "    }\n" +
                    "    uint64_t bvk_cap = (uint64_t)*pDataSize + 16;\n" +
                    "    if (bvk_cap > 0xFFFFFFFFu) bvk_cap = 0xFFFFFFFFu;\n" +
                    "    unsigned char *bvk_out = (unsigned char *)malloc((size_t)bvk_cap);\n" +
                    "    if (!bvk_out) return VK_ERROR_OUT_OF_HOST_MEMORY;\n" +
                    "    unsigned int bvk_outLen = 0;\n" +
                    "    int bvk_r = bvk_rq_send(BVK_vkGetPipelineCacheData, bvk_out, (unsigned int)bvk_cap, &bvk_outLen);\n" +
                    "    if (bvk_r >= 0 && bvk_outLen >= 12)\n" +
                    "    {\n" +
                    "        uint64_t n; memcpy(&n, bvk_out + 4, 8);\n" +
                    "        if (n > (uint64_t)*pDataSize) n = (uint64_t)*pDataSize;\n" +
                    "        if (bvk_outLen >= 12 + n) memcpy(pData, bvk_out + 12, (size_t)n);\n" +
                    "        *pDataSize = (size_t)n;\n" +
                    "    }\n" +
                    "    free(bvk_out);\n" +
                    "    return (VkResult)bvk_r;\n" +
                    "}\n";

            StringBuilder sig = new StringBuilder();
            for (int i = 0; i < c.Params.Count; i++)
            {
                if (i > 0) sig.Append(", ");
                sig.Append(CSig(c.Params[i]));
            }
            StringBuilder b = new StringBuilder();
            b.Append("VKAPI_ATTR ").Append(c.Ret).Append(" VKAPI_CALL ").Append(c.Name).Append("(").Append(sig).Append(")\n{\n");
            b.Append("    bvk_rq_reset();\n");
            for (int i = 0; i < c.Params.Count; i++)
            {
                Param p = c.Params[i];
                if (IsCountArrayPair(m, c, i))
                {
                    Param a = c.Params[i + 1];
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? *").Append(p.Name).Append(" : 0);\n");
                    b.Append("    bvk_w_u32(").Append(a.Name).Append(" ? 1 : 0);\n");
                    if (m.Structs.ContainsKey(a.Type) && StructHasPNext(m, a.Type))
                        b.Append("    if (").Append(a.Name).Append(" && ").Append(p.Name).Append(") for (uint32_t k = 0; k < *").Append(p.Name).Append("; k++) bvk_w_u32(*(const uint32_t*)&").Append(a.Name).Append("[k]);\n");
                    i++;
                    continue;
                }
                string kind = ParamKind(m, p);
                if (kind == "ScalarIn")
                {
                    int w = ScalarWidth(m, p.Type);
                    b.Append("    bvk_w_u").Append(w == 8 ? "64" : "32").Append("((").Append(w == 8 ? "uint64_t" : "uint32_t").Append(")").Append(p.Name).Append(");\n");
                }
                else if (kind == "HandleIn")
                {
                    b.Append("    bvk_w_u32((uint32_t)(uintptr_t)").Append(p.Name).Append(");\n");
                }
                else if (kind == "AllocatorIn")
                {
                    b.Append("    (void)").Append(p.Name).Append(";\n");
                }
                else if (kind == "FixedArrayIn")
                {
                    b.Append("    bvk_w_bytes(").Append(p.Name).Append(", ").Append(p.ArrayLen * ScalarWidth(m, p.Type)).Append(");\n");
                }
                else if (kind == "StructIn" && StructId.ContainsKey(p.Type))
                {
                    b.Append("    if (").Append(p.Name).Append(") { bvk_w_u32(1); bvk_ser_struct(").Append(StructId[p.Type]).Append(", (const unsigned char*)").Append(p.Name).Append("); } else bvk_w_u32(0);\n");
                }
                else if (kind == "ArrayIn" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? (uint32_t)").Append(p.Length).Append(" : 0);\n");
                    b.Append("    if (").Append(p.Name).Append(") for (uint32_t k = 0; k < (uint32_t)").Append(p.Length).Append("; k++) ");
                    if (m.Structs.ContainsKey(p.Type))
                        b.Append("bvk_ser_struct(").Append(StructId[p.Type]).Append(", (const unsigned char*)&").Append(p.Name).Append("[k]);\n");
                    else if (m.Handles.ContainsKey(p.Type))
                        b.Append("bvk_w_u32((uint32_t)(uintptr_t)").Append(p.Name).Append("[k]);\n");
                    else
                        b.Append("bvk_w_bytes(&").Append(p.Name).Append("[k], ").Append(ScalarWidth(m, p.Type)).Append(");\n");
                }
                else if (kind == "VoidIn" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? (uint32_t)").Append(p.Length).Append(" : 0);\n");
                    b.Append("    if (").Append(p.Name).Append(") bvk_w_bytes(").Append(p.Name).Append(", (uint32_t)").Append(p.Length).Append(");\n");
                }
                else if (kind == "VoidOut" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? (uint32_t)").Append(p.Length).Append(" : 0);\n");
                }
                else if (IsStructLenHandleArrayOut(m, p))
                {
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? ").Append(StructLenGuestExpr(p.Length)).Append(" : 0);\n");
                }
                else if (kind == "ChainOut")
                {
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? *(const uint32_t*)").Append(p.Name).Append(" : 0);\n");
                    b.Append("    if (").Append(p.Name).Append(") { const void *bvk_pn = *(const void*const*)((const char*)").Append(p.Name).Append(" + 8); while (bvk_pn) { int bvk_sd = bvk_pnext_sid(*(const uint32_t*)bvk_pn); if (bvk_sd >= 0) { bvk_w_u32(1); bvk_w_u32(*(const uint32_t*)bvk_pn); bvk_w_u32((uint32_t)bvk_sd); } bvk_pn = *(const void*const*)((const char*)bvk_pn + 8); } }\n");
                    b.Append("    bvk_w_u32(0);\n");
                }
            }
            if (c.Name == "vkBeginCommandBuffer" || c.Name == "vkEndCommandBuffer" || c.Name.StartsWith("vkCmd"))
            {
                string cb = c.Params[0].Name;
                if (c.Name == "vkBeginCommandBuffer")
                    b.Append("    bvk_rec_begin(").Append(cb).Append(");\n    bvk_rec_append(").Append(cb).Append(", BVK_vkBeginCommandBuffer);\n    return VK_SUCCESS;\n}\n");
                else if (c.Name == "vkEndCommandBuffer")
                    b.Append("    bvk_rec_append(").Append(cb).Append(", BVK_vkEndCommandBuffer);\n    return (VkResult)bvk_rec_flush(").Append(cb).Append(");\n}\n");
                else
                    b.Append("    bvk_rec_append(").Append(cb).Append(", BVK_").Append(c.Name).Append(");\n}\n");
                return b.ToString();
            }
            b.Append("    unsigned char bvk_out[").Append(GuestOutSize(m, c)).Append("]; unsigned int bvk_outLen = 0;\n");
            if (c.Params.Any(x => IsWaitTimeoutParam(m, x)))
            {
                b.Append("    int bvk_r;\n");
                b.Append("    uint64_t bvk_start = GetTickCount64();\n");
                b.Append("    for (;;)\n    {\n");
                b.Append("        bvk_r = bvk_rq_send(BVK_").Append(c.Name).Append(", bvk_out, sizeof(bvk_out), &bvk_outLen);\n");
                b.Append("        if ((bvk_r != VK_TIMEOUT && bvk_r != VK_NOT_READY) || timeout == 0) break;\n");
                b.Append("        if (timeout != UINT64_MAX && (GetTickCount64() - bvk_start) * 1000000ull >= timeout)\n");
                b.Append("        {\n            if (bvk_r == VK_NOT_READY) bvk_r = VK_TIMEOUT;\n            break;\n        }\n");
                b.Append("        Sleep(0);\n    }\n");
            }
            else
                b.Append("    int bvk_r = bvk_rq_send(BVK_").Append(c.Name).Append(", bvk_out, sizeof(bvk_out), &bvk_outLen);\n");
            b.Append("    unsigned int bvk_off = 4; (void)bvk_off;\n");
            for (int i = 0; i < c.Params.Count; i++)
            {
                Param p = c.Params[i];
                if (IsCountArrayPair(m, c, i))
                {
                    Param a = c.Params[i + 1];
                    bool elemHandle = m.Handles.ContainsKey(a.Type);
                    bool elemChain = m.Structs.ContainsKey(a.Type) && StructHasPNext(m, a.Type);
                    b.Append("    if (bvk_r >= 0) { uint32_t bvk_oc = 0; if (bvk_outLen >= bvk_off + 4) { memcpy(&bvk_oc, bvk_out + bvk_off, 4); bvk_off += 4; } if (").Append(p.Name).Append(") *").Append(p.Name).Append(" = bvk_oc;\n");
                    if (elemHandle)
                        b.Append("        if (").Append(a.Name).Append(") for (uint32_t k = 0; k < bvk_oc; k++) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; ").Append(a.Name).Append("[k] = (").Append(a.Type).Append(")(uintptr_t)id; } }\n");
                    else if (elemChain)
                        b.Append("        if (").Append(a.Name).Append(") for (uint32_t k = 0; k < bvk_oc; k++) { memcpy((char*)&").Append(a.Name).Append("[k] + 16, bvk_out + bvk_off, sizeof(*").Append(a.Name).Append(") - 16); bvk_off += (unsigned int)sizeof(*").Append(a.Name).Append(") - 16; } }\n");
                    else
                        b.Append("        if (").Append(a.Name).Append(") { memcpy(").Append(a.Name).Append(", bvk_out + bvk_off, bvk_oc * sizeof(*").Append(a.Name).Append(")); bvk_off += bvk_oc * (unsigned int)sizeof(*").Append(a.Name).Append("); } }\n");
                    i++;
                    continue;
                }
                string kind = ParamKind(m, p);
                if (kind == "ScalarOut")
                {
                    int w = ScalarWidth(m, p.Type);
                    b.Append("    if (bvk_r == 0 && ").Append(p.Name).Append(" && bvk_outLen >= bvk_off + ").Append(w).Append(") { memcpy(").Append(p.Name).Append(", bvk_out + bvk_off, ").Append(w).Append("); bvk_off += ").Append(w).Append("; }\n");
                }
                else if (kind == "HandleOut")
                {
                    b.Append("    if (bvk_r == 0 && ").Append(p.Name).Append(" && bvk_outLen >= bvk_off + 4) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; *").Append(p.Name).Append(" = (").Append(p.Type).Append(")(uintptr_t)id; }\n");
                }
                else if (IsStructLenHandleArrayOut(m, p))
                {
                    b.Append("    if (bvk_r == 0 && ").Append(p.Name).Append(") for (uint32_t k = 0; k < ").Append(StructLenGuestExpr(p.Length)).Append("; k++) { if (bvk_outLen >= bvk_off + 4) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; ").Append(p.Name).Append("[k] = (").Append(p.Type).Append(")(uintptr_t)id; } }\n");
                }
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(p.Type) && ParamLenIndex(c, p, i) >= 0)
                {
                    b.Append("    if (bvk_r == 0 && ").Append(p.Name).Append(") for (uint32_t k = 0; k < (uint32_t)").Append(p.Length).Append("; k++) { if (bvk_outLen >= bvk_off + 4) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; ").Append(p.Name).Append("[k] = (").Append(p.Type).Append(")(uintptr_t)id; } }\n");
                }
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(p.Type))
                {
                    b.Append("    if (bvk_r == 0 && ").Append(p.Name).Append(" && bvk_outLen >= bvk_off + 4) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; ").Append(p.Name).Append("[0] = (").Append(p.Type).Append(")(uintptr_t)id; }\n");
                }
                else if (kind == "StructOut")
                {
                    b.Append("    if (bvk_r == 0 && ").Append(p.Name).Append(") { memcpy(").Append(p.Name).Append(", bvk_out + bvk_off, sizeof(*").Append(p.Name).Append(")); bvk_off += (unsigned int)sizeof(*").Append(p.Name).Append("); }\n");
                }
                else if (kind == "ChainOut")
                {
                    int baseSid = StructId[p.Type];
                    b.Append("    if (bvk_r == 0 && ").Append(p.Name).Append(") { memcpy((char*)").Append(p.Name).Append(" + 16, bvk_out + bvk_off, bvk_struct_sizes[").Append(baseSid).Append("] - 16); bvk_off += (unsigned int)(bvk_struct_sizes[").Append(baseSid).Append("] - 16); void *bvk_pn = *(void**)((char*)").Append(p.Name).Append(" + 8); while (bvk_pn) { int bvk_sd = bvk_pnext_sid(*(const uint32_t*)bvk_pn); if (bvk_sd >= 0) { memcpy((char*)bvk_pn + 16, bvk_out + bvk_off, bvk_struct_sizes[bvk_sd] - 16); bvk_off += (unsigned int)(bvk_struct_sizes[bvk_sd] - 16); } bvk_pn = *(void**)((char*)bvk_pn + 8); } }\n");
                }
                else if (kind == "VoidOut" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(" && bvk_outLen >= bvk_off + (uint32_t)").Append(p.Length).Append(") { memcpy(").Append(p.Name).Append(", bvk_out + bvk_off, (uint32_t)").Append(p.Length).Append("); bvk_off += (uint32_t)").Append(p.Length).Append("; }\n");
                }
            }
            if (c.Name == "vkGetPhysicalDeviceMemoryProperties")
                b.Append("    if (bvk_r == 0 && pMemoryProperties) bvk_note_memprops(pMemoryProperties);\n");
            else if (c.Name == "vkGetPhysicalDeviceMemoryProperties2")
                b.Append("    if (bvk_r == 0 && pMemoryProperties) bvk_note_memprops(&pMemoryProperties->memoryProperties);\n");
            if (Ret64(c))
            {
                b.Append("    uint64_t bvk_rv = 0;\n");
                b.Append("    if (bvk_r == 0 && bvk_outLen >= bvk_off + 8) memcpy(&bvk_rv, bvk_out + bvk_off, 8);\n");
                b.Append("    return (").Append(c.Ret).Append(")bvk_rv;\n");
            }
            else if (c.Ret != "void")
                b.Append("    return (").Append(c.Ret).Append(")bvk_r;\n");
            b.Append("}\n");
            return b.ToString();
        }

        private static int GuestOutSize(Model m, Command c)
        {
            int size = 4;
            for (int i = 0; i < c.Params.Count; i++)
            {
                if (IsCountArrayPair(m, c, i))
                    return 65536;
                if (IsStructLenHandleArrayOut(m, c.Params[i]))
                    return 8192;
                string kind = ParamKind(m, c.Params[i]);
                if (kind == "ChainOut")
                    return 65536;
                if (kind == "VoidOut" && c.Params.Any(x => x.Name == c.Params[i].Length))
                    return 65536;
                if (kind == "StructOut")
                    return 8192;
                if (kind == "ScalarOut")
                    size += ScalarWidth(m, c.Params[i].Type);
                else if (kind == "HandleOut")
                    size += 4;
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(c.Params[i].Type) && ParamLenIndex(c, c.Params[i], i) >= 0)
                    return 8192;
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(c.Params[i].Type))
                    size += 4;
            }
            return size < 32 ? 32 : size;
        }

        private static string ParamKind(Model m, Param p)
        {
            if (p.Name == "pNext") return "PNextIn";
            if (p.Type == "VkAllocationCallbacks") return "AllocatorIn";
            if (p.PtrDepth == 0 && p.ArrayLen > 1 && !m.Handles.ContainsKey(p.Type)) return "FixedArrayIn";
            if (p.PtrDepth == 0)
                return m.Handles.ContainsKey(p.Type) ? "HandleIn" : "ScalarIn";
            if (p.Type == "void") return p.IsConst ? "VoidIn" : "VoidOut";
            if (p.Type == "char") return p.PtrDepth >= 2 ? "StringArrayIn" : "StringIn";
            bool hasLen = p.Length != null && p.Length != "null-terminated";
            if (p.IsConst)
            {
                if (hasLen) return "ArrayIn";
                return m.Structs.ContainsKey(p.Type) ? "StructIn" : "ArrayIn";
            }
            if (hasLen) return "ArrayOut";
            if (m.Handles.ContainsKey(p.Type)) return "HandleOut";
            if (m.Structs.ContainsKey(p.Type)) return p.Name != "pNext" && StructHasPNext(m, p.Type) ? "ChainOut" : "StructOut";
            return "ScalarOut";
        }

        private static void Emit(SourceProductionContext spc, string vkXmlPath, string xml)
        {
            Model m;
            try
            {
                m = Parse(xml);
            }
            catch (Exception ex)
            {
                spc.AddSource("BrovVulkApi.g.cs", "// vk.xml parse failed: " + ex.Message.Replace("*/", "* /"));
                return;
            }

            List<Command> cmds = m.Commands.Values.Where(Keep).OrderBy(c => c.Name, StringComparer.Ordinal).ToList();

            StringBuilder b = new StringBuilder();
            b.AppendLine("// <auto-generated> BrovVulk Vulkan API surface, generated from vk.xml by Brovan.Generators.");
            b.AppendLine("using System;");
            b.AppendLine("using System.Runtime.InteropServices;");
            b.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            b.AppendLine("{");
            b.AppendLine("    internal static unsafe class BrovVulkApi");
            b.AppendLine("    {");
            b.AppendLine("        internal const int CommandCount = " + cmds.Count + ";");
            b.AppendLine("        internal static readonly string[] CommandNames = new string[]");
            b.AppendLine("        {");
            foreach (Command c in cmds)
                b.AppendLine("            \"" + c.Name + "\",");
            b.AppendLine("        };");
            b.AppendLine();
            foreach (Command c in cmds)
            {
                StringBuilder args = new StringBuilder();
                for (int i = 0; i < c.Params.Count; i++)
                {
                    if (i > 0) args.Append(", ");
                    args.Append(CsType(m, c.Params[i].Type, c.Params[i].PtrDepth)).Append(" a").Append(i);
                }
                b.AppendLine("        [DllImport(\"vulkan-1.dll\", EntryPoint = \"" + c.Name + "\", CallingConvention = CallingConvention.Winapi)]");
                b.AppendLine("        internal static extern " + CsRet(m, c.Ret) + " " + c.Name + "(" + args + ");");
            }
            b.AppendLine("    }");
            b.AppendLine("}");

            spc.AddSource("BrovVulkApi.g.cs", SourceText.From(b.ToString(), Encoding.UTF8));

            StringBuilder hb = new StringBuilder();
            hb.AppendLine("// <auto-generated> dispatchable Vulkan handles from vk.xml.");
            hb.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            hb.AppendLine("{");
            hb.AppendLine("    internal static class BrovVulkHandles");
            hb.AppendLine("    {");
            hb.AppendLine("        internal static readonly string[] Dispatchable = new string[]");
            hb.AppendLine("        {");
            foreach (KeyValuePair<string, bool> h in m.Handles.OrderBy(k => k.Key, StringComparer.Ordinal))
                if (h.Value)
                    hb.AppendLine("            \"" + h.Key + "\",");
            hb.AppendLine("        };");
            hb.AppendLine("    }");
            hb.AppendLine("}");

            spc.AddSource("BrovVulkHandles.g.cs", SourceText.From(hb.ToString(), Encoding.UTF8));

            Dictionary<string, Layout> cache = new Dictionary<string, Layout>();
            StringBuilder lb = new StringBuilder();
            lb.AppendLine("// <auto-generated> Vulkan struct layout (x64) computed from vk.xml.");
            lb.AppendLine("using System.Collections.Generic;");
            lb.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            lb.AppendLine("{");
            lb.AppendLine("    internal static class BrovVulkLayout");
            lb.AppendLine("    {");
            lb.AppendLine("        internal static readonly Dictionary<string, int> StructSize = new Dictionary<string, int>");
            lb.AppendLine("        {");
            foreach (KeyValuePair<string, VkStruct> kv in m.Structs.OrderBy(k => k.Key, StringComparer.Ordinal))
            {
                int sz;
                try { sz = ComputeLayout(m, kv.Key, cache).Size; }
                catch { sz = -1; }
                lb.AppendLine("            [\"" + kv.Key + "\"] = " + sz + ",");
            }
            lb.AppendLine("        };");
            lb.AppendLine();
            lb.AppendLine("        internal static readonly Dictionary<string, int> MemberOffset = new Dictionary<string, int>");
            lb.AppendLine("        {");
            foreach (KeyValuePair<string, VkStruct> kv in m.Structs.OrderBy(k => k.Key, StringComparer.Ordinal))
            {
                if (!cache.TryGetValue(kv.Key, out Layout lay))
                    continue;
                foreach (KeyValuePair<string, int> off in lay.Offsets)
                    lb.AppendLine("            [\"" + kv.Key + "." + off.Key + "\"] = " + off.Value + ",");
            }
            lb.AppendLine("        };");
            lb.AppendLine("    }");
            lb.AppendLine("}");

            spc.AddSource("BrovVulkLayout.g.cs", SourceText.From(lb.ToString(), Encoding.UTF8));

            StringBuilder mb = new StringBuilder();
            mb.AppendLine("// <auto-generated> Vulkan command parameter descriptors from vk.xml.");
            mb.AppendLine("using System.Collections.Generic;");
            mb.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            mb.AppendLine("{");
            mb.AppendLine("    internal enum BvkParamKind : byte");
            mb.AppendLine("    {");
            mb.AppendLine("        ScalarIn, HandleIn, StructIn, ArrayIn, StringIn, StringArrayIn, PNextIn, AllocatorIn, FixedArrayIn,");
            mb.AppendLine("        ScalarOut, HandleOut, StructOut, ArrayOut, VoidIn, VoidOut, ChainOut,");
            mb.AppendLine("    }");
            mb.AppendLine();
            mb.AppendLine("    internal readonly struct BvkParam");
            mb.AppendLine("    {");
            mb.AppendLine("        public readonly BvkParamKind Kind;");
            mb.AppendLine("        public readonly string Type;");
            mb.AppendLine("        public readonly string Len;");
            mb.AppendLine("        public BvkParam(BvkParamKind kind, string type, string len) { Kind = kind; Type = type; Len = len; }");
            mb.AppendLine("    }");
            mb.AppendLine();
            mb.AppendLine("    internal static class BrovVulkCommandMeta");
            mb.AppendLine("    {");
            mb.AppendLine("        internal static readonly Dictionary<string, BvkParam[]> Params = new Dictionary<string, BvkParam[]>");
            mb.AppendLine("        {");
            foreach (Command c in cmds)
            {
                mb.Append("            [\"").Append(c.Name).Append("\"] = new BvkParam[] { ");
                for (int i = 0; i < c.Params.Count; i++)
                {
                    Param p = c.Params[i];
                    string len = p.Length == null ? "null" : "\"" + p.Length.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
                    mb.Append("new BvkParam(BvkParamKind.").Append(ParamKind(m, p)).Append(", \"").Append(p.Type).Append("\", ").Append(len).Append("), ");
                }
                mb.AppendLine("},");
            }
            mb.AppendLine("        };");
            mb.AppendLine("    }");
            mb.AppendLine("}");
            spc.AddSource("BrovVulkCommandMeta.g.cs", SourceText.From(mb.ToString(), Encoding.UTF8));

            StringBuilder gh = new StringBuilder();
            gh.Append("/* <auto-generated> BrovVulk command ids from vk.xml. Do not edit. */\n");
            gh.Append("#ifndef BROVVULK_GEN_H\n#define BROVVULK_GEN_H\n");
            for (int i = 0; i < cmds.Count; i++)
                gh.Append("#define BVK_").Append(cmds[i].Name).Append(" ").Append(i).Append("u\n");
            gh.Append("#define BVK_COMMAND_COUNT ").Append(cmds.Count).Append("u\n");
            gh.Append("#endif\n");
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_gen.h"), gh.ToString());

            List<Command> allowed = cmds.Where(x => GenAllowlist.Contains(x.Name)).ToList();
            foreach (string en in ExtAllowlist)
            {
                if (!m.Extensions.TryGetValue(en, out VkExtension ext))
                {
                    spc.ReportDiagnostic(Diagnostic.Create(ExtGuard, Location.None, en, "not found in vk.xml"));
                    continue;
                }
                foreach (string cn in ext.Commands)
                    if (!GenAllowlist.Contains(cn))
                        spc.ReportDiagnostic(Diagnostic.Create(ExtGuard, Location.None, en, "requires command " + cn + " missing from GenAllowlist"));
            }
            PNextSet = ComputePNextSet(m, allowed, cache);
            List<string> needed = ComputeNeededStructs(m, allowed, cache);
            StructId = new Dictionary<string, int>();
            for (int i = 0; i < needed.Count; i++)
                StructId[needed[i]] = i;

            StringBuilder sm = new StringBuilder();
            sm.AppendLine("// <auto-generated> Vulkan struct member descriptors from vk.xml.");
            sm.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            sm.AppendLine("{");
            sm.AppendLine("    internal enum BvkMK : byte { Scalar, Handle, StructValue, StructPtr, StructArray, HandleArray, ScalarArray, StringZ, StringArray, PNext, Ignore, BlobPtr, SelectArray }");
            sm.AppendLine("    internal readonly struct BvkM");
            sm.AppendLine("    {");
            sm.AppendLine("        public readonly BvkMK Kind; public readonly int Offset; public readonly int Size; public readonly int Sub; public readonly int LenOffset; public readonly string HandleType; public readonly int SelOffset; public readonly uint SelMask;");
            sm.AppendLine("        public BvkM(BvkMK k, int o, int s, int sub, int lo, string ht, int so, uint sm) { Kind = k; Offset = o; Size = s; Sub = sub; LenOffset = lo; HandleType = ht; SelOffset = so; SelMask = sm; }");
            sm.AppendLine("    }");
            sm.AppendLine("    internal static class BrovVulkStructMeta");
            sm.AppendLine("    {");
            sm.Append("        internal static readonly int[] Sizes = { ");
            foreach (string n in needed) sm.Append(ComputeLayout(m, n, cache).Size).Append(", ");
            sm.AppendLine("};");
            sm.Append("        internal static readonly bool[] PNext = { ");
            foreach (string n in needed) sm.Append(PNextSet.Contains(n) ? "true" : "false").Append(", ");
            sm.AppendLine("};");
            sm.AppendLine("        internal static readonly BvkM[][] Members = new BvkM[][]");
            sm.AppendLine("        {");

            StringBuilder gs = new StringBuilder();
            gs.Append("/* <auto-generated> Vulkan struct member descriptors from vk.xml. */\n");
            gs.Append("#ifndef BROVVULK_STRUCTS_H\n#define BROVVULK_STRUCTS_H\n");
            gs.Append("typedef struct { unsigned char kind; int offset; int size; int sub; int lenOffset; int selOffset; unsigned int selMask; } BvkM;\n");

            for (int si = 0; si < needed.Count; si++)
            {
                string n = needed[si];
                VkStruct s = m.Structs[n];
                Layout lay = ComputeLayout(m, n, cache);
                sm.Append("            new BvkM[] { ");
                gs.Append("static const BvkM bvk_s").Append(si).Append("[] = { ");
                if (s.IsUnion)
                {
                    sm.Append("new BvkM(BvkMK.Scalar, 0, ").Append(lay.Size).Append(", -1, -1, \"\", -1, 0u), ");
                    gs.Append("{0,0,").Append(lay.Size).Append(",-1,-1,-1,0}, ");
                }
                else
                {
                    foreach (Member mem in s.Members)
                    {
                        MDesc d = ClassifyMember(m, s, mem, lay.Offsets, cache);
                        int sub = d.SubName != null && StructId.ContainsKey(d.SubName) ? StructId[d.SubName] : -1;
                        sm.Append("new BvkM(BvkMK.").Append(d.Kind).Append(", ").Append(d.Offset).Append(", ").Append(d.Size).Append(", ").Append(sub).Append(", ").Append(d.LenOffset).Append(", \"").Append(d.HandleType).Append("\", ").Append(d.SelOffset).Append(", ").Append(d.SelMask).Append("u), ");
                        gs.Append("{").Append(KindNum[d.Kind]).Append(",").Append(d.Offset).Append(",").Append(d.Size).Append(",").Append(sub).Append(",").Append(d.LenOffset).Append(",").Append(d.SelOffset).Append(",").Append(d.SelMask).Append("u}, ");
                    }
                }
                sm.AppendLine("},");
                gs.Append("};\n");
            }
            sm.AppendLine("        };");
            sm.AppendLine("    }");
            sm.AppendLine("}");
            spc.AddSource("BrovVulkStructMeta.g.cs", SourceText.From(sm.ToString(), Encoding.UTF8));

            StringBuilder xb = new StringBuilder();
            xb.AppendLine("// <auto-generated> BrovVulk advertisable extensions from vk.xml.");
            xb.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            xb.AppendLine("{");
            xb.AppendLine("    internal static class BrovVulkExtensions");
            xb.AppendLine("    {");
            foreach (string scope in new[] { "instance", "device" })
            {
                string field = scope == "instance" ? "Instance" : "Device";
                xb.AppendLine("        internal static readonly (string Name, uint Version)[] " + field + " =");
                xb.AppendLine("        {");
                foreach (string en in ExtAllowlist.OrderBy(x => x, StringComparer.Ordinal))
                    if (m.Extensions.TryGetValue(en, out VkExtension ext) && ext.Type == scope)
                        xb.AppendLine("            (\"" + en + "\", " + ext.SpecVersion + "u),");
                xb.AppendLine("        };");
            }
            xb.AppendLine("    }");
            xb.AppendLine("}");
            spc.AddSource("BrovVulkExtensions.g.cs", SourceText.From(xb.ToString(), Encoding.UTF8));

            gs.Append("static const BvkM* const bvk_structs[] = { ");
            for (int si = 0; si < needed.Count; si++) gs.Append("bvk_s").Append(si).Append(", ");
            gs.Append("};\n");
            gs.Append("static const int bvk_struct_counts[] = { ");
            foreach (string n in needed) gs.Append(m.Structs[n].IsUnion ? 1 : m.Structs[n].Members.Count).Append(", ");
            gs.Append("};\n");
            gs.Append("static const int bvk_struct_sizes[] = { ");
            foreach (string n in needed) gs.Append(ComputeLayout(m, n, cache).Size).Append(", ");
            gs.Append("};\n");
            gs.Append("static int bvk_pnext_sid(unsigned int stype) {\n    switch (stype) {\n");
            foreach (string n in needed)
            {
                if (!PNextSet.Contains(n)) continue;
                string st = StructSType(m.Structs[n]);
                if (st == null) continue;
                gs.Append("    case ").Append(st).Append(": return ").Append(StructId[n]).Append(";\n");
            }
            gs.Append("    default: return -1;\n    }\n}\n");
            gs.Append("#endif\n");
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_structs.h"), gs.ToString());

            StringBuilder db = new StringBuilder();
            db.AppendLine("// <auto-generated> BrovVulk generic host dispatch from vk.xml.");
            db.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            db.AppendLine("{");
            db.AppendLine("    internal static unsafe class BrovVulkGenDispatch");
            db.AppendLine("    {");
            db.AppendLine("        internal static int Dispatch(uint id, GenReader r, GenBuf w, GenState st, BinaryEmulator inst)");
            db.AppendLine("        {");
            db.AppendLine("            switch (id)");
            db.AppendLine("            {");
            StringBuilder cb = new StringBuilder();
            StringBuilder pb = new StringBuilder();
            StringBuilder procB = new StringBuilder();
            StringBuilder defB = new StringBuilder();
            defB.Append("LIBRARY vulkan-1\nEXPORTS\n");
            defB.Append("vkGetInstanceProcAddr\nvkGetDeviceProcAddr\n");
            defB.Append("vkEnumerateInstanceLayerProperties\n");
            defB.Append("vkCreateDescriptorUpdateTemplate\nvkDestroyDescriptorUpdateTemplate\nvkUpdateDescriptorSetWithTemplate\n");
            defB.Append("vkCreatePrivateDataSlot\nvkDestroyPrivateDataSlot\nvkSetPrivateData\nvkGetPrivateData\n");
            pb.Append("#ifndef BROVVULK_GEN_PROTOS_H\n#define BROVVULK_GEN_PROTOS_H\n");
            for (int i = 0; i < cmds.Count; i++)
            {
                Command c = cmds[i];
                if (!GenAllowlist.Contains(c.Name))
                    continue;
                string hostCase = EmitHostCase(m, c, i);
                if (hostCase == null)
                    continue;
                db.Append(hostCase);
                cb.Append(EmitGuestTrampoline(m, c)).Append("\n");
                if (c.Name == "vkCreateWin32SurfaceKHR")
                    pb.Append("VKAPI_ATTR VkResult VKAPI_CALL vkCreateWin32SurfaceKHR(VkInstance instance, const VkWin32SurfaceCreateInfoKHR *pCreateInfo, const VkAllocationCallbacks *pAllocator, VkSurfaceKHR *pSurface);\n");
                else
                    pb.Append("VKAPI_ATTR ").Append(c.Ret).Append(" VKAPI_CALL ").Append(c.Name).Append("(").Append(GuestSig(c)).Append(");\n");
                procB.Append("M(").Append(c.Name).Append(");\n");
                if (c.Name != "vkGetInstanceProcAddr" && c.Name != "vkGetDeviceProcAddr"
                    && c.Name != "vkEnumerateInstanceLayerProperties")
                    defB.Append(c.Name).Append("\n");
            }
            foreach (Command alias in m.Commands.Values)
            {
                if (alias.Alias == null || !GenAllowlist.Contains(alias.Alias) || GenAllowlist.Contains(alias.Name))
                    continue;
                procB.Append("if (strcmp(pName, \"").Append(alias.Name).Append("\") == 0) return (PFN_vkVoidFunction)")
                     .Append(alias.Alias).Append(";\n");
            }
            pb.Append("#endif\n");
            db.AppendLine("                default: return -3;");
            db.AppendLine("            }");
            db.AppendLine("        }");
            db.AppendLine("    }");
            db.AppendLine("}");
            spc.AddSource("BrovVulkGenDispatch.g.cs", SourceText.From(db.ToString(), Encoding.UTF8));

            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_gen.c"), cb.ToString());
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_gen_protos.h"), pb.ToString());
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_gen_procs.inc"), procB.ToString());
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "exports.def"), defB.ToString());
        }
    }
}
