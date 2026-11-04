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
            public bool Optional;
            public bool OptionalElements;
        }

        private sealed class VkStruct
        {
            public string Name;
            public bool IsUnion;
            public string[] Extends = Array.Empty<string>();
            public bool AllowDuplicate;
            public readonly List<Member> Members = new List<Member>();
        }

        private sealed class VkExtension
        {
            public string Name;
            public string Type;
            public string Platform;
            public string Depends;
            public uint SpecVersion;
            public readonly HashSet<string> Commands = new HashSet<string>();
            public readonly HashSet<string> Types = new HashSet<string>();
            public readonly List<(string Depends, HashSet<string> Commands, HashSet<string> Types)> Gated = new List<(string, HashSet<string>, HashSet<string>)>();
        }

        private sealed class Param
        {
            public string Name;
            public string Type;
            public int PtrDepth;
            public bool IsConst;
            public string Length;
            public string AltLength;
            public int ArrayLen = 1;
            public bool Optional;
            public bool OptionalElement;
        }

        private sealed class Command
        {
            public string Name;
            public string Ret;
            public readonly List<Param> Params = new List<Param>();
            public string Alias;
            public string ErrorCodes;
        }

        private sealed class Model
        {
            public readonly Dictionary<string, bool> Handles = new Dictionary<string, bool>();
            public readonly Dictionary<string, string> HandleParents = new Dictionary<string, string>();
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
            public readonly Dictionary<string, double> CoreCommandVersion = new Dictionary<string, double>();
            public XElement Formats;
        }

        private static readonly string[] SkipPlatform =
        {
            "Android", "ANDROID", "Xlib", "Xcb", "Wayland", "DirectFB", "Metal", "MacOS", "IOS",
            "Screen", "ViSurface", "OHOS", "Fuchsia", "GGP", "QNX", "Winrt",
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
            m.Formats = root.Element("formats");

            foreach (XElement e in root.Descendants("enum"))
            {
                string name = (string)e.Attribute("name");
                string val = (string)e.Attribute("value");
                if (name != null && val != null && !m.Constants.ContainsKey(name) && TryParseIntLiteral(val, out int cv))
                    m.Constants[name] = cv;
            }

            foreach (XElement e in root.Descendants("enum"))
            {
                string name = (string)e.Attribute("name");
                string bit = (string)e.Attribute("bitpos");
                if (name != null && bit != null && !m.Constants.ContainsKey(name) && TryParseIntLiteral(bit, out int pos) && pos >= 0 && pos < 31)
                    m.Constants[name] = 1 << pos;
            }

            // An extension enum carries a block number and an offset instead of a value.
            foreach (XElement e in root.Descendants("enum"))
            {
                string name = (string)e.Attribute("name");
                string offset = (string)e.Attribute("offset");
                if (name == null || offset == null || m.Constants.ContainsKey(name)
                    || !TryParseIntLiteral(offset, out int off))
                    continue;
                string number = (string)e.Attribute("extnumber") ?? (string)e.Ancestors("extension").FirstOrDefault()?.Attribute("number");
                if (number == null || !TryParseIntLiteral(number, out int ext))
                    continue;
                int value = 1000000000 + (ext - 1) * 1000 + off;
                m.Constants[name] = (string)e.Attribute("dir") == "-" ? -value : value;
            }

            foreach (XElement t in root.Descendants("type"))
            {
                string cat = (string)t.Attribute("category");
                if (cat == null)
                    continue;
                string name = (string)t.Attribute("name") ?? t.Element("name")?.Value ?? t.Element("proto")?.Element("name")?.Value;
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
                    string parent = (string)t.Attribute("parent");
                    if (!string.IsNullOrEmpty(parent))
                        m.HandleParents[name] = parent.Split(',')[0].Trim();
                }
                else if (cat == "struct" || cat == "union")
                {
                    string extends = (string)t.Attribute("structextends");
                    VkStruct s = new VkStruct
                    {
                        Name = name,
                        IsUnion = cat == "union",
                        Extends = extends == null ? Array.Empty<string>() : extends.Split(','),
                        AllowDuplicate = (string)t.Attribute("allowduplicate") == "true",
                    };
                    foreach (XElement mem in t.Elements("member"))
                    {
                        if ((string)mem.Attribute("api") == "vulkansc")
                            continue;
                        ParseTyped(mem, out string ty, out string nm, out int pd, out bool isc);
                        int alen = pd == 0 ? ResolveArrayLen(mem, m.Constants) : 1;
                        s.Members.Add(new Member { Name = nm, Type = ty, PtrDepth = pd, IsConst = isc, Length = (string)mem.Attribute("len"), AltLength = (string)mem.Attribute("altlen"), ArrayLen = alen, Values = (string)mem.Attribute("values"), Optional = OptionalAt(mem, 0), OptionalElements = OptionalElementsOf(mem) });
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
                
                // vk.xml lists some commands twice, and the Vulkan SC copy drops optional.
                string commandApi = (string)c.Attribute("api");
                if (commandApi != null && Array.IndexOf(commandApi.Split(','), "vulkan") < 0)
                    continue;
                XElement proto = c.Element("proto");
                if (proto == null)
                    continue;
                Command cmd = new Command { Name = proto.Element("name")?.Value, Ret = proto.Element("type")?.Value, ErrorCodes = (string)c.Attribute("errorcodes") };
                foreach (XElement p in c.Elements("param"))
                {
                    if ((string)p.Attribute("api") == "vulkansc")
                        continue;
                    ParseTyped(p, out string ty, out string nm, out int pd, out bool isc);
                    int palen = pd == 0 ? ResolveArrayLen(p, m.Constants) : 1;
                    // One optional component covers the pointer, a second covers the elements.
                    string[] optParts = ((string)p.Attribute("optional") ?? "").Split(',');
                    bool opt = optParts[0].StartsWith("true", StringComparison.Ordinal) && !RequiredHandles.Contains(cmd.Name + "." + nm);
                    cmd.Params.Add(new Param { Name = nm, Type = ty, PtrDepth = pd, IsConst = isc, Length = (string)p.Attribute("len"), AltLength = (string)p.Attribute("altlen"), ArrayLen = palen, Optional = opt, OptionalElement = optParts[optParts.Length - 1].StartsWith("true", StringComparison.Ordinal) });
                }
                if (cmd.Name != null)
                    m.Commands[cmd.Name] = cmd;
            }

            string Canonical(string ty) => m.TypeAlias.TryGetValue(ty, out string tgt) ? tgt : ty;

            string Resolve(string ty)
            {
                for (int hops = 0; ty != null && hops < 8 && m.TypeAlias.TryGetValue(ty, out string tgt); hops++)
                    ty = tgt;
                return ty;
            }
            foreach (VkStruct s in m.Structs.Values)
                foreach (Member mem in s.Members)
                    mem.Type = Resolve(mem.Type);
            foreach (Command cmd in m.Commands.Values)
                foreach (Param p in cmd.Params)
                    p.Type = Resolve(p.Type);

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
                    foreach (XElement cn in req.Elements("command"))
                    {
                        string cname = (string)cn.Attribute("name");
                        if (cname != null && (!m.CoreCommandVersion.TryGetValue(cname, out double cv) || ver < cv))
                            m.CoreCommandVersion[cname] = ver;
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
                    VkExtension ext = new VkExtension { Name = name, Type = (string)e.Attribute("type"), Platform = platform, Depends = (string)e.Attribute("depends") };
                    foreach (XElement req in e.Elements("require"))
                    {
                        string gate = (string)req.Attribute("depends");
                        foreach (XElement en in req.Elements("enum"))
                        {
                            string enName = (string)en.Attribute("name");
                            if (enName != null && enName.EndsWith("_SPEC_VERSION", StringComparison.Ordinal)
                                && TryParseIntLiteral((string)en.Attribute("value"), out int sv))
                                ext.SpecVersion = (uint)sv;
                        }
                        HashSet<string> cmdSet = ext.Commands, typeSet = ext.Types;
                        if (gate != null)
                        {
                            cmdSet = new HashSet<string>();
                            typeSet = new HashSet<string>();
                            ext.Gated.Add((gate, cmdSet, typeSet));
                        }
                        foreach (XElement cn in req.Elements("command"))
                        {
                            string cname = (string)cn.Attribute("name");
                            if (cname == null)
                                continue;
                            if (m.Commands.TryGetValue(cname, out Command cc) && cc.Alias != null)
                                cname = cc.Alias;
                            cmdSet.Add(cname);
                        }
                        foreach (XElement tn in req.Elements("type"))
                        {
                            string ty = Canonical((string)tn.Attribute("name") ?? "");
                            if (ty.Length > 0)
                                typeSet.Add(ty);
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

        private static bool ScalarSizeAlign(string ty, out int size, out int align)
        {
            switch (ty)
            {
                case "uint8_t": case "int8_t": case "char": size = 1; align = 1; return true;
                case "uint16_t": case "int16_t": size = 2; align = 2; return true;
                case "uint32_t":
                case "int32_t":
                case "int":
                case "float":
                case "VkBool32":
                case "VkFlags":
                case "VkSampleMask": size = 4; align = 4; return true;
                case "uint64_t":
                case "int64_t":
                case "double":
                case "size_t":
                case "VkDeviceSize":
                case "VkDeviceAddress":
                case "VkFlags64": size = 8; align = 8; return true;
                case "HINSTANCE": case "HWND": case "HANDLE": case "HMONITOR": case "HDC": case "LPCWSTR": size = 8; align = 8; return true;
                case "DWORD": case "BOOL": case "LONG": case "UINT": size = 4; align = 4; return true;
            }
            size = 0;
            align = 0;
            return false;
        }

        // Only gapped structs may use the 4-byte fallback.
        private static bool IsSizedType(Model m, string ty) =>
            m.Handles.ContainsKey(ty) || m.FuncPointers.Contains(ty) || ScalarSizeAlign(ty, out _, out _)
            || m.Enums.Contains(ty) || m.BitmaskWidth.ContainsKey(ty) || m.Structs.ContainsKey(ty);

        private static void SizeAlign(Model m, string ty, int ptrDepth, Dictionary<string, Layout> cache, out int size, out int align)
        {
            if (ptrDepth > 0 || m.Handles.ContainsKey(ty) || m.FuncPointers.Contains(ty)) { size = 8; align = 8; return; }
            if (ScalarSizeAlign(ty, out size, out align)) return;
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

        // vk.xml leaves these unmarked, but the spec lets each one be null.
        private static readonly HashSet<string> NullableMembers = new HashSet<string>
        {
            "VkWriteDescriptorSet.dstSet",
            "VkDescriptorImageInfo.sampler",
            "VkDescriptorImageInfo.imageView",
        };

        // VK_GOOGLE_surfaceless_query is what marks these optional, and it is denied. The loader
        // dereferences the surface before any driver sees it.
        private static readonly HashSet<string> RequiredHandles = new HashSet<string>
        {
            "VkPhysicalDeviceSurfaceInfo2KHR.surface",
            "vkGetPhysicalDeviceSurfaceFormatsKHR.surface",
            "vkGetPhysicalDeviceSurfacePresentModesKHR.surface",
        };

        private static bool OptionalAt(XElement e, int index)
        {
            string owner = (string)e.Parent?.Attribute("name");
            string qualified = owner == null ? null : owner + "." + e.Element("name")?.Value;
            if (qualified != null && RequiredHandles.Contains(qualified))
                return false;

            string[] parts = ((string)e.Attribute("optional") ?? "").Split(',');
            if (parts.Length > index && parts[index] == "true")
                return true;

            return qualified != null && NullableMembers.Contains(qualified);
        }

        // One optional component in vk.xml covers the pointer and its elements, so such an array may hold
        // null handles.
        private static bool OptionalElementsOf(XElement e)
        {
            string[] parts = ((string)e.Attribute("optional") ?? "").Split(',');
            return parts.Length > 1 ? parts[1] == "true" : parts[0] == "true";
        }

        private static bool Keep(Command c)
        {
            if (c.Alias != null) return false;
            foreach (string s in SkipPlatform)
                if (c.Name.IndexOf(s, StringComparison.Ordinal) >= 0)
                    return false;
            return true;
        }

        private static readonly HashSet<string> GuestLocal = new HashSet<string>
        {
            "vkGetInstanceProcAddr",
            "vkGetDeviceProcAddr",
            "vkEnumerateInstanceLayerProperties",
            "vkEnumerateDeviceLayerProperties",
            "vkCreateDescriptorUpdateTemplate",
            "vkDestroyDescriptorUpdateTemplate",
            "vkUpdateDescriptorSetWithTemplate",
            "vkCmdPushDescriptorSetWithTemplate",
            "vkCmdPushDescriptorSetWithTemplate2",
            "vkCreatePrivateDataSlot",
            "vkDestroyPrivateDataSlot",
            "vkSetPrivateData",
            "vkGetPrivateData",
            "vkCreateDebugUtilsMessengerEXT",
            "vkDestroyDebugUtilsMessengerEXT",
            "vkSubmitDebugUtilsMessageEXT",
            "vkSetDebugUtilsObjectNameEXT",
            "vkSetDebugUtilsObjectTagEXT",
            "vkQueueBeginDebugUtilsLabelEXT",
            "vkQueueEndDebugUtilsLabelEXT",
            "vkQueueInsertDebugUtilsLabelEXT",
            "vkCmdBeginDebugUtilsLabelEXT",
            "vkCmdEndDebugUtilsLabelEXT",
            "vkCmdInsertDebugUtilsLabelEXT",
        };

        private static readonly Dictionary<string, string> ExtDenylist = new Dictionary<string, string>
        {
            ["VK_KHR_external_semaphore_win32"] = "host handle crosses the boundary",
            ["VK_KHR_external_fence_win32"] = "host handle crosses the boundary",
            ["VK_KHR_win32_keyed_mutex"] = "host handle crosses the boundary",
            ["VK_NV_external_memory_win32"] = "host handle crosses the boundary",
            ["VK_NV_win32_keyed_mutex"] = "host handle crosses the boundary",
            ["VK_KHR_external_memory_fd"] = "host file descriptor crosses the boundary",
            ["VK_KHR_external_semaphore_fd"] = "host file descriptor crosses the boundary",
            ["VK_KHR_external_fence_fd"] = "host file descriptor crosses the boundary",
            ["VK_EXT_external_memory_dma_buf"] = "host file descriptor crosses the boundary",
            ["VK_EXT_external_memory_host"] = "host and guest pointers cross the boundary",
            ["VK_LUNARG_direct_driver_loading"] = "the host loader calls a function pointer from the create info",
            ["VK_NV_external_memory_rdma"] = "returns a driver address (VkRemoteAddressNV)",
            ["VK_EXT_pipeline_properties"] = "output is a generic VkBaseOutStructure the driver writes past",
            ["VK_EXT_map_memory_placed"] = "host and guest pointers cross the boundary",
            ["VK_KHR_map_memory2"] = "host and guest pointers cross the boundary",
            ["VK_EXT_host_image_copy"] = "host and guest pointers cross the boundary",
            ["VK_EXT_debug_report"] = "guest callbacks and raw object handles",
            ["VK_EXT_debug_marker"] = "guest callbacks and raw object handles",
            ["VK_EXT_device_memory_report"] = "guest callbacks and raw object handles",
            ["VK_EXT_device_address_binding_report"] = "guest callbacks and raw object handles",
            ["VK_EXT_validation_features"] = "layer only",
            ["VK_EXT_validation_flags"] = "layer only",
            ["VK_EXT_validation_cache"] = "layer only",
            ["VK_EXT_layer_settings"] = "layer only",
            ["VK_KHR_display"] = "host display and window ownership",
            ["VK_KHR_display_swapchain"] = "host display and window ownership",
            ["VK_KHR_get_display_properties2"] = "host display and window ownership",
            ["VK_EXT_direct_mode_display"] = "host display and window ownership",
            ["VK_EXT_display_control"] = "host display and window ownership",
            ["VK_EXT_display_surface_counter"] = "host display and window ownership",
            ["VK_EXT_acquire_drm_display"] = "host display and window ownership",
            ["VK_NV_acquire_winrt_display"] = "host display and window ownership",
            ["VK_EXT_headless_surface"] = "host display and window ownership",
            ["VK_EXT_full_screen_exclusive"] = "host display and window ownership",
            ["VK_KHR_calibrated_timestamps"] = "guest clock differs from the host clock",
            ["VK_EXT_calibrated_timestamps"] = "guest clock differs from the host clock",
            ["VK_NV_low_latency2"] = "blocks the dispatch thread without a timeout",
            ["VK_NVX_binary_import"] = "host CUDA interop",
            ["VK_NVX_image_view_handle"] = "host CUDA interop",
            ["VK_EXT_multi_draw"] = "strided array parameters",
            ["VK_EXT_shader_object"] = "bypasses the shader module stand-ins",
            ["VK_GOOGLE_surfaceless_query"] = "a null surface reaches the host loader",
        };

        // Advertised, but the listed chain structs are dropped and nothing is written back to them.
        private static readonly Dictionary<string, string[]> ExtKnownGaps = new Dictionary<string, string[]>
        {
            ["VK_KHR_maintenance6"] = new[] { "VkBindMemoryStatus" },
            ["VK_KHR_external_memory_win32"] = new[] { "VkExportMemoryWin32HandleInfoKHR" },
            ["VK_EXT_debug_utils"] = new[] { "VkDebugUtilsMessengerCreateInfoEXT", "VkDebugUtilsObjectNameInfoEXT" },
        };

        private static readonly HashSet<string> KnownGapTypes = new HashSet<string>(ExtKnownGaps.Values.SelectMany(gaps => gaps), StringComparer.Ordinal);

        private static readonly Dictionary<string, string> HostReplaced = new Dictionary<string, string>
        {
            ["vkGetMemoryWin32HandleKHR"] = "BrovVulkGenMemory.GetMemoryWin32Handle",
            ["vkGetMemoryWin32HandlePropertiesKHR"] = "BrovVulkGenMemory.GetMemoryWin32HandleProperties",
            ["vkWaitForFences"] = "BrovVulkWaits.WaitForFences",
            ["vkWaitSemaphores"] = "BrovVulkWaits.WaitSemaphores",
            ["vkQueueSubmit"] = "BrovVulkRetire.QueueSubmit",
            ["vkQueueSubmit2"] = "BrovVulkRetire.QueueSubmit2",
            ["vkQueueBindSparse"] = "BrovVulkRetire.QueueBindSparse",
            ["vkFreeCommandBuffers"] = "BrovVulkRetire.FreeCommandBuffers",
            ["vkFreeDescriptorSets"] = "BrovVulkRetire.FreeDescriptorSets",
        };

        // The guest does not wait for a reply to these. It sends them in one batch before its next ioctl.
        private static readonly HashSet<string> PostedCommands = new HashSet<string>
        {
            "vkUpdateDescriptorSets",
        };

        // Host drivers may keep these pNext chains until object destruction.
        private static readonly HashSet<string> RetainedChains = new HashSet<string>
        {
            "vkCreateDescriptorSetLayout",
        };

        // The guest picks the handle ids of these creations, so that it can post them.
        private static readonly HashSet<string> GuestIds = new HashSet<string>
        {
            "vkAllocateDescriptorSets",
        };

        // vulkan_shim.c exports these by hand and calls the generated bvk_gen_<name>.
        private static readonly HashSet<string> GuestWrapped = new HashSet<string>
        {
            "vkAllocateDescriptorSets", "vkCreateDescriptorPool", "vkResetDescriptorPool", "vkDestroyDescriptorPool",
            "vkCreateDescriptorSetLayout", "vkDestroyDescriptorSetLayout", "vkDestroyDevice",
        };

        private const uint PostedBatchId = 0xFFFFFFFD;
        private const uint GuestIdBase = 0x80000000;

        // Keep this in step with the handle types that BrovVulkWaits pins.
        private static readonly HashSet<string> ParkedWaitHandleTypes = new HashSet<string>
        {
            "VkFence", "VkSemaphore", "VkDevice", "VkInstance",
        };

        // These extensions bypass CPU shader or resource checks.
        private static readonly HashSet<string> CpuWithheldNames = new HashSet<string>(StringComparer.Ordinal)
        {
            "VK_EXT_shader_module_identifier", "VK_KHR_pipeline_binary", "VK_NV_ray_tracing",
            "VK_EXT_fragment_density_map", "VK_EXT_fragment_density_map2", "VK_EXT_fragment_density_map_offset", "VK_QCOM_fragment_density_map_offset",
            "VK_EXT_mutable_descriptor_type", "VK_VALVE_mutable_descriptor_type", "VK_KHR_pipeline_executable_properties",
        };

        private static readonly HashSet<string> ComputeDispatches = new HashSet<string>(StringComparer.Ordinal)
        {
            "vkCmdDispatch", "vkCmdDispatchBase", "vkCmdDispatchIndirect",
        };

        private static bool RunsShaders(string name) =>
            name.Contains("Dispatch") || name.Contains("TraceRays") || name.Contains("Launch") || name.Contains("SubpassShading")
            || name.Contains("ExecuteGeneratedCommands");

        private static readonly HashSet<string> AddressQueries = new HashSet<string>(StringComparer.Ordinal)
        {
            "vkGetBufferDeviceAddress", "vkGetBufferOpaqueCaptureAddress", "vkGetDeviceMemoryOpaqueCaptureAddress",
        };

        private static bool WithheldOnCpu(Model m, VkExtension ext, Dictionary<string, bool> carries)
        {
            if (CpuWithheldNames.Contains(ext.Name))
                return true;

            foreach (string name in EffectiveCommands(ext))
            {
                if (!m.Commands.TryGetValue(name, out Command c))
                    continue;
                for (int hops = 0; c.Alias != null && hops < 8 && m.Commands.TryGetValue(c.Alias, out Command target); hops++)
                    c = target;
                if (!AddressQueries.Contains(c.Name) && (CarriesAddress(m, c.Ret, carries) || c.Params.Any(p => CarriesAddress(m, p.Type, carries))))
                    return true;
            }

            return EffectiveTypes(ext).Any(t => CarriesAddress(m, t, carries));
        }

        private static bool CarriesAddress(Model m, string type, Dictionary<string, bool> carries)
        {
            if (type == null)
                return false;
            if (m.TypeAlias.TryGetValue(type, out string target))
                type = target;
            if (type == "VkDeviceAddress")
                return true;
            if (!m.Structs.TryGetValue(type, out VkStruct s))
                return false;
            if (carries.TryGetValue(type, out bool known))
                return known;

            carries[type] = false;
            bool found = s.Members.Any(mem => CarriesAddress(m, mem.Type, carries));
            carries[type] = found;
            return found;
        }

        private static bool HostImplemented(VkExtension ext)
        {
            List<string> commands = EffectiveCommands(ext).ToList();
            return commands.Count != 0 && commands.All(HostReplaced.ContainsKey);
        }

        private static HashSet<string> Advertised = new HashSet<string>();

        private static HashSet<string> AdvertisedTypes = new HashSet<string>();

        private const double MaxCoreVersion = 1.3;

        private static uint MaxApiVersion => ApiVersion(MaxCoreVersion);

        private static uint ApiVersion(double version) => ((uint)version << 22) | (((uint)Math.Round(version * 10) % 10) << 12);

        private static bool IsWaitTimeoutParam(Model m, Param p)
            => p.Name == "timeout" && ParamKind(m, p) == "ScalarIn" && ScalarWidth(m, p.Type) == 8;

        private static Param WaitTimeoutStructParam(Model m, Command c)
        {
            foreach (Param p in c.Params)
                if (ParamKind(m, p) == "StructIn" && m.Structs.TryGetValue(p.Type, out VkStruct s)
                    && s.Members.Any(x => x.Name == "timeout" && x.PtrDepth == 0 && ScalarWidth(m, x.Type) == 8))
                    return p;
            return null;
        }

        private static HashSet<string> PNextSet = new HashSet<string>();

        private static string StructSType(VkStruct s)
        {
            foreach (Member mem in s.Members)
                if (mem.Name == "sType" && mem.Values != null)
                    return mem.Values;
            return null;
        }

        // Zero when vk.xml gives no sType value, which the host then cannot check.
        private static uint STypeValue(Model m, string name)
        {
            string tag = m.Structs.TryGetValue(name, out VkStruct s) ? StructSType(s) : null;
            return tag != null && m.Constants.TryGetValue(tag, out int v) && v > 0 ? (uint)v : 0u;
        }

        private static int ScalarWidth(Model m, string ty)
        {
            SizeAlign(m, ty, 0, new Dictionary<string, Layout>(), out int sz, out _);
            return sz;
        }

        private static string GuestOffset(string structName, string memberName, int fallback)
            => memberName == null ? fallback.ToString() : "(int)offsetof(" + structName + "," + memberName + ")";

        private static string GuestNativeSize(string structName, MDesc d)
        {
            if (d.MemName == null)
                return d.Size.ToString();

            string field = "((" + structName + "*)0)->" + d.MemName;
            switch (d.Kind)
            {
                case "Scalar":
                    return "(int)sizeof(" + field + ")";
                case "ScalarArray":
                case "HandleArray":
                case "SelectArray":
                    return "(int)sizeof(*" + field + ")";
                case "BlobPtr":
                    return d.LenName == null ? d.Size.ToString() : "(int)sizeof(((" + structName + "*)0)->" + d.LenName + ")";
                default:
                    return d.Size.ToString();
            }
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

        private static Dictionary<int, string> WireShapes = new Dictionary<int, string>();

        private static readonly DiagnosticDescriptor ExtGuard = new DiagnosticDescriptor(
            "BVK001", "BrovVulk extension table drift",
            "{0}: {1}", "BrovVulk", DiagnosticSeverity.Error, true);

        private static readonly DiagnosticDescriptor GuestAnswerGuard = new DiagnosticDescriptor(
            "BVK002", "BrovVulk command the guest answers has an unsupported shape",
            "{0}: {1}", "BrovVulk", DiagnosticSeverity.Error, true);

        private static readonly DiagnosticDescriptor RetainedChainGuard = new DiagnosticDescriptor(
            "BVK003", "BrovVulk command whose create-info chains are kept has an unsupported shape",
            "{0}: {1}", "BrovVulk", DiagnosticSeverity.Error, true);

        private static IEnumerable<(string Name, string Problem)> RetainedChainProblems(Model m)
        {
            foreach (string n in RetainedChains)
            {
                if (!m.Commands.TryGetValue(n, out Command c))
                    yield return (n, "not found in vk.xml");
                else if (c.Ret != "VkResult" || GuestIds.Contains(n)
                         || c.Params.Count(p => ParamKind(m, p).EndsWith("Out", StringComparison.Ordinal)) != 1
                         || !c.Params.Any(p => ParamKind(m, p) == "HandleOut")
                         || c.Params.Count(p => ParamKind(m, p) == "StructIn" && StructId.ContainsKey(p.Type)) != 1)
                    yield return (n, "the chains are kept per created handle, so the command must be a VkResult create of one host-id handle from one create info");
            }
        }

        private static IEnumerable<(string Name, string Problem)> GuestAnswerProblems(Model m)
        {
            foreach (string n in PostedCommands)
            {
                if (!m.Commands.TryGetValue(n, out Command c))
                    yield return (n, "not found in vk.xml");
                else if (c.Ret != "void" || c.Name.StartsWith("vkCmd", StringComparison.Ordinal)
                         || c.Params.Count == 0 || (c.Params[0].Type != "VkDevice" && c.Params[0].Type != "VkQueue"))
                    yield return (n, "a posted command must be a void device or queue command");
                else if (c.Params.Any(p => ParamKind(m, p).EndsWith("Out", StringComparison.Ordinal)))
                    yield return (n, "a posted command cannot have outputs");
                else if (HostReplaced.ContainsKey(n) || ReleasesMappings(c))
                    yield return (n, "the host side of a posted command must be generated and read no guest pages");
                else if (!EmitGuestTrampoline(m, c).Contains("bvk_post(BVK_" + n + ")"))
                    yield return (n, "the guest trampoline is written by hand and does not post");
            }

            foreach (string n in GuestIds)
            {
                if (!m.Commands.TryGetValue(n, out Command c))
                    yield return (n, "not found in vk.xml");
                else if (c.Ret != "VkResult" || c.Params.Count == 0 || c.Params[0].Type != "VkDevice")
                    yield return (n, "a guest-id command must be a VkResult device command");
                else if (GuestIdOutIndex(m, c) < 0 || c.Params.Count(p => ParamKind(m, p).EndsWith("Out", StringComparison.Ordinal) || IsStructLenHandleArrayOut(m, p)) != 1)
                    yield return (n, "a guest-id command needs one output, a handle array sized by a struct member");
                else if (!FindParent(m, c, c.Params[GuestIdOutIndex(m, c)].Type, out _, out _))
                    yield return (n, "the parent of a guest-id handle is not an argument");
            }
        }

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

            public string MemName;
            public string LenName;
            public string SelName;
            public bool Optional;
            public bool OptionalElements;
            public bool LenSamples;
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

        private static readonly HashSet<string> PointerWidthTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            "size_t", "HINSTANCE", "HWND", "HANDLE", "HMONITOR", "HDC", "LPCWSTR"
        };

        private static void FlatPadding(Model m, string type, int baseOffset, Dictionary<string, Layout> cache, List<int> ranges)
        {
            bool[] covered = new bool[ComputeLayout(m, type, cache).Size];
            MarkCovered(m, type, 0, cache, covered);
            for (int i = 0; i < covered.Length; i++)
            {
                if (covered[i])
                    continue;
                int start = i;
                while (i < covered.Length && !covered[i])
                    i++;
                ranges.Add(baseOffset + start);
                ranges.Add(i - start);
            }
        }

        private static void MarkCovered(Model m, string type, int at, Dictionary<string, Layout> cache, bool[] covered)
        {
            VkStruct s = m.Structs[type];
            Layout lay = ComputeLayout(m, type, cache);
            if (s.IsUnion)
            {
                Cover(covered, at, lay.Size);
                return;
            }
            foreach (Member mem in s.Members)
            {
                if (!lay.Offsets.TryGetValue(mem.Name, out int off))
                {
                    Cover(covered, at, lay.Size);
                    return;
                }
                off += at;
                int count = Math.Max(1, mem.ArrayLen);
                if (mem.PtrDepth == 0 && m.Structs.ContainsKey(mem.Type))
                {
                    int esz = ComputeLayout(m, mem.Type, cache).Size;
                    for (int k = 0; k < count; k++)
                        MarkCovered(m, mem.Type, off + k * esz, cache, covered);
                    continue;
                }
                SizeAlign(m, mem.Type, mem.PtrDepth, cache, out int w, out _);
                Cover(covered, off, w * count);
            }
        }

        private static void Cover(bool[] covered, int from, int length)
        {
            for (int i = from; i < from + length && i < covered.Length; i++)
                covered[i] = true;
        }

        private static bool StructIsFlat(Model m, string name, HashSet<string> seen)
        {
            if (!seen.Add(name)) return true;
            if (!m.Structs.TryGetValue(name, out VkStruct s)) return false;
            if (s.IsUnion) return false;
            foreach (Member mem in s.Members)
            {
                if (mem.PtrDepth > 0) return false;
                if (m.Handles.ContainsKey(mem.Type) || m.FuncPointers.Contains(mem.Type)) return false;
                if (PointerWidthTypes.Contains(mem.Type)) return false;
                if (m.Structs.ContainsKey(mem.Type) && !StructIsFlat(m, mem.Type, seen)) return false;
            }
            return true;
        }

        private static int ResolveLen(Member mem, Dictionary<string, int> offsets, out string lenName)
        {
            lenName = null;
            string len = mem.Length;
            if (len == null || len == "null-terminated") return -1;
            int comma = len.IndexOf(',');
            if (comma >= 0) len = len.Substring(0, comma);
            if (len.IndexOfAny(new[] { '/', '*', '-', '>', '(', ' ', '+' }) >= 0) return -1;
            if (!offsets.TryGetValue(len, out int o)) return -1;
            lenName = len;
            return o;
        }

        private const string SampleWordsTail = " + 31) / 32";

        private static bool SampleWordsLen(string altLen, out string samples)
        {
            samples = null;
            if (altLen == null || altLen.Length <= SampleWordsTail.Length + 1 || altLen[0] != '(' || !altLen.EndsWith(SampleWordsTail, StringComparison.Ordinal))
                return false;
            samples = altLen.Substring(1, altLen.Length - SampleWordsTail.Length - 1);
            return true;
        }

        private static int ArrayLenIndex(Command c, Param p, out bool samples)
        {
            samples = SampleWordsLen(p.AltLength, out string name);
            if (!samples)
                name = p.Length;
            return name == null ? -1 : c.Params.FindIndex(x => x.Name == name);
        }

        private static MDesc ClassifyMember(Model m, VkStruct owner, Member mem, Dictionary<string, int> offsets, Dictionary<string, Layout> cache)
        {
            MDesc d = new MDesc { Offset = offsets.TryGetValue(mem.Name, out int mo) ? mo : 0, MemName = mem.Name, Optional = mem.Optional, OptionalElements = mem.OptionalElements };
            if (mem.Name == "pNext") { d.Kind = "PNext"; d.Size = 8; return d; }
            if (owner.Name == "VkWriteDescriptorSet" && (mem.Name == "pImageInfo" || mem.Name == "pBufferInfo" || mem.Name == "pTexelBufferView"))
            {
                d.Kind = "SelectArray";
                d.SelOffset = offsets["descriptorType"];
                d.SelName = "descriptorType";
                d.LenOffset = offsets["descriptorCount"];
                d.LenName = "descriptorCount";
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
                if (mem.PtrDepth >= 2) { int lo = ResolveLen(mem, offsets, out string saLen); if (lo >= 0) { d.Kind = "StringArray"; d.LenOffset = lo; d.LenName = saLen; } else d.Kind = "Ignore"; return d; }
                d.Kind = "StringZ"; return d;
            }
            if (SampleWordsLen(mem.AltLength, out string sampleCount) && offsets.TryGetValue(sampleCount, out int sco))
            {
                SizeAlign(m, mem.Type, 0, cache, out int sw, out _);
                d.Kind = "ScalarArray"; d.Size = sw; d.LenOffset = sco; d.LenName = sampleCount; d.LenSamples = true; return d;
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
                    d.Kind = "BlobPtr"; d.LenOffset = blo; d.LenName = num; d.Size = lenMem != null ? ScalarWidth(m, lenMem.Type) : 8;
                    return d;
                }
            }
            if (mem.Type == "void") { d.Kind = "Ignore"; return d; }
            int len = ResolveLen(mem, offsets, out string lenName);
            if (len >= 0)
            {
                d.LenOffset = len;
                d.LenName = lenName;
                if (m.Handles.ContainsKey(mem.Type)) { d.Kind = "HandleArray"; d.HandleType = mem.Type; return d; }
                if (m.Structs.ContainsKey(mem.Type)) { d.Kind = "StructArray"; d.SubName = mem.Type; return d; }
                SizeAlign(m, mem.Type, 0, cache, out int ew, out _); d.Kind = "ScalarArray"; d.Size = ew; return d;
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
                    if ((k == "StructIn" || k == "ArrayIn" || k == "ChainOut" || k == "StructOut" || k == "ArrayOut")
                        && m.Structs.ContainsKey(p.Type) && need.Add(p.Type))
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

        private static string StructGap(Model m, string name, HashSet<string> seen, Dictionary<string, Layout> cache)
        {
            if (!m.Structs.TryGetValue(name, out VkStruct s))
                return name + " is not a struct";
            if (!seen.Add(name))
                return null;
            if (s.IsUnion)
            {
                foreach (Member mem in s.Members)
                {
                    if (mem.PtrDepth > 0 || m.Handles.ContainsKey(mem.Type) || m.FuncPointers.Contains(mem.Type))
                        return name + "." + mem.Name + " is a pointer inside a union";
                    if (!IsSizedType(m, mem.Type))
                        return name + "." + mem.Name + " has a type this layer cannot size";
                    if (m.Structs.ContainsKey(mem.Type))
                    {
                        string sub = StructGap(m, mem.Type, seen, cache);
                        if (sub != null)
                            return sub;
                    }
                }
                return null;
            }
            Layout lay = ComputeLayout(m, name, cache);
            foreach (Member mem in s.Members)
            {
                if (mem.Name == "pNext")
                    continue;
                if (m.FuncPointers.Contains(mem.Type))
                    return name + "." + mem.Name + " is a function pointer";
                if (mem.Type != "void" && !IsSizedType(m, mem.Type))
                    return name + "." + mem.Name + " has a type this layer cannot size";
                MDesc d = ClassifyMember(m, s, mem, lay.Offsets, cache);
                if (d.Kind == "Ignore")
                    return name + "." + mem.Name + " is not forwarded";
                if (d.SubName != null)
                {
                    string sub = StructGap(m, d.SubName, seen, cache);
                    if (sub != null)
                        return sub;
                }
            }
            return null;
        }

        private static string WritebackGap(Model m, string name, HashSet<string> seen, Dictionary<string, Layout> cache)
        {
            if (!m.Structs.TryGetValue(name, out VkStruct s) || !seen.Add(name))
                return null;
            if (s.IsUnion)
                return StructGap(m, name, new HashSet<string>(), cache);
            Layout lay = ComputeLayout(m, name, cache);
            foreach (Member mem in s.Members)
            {
                if (mem.Name == "pNext")
                    continue;
                if (mem.ArrayLen > 1 && m.Handles.ContainsKey(mem.Type))
                    return name + "." + mem.Name + " holds handles";
                MDesc d = ClassifyMember(m, s, mem, lay.Offsets, cache);
                if (d.Kind == "StructValue")
                {
                    string sub = WritebackGap(m, d.SubName, seen, cache);
                    if (sub != null)
                        return sub;
                }
                else if (d.Kind != "Scalar")
                    return name + "." + mem.Name + " is not written back";
            }
            return null;
        }

        private static bool PNextOwnerAllowed(Model m, string name)
        {
            if (KnownGapTypes.Contains(name))
                return false;
            if (m.CoreTypeVersion.TryGetValue(name, out double ver) && ver <= MaxCoreVersion)
                return true;
            return AdvertisedTypes.Contains(name);
        }

        private static IEnumerable<string> EffectiveCommands(VkExtension ext)
        {
            foreach (string c in ext.Commands)
                yield return c;
            foreach ((string depends, HashSet<string> cmds, HashSet<string> _) in ext.Gated)
                if (DependsSatisfied(depends, Advertised))
                    foreach (string c in cmds)
                        yield return c;
        }

        private static IEnumerable<string> EffectiveTypes(VkExtension ext)
        {
            foreach (string t in ext.Types)
                yield return t;
            foreach ((string depends, HashSet<string> _, HashSet<string> types) in ext.Gated)
                if (DependsSatisfied(depends, Advertised))
                    foreach (string t in types)
                        yield return t;
        }

        private static HashSet<string> ComputePNextSet(Model m, List<Command> allowed, Dictionary<string, Layout> cache, out HashSet<string> closureOut)
        {
            HashSet<string> closure = new HashSet<string>();
            closureOut = closure;
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
                    if (StructGap(m, s.Name, new HashSet<string>(), cache) != null)
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

        private static string Canon(Model m, string ty) => m.TypeAlias.TryGetValue(ty, out string cx) ? cx : ty;

        private static string InGap(Model m, Command c, Dictionary<string, Layout> cache)
        {
            foreach (Param p in c.Params)
            {
                string k = ParamKind(m, p);
                if ((k == "StructIn" || k == "ArrayIn") && m.Structs.ContainsKey(p.Type))
                {
                    string gap = StructGap(m, p.Type, new HashSet<string>(), cache);
                    if (gap != null)
                        return gap;
                }
            }
            return null;
        }

        private static string OutGap(Model m, Command c, Dictionary<string, Layout> cache)
        {
            foreach (Param p in c.Params)
            {
                string k = ParamKind(m, p);
                if ((k == "ChainOut" || k == "StructOut" || k == "ArrayOut") && m.Structs.ContainsKey(p.Type))
                {
                    string gap = WritebackGap(m, p.Type, new HashSet<string>(), cache);
                    if (gap != null)
                        return gap;
                }
            }
            return null;
        }

        private static HashSet<string> OutSideStructs(Model m, List<Command> exported)
        {
            HashSet<string> set = new HashSet<string>(StringComparer.Ordinal);
            foreach (Command c in exported)
                foreach (Param p in c.Params)
                {
                    string k = ParamKind(m, p);
                    if ((k == "ChainOut" || k == "StructOut" || k == "ArrayOut") && m.Structs.ContainsKey(p.Type))
                        set.Add(p.Type);
                }
            bool grew = true;
            while (grew)
            {
                grew = false;
                foreach (VkStruct s in m.Structs.Values)
                {
                    if (set.Contains(s.Name))
                        continue;
                    foreach (string target in s.Extends)
                    {
                        if (!set.Contains(Canon(m, target)))
                            continue;
                        set.Add(s.Name);
                        grew = true;
                        break;
                    }
                }
            }
            return set;
        }

        private static List<Command> ExportedCommands(Model m, List<Command> cmds, Dictionary<string, bool> hostOk, Dictionary<string, Layout> cache)
        {
            HashSet<string> owned = new HashSet<string>(StringComparer.Ordinal);
            foreach (string en in Advertised)
                owned.UnionWith(EffectiveCommands(m.Extensions[en]));
            List<Command> result = new List<Command>();
            foreach (Command c in cmds)
            {
                if (GuestLocal.Contains(c.Name) || !hostOk[c.Name])
                    continue;
                bool core = m.CoreCommandVersion.TryGetValue(c.Name, out double ver) && ver <= MaxCoreVersion;
                if (core ? OutGap(m, c, cache) == null : owned.Contains(c.Name))
                    result.Add(c);
            }
            return result;
        }

        private static string ExtensionGap(Model m, VkExtension ext, Dictionary<string, bool> hostOk, HashSet<string> closure, HashSet<string> outSide, Dictionary<string, Layout> cache)
        {
            if (ExtDenylist.TryGetValue(ext.Name, out string denied))
                return denied;
            if (ext.Platform != null && ext.Name != "VK_KHR_win32_surface" && !HostImplemented(ext))
                return "platform " + ext.Platform;
            foreach (string cn in EffectiveCommands(ext).OrderBy(x => x, StringComparer.Ordinal))
            {
                if (GuestLocal.Contains(cn))
                    continue;
                if (!hostOk.TryGetValue(cn, out bool ok))
                    return "command " + cn + " is platform specific";
                if (!ok)
                    return "command " + cn + " is not forwardable";
                string gap = InGap(m, m.Commands[cn], cache) ?? OutGap(m, m.Commands[cn], cache);
                if (gap != null)
                    return "command " + cn + ": " + gap;
            }
            ExtKnownGaps.TryGetValue(ext.Name, out string[] known);
            foreach (string ty in EffectiveTypes(ext).OrderBy(x => x, StringComparer.Ordinal))
            {
                if (!m.Structs.TryGetValue(ty, out VkStruct s) || s.Extends.Length == 0 || StructSType(s) == null)
                    continue;
                if (known != null && Array.IndexOf(known, ty) >= 0)
                    continue;
                string gap = StructGap(m, ty, new HashSet<string>(), cache);
                if (gap != null)
                    return gap;
                foreach (string target in s.Extends)
                {
                    string ct = Canon(m, target);
                    if (!closure.Contains(ct) || !outSide.Contains(ct))
                        continue;
                    gap = WritebackGap(m, ty, new HashSet<string>(), cache);
                    if (gap != null)
                        return gap;
                }
            }
            return null;
        }

        private static List<string> ElementChainGaps(Model m, VkExtension ext, HashSet<string> closure, HashSet<string> outSide)
        {
            List<string> gaps = new List<string>();
            foreach (string ty in EffectiveTypes(ext).OrderBy(x => x, StringComparer.Ordinal))
            {
                if (!m.Structs.TryGetValue(ty, out VkStruct s) || s.Extends.Length == 0 || StructSType(s) == null)
                    continue;
                if (s.Extends.Any(x => outSide.Contains(Canon(m, x)) && !closure.Contains(Canon(m, x))))
                    gaps.Add(ty);
            }
            return gaps;
        }

        private static bool DependsSatisfied(string expr, HashSet<string> have)
        {
            int pos = 0;
            return DependsOr(expr, ref pos, have);
        }

        private static bool DependsOr(string expr, ref int pos, HashSet<string> have)
        {
            bool v = DependsAnd(expr, ref pos, have);
            while (pos < expr.Length && expr[pos] == ',')
            {
                pos++;
                v |= DependsAnd(expr, ref pos, have);
            }
            return v;
        }

        private static bool DependsAnd(string expr, ref int pos, HashSet<string> have)
        {
            bool v = DependsTerm(expr, ref pos, have);
            while (pos < expr.Length && expr[pos] == '+')
            {
                pos++;
                v &= DependsTerm(expr, ref pos, have);
            }
            return v;
        }

        private static bool DependsTerm(string expr, ref int pos, HashSet<string> have)
        {
            if (pos < expr.Length && expr[pos] == '(')
            {
                pos++;
                bool inner = DependsOr(expr, ref pos, have);
                if (pos < expr.Length && expr[pos] == ')')
                    pos++;
                return inner;
            }
            int start = pos;
            while (pos < expr.Length && expr[pos] != '+' && expr[pos] != ',' && expr[pos] != ')')
                pos++;
            string token = expr.Substring(start, pos - start);
            if (!token.StartsWith("VK_VERSION_", StringComparison.Ordinal))
                return have.Contains(token);
            string[] parts = token.Substring(11).Split('_');
            return parts.Length == 2
                && double.TryParse(parts[0] + "." + parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double ver)
                && ver <= MaxCoreVersion;
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

        private static int DeferredDestroyParentIndex(Model m, Command c, int destroyed)
        {
            for (int i = 0; i < c.Params.Count; i++)
                if (i != destroyed && ParamKind(m, c.Params[i]) == "HandleIn")
                    return i;
            return -1;
        }

        private static string DeferredDestroyCall(Model m, Command c)
        {
            int destroyed = DestroyedHandleIndex(m, c);
            if (destroyed < 0 || c.Ret != "void" || !c.Name.StartsWith("vkDestroy", StringComparison.Ordinal))
                return null;

            int parent = DeferredDestroyParentIndex(m, c, destroyed);
            List<string> args = new List<string>();
            for (int i = 0; i < c.Params.Count; i++)
            {
                string kind = ParamKind(m, c.Params[i]);
                if (i == destroyed)
                    args.Add("handle");
                else if (i == parent)
                    args.Add("parent");
                else if (kind == "AllocatorIn")
                    args.Add("System.IntPtr.Zero");
                else
                    return null;
            }

            return "BrovVulkApi." + c.Name + "(" + string.Join(", ", args) + ")";
        }

        // A vkGet or vkEnumerate command hands back the same object on every call, so it keeps one id.
        private static string RegisterCall(Model m, Command c, string ptrExpr, string handleType)
        {
            bool queried = c.Name.StartsWith("vkGet", StringComparison.Ordinal) || c.Name.StartsWith("vkEnumerate", StringComparison.Ordinal);
            return "st." + (queried ? "RegisterQueried" : "Register") + "(" + ptrExpr + ", \"" + handleType + "\", " + ParentIdExpr(m, c, handleType) + ")";
        }

        private static string ParentIdExpr(Model m, Command c, string handleType)
        {
            if (!FindParent(m, c, handleType, out int j, out Member owner))
                return "0u";
            if (owner == null)
                return "p" + j + "Id";

            string structType = c.Params[j].Type;
            return "(p" + j + " != System.IntPtr.Zero ? st.IdOf(*(System.IntPtr*)(p" + j + " + BrovVulkLayout.MemberOffset[\"" + structType + "." + owner.Name + "\"]), \"" + owner.Type + "\") : 0u)";
        }

        private static string GuestParentExpr(Model m, Command c, string handleType)
        {
            if (!FindParent(m, c, handleType, out int j, out Member owner))
                return "0u";
            string name = c.Params[j].Name;
            return owner == null ? "(uint32_t)(uintptr_t)" + name : "(" + name + " ? (uint32_t)(uintptr_t)" + name + "->" + owner.Name + " : 0u)";
        }

        // Swapchain images end with their swapchain, not with the device vk.xml names.
        private static bool FindParent(Model m, Command c, string handleType, out int paramIndex, out Member member)
        {
            paramIndex = -1;
            member = null;
            string parentType = c.Name == "vkGetSwapchainImagesKHR" ? "VkSwapchainKHR"
                : m.HandleParents.TryGetValue(handleType, out string declared) ? declared : null;
            if (parentType == null)
                return false;

            for (int j = 0; j < c.Params.Count; j++)
            {
                if (c.Params[j].Type == parentType && ParamKind(m, c.Params[j]) == "HandleIn")
                {
                    paramIndex = j;
                    return true;
                }
            }

            for (int j = 0; j < c.Params.Count; j++)
            {
                Param sp = c.Params[j];
                if (ParamKind(m, sp) != "StructIn" || !StructId.ContainsKey(sp.Type) || !m.Structs.TryGetValue(sp.Type, out VkStruct s))
                    continue;

                Member owner = s.Members.FirstOrDefault(x => x.Type == parentType && x.PtrDepth == 0 && x.ArrayLen == 1);
                if (owner != null)
                {
                    paramIndex = j;
                    member = owner;
                    return true;
                }
            }

            return false;
        }

        private static bool ReleasesMappings(Command c)
        {
            return c.Name == "vkDestroyDevice" || c.Name == "vkDestroyInstance";
        }

        private static bool ReleasesHandles(Model m, Command c)
        {
            return DestroyedHandleIndex(m, c) >= 0 || c.Name.StartsWith("vkFree", StringComparison.Ordinal) || ResetChildrenIndex(m, c) >= 0;
        }

        // Resetting a descriptor pool frees every set allocated from it.
        private static int ResetChildrenIndex(Model m, Command c)
        {
            return c.Name == "vkResetDescriptorPool" ? c.Params.FindIndex(x => x.Type == "VkDescriptorPool" && ParamKind(m, x) == "HandleIn") : -1;
        }

        private static int GuestIdOutIndex(Model m, Command c)
        {
            return GuestIds.Contains(c.Name) ? c.Params.FindIndex(p => IsStructLenHandleArrayOut(m, p)) : -1;
        }

        private static HashSet<string> GuestIdTypes(Model m)
        {
            HashSet<string> types = new HashSet<string>(StringComparer.Ordinal);
            foreach (string n in GuestIds)
            {
                if (m.Commands.TryGetValue(n, out Command c) && GuestIdOutIndex(m, c) >= 0)
                    types.Add(c.Params[GuestIdOutIndex(m, c)].Type);
            }
            return types;
        }

        private static string HostIdGuard(string count)
        {
            return "                if (!st.HasHostIds(" + count + ")) return BrovVulkConstants.VK_ERROR_OUT_OF_HOST_MEMORY;\n";
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

        // The length of a blob is not always uint32_t, and the driver takes it as the byte count it may touch.
        private static int BlobLenIndex(Model m, Command c, Param p, int i)
        {
            if (p.Length == null)
                return -1;
            for (int j = 0; j < i; j++)
                if (c.Params[j].Name == p.Length && ParamKind(m, c.Params[j]) == "ScalarIn"
                    && c.Params[j].Type != "float" && c.Params[j].Type != "double")
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

        private static string BlobLenExpr(Command c, string len)
        {
            Param Lp = c.Params.FirstOrDefault(x => x.Name == len);
            if (Lp == null || Lp.PtrDepth == 0)
                return "(uint32_t)" + len;

            return "(" + len + " ? (uint32_t)*" + len + " : 0)";
        }

        private static string EmitHostCase(Model m, Command c, int id)
        {
            if (c.Name == "vkMapMemory")
                return "                return BrovVulkGenMemory.MapMemory(r, st, inst);\n";
            if (c.Name == "vkUnmapMemory")
                return "                return BrovVulkGenMemory.UnmapMemory(r, st, inst);\n";
            if (c.Name == "vkAllocateMemory")
                return "                return BrovVulkGenMemory.AllocateMemory(r, w, st, inst, " + StructId["VkMemoryAllocateInfo"] + ");\n";
            if (c.Name == "vkFreeMemory")
                return "                return BrovVulkGenMemory.FreeMemory(r, st, inst);\n";
            if (c.Name == "vkCreateDevice")
                return "                return BrovVulkGenMemory.CreateDevice(r, w, st, " + StructId["VkDeviceCreateInfo"] + ");\n";
            if (c.Name == "vkFlushMappedMemoryRanges")
                return "                return BrovVulkGenMemory.FlushMappedMemoryRanges(r, st, inst);\n";
            if (c.Name == "vkInvalidateMappedMemoryRanges")
                return "                return BrovVulkGenMemory.InvalidateMappedMemoryRanges(r, st, inst);\n";
            if (c.Name == "vkCreateInstance")
                return "            {\n" +
                    "                uint hasCi = r.ReadU32();\n" +
                    "                System.IntPtr ci = System.IntPtr.Zero;\n" +
                    "                if (hasCi != 0) ci = BrovVulkGenStruct.Rebuild(" + StructId["VkInstanceCreateInfo"] + ", r, st);\n" +
                    "                BrovVulkGenMemory.RestrictInstanceCreateInfo(st, ci);\n" +
                    "                if ((Brovan.GeneralHelper.IsLinux || Brovan.Android.AndroidHost.IsActive) && ci != System.IntPtr.Zero)\n" +
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
                    "                            System.IntPtr xcbName = System.Runtime.InteropServices.Marshal.StringToHGlobalAnsi(Brovan.Android.AndroidHost.IsActive ? \"VK_KHR_android_surface\" : \"VK_KHR_xcb_surface\");\n" +
                    "                            System.Runtime.InteropServices.Marshal.WriteIntPtr(newArr, (int)(newCount * 8), xcbName);\n" +
                    "                            newCount++;\n" +
                    "                            *(uint*)(ci + 48) = newCount;\n" +
                    "                            *(System.IntPtr*)(ci + 56) = newArr;\n" +
                    "                        }\n" +
                    "                    }\n" +
                    "                }\n" +
                    "                if (ci != System.IntPtr.Zero)\n" +
                    "                {\n" +
                    "                    // The host loader only exports the promoted names of commands like\n" +
                    "                    // vkCmdBindIndexBuffer2, and its device dispatch slot for them stays NULL unless the\n" +
                    "                    // instance asks for the core version they were promoted in. Guests target older\n" +
                    "                    // versions and reach those commands through the KHR alias, which the loader does not\n" +
                    "                    // export, so raise the host instance to the loader's own version.\n" +
                    "                    System.IntPtr ai = *(System.IntPtr*)(ci + 24);\n" +
                    "                    uint loaderVersion = 0;\n" +
                    "                    if (ai != System.IntPtr.Zero && BrovVulkApi.vkEnumerateInstanceVersion((System.IntPtr)(&loaderVersion)) >= 0 && loaderVersion > *(uint*)(ai + 44))\n" +
                    "                        *(uint*)(ai + 44) = loaderVersion;\n" +
                    "                }\n" +
                    "                System.IntPtr vki = System.IntPtr.Zero;\n" +
                    "                int rr = (int)BrovVulkApi.vkCreateInstance(ci, System.IntPtr.Zero, (System.IntPtr)(&vki));\n" +
                    "                if (rr >= 0 && vki == System.IntPtr.Zero) rr = -3;\n" +
                    "                if (rr >= 0) BrovVulkProc.HostInstance = vki;\n" +
                    "                w.WriteU32(rr >= 0 ? st.Register(vki, \"VkInstance\", 0u) : 0u);\n" +
                    "                return rr;\n            }\n";
            if (c.Name == "vkCreateWin32SurfaceKHR")
                return "            {\n" +
                    "                uint viId = r.ReadU32();\n" +
                    "                System.IntPtr vi = st.Lookup(viId, \"VkInstance\");\n" +
                    "                ulong gh = r.Remaining >= 8 ? r.ReadU64() : 0;\n" +
                    HostIdGuard("1u") +
                    "                System.IntPtr surf = System.IntPtr.Zero;\n" +
                    "                int rr;\n" +
                    "                if (Brovan.Android.AndroidHost.IsActive)\n" +
                    "                {\n" +
                    "                    System.IntPtr awin = inst.EnsureHostWindowHandle(gh);\n" +
                    "                    byte* ci = stackalloc byte[32];\n" +
                    "                    for (int z = 0; z < 32; z++) ci[z] = 0;\n" +
                    "                    *(int*)(ci + 0) = " + "1000008000" + ";\n" +
                    "                    *(void**)(ci + 24) = (void*)awin;\n" +
                    "                    rr = (int)Brovan.Android.AndroidVulkanWsi.vkCreateAndroidSurfaceKHR(vi, (System.IntPtr)ci, System.IntPtr.Zero, (System.IntPtr)(&surf));\n" +
                    "                }\n" +
                    "                else if (Brovan.GeneralHelper.IsLinux)\n" +
                    "                {\n" +
                    "                    System.IntPtr xdpy; System.IntPtr xwin;\n" +
                    "                    inst.EnsureHostXlibSurfaceHandles(out xdpy, out xwin);\n" +
                    "                    byte* ci = stackalloc byte[40];\n" +
                    "                    for (int z = 0; z < 40; z++) ci[z] = 0;\n" +
                    "                    *(int*)(ci + 0) = 1000005000;\n" +
                    "                    *(void**)(ci + 24) = (void*)xdpy;\n" +
                    "                    *(uint*)(ci + 32) = (uint)xwin;\n" +
                    "                    rr = (int)BrovVulkLinuxWsi.vkCreateXcbSurfaceKHR(vi, (System.IntPtr)ci, System.IntPtr.Zero, (System.IntPtr)(&surf));\n" +
                    "                }\n" +
                    "                else\n" +
                    "                {\n" +
                    "                    System.IntPtr hwnd = inst.EnsureHostWindowHandle(gh);\n" +
                    "                    System.IntPtr hinst = BrovVulkGenNative.GetModuleHandleW(System.IntPtr.Zero);\n" +
                    "                    byte* ci = stackalloc byte[40];\n" +
                    "                    for (int z = 0; z < 40; z++) ci[z] = 0;\n" +
                    "                    *(int*)(ci + 0) = 1000009000;\n" +
                    "                    *(void**)(ci + 24) = (void*)hinst;\n" +
                    "                    *(void**)(ci + 32) = (void*)hwnd;\n" +
                    "                    rr = (int)BrovVulkApi.vkCreateWin32SurfaceKHR(vi, (System.IntPtr)ci, System.IntPtr.Zero, (System.IntPtr)(&surf));\n" +
                    "                }\n" +
                    "                if (rr >= 0 && surf == System.IntPtr.Zero) rr = -3;\n" +
                    "                w.WriteU32(rr >= 0 ? st.Register(surf, \"VkSurfaceKHR\", viId) : 0u);\n" +
                    "                return rr;\n            }\n";
            if (c.Name == "vkEnumerateInstanceExtensionProperties")
                return "                return BrovVulkGenExt.Instance(w);\n";
            if (c.Name == "vkEnumerateDeviceExtensionProperties")
                return "                return BrovVulkGenExt.Device(st.Lookup(r.ReadU32(), \"VkPhysicalDevice\"), w);\n";
            if (c.Name == "vkGetPhysicalDeviceWin32PresentationSupportKHR")
                return "            {\n" +
                    "                System.IntPtr pd = st.Lookup(r.ReadU32(), \"VkPhysicalDevice\");\n" +
                    "                uint qf = r.ReadU32();\n" +
                    "                return Brovan.GeneralHelper.IsLinux ? 1 : (int)BrovVulkApi.vkGetPhysicalDeviceWin32PresentationSupportKHR(pd, qf);\n" +
                    "            }\n";
            // Driver cache entries can contain host heap pointers.
            if (c.Name == "vkGetPipelineCacheData")
                return "            {\n" +
                    "                System.IntPtr dev = st.Lookup(r.ReadU32(), \"VkDevice\");\n" +
                    "                System.IntPtr pc = st.Lookup(r.ReadU32(), \"VkPipelineCache\");\n" +
                    "                uint want = r.ReadU32();\n" +
                    "                ulong req = r.ReadU64();\n" +
                    "                int headerBytes = BrovVulkLayout.StructSize[\"VkPipelineCacheHeaderVersionOne\"];\n" +
                    "                System.IntPtr buf = st.Alloc(headerBytes);\n" +
                    "                ulong got = (ulong)headerBytes;\n" +
                    "                int rr = (int)BrovVulkApi.vkGetPipelineCacheData(dev, pc, (System.IntPtr)(&got), buf);\n" +
                    "                if (rr < 0) return rr;\n" +
                    "                bool header = got == (ulong)headerBytes && *(uint*)(buf + BrovVulkLayout.MemberOffset[\"VkPipelineCacheHeaderVersionOne.headerSize\"]) == (uint)headerBytes\n" +
                    "                    && *(uint*)(buf + BrovVulkLayout.MemberOffset[\"VkPipelineCacheHeaderVersionOne.headerVersion\"]) == BrovVulkConstants.VK_PIPELINE_CACHE_HEADER_VERSION_ONE;\n" +
                    "                ulong total = header ? (ulong)headerBytes : 0;\n" +
                    "                if (want == 0)\n" +
                    "                {\n" +
                    "                    w.WriteU64(total);\n" +
                    "                    return BrovVulkConstants.VK_SUCCESS;\n" +
                    "                }\n" +
                    "                ulong take = req < total ? 0 : total;\n" +
                    "                w.WriteU64(take);\n" +
                    "                if (take > 0) w.WriteBytesFrom(buf, (uint)take);\n" +
                    "                return take < total ? BrovVulkConstants.VK_INCOMPLETE : BrovVulkConstants.VK_SUCCESS;\n            }\n";

            StringBuilder b = new StringBuilder();
            List<string> callArgs = new List<string>();
            List<string> shape = new List<string>();
            List<string> check = new List<string>();
            List<string> post = new List<string>();
            bool vkRes = c.Ret == "VkResult";
            bool retainsChains = RetainedChains.Contains(c.Name);
            string gate = vkRes ? "rr >= 0 && " : "";
            int forgetIdx = DestroyedHandleIndex(m, c);
            bool replaced = HostReplaced.ContainsKey(c.Name);
            string guestTimeout = null;
            if (c.Params.Any(x => x.Type != "void" && !IsSizedType(m, x.Type)))
                return null;
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
                    if (vkRes && elemHandle)
                        b.Append(HostIdGuard(local + "pr != 0 ? " + local + "c : 0u"));
                    b.Append("                System.IntPtr ").Append(local).Append("a = ").Append(local).Append("pr != 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("c, ").Append(esz).Append(")) : System.IntPtr.Zero;\n");
                    if (elemChain)
                        b.Append("                if (").Append(local).Append("pr != 0) for (uint k = 0; k < ").Append(local).Append("c; k++) *(uint*)(").Append(local).Append("a + (int)(k * (uint)(").Append(esz).Append("))) = r.ReadU32();\n");
                    shape.Add(elemChain && StructId.TryGetValue(a.Type, out int chainSid) ? "p:" + chainSid : "p");
                    callArgs.Add("(System.IntPtr)(&" + local + "c)");
                    callArgs.Add(local + "a");
                    if (vkRes && elemHandle)
                        check.Add("                if (rr >= 0 && " + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) if (System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + "a, (int)k * 8) == System.IntPtr.Zero) { rr = -3; break; }");
                    post.Add("                w.WriteU32(" + local + "c);");
                    if (elemHandle)
                        post.Add("                if (" + gate + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) w.WriteU32(" + RegisterCall(m, c, "System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + "a, (int)k * 8)", a.Type) + ");");
                    else if (elemStruct && StructId.ContainsKey(a.Type))
                        post.Add("                if (" + gate + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) BrovVulkGenStruct.WritebackBody(" + StructId[a.Type] + ", w, " + local + "a + (int)(k * (uint)(" + esz + ")));");
                    else if (elemChain)
                        post.Add("                if (" + gate + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) w.WriteBytesFrom(" + local + "a + (int)(k * (uint)(" + esz + ")) + 16, (uint)(" + esz + " - 16));");
                    else
                        post.Add("                if (" + gate + local + "pr != 0) for (uint k = 0; k < " + local + "c; k++) w.WriteBytesFrom(" + local + "a + (int)k * (" + esz + "), (uint)(" + esz + "));");
                    i++;
                    continue;
                }
                string kind = ParamKind(m, p);
                int arrLen = ArrayLenIndex(c, p, out bool arrSamples);
                if (kind == "ChainOut" && StructId.ContainsKey(p.Type))
                {
                    int baseSid = StructId[p.Type];
                    b.Append("                uint ").Append(local).Append("bst = r.ReadU32();\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = st.Alloc(BrovVulkStructMeta.Sizes[").Append(baseSid).Append("]);\n");
                    b.Append("                *(uint*)").Append(local).Append(" = BrovVulkGenStruct.CheckedSType(").Append(local).Append("bst, ").Append(baseSid).Append(");\n");
                    b.Append("                System.IntPtr ").Append(local).Append("tail = ").Append(local).Append(";\n");
                    b.Append("                var ").Append(local).Append("ch = new System.Collections.Generic.List<(System.IntPtr, int)>();\n");
                    b.Append("                ").Append(local).Append("ch.Add((").Append(local).Append(", ").Append(baseSid).Append("));\n");
                    b.Append("                while (r.ReadU32() == 1) { uint ").Append(local).Append("st = r.ReadU32(); int ").Append(local).Append("sd = (int)r.ReadU32(); if (").Append(local).Append("sd < 0 || ").Append(local).Append("sd >= BrovVulkStructMeta.PNext.Length || !BrovVulkStructMeta.PNext[").Append(local).Append("sd]) throw new System.InvalidOperationException(\"BrovVulk generic: pNext sid not allowed.\"); System.IntPtr ").Append(local).Append("nd = st.Alloc(BrovVulkStructMeta.Sizes[").Append(local).Append("sd]); *(uint*)").Append(local).Append("nd = BrovVulkGenStruct.CheckedSType(").Append(local).Append("st, ").Append(local).Append("sd); *(System.IntPtr*)(").Append(local).Append("tail + 8) = ").Append(local).Append("nd; ").Append(local).Append("tail = ").Append(local).Append("nd; ").Append(local).Append("ch.Add((").Append(local).Append("nd, ").Append(local).Append("sd)); }\n");
                    b.Append("                *(System.IntPtr*)(").Append(local).Append("tail + 8) = System.IntPtr.Zero;\n");
                    shape.Add("c:" + baseSid);
                    callArgs.Add(local);
                    post.Add("                foreach (var e in " + local + "ch) BrovVulkGenStruct.WritebackBody(e.Item2, w, e.Item1);");
                }
                else if (kind == "ScalarIn")
                {
                    string ct = CsType(m, p.Type, 0);
                    int w = ScalarWidth(m, p.Type);
                    if (p.Type == "float")
                        b.Append("                float ").Append(local).Append(" = System.BitConverter.Int32BitsToSingle((int)r.ReadU32());\n");
                    else if (p.Type == "double")
                        b.Append("                double ").Append(local).Append(" = System.BitConverter.Int64BitsToDouble((long)r.ReadU64());\n");
                    else
                        b.Append("                ").Append(ct).Append(" ").Append(local).Append(" = (").Append(ct).Append(")r.Read").Append(w == 8 ? "U64" : "U32").Append("();\n");
                    shape.Add(w == 8 || p.Type == "double" ? "u8" : "u4");
                    if (IsWaitTimeoutParam(m, p))
                    {
                        guestTimeout = local + "t";
                        b.Append("                ulong ").Append(guestTimeout).Append(" = ").Append(local).Append(";\n");
                        if (!replaced)
                            b.Append("                ").Append(local).Append(" = 0;\n");
                    }
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
                    b.Append("                uint ").Append(local).Append("Id = r.ReadU32();\n");
                    shape.Add("h:" + p.Type);
                    if (i == forgetIdx)
                    {
                        b.Append("                System.IntPtr ").Append(local).Append(" = st.Lookup(").Append(local).Append("Id, \"").Append(p.Type).Append("\");\n");
                        post.Add("                st.Forget(" + local + "Id);");
                    }
                    else
                    {
                        b.Append("                System.IntPtr ").Append(local).Append(" = st.").Append(p.Optional ? "Lookup" : "LookupRequired").Append("(").Append(local).Append("Id, \"").Append(p.Type).Append("\");\n");
                    }
                    if (i == 0 && p.Type == "VkDevice")
                        b.Append("                st.SetCallDevice(").Append(local).Append(");\n");
                    else if (i == 0 && p.Type == "VkCommandBuffer" && c.Name.StartsWith("vkCmd", StringComparison.Ordinal))
                        b.Append("                st.BeginCommand(").Append(local).Append(");\n");
                    callArgs.Add(local);
                }
                else if (kind == "HandleOut")
                {
                    b.Append("                System.IntPtr ").Append(local).Append(" = System.IntPtr.Zero;\n");
                    shape.Add("H:" + p.Type);
                    callArgs.Add("(System.IntPtr)(&" + local + ")");
                    if (vkRes)
                    {
                        b.Append(HostIdGuard("1u"));
                        check.Add("                if (rr >= 0 && " + local + " == System.IntPtr.Zero) rr = -3;");
                        if (retainsChains)
                        {
                            b.Append("                if (!st.RetainFits()) return BrovVulkConstants.VK_ERROR_OUT_OF_HOST_MEMORY;\n");
                            post.Add("                uint " + local + "Id = rr >= 0 ? " + RegisterCall(m, c, local, p.Type) + " : 0u;");
                            post.Add("                w.WriteU32(" + local + "Id);");
                            post.Add("                st.KeepRetained(" + local + "Id);");
                        }
                        else
                            post.Add("                w.WriteU32(rr >= 0 ? " + RegisterCall(m, c, local, p.Type) + " : 0u);");
                    }
                    else
                        post.Add("                w.WriteU32(" + RegisterCall(m, c, local, p.Type) + ");");
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
                    shape.Add("x:" + bytes);
                    callArgs.Add(local);
                }
                else if (kind == "StructIn" && StructId.ContainsKey(p.Type))
                {
                    if (retainsChains)
                        b.Append("                st.RetainChains();\n");
                    if (p.Optional)
                        b.Append("                System.IntPtr ").Append(local).Append(" = r.ReadU32() != 0 ? BrovVulkGenStruct.Rebuild(").Append(StructId[p.Type]).Append(", r, st) : System.IntPtr.Zero;\n");
                    else
                        b.Append("                System.IntPtr ").Append(local).Append(" = BrovVulkGenStruct.RebuildRequired(").Append(StructId[p.Type]).Append(", r, st, \"").Append(p.Type).Append("\");\n");
                    shape.Add("s:" + StructId[p.Type]);
                    if (p == WaitTimeoutStructParam(m, c))
                    {
                        string timeout = "*(ulong*)(" + local + " + BrovVulkLayout.MemberOffset[\"" + p.Type + ".timeout\"])";
                        guestTimeout = local + "t";
                        b.Append("                ulong ").Append(guestTimeout).Append(" = ").Append(local).Append(" != System.IntPtr.Zero ? ").Append(timeout).Append(" : 0;\n");
                        if (!replaced)
                            b.Append("                if (").Append(local).Append(" != System.IntPtr.Zero) ").Append(timeout).Append(" = 0;\n");
                    }
                    callArgs.Add(local);
                }
                else if (kind == "StructOut")
                {
                    b.Append("                int sz").Append(i).Append(" = BrovVulkLayout.StructSize[\"").Append(p.Type).Append("\"];\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = st.Alloc(sz").Append(i).Append(");\n");
                    callArgs.Add(local);
                    post.Add(StructId.ContainsKey(p.Type)
                        ? "                BrovVulkGenStruct.WritebackBody(" + StructId[p.Type] + ", w, " + local + ");"
                        : "                w.WriteBytesFrom(" + local + ", (uint)sz" + i + ");");
                }
                else if (kind == "ArrayIn" && (!m.Structs.ContainsKey(p.Type) || StructId.ContainsKey(p.Type)) && arrLen >= 0)
                {
                    b.Append("                uint ").Append(local).Append("n = r.ReadU32();\n");
                    shape.Add(m.Structs.ContainsKey(p.Type) ? "a:s:" + StructId[p.Type]
                        : m.Handles.ContainsKey(p.Type) ? "a:h:" + p.Type
                        : "a:" + ScalarWidth(m, p.Type));
                    int liIn = arrSamples ? arrLen : ParamLenIndex(c, p, i);
                    string declared = arrSamples ? "((uint)p" + liIn + " + 31) / 32" : "p" + liIn;
                    if (liIn >= 0 && liIn < i)
                        b.Append("                if (").Append(p.Optional ? local + "n != 0 && " : "").Append(local).Append("n != ").Append(declared).Append(") throw new System.InvalidOperationException(\"BrovVulk generic: array count mismatch.\");\n");
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
                            b.Append("                if (").Append(local).Append("n > 0) { ").Append(local).Append(" = st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 8)); for (uint k = 0; k < ").Append(local).Append("n; k++) *(System.IntPtr*)(").Append(local).Append(" + (int)(k * 8)) = st.").Append(p.OptionalElement ? "Lookup" : "LookupRequired").Append("(r.ReadU32(), \"").Append(p.Type).Append("\"); }\n");
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
                    shape.Add((GuestIds.Contains(c.Name) ? "o:g:" : "o:") + p.Type);
                    // The field also sizes input arrays that RebuildAt has already checked against it.
                    b.Append("                if (p").Append(spi).Append(" == System.IntPtr.Zero) { if (").Append(local).Append("n != 0) throw new System.InvalidOperationException(\"BrovVulk generic: array count mismatch.\"); }\n");
                    b.Append("                else if (").Append(local).Append("n != *(uint*)(p").Append(spi).Append(" + BrovVulkLayout.MemberOffset[\"").Append(c.Params[spi].Type).Append(".").Append(fld).Append("\"])) throw new System.InvalidOperationException(\"BrovVulk generic: array count mismatch.\");\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = ").Append(local).Append("n > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 8)) : System.IntPtr.Zero;\n");
                    callArgs.Add(local);
                    if (vkRes)
                        check.Add("                if (rr >= 0) for (uint k = 0; k < " + local + "n; k++) if (System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + ", (int)k * 8) == System.IntPtr.Zero) { rr = -3; break; }");
                    if (GuestIds.Contains(c.Name))
                    {
                        b.Append("                System.IntPtr ").Append(local).Append("ids = ").Append(local).Append("n > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 4)) : System.IntPtr.Zero;\n");
                        b.Append("                if (").Append(local).Append("n > 0) r.CopyInto(").Append(local).Append("ids, (uint)BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 4));\n");
                        b.Append("                st.CheckGuestIds(").Append(local).Append("ids, ").Append(local).Append("n, \"").Append(p.Type).Append("\");\n");
                        post.Add("                if (rr >= 0) st.AddGuestIds(" + local + "ids, " + local + ", " + local + "n, \"" + p.Type + "\", " + ParentIdExpr(m, c, p.Type) + ");");
                    }
                    else
                    {
                        if (vkRes)
                            b.Append(HostIdGuard(local + "n"));
                        post.Add("                " + (vkRes ? "if (rr >= 0) " : "") + "for (uint k = 0; k < " + local + "n; k++) w.WriteU32(" + RegisterCall(m, c, "System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + ", (int)k * 8)", p.Type) + ");");
                    }
                }
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(p.Type) && ParamLenIndex(c, p, i) >= 0)
                {
                    int liOut = ParamLenIndex(c, p, i);
                    b.Append("                System.IntPtr ").Append(local).Append(" = p").Append(liOut).Append(" > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(p").Append(liOut).Append(", 8)) : System.IntPtr.Zero;\n");
                    shape.Add("H:" + p.Type);
                    callArgs.Add(local);
                    if (vkRes)
                    {
                        b.Append(HostIdGuard("p" + liOut));
                        check.Add("                if (rr >= 0) for (uint k = 0; k < p" + liOut + "; k++) if (System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + ", (int)k * 8) == System.IntPtr.Zero) { rr = -3; break; }");
                    }
                    post.Add("                " + (vkRes ? "if (rr >= 0) " : "") + "for (uint k = 0; k < p" + liOut + "; k++) w.WriteU32(" + RegisterCall(m, c, "System.Runtime.InteropServices.Marshal.ReadIntPtr(" + local + ", (int)k * 8)", p.Type) + ");");
                }
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(p.Type))
                {
                    b.Append("                System.IntPtr ").Append(local).Append(" = System.IntPtr.Zero;\n");
                    shape.Add("H:" + p.Type);
                    callArgs.Add("(System.IntPtr)(&" + local + ")");
                    if (vkRes)
                    {
                        b.Append(HostIdGuard("1u"));
                        check.Add("                if (rr >= 0 && " + local + " == System.IntPtr.Zero) rr = -3;");
                        post.Add("                w.WriteU32(rr >= 0 ? " + RegisterCall(m, c, local, p.Type) + " : 0u);");
                    }
                    else
                        post.Add("                w.WriteU32(" + RegisterCall(m, c, local, p.Type) + ");");
                }
                else if (kind == "VoidIn" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("                uint ").Append(local).Append("n = r.ReadU32();\n");
                    shape.Add("v");
                    int lvIn = BlobLenIndex(m, c, p, i);
                    if (lvIn >= 0)
                        b.Append("                if (").Append(local).Append("n != (ulong)p").Append(lvIn).Append(") throw new System.InvalidOperationException(\"BrovVulk generic: blob length mismatch.\");\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = ").Append(local).Append("n > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 1)) : System.IntPtr.Zero;\n");
                    b.Append("                if (").Append(local).Append("n > 0) r.CopyInto(").Append(local).Append(", ").Append(local).Append("n);\n");
                    callArgs.Add(local);
                }
                else if (kind == "VoidOut" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("                uint ").Append(local).Append("n = r.ReadU32();\n");
                    shape.Add("V");
                    int lvOut = BlobLenIndex(m, c, p, i);
                    if (lvOut >= 0)
                        b.Append("                if (").Append(local).Append("n != (ulong)p").Append(lvOut).Append(") throw new System.InvalidOperationException(\"BrovVulk generic: blob length mismatch.\");\n");
                    b.Append("                System.IntPtr ").Append(local).Append(" = ").Append(local).Append("n > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(").Append(local).Append("n, 1)) : System.IntPtr.Zero;\n");
                    callArgs.Add(local);
                    post.Add("                if (" + local + "n > 0) w.WriteBytesFrom(" + local + ", " + local + "n);");
                }
                else
                {
                    return null;
                }
            }

            if (ReleasesMappings(c))
                b.Append("                BrovVulkGenMemory.ReleaseMappings(st, inst);\n");

            // VUID-09647.
            if (c.Name == "vkCmdSetDepthClampRangeEXT")
            {
                int modeIdx = c.Params.FindIndex(x => x.Name == "depthClampMode");
                int rangeIdx = c.Params.FindIndex(x => x.Name == "pDepthClampRange");
                if (modeIdx >= 0 && rangeIdx >= 0)
                    b.Append("                if (p").Append(modeIdx).Append(" == BrovVulkConstants.VK_DEPTH_CLAMP_MODE_USER_DEFINED_RANGE_EXT && p").Append(rangeIdx)
                     .Append(" == System.IntPtr.Zero) throw new System.InvalidOperationException(\"BrovVulk generic: a user defined depth clamp mode needs pDepthClampRange.\");\n");
            }

            if (c.Name == "vkCreatePipelineCache")
            {
                int infoIdx = c.Params.FindIndex(x => ParamKind(m, x) == "StructIn" && StructId.ContainsKey(x.Type));
                if (infoIdx < 0)
                    return null;

                b.Append("                *(System.UIntPtr*)(p").Append(infoIdx).Append(" + BrovVulkLayout.MemberOffset[\"VkPipelineCacheCreateInfo.initialDataSize\"]) = System.UIntPtr.Zero;\n");
                b.Append("                *(System.IntPtr*)(p").Append(infoIdx).Append(" + BrovVulkLayout.MemberOffset[\"VkPipelineCacheCreateInfo.pInitialData\"]) = System.IntPtr.Zero;\n");
            }

            if (!EmitRenderTracking(m, c, b, post))
                return null;
            EmitRetireHooks(c, b);
            if (!EmitExtentChecks(m, c, b, post))
                return null;
            int poolIdx = c.Params.FindIndex(x => x.Type == "VkQueryPool" && x.PtrDepth == 0);
            if (poolIdx >= 0)
                EmitQueryChecks(c, b, poolIdx);

            if (c.Name == "vkEnumerateInstanceVersion")
                post.Insert(0, "                p0 = BrovVulkGenExt.ClampApiVersion(p0);");
            else if (c.Name == "vkGetPhysicalDeviceProperties")
                post.Insert(0, "                BrovVulkGenExt.ClampApiVersion(p1);");
            else if (c.Name == "vkGetPhysicalDeviceProperties2")
                post.Insert(0, "                BrovVulkGenExt.ClampApiVersion(p1 + BrovVulkLayout.MemberOffset[\"VkPhysicalDeviceProperties2.properties\"]);");
            // CPU device addresses and capture addresses can expose host pointers.
            else if (c.Name == "vkGetBufferDeviceAddress")
                post.Insert(0, "                if ((st.DeviceStandIns(p0) & VulkanStandIns.HostCpuDeviceBit) != 0) rv = st.GuestBufferAddress(p1);");
            else if (c.Name == "vkGetBufferOpaqueCaptureAddress" || c.Name == "vkGetDeviceMemoryOpaqueCaptureAddress")
                post.Insert(0, "                if ((st.DeviceStandIns(p0) & VulkanStandIns.HostCpuDeviceBit) != 0) rv = 0;");

            if (c.Name == "vkCreatePipelineLayout" || c.Name == "vkCreateBuffer")
            {
                int outIdx = c.Params.FindIndex(x => ParamKind(m, x) == "HandleOut");
                int infoIdx = c.Params.FindIndex(x => ParamKind(m, x) == "StructIn" && StructId.ContainsKey(x.Type));
                if (outIdx >= 0 && infoIdx >= 0)
                {
                    post.Add(c.Name == "vkCreateBuffer"
                        ? "                if (rr >= 0) st.SetBuffer(p0, p" + outIdx + ", p" + infoIdx + ");"
                        : "                if (rr >= 0) st.SetPipelineLayoutSets(p" + outIdx + ", p" + infoIdx + ");");
                }
            }

            if (c.Name == "vkCreateQueryPool")
            {
                int outIdx = c.Params.FindIndex(x => ParamKind(m, x) == "HandleOut");
                int infoIdx = c.Params.FindIndex(x => ParamKind(m, x) == "StructIn" && StructId.ContainsKey(x.Type));
                if (outIdx < 0 || infoIdx < 0)
                    return null;

                b.Append("                uint p").Append(infoIdx).Append("q = GenState.QueryResultValues(p").Append(infoIdx).Append(");\n");
                post.Add("                if (rr >= 0) st.SetQueryPool(p" + outIdx + ", *(uint*)(p" + infoIdx + " + BrovVulkLayout.MemberOffset[\"VkQueryPoolCreateInfo.queryCount\"]), p" + infoIdx + "q);");
            }

            int resetIdx = ResetChildrenIndex(m, c);
            if (resetIdx >= 0)
                post.Add("                if (rr >= 0) st.ForgetChildren(p" + resetIdx + "Id);");

            bool early = EmitStandInHooks(c, b, post, out string guard);

            EmitWsiHooks(c, b, check, post);

            StringBuilder head = new StringBuilder();
            head.Append("            {\n");
            if (c.Name == "vkQueueSubmit" || c.Name == "vkQueueSubmit2")
                head.Append("                BrovVulkGenMemory.SyncAllMappingsToHost(st, inst);\n");
            head.Append(b);
            string hostGate = replaced ? null : PhysicalDeviceGate(m, c);
            if (hostGate != null)
                callArgs[0] = hostGate;
            string call = HostReplaced.TryGetValue(c.Name, out string replacement)
                ? replacement + "(st, inst, " + string.Join(", ", callArgs) + ")"
                : "BrovVulkApi." + c.Name + "(" + string.Join(", ", callArgs) + ")";
            WireShapes[id] = string.Join(" ", shape);
            if (DeferredDestroyCall(m, c) != null)
            {
                int parent = DeferredDestroyParentIndex(m, c, forgetIdx);
                string type = c.Params[forgetIdx].Type;
                string waits = ParkedWaitHandleTypes.Contains(type)
                    ? "st.Waits.TryDeferDestroy(" + id + "u, \"" + type + "\", " + (parent >= 0 ? "p" + parent : "System.IntPtr.Zero") + ", p" + forgetIdx + ")"
                    : null;
                string retire = type == "VkDevice" ? "st.Retire.TryDeferDevice(" + id + "u, p" + forgetIdx + ")"
                    : type == "VkInstance" ? "st.Retire.TryDeferInstance(" + id + "u, p" + forgetIdx + ")"
                    : parent >= 0 && c.Params[parent].Type == "VkDevice"
                        ? "st.Retire.TryDefer(" + id + "u, \"" + type + "\", p" + parent + ", p" + forgetIdx + ")"
                    : type == "VkSurfaceKHR" && parent >= 0
                        ? "st.Retire.TryDeferHeld(" + id + "u, \"" + type + "\", p" + parent + ", p" + forgetIdx + ")"
                        : null;
                string defer = retire == null ? waits : waits == null ? retire : retire + " || " + waits;
                if (defer != null)
                    guard = guard == null ? defer : "(" + guard + ") || " + defer;
            }

            if (c.Ret == "void")
            {
                head.Append("                ");
                if (guard != null)
                    head.Append("if (!(").Append(guard).Append(")) ");
                head.Append(call).Append(";\n");
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
                head.Append(early ? "                int rr = early < 0 ? early : (int)" : "                int rr = (int)").Append(call).Append(";\n");
                // A host answer at timeout 0 is a poll, not the end of the guest's timeout.
                if (guestTimeout != null)
                    head.Append("                if (rr == BrovVulkConstants.VK_TIMEOUT && ").Append(guestTimeout).Append(" != 0 && !st.Waits.Waited) rr = BrovVulkConstants.VK_NOT_READY;\n");
                foreach (string s in check) head.Append(s).Append("\n");
                foreach (string s in post) head.Append(s).Append("\n");
                head.Append("                return rr;\n            }\n");
            }
            return head.ToString();
        }

        private static void EmitQueryChecks(Command c, StringBuilder b, int poolIdx)
        {
            int Find(string name) => c.Params.FindIndex(x => x.Name == name);
            int firstIdx = Find("firstQuery");
            int queryIdx = Find("query");
            int countIdx = Find("queryCount");
            if (firstIdx >= 0 && countIdx < 0)
                countIdx = c.Params.FindIndex(x => x.Type == "uint32_t" && x.PtrDepth == 0 && x.Name.EndsWith("Count", StringComparison.Ordinal));

            if (firstIdx < 0 && queryIdx < 0)
                return;

            string refuse = "                throw new System.InvalidOperationException(\"BrovVulk generic: " + c.Name + " has no query range this layer can check.\");\n";
            string pool = "p" + poolIdx;
            if (c.Name == "vkGetQueryPoolResults")
            {
                int sizeIdx = Find("dataSize"), strideIdx = Find("stride"), flagsIdx = Find("flags");
                b.Append(firstIdx < 0 || countIdx < 0 || sizeIdx < 0 || strideIdx < 0 || flagsIdx < 0
                    ? refuse
                    : "                st.CheckQueryResults(" + pool + ", p" + firstIdx + ", p" + countIdx + ", p" + strideIdx + ", p" + flagsIdx + ", (ulong)p" + sizeIdx + ");\n");
            }
            else if (c.Name == "vkCmdCopyQueryPoolResults")
            {
                int bufferIdx = Find("dstBuffer"), offsetIdx = Find("dstOffset"), strideIdx = Find("stride"), flagsIdx = Find("flags");
                b.Append(firstIdx < 0 || countIdx < 0 || bufferIdx < 0 || offsetIdx < 0 || strideIdx < 0 || flagsIdx < 0
                    ? refuse
                    : "                st.CheckQueryCopy(" + pool + ", p" + firstIdx + ", p" + countIdx + ", p" + bufferIdx + ", p" + offsetIdx + ", p" + strideIdx + ", p" + flagsIdx + ");\n");
            }
            else if (firstIdx >= 0)
                b.Append(countIdx < 0 ? refuse : "                st.CheckQueryRange(" + pool + ", p" + firstIdx + ", p" + countIdx + ");\n");
            else
                b.Append("                st.CheckQueryRange(" + pool + ", p" + queryIdx + ", " + (c.Params[0].Type == "VkCommandBuffer" ? "st.QueryViews(p0)" : "1u") + ");\n");
        }

        private static void EmitRetireHooks(Command c, StringBuilder b)
        {
            const string Lost = "                { st.MarkDeviceLostOf(p0Id); return BrovVulkConstants.VK_ERROR_DEVICE_LOST; }\n";
            switch (c.Name)
            {
                case "vkResetCommandBuffer":
                case "vkBeginCommandBuffer":
                    b.Append("                if (st.Retire.Active && !st.Retire.CommandBufferIdle(st, p0))\n").Append(Lost);
                    break;
                case "vkResetCommandPool":
                    b.Append("                if (st.Retire.Active && (!st.Retire.CommandPoolIdle(st, p1) || !st.Retire.PoolIdle(p1)))\n").Append(Lost);
                    break;
                case "vkResetDescriptorPool":
                    b.Append("                if (st.Retire.Active && !st.Retire.PoolIdle(p1))\n").Append(Lost);
                    b.Append("                if (st.Retire.Active) st.Retire.DropSetFrees(p1);\n");
                    break;
                case "vkResetQueryPool":
                    b.Append("                if (st.Retire.Active && !st.Retire.PoolIdle(p1)) { st.MarkDeviceLostOf(p0Id); return 0; }\n");
                    break;
            }
        }

        // A 24-bit depth aspect copies as 32 bits.
        private static string EmitFormats(Model m)
        {
            StringBuilder fb = new StringBuilder();
            fb.AppendLine("// <auto-generated> BrovVulk copy layout of each format, from vk.xml.");
            fb.AppendLine("using System.Collections.Generic;");
            fb.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            fb.AppendLine("{");
            fb.AppendLine("    internal readonly struct BrovVulkFormat");
            fb.AppendLine("    {");
            fb.AppendLine("        public readonly byte Bytes, Width, Height, Depth, DepthBytes, StencilBytes;");
            fb.AppendLine("        public readonly byte[] Planes;");
            fb.AppendLine("        public BrovVulkFormat(byte bytes, byte width, byte height, byte depth, byte depthBytes, byte stencilBytes, byte[] planes)");
            fb.AppendLine("        {");
            fb.AppendLine("            Bytes = bytes; Width = width; Height = height; Depth = depth; DepthBytes = depthBytes; StencilBytes = stencilBytes; Planes = planes;");
            fb.AppendLine("        }");
            fb.AppendLine("    }");
            fb.AppendLine();
            fb.AppendLine("    internal static class BrovVulkFormats");
            fb.AppendLine("    {");
            fb.AppendLine("        private static readonly Dictionary<int, BrovVulkFormat> Table = new Dictionary<int, BrovVulkFormat>");
            fb.AppendLine("        {");

            XElement formats = m.Formats;
            Dictionary<string, int> blockBytes = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (XElement f in formats?.Elements("format") ?? Enumerable.Empty<XElement>())
                blockBytes[(string)f.Attribute("name")] = int.Parse((string)f.Attribute("blockSize"));

            foreach (XElement f in formats?.Elements("format") ?? Enumerable.Empty<XElement>())
            {
                string name = (string)f.Attribute("name");
                if (!m.Constants.TryGetValue(name, out int value))
                    continue;
                string[] extent = ((string)f.Attribute("blockExtent") ?? "1,1,1").Split(',');
                int depthBits = 0, stencilBits = 0;
                foreach (XElement component in f.Elements("component"))
                {
                    int.TryParse((string)component.Attribute("bits"), out int bits);
                    if ((string)component.Attribute("name") == "D") depthBits = bits;
                    else if ((string)component.Attribute("name") == "S") stencilBits = bits;
                }
                List<string> planes = new List<string>();
                foreach (XElement plane in f.Elements("plane").OrderBy(p => int.Parse((string)p.Attribute("index"))))
                {
                    blockBytes.TryGetValue((string)plane.Attribute("compatible"), out int bytes);
                    planes.Add(bytes + ", " + (string)plane.Attribute("widthDivisor") + ", " + (string)plane.Attribute("heightDivisor"));
                }
                fb.Append("            [").Append(value).Append("] = new BrovVulkFormat(").Append((string)f.Attribute("blockSize")).Append(", ")
                  .Append(extent[0]).Append(", ").Append(extent[1]).Append(", ").Append(extent[2]).Append(", ")
                  .Append(depthBits == 0 ? 0 : depthBits <= 16 ? 2 : 4).Append(", ").Append(stencilBits == 0 ? 0 : 1).Append(", ")
                  .Append(planes.Count == 0 ? "null" : "new byte[] { " + string.Join(", ", planes) + " }").AppendLine("),");
            }

            fb.AppendLine("        };");
            fb.AppendLine();
            fb.AppendLine("        internal static bool TryGet(int format, out BrovVulkFormat info) => Table.TryGetValue(format, out info);");
            fb.AppendLine("    }");
            fb.AppendLine("}");
            return fb.ToString();
        }

        private static readonly Dictionary<string, string> IndirectCommands = new Dictionary<string, string>
        {
            ["vkCmdDrawIndirect"] = "VkDrawIndirectCommand",
            ["vkCmdDrawIndirectCount"] = "VkDrawIndirectCommand",
            ["vkCmdDrawIndexedIndirect"] = "VkDrawIndexedIndirectCommand",
            ["vkCmdDrawIndexedIndirectCount"] = "VkDrawIndexedIndirectCommand",
            ["vkCmdDispatchIndirect"] = "VkDispatchIndirectCommand",
            ["vkCmdDrawMeshTasksIndirectEXT"] = "VkDrawMeshTasksIndirectCommandEXT",
            ["vkCmdDrawMeshTasksIndirectCountEXT"] = "VkDrawMeshTasksIndirectCommandEXT",
            ["vkCmdDrawMeshTasksIndirectNV"] = "VkDrawMeshTasksIndirectCommandNV",
            ["vkCmdDrawMeshTasksIndirectCountNV"] = "VkDrawMeshTasksIndirectCommandNV",
        };

        private static bool EmitExtentChecks(Model m, Command c, StringBuilder b, List<string> post)
        {
            Dictionary<string, Layout> cache = new Dictionary<string, Layout>();
            int Size(string type) => ComputeLayout(m, type, cache).Size;
            int Off(string type, string member) => ComputeLayout(m, type, cache).Offsets[member];
            int Find(string name) => c.Params.FindIndex(x => x.Name == name);
            string Field(string type, string member) => "*(System.IntPtr*)(p1 + " + Off(type, member) + ")";
            string Subresource(string type, string member) => (Off(type, member) + Off("VkImageSubresourceLayers", "aspectMask")).ToString();
            string ImageCopyLayout(string region) => Size(region) + ", " + Subresource(region, "srcSubresource") + ", " + Off(region, "srcOffset") + ", "
                + Subresource(region, "dstSubresource") + ", " + Off(region, "dstOffset") + ", " + Off(region, "extent");
            string BlitLayout(string region) => Size(region) + ", " + Subresource(region, "srcSubresource") + ", " + Off(region, "srcOffsets") + ", "
                + Subresource(region, "dstSubresource") + ", " + Off(region, "dstOffsets");

            string line;
            switch (c.Name)
            {
                case "vkBindBufferMemory":
                    line = "st.CheckBufferBind(p0, p1, p2, p3);";
                    post.Add("                if (rr >= 0) st.HoldMemory(p0, p1, \"VkBuffer\", p2);");
                    post.Add("                if (rr >= 0) rr = st.RegisterAddress(p0, p1);");
                    break;
                case "vkBindImageMemory":
                    line = "st.CheckImageBind(p0, p1, p2, p3, 0u);";
                    post.Add("                if (rr >= 0) st.HoldMemory(p0, p1, \"VkImage\", p2);");
                    break;
                case "vkBindBufferMemory2":
                    line = "st.CheckBufferBinds(p0, p2, p1);";
                    post.Add("                if (rr >= 0) st.HoldMemories(p0, p2, p1, false);");
                    post.Add("                if (rr >= 0) rr = st.RegisterAddresses(p0, p2, p1);");
                    break;
                case "vkBindImageMemory2":
                    line = "st.CheckImageBinds(p0, p2, p1);";
                    post.Add("                if (rr >= 0) st.HoldMemories(p0, p2, p1, true);");
                    break;
                case "vkCreateBufferView":
                    post.Add("                if (rr >= 0) st.SetBufferView(p3, p1);");
                    return true;
                case "vkCmdBindIndexBuffer": line = "st.CheckBufferSpanOrRest(p1, p2, ulong.MaxValue);"; break;
                case "vkCmdBindIndexBuffer2": line = "st.CheckBufferSpanOrRest(p1, p2, p3);"; break;
                case "vkCmdBindVertexBuffers": line = "st.CheckVertexBindingRange(p1, p2); st.CheckBufferSpans(p3, p4, System.IntPtr.Zero, p2);"; break;
                case "vkCmdBindVertexBuffers2": line = "st.CheckVertexBindingRange(p1, p2); st.CheckBufferSpans(p3, p4, p5, p2);"; break;
                case "vkCmdBindTransformFeedbackBuffersEXT": line = "st.CheckFeedbackBufferRange(p1, p2); st.CheckBufferSpans(p3, p4, p5, p2);"; break;
                case "vkCmdSetVertexInputEXT": line = "st.CheckVertexInput(p1, p2, p3, p4);"; break;
                case "vkCmdPushConstants": line = "st.CheckPushConstants(p3, p4);"; break;
                case "vkCmdPushConstants2":
                    line = "if (p1 != System.IntPtr.Zero) st.CheckPushConstants(*(uint*)(p1 + " + Off("VkPushConstantsInfo", "offset") + "), *(uint*)(p1 + "
                        + Off("VkPushConstantsInfo", "size") + "));";
                    break;
                case "vkCmdBeginTransformFeedbackEXT":
                case "vkCmdEndTransformFeedbackEXT": line = "st.CheckBufferWords(p3, p4, p2);"; break;
                case "vkCmdDrawIndirectByteCountEXT": line = "st.CheckBufferSpan(p3, p4, 4);"; break;
                case "vkCmdWriteBufferMarkerAMD":
                case "vkCmdWriteBufferMarker2AMD": line = "st.CheckBufferSpan(p2, p3, 4);"; break;
                case "vkCmdBeginConditionalRenderingEXT":
                    line = "if (p1 != System.IntPtr.Zero) st.CheckBufferSpan(*(System.IntPtr*)(p1 + " + Off("VkConditionalRenderingBeginInfoEXT", "buffer")
                        + "), *(ulong*)(p1 + " + Off("VkConditionalRenderingBeginInfoEXT", "offset") + "), 4);";
                    break;
                case "vkCmdFillBuffer": line = "st.CheckBufferSpanOrRest(p1, p2, p3);"; break;
                case "vkCmdCopyImage":
                case "vkCmdResolveImage":
                {
                    string region = c.Name == "vkCmdCopyImage" ? "VkImageCopy" : "VkImageResolve";
                    line = "st.CheckImageCopies(p1, p3, p6, p5, " + ImageCopyLayout(region) + ");";
                    break;
                }
                case "vkCmdCopyImage2":
                case "vkCmdResolveImage2":
                {
                    string info = c.Name == "vkCmdCopyImage2" ? "VkCopyImageInfo2" : "VkResolveImageInfo2";
                    string region = c.Name == "vkCmdCopyImage2" ? "VkImageCopy2" : "VkImageResolve2";
                    line = "if (p1 != System.IntPtr.Zero) st.CheckImageCopies(" + Field(info, "srcImage") + ", " + Field(info, "dstImage") + ", "
                        + Field(info, "pRegions") + ", *(uint*)(p1 + " + Off(info, "regionCount") + "), " + ImageCopyLayout(region) + ");";
                    break;
                }
                case "vkCmdBlitImage":
                    line = "st.CheckImageBlits(p1, p3, p6, p5, " + BlitLayout("VkImageBlit") + ");";
                    break;
                case "vkCmdBlitImage2":
                    line = "if (p1 != System.IntPtr.Zero) st.CheckImageBlits(" + Field("VkBlitImageInfo2", "srcImage") + ", " + Field("VkBlitImageInfo2", "dstImage") + ", "
                        + Field("VkBlitImageInfo2", "pRegions") + ", *(uint*)(p1 + " + Off("VkBlitImageInfo2", "regionCount") + "), " + BlitLayout("VkImageBlit2") + ");";
                    break;
                case "vkCmdCopyBufferToImage":
                    line = "st.CheckBufferImageCopies(p1, p2, p5, p4, " + Size("VkBufferImageCopy") + ", " + Off("VkBufferImageCopy", "bufferOffset") + ");";
                    break;
                case "vkCmdCopyImageToBuffer":
                    line = "st.CheckBufferImageCopies(p3, p1, p5, p4, " + Size("VkBufferImageCopy") + ", " + Off("VkBufferImageCopy", "bufferOffset") + ");";
                    break;
                case "vkCmdCopyBufferToImage2":
                    line = "if (p1 != System.IntPtr.Zero) st.CheckBufferImageCopies(" + Field("VkCopyBufferToImageInfo2", "srcBuffer") + ", " + Field("VkCopyBufferToImageInfo2", "dstImage") + ", "
                        + Field("VkCopyBufferToImageInfo2", "pRegions") + ", *(uint*)(p1 + " + Off("VkCopyBufferToImageInfo2", "regionCount") + "), "
                        + Size("VkBufferImageCopy2") + ", " + Off("VkBufferImageCopy2", "bufferOffset") + ");";
                    break;
                case "vkCmdCopyImageToBuffer2":
                    line = "if (p1 != System.IntPtr.Zero) st.CheckBufferImageCopies(" + Field("VkCopyImageToBufferInfo2", "dstBuffer") + ", " + Field("VkCopyImageToBufferInfo2", "srcImage") + ", "
                        + Field("VkCopyImageToBufferInfo2", "pRegions") + ", *(uint*)(p1 + " + Off("VkCopyImageToBufferInfo2", "regionCount") + "), "
                        + Size("VkBufferImageCopy2") + ", " + Off("VkBufferImageCopy2", "bufferOffset") + ");";
                    break;
                case "vkCmdClearColorImage":
                case "vkCmdClearDepthStencilImage":
                    line = "st.CheckImageRanges(p1, p5, p4);";
                    break;
                case "vkCreateImage":
                    line = "GenState.ImageExtent p1image = GenState.ReadImage(p1);";
                    post.Add("                if (rr >= 0) st.SetImage(p3, p1image);");
                    break;
                case "vkCreateSwapchainKHR":
                    post.Add("                if (rr >= 0) st.SetSwapchainExtent(p3, p1);");
                    return true;
                case "vkGetSwapchainImagesKHR":
                    post.Add("                if (rr >= 0 && p2pr != 0) st.SetSwapchainImages(p1, p2a, p2c);");
                    return true;
                case "vkCmdUpdateBuffer": line = "st.CheckBufferSpan(p1, p2, p3);"; break;
                case "vkCreateDescriptorSetLayout":
                    line = "GenState.SetLayoutShape p1layout = st.ReadSetLayout(p1);";
                    post.Add("                if (rr >= 0) st.SetSetLayout(p3, p1layout);");
                    break;
                case "vkAllocateDescriptorSets":
                    line = "st.ForceVariableCounts(p0, p1);";
                    post.Add("                if (rr >= 0) st.AddSets(p0, p1, p2, p2n);");
                    break;
                case "vkUpdateDescriptorSets": line = "if (!st.CheckDescriptorUpdates(p1, p2, p3, p4)) { st.MarkDeviceLostOf(p0Id); return 0; }"; break;
                case "vkCmdBindDescriptorSets": line = "st.CheckBindDescriptorSets(p0, GenState.BindPointMask(p1), p2, p3, p4, p5, p6, p7);"; break;
                case "vkCmdBindDescriptorSets2":
                {
                    string info = "VkBindDescriptorSetsInfo";
                    line = "if (p1 != System.IntPtr.Zero) st.CheckBindDescriptorSets(p0, GenState.StageMask(*(uint*)(p1 + " + Off(info, "stageFlags") + ")), " + Field(info, "layout") + ", *(uint*)(p1 + " + Off(info, "firstSet") + "), *(uint*)(p1 + "
                        + Off(info, "descriptorSetCount") + "), " + Field(info, "pDescriptorSets") + ", *(uint*)(p1 + " + Off(info, "dynamicOffsetCount") + "), " + Field(info, "pDynamicOffsets") + ");";
                    break;
                }
                case "vkCmdPushDescriptorSet": line = "st.CheckPushDescriptors(GenState.BindPointMask(p1), p2, p3, p4, p5);"; break;
                case "vkCmdPushDescriptorSet2":
                {
                    string info = "VkPushDescriptorSetInfo";
                    line = "if (p1 != System.IntPtr.Zero) st.CheckPushDescriptors(GenState.StageMask(*(uint*)(p1 + " + Off(info, "stageFlags") + ")), " + Field(info, "layout") + ", *(uint*)(p1 + " + Off(info, "set") + "), *(uint*)(p1 + "
                        + Off(info, "descriptorWriteCount") + "), " + Field(info, "pDescriptorWrites") + ");";
                    break;
                }
                case "vkCmdCopyBuffer":
                    line = "st.CheckBufferCopies(p1, p2, p4, p3, " + Size("VkBufferCopy") + ", " + Off("VkBufferCopy", "srcOffset") + ", "
                        + Off("VkBufferCopy", "dstOffset") + ", " + Off("VkBufferCopy", "size") + ");";
                    break;
                case "vkCmdCopyBuffer2":
                    line = "if (p1 != System.IntPtr.Zero) st.CheckBufferCopies(*(System.IntPtr*)(p1 + " + Off("VkCopyBufferInfo2", "srcBuffer")
                        + "), *(System.IntPtr*)(p1 + " + Off("VkCopyBufferInfo2", "dstBuffer") + "), *(System.IntPtr*)(p1 + " + Off("VkCopyBufferInfo2", "pRegions")
                        + "), *(uint*)(p1 + " + Off("VkCopyBufferInfo2", "regionCount") + "), " + Size("VkBufferCopy2") + ", " + Off("VkBufferCopy2", "srcOffset")
                        + ", " + Off("VkBufferCopy2", "dstOffset") + ", " + Off("VkBufferCopy2", "size") + ");";
                    break;
                default:
                    if (IndirectCommands.TryGetValue(c.Name, out string record))
                    {
                        int buffer = Find("buffer"), offset = Find("offset"), countBuffer = Find("countBuffer"), countOffset = Find("countBufferOffset");
                        int count = countBuffer >= 0 ? Find("maxDrawCount") : Find("drawCount"), stride = Find("stride");
                        line = "st.CheckIndirect(p" + buffer + ", p" + offset + ", " + (count >= 0 ? "p" + count : "1u") + ", " + (stride >= 0 ? "p" + stride : "0u") + ", " + Size(record) + ");";
                        if (countBuffer >= 0)
                            line += " st.CheckBufferSpan(p" + countBuffer + ", p" + countOffset + ", 4);";
                        break;
                    }
                    return !(c.Name.StartsWith("vkCmd", StringComparison.Ordinal) && c.Name.Contains("Indirect")
                        && c.Params.Any(x => x.Type == "VkBuffer" && x.PtrDepth == 0));
            }

            b.Append("                ").Append(line).Append('\n');
            return true;
        }

        private static bool EmitRenderTracking(Model m, Command c, StringBuilder b, List<string> post)
        {
            string line;
            switch (c.Name)
            {
                case "vkCreateRenderPass":
                case "vkCreateRenderPass2":
                    {
                        int outIdx = c.Params.FindIndex(x => ParamKind(m, x) == "HandleOut");
                        int infoIdx = c.Params.FindIndex(x => ParamKind(m, x) == "StructIn" && StructId.ContainsKey(x.Type));
                        if (outIdx < 0 || infoIdx < 0)
                            return false;
                        b.Append("                GenState.RenderPassShape p").Append(infoIdx).Append("pass = st.ReadRenderPass(p").Append(infoIdx).Append(", ")
                         .Append(c.Name == "vkCreateRenderPass2" ? "true" : "false").Append(");\n");
                        post.Add("                if (rr >= 0) st.SetRenderPass(p" + outIdx + ", p" + infoIdx + "pass);");
                        return true;
                    }
                case "vkCreateFramebuffer":
                    b.Append("                GenState.FramebufferExtent p1framebuffer = st.ReadFramebuffer(p1);\n");
                    post.Add("                if (rr >= 0) st.SetFramebuffer(p3, p1framebuffer);");
                    return true;
                case "vkCreateImageView":
                    post.Add("                if (rr >= 0) st.SetView(p3, p1);");
                    return true;
                case "vkAllocateCommandBuffers":
                    post.Add("                if (rr >= 0) st.AddRecordings(p0, p1, p2, p2n);");
                    return true;
                case "vkCmdBeginRenderPass":
                case "vkCmdBeginRenderPass2": line = "st.BeginRenderPass(p0, p1);"; break;
                case "vkCmdNextSubpass":
                case "vkCmdNextSubpass2": line = "st.NextSubpass(p0);"; break;
                case "vkCmdEndRenderPass":
                case "vkCmdEndRenderPass2": line = "st.EndInstance(p0, true);"; break;
                case "vkCmdEndRendering":
                case "vkCmdEndRendering2KHR": line = "st.EndInstance(p0, false);"; break;
                case "vkCmdBeginRendering": line = "st.BeginRendering(p0, p1);"; break;
                case "vkBeginCommandBuffer":
                    post.Add("                if (rr >= 0) st.BeginRecording(p0, p1, true);");
                    line = "st.BeginRecording(p0, p1, false);";
                    break;
                case "vkCmdSetColorBlendEnableEXT":
                case "vkCmdSetColorBlendEquationEXT":
                case "vkCmdSetColorWriteMaskEXT":
                case "vkCmdSetColorBlendAdvancedEXT": line = "st.CheckColorRange(p1, p2);"; break;
                case "vkCmdSetColorWriteEnableEXT": line = "st.CheckColorRange(0u, p1);"; break;
                case "vkEndCommandBuffer":
                    post.Add("                if (rr < 0) st.ResetRecording(p0);");
                    line = "st.EndRecording(p0);";
                    break;
                case "vkResetCommandBuffer": line = "st.ResetRecording(p0);"; break;
                case "vkResetCommandPool": line = "st.ResetPoolRecordings(p1Id);"; break;
                case "vkCmdClearAttachments": line = "st.CheckClearAttachments(p0, p1, p2, p3, p4);"; break;
                case "vkCmdExecuteCommands": line = "st.ExecuteCommands(p0, p1, p2);"; break;
                case "vkCmdBindPipeline": line = "st.NotePipelineBind(p1, p2);"; break;
                default:
                    if (c.Name.StartsWith("vkCmdDraw", StringComparison.Ordinal))
                        line = "st.CheckBoundSets(0);";
                    else if (ComputeDispatches.Contains(c.Name))
                        line = "st.CheckBoundSets(1);";
                    else if (RunsShaders(c.Name))
                        line = "st.RefuseOnCpu();";
                    else
                        return true;
                    break;
            }

            b.Append("                ").Append(line).Append('\n');
            return true;
        }

        // A switch that holds every body is past the JIT size limit, so it runs unoptimized and each call zeroes one
        // frame for the locals of all bodies. A body in braces gets its own method, and NoInlining keeps its locals
        // out of Dispatch.
        private static void AppendHostCase(StringBuilder cases, StringBuilder methods, string name, int id, string body)
        {
            cases.Append("            case ").Append(id).Append(":\n");
            if (!body.StartsWith("            {\n", StringComparison.Ordinal))
            {
                cases.Append(body);
                return;
            }

            cases.Append("                return ").Append(name).Append("(r, w, st, inst);\n");
            methods.Append("\n        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]\n");
            methods.Append("        private static int ").Append(name).Append("(GenReader r, GenBuf w, GenState st, Brovan.Core.Emulation.IGuestMemory inst)\n");
            methods.Append(body.Substring(4).Replace("\n    ", "\n"));
        }

        // Resolve newer commands through their owner when the loader predates them.
        private static bool OwnerRouted(Model m, Command c)
        {
            if (c.Params.Count == 0)
                return false;
            if (m.CoreCommandVersion.TryGetValue(c.Name, out double version) && version <= 1.0)
                return false;
            string first = c.Params[0].Type;
            return c.Params[0].PtrDepth == 0
                && (first == "VkDevice" || first == "VkQueue" || first == "VkCommandBuffer" || first == "VkPhysicalDevice");
        }

        // Loader trampolines can reach null driver slots for unsupported device extensions.
        private static string PhysicalDeviceGate(Model m, Command c)
        {
            if (!OwnerRouted(m, c) || c.Params[0].Type != "VkPhysicalDevice" || IsCountArrayPair(m, c, 0)
                || ParamKind(m, c.Params[0]) != "HandleIn")
                return null;

            bool core = m.CoreCommandVersion.TryGetValue(c.Name, out double version);
            List<VkExtension> providers = m.Extensions.Values
                .Where(e => e.Commands.Contains(c.Name) || e.Gated.Any(g => g.Commands.Contains(c.Name)))
                .OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
            if ((providers.Count == 0 && !core) || providers.Any(e => e.Type != "device"))
                return null;
            uint coreVersion = core ? ApiVersion(version) : 0;
            return "BrovVulkGenExt.PhysicalDeviceCommand(p0, " + coreVersion + "u"
                + string.Concat(providers.Select(e => ", \"" + e.Name + "\"")) + ")";
        }

        private static string Arg(Command c, string name)
        {
            int i = c.Params.FindIndex(x => x.Name == name);
            return i < 0 ? null : "p" + i;
        }

        // True when the pre-call code declared an `early` VkResult that replaces the host call while negative.
        // A non-null guard is a bool expression that replaces a void host call when true.
        private static bool EmitStandInHooks(Command c, StringBuilder b, List<string> post, out string guard)
        {
            guard = null;
            string device = Arg(c, "device");
            string commandBuffer = Arg(c, "commandBuffer");
            string name = c.Name.EndsWith("KHR", StringComparison.Ordinal) ? c.Name.Substring(0, c.Name.Length - 3) : c.Name;

            switch (name)
            {
                case "vkGetPhysicalDeviceFeatures":
                    post.Insert(0, "                VulkanStandIns.Advertise(p0, p1);");
                    return false;
                case "vkGetPhysicalDeviceFeatures2":
                    post.Insert(0, "                VulkanStandIns.Advertise2(p0, p1);");
                    return false;
                case "vkGetPhysicalDeviceProperties":
                    post.Insert(0, "                VulkanStandIns.Properties(p0, p1);");
                    return false;
                case "vkGetPhysicalDeviceProperties2":
                    post.Insert(0, "                VulkanStandIns.Properties2(p0, p1);");
                    return false;
                case "vkGetPhysicalDeviceFormatProperties":
                    b.Append("                p1 = VulkanStandIns.QueryFormat(p0, p1);\n");
                    post.Insert(0, "                VulkanStandIns.FormatProperties(p0, p1, p2);");
                    return false;
                case "vkGetPhysicalDeviceFormatProperties2":
                    b.Append("                p1 = VulkanStandIns.QueryFormat(p0, p1);\n");
                    post.Insert(0, "                VulkanStandIns.FormatProperties2(p0, p1, p2);");
                    return false;
                case "vkGetPhysicalDeviceImageFormatProperties":
                    b.Append("                int early = VulkanStandIns.ImageFormatProperties(p0, ref p1, p2, p3, ref p4, ref p5);\n");
                    return true;
                case "vkGetPhysicalDeviceImageFormatProperties2":
                    b.Append("                int early = VulkanStandIns.ImageFormatProperties2(st, p0, p1);\n");
                    return true;
                case "vkGetPhysicalDeviceQueueFamilyProperties":
                    post.Insert(0, "                VulkanStandIns.QueueFamilyProperties(p0, p1c, p1a, BrovVulkLayout.StructSize[\"VkQueueFamilyProperties\"], BrovVulkLayout.MemberOffset[\"VkQueueFamilyProperties.queueFlags\"]);");
                    return false;
                case "vkGetPhysicalDeviceQueueFamilyProperties2":
                    post.Insert(0, "                VulkanStandIns.QueueFamilyProperties(p0, p1c, p1a, BrovVulkLayout.StructSize[\"VkQueueFamilyProperties2\"], BrovVulkLayout.MemberOffset[\"VkQueueFamilyProperties2.queueFamilyProperties\"] + BrovVulkLayout.MemberOffset[\"VkQueueFamilyProperties.queueFlags\"]);");
                    return false;
            }

            if (name == "vkCreateGraphicsPipelines")
            {
                int infoIdx = c.Params.FindIndex(x => x.Type == "VkGraphicsPipelineCreateInfo");
                int countIdx = c.Params.FindIndex(x => x.Name == "createInfoCount");
                string cache = Arg(c, "pipelineCache");
                string pipelines = Arg(c, "pPipelines");
                if (device != null && cache != null && pipelines != null && infoIdx >= 0 && countIdx >= 0 && StructId.TryGetValue("VkGraphicsPipelineCreateInfo", out int sid))
                {
                    b.Append("                VulkanStandIns.PreparePipelines(st, ").Append(device).Append(", p").Append(infoIdx)
                     .Append(", p").Append(countIdx).Append(", BrovVulkStructMeta.Sizes[").Append(sid).Append("]);\n");
                    post.Insert(0, "                VulkanStandIns.FinishPipelines(st, " + device + ", " + cache + ", " + pipelines + ", rr);");
                    post.Add("                st.NotePipelines(rr >= 0 ? " + pipelines + " : System.IntPtr.Zero, p" + countIdx + ");");
                }
                return false;
            }

            if (name == "vkCreateComputePipelines")
            {
                int infoIdx = c.Params.FindIndex(x => x.Type == "VkComputePipelineCreateInfo");
                int countIdx = c.Params.FindIndex(x => x.Name == "createInfoCount");
                if (device != null && infoIdx >= 0 && countIdx >= 0 && StructId.TryGetValue("VkComputePipelineCreateInfo", out int sid))
                {
                    b.Append("                VulkanStandIns.PrepareComputePipelines(st, ").Append(device).Append(", p").Append(infoIdx)
                     .Append(", p").Append(countIdx).Append(", BrovVulkStructMeta.Sizes[").Append(sid).Append("]);\n");
                    post.Insert(0, "                VulkanStandIns.FinishComputePipelines(st, " + device + ");");
                    string computePipelines = Arg(c, "pPipelines");
                    if (computePipelines != null)
                        post.Add("                st.NotePipelines(rr >= 0 ? " + computePipelines + " : System.IntPtr.Zero, p" + countIdx + ");");
                }
                return false;
            }

            if (name == "vkCreateRayTracingPipelinesNV" || name == "vkCreateRayTracingPipelinesKHR")
            {
                int infoIdx = c.Params.FindIndex(x => x.Type == "VkRayTracingPipelineCreateInfoNV" || x.Type == "VkRayTracingPipelineCreateInfoKHR");
                int countIdx = c.Params.FindIndex(x => x.Name == "createInfoCount");
                if (device != null && infoIdx >= 0 && countIdx >= 0 && StructId.TryGetValue(c.Params[infoIdx].Type, out int rtSid))
                {
                    string t = c.Params[infoIdx].Type;
                    b.Append("                VulkanStandIns.PrepareStagePipelines(st, ").Append(device).Append(", p").Append(infoIdx)
                     .Append(", p").Append(countIdx).Append(", BrovVulkStructMeta.Sizes[").Append(rtSid)
                     .Append("], BrovVulkLayout.MemberOffset[\"").Append(t).Append(".flags\"], BrovVulkLayout.MemberOffset[\"").Append(t)
                     .Append(".pStages\"], BrovVulkLayout.MemberOffset[\"").Append(t).Append(".stageCount\"]);\n");
                    post.Insert(0, "                VulkanStandIns.FinishComputePipelines(st, " + device + ");");
                }
                return false;
            }

            if ((name == "vkCreateBufferView" || name == "vkCreateSampler") && device != null)
            {
                b.Append("                VulkanStandIns.").Append(name == "vkCreateBufferView" ? "CreateBufferView" : "CreateSampler").Append("(st, ").Append(device).Append(", p1);\n");
                return false;
            }

            if ((name == "vkCreateRenderPass" || name == "vkCreateRenderPass2") && device != null)
            {
                b.Append("                VulkanStandIns.CreateRenderPass(st, ").Append(device).Append(", p1, ").Append(name == "vkCreateRenderPass2" ? "true" : "false").Append(");\n");
                return false;
            }

            if (device != null)
            {
                switch (name)
                {
                    case "vkGetImageSubresourceLayout2":
                        guard = "VulkanStandIns.ImageSubresourceLayout2(st, p0, p1, p2, p3)";
                        return false;
                    case "vkGetDeviceImageSubresourceLayout":
                        guard = "VulkanStandIns.DeviceImageSubresourceLayout(st, p0, p1, p2)";
                        return false;
                    case "vkGetRenderingAreaGranularity":
                        guard = "VulkanStandIns.RenderingAreaGranularity(st, p0, p2)";
                        return false;
                }
            }

            if (name == "vkCreateShaderModule")
            {
                string ci = Arg(c, "pCreateInfo");
                string module = Arg(c, "pShaderModule");
                if (device != null && ci != null && module != null)
                {
                    b.Append("                if (").Append(ci).Append(" != System.IntPtr.Zero) VulkanStandIns.PatchShaderModule(st, ").Append(device).Append(", ").Append(ci).Append(");\n");
                    post.Add("                if (rr >= 0 && " + ci + " != System.IntPtr.Zero) VulkanStandIns.NoteShaderModule(st, " + device + ", " + ci + ", " + module + ");");
                }
                return false;
            }

            if (name == "vkDestroyShaderModule")
            {
                string module = Arg(c, "shaderModule");
                if (module != null)
                    b.Append("                VulkanStandIns.ForgetShaderModule(st, ").Append(module).Append(");\n");
                return false;
            }

            if (name == "vkDestroyPipeline")
            {
                string pipeline = Arg(c, "pipeline");
                if (device != null && pipeline != null)
                    b.Append("                VulkanStandIns.DestroyPipeline(st, ").Append(device).Append(", ").Append(pipeline).Append(");\n");
                return false;
            }

            if (name == "vkDestroyDevice" || name == "vkDestroyInstance")
            {
                b.Append("                VulkanStandIns.ReleaseDevice(st, ").Append(name == "vkDestroyDevice" && device != null ? device : "System.IntPtr.Zero").Append(");\n");
                return false;
            }

            if (name == "vkCreateImage")
            {
                string image = Arg(c, "pImage");
                if (device != null && image != null)
                {
                    b.Append("                int early = VulkanStandIns.CreateImage(st, ").Append(device).Append(", p1);\n");
                    post.Insert(0, "                if (rr >= 0) VulkanStandIns.NoteImage(st, " + image + ");");
                    return true;
                }
                return false;
            }

            if (name == "vkDestroyImage")
            {
                string image = Arg(c, "image");
                if (device != null && image != null)
                    b.Append("                VulkanStandIns.DestroyImage(st, ").Append(device).Append(", ").Append(image).Append(");\n");
                return false;
            }

            if (name == "vkCreateImageView" && device != null)
            {
                b.Append("                int early = VulkanStandIns.CreateImageView(st, ").Append(device).Append(", p1);\n");
                return true;
            }

            if (name == "vkCreateBuffer" && device != null)
            {
                b.Append("                VulkanStandIns.CreateBuffer(st, ").Append(device).Append(", p1);\n");
                return false;
            }

            if (name == "vkCreateCommandPool")
            {
                string pool = Arg(c, "pCommandPool");
                if (device != null && pool != null)
                    post.Add("                if (rr >= 0) VulkanStandIns.NoteCommandPool(st, " + device + ", p1, " + pool + ");");
                return false;
            }

            if (name == "vkDestroyCommandPool" || name == "vkResetCommandPool")
            {
                string pool = Arg(c, "commandPool");
                if (pool != null)
                    b.Append("                VulkanStandIns.").Append(name == "vkDestroyCommandPool" ? "DestroyCommandPool" : "ResetCommandPool").Append("(st, ").Append(pool).Append(");\n");
                return false;
            }

            int buffersIdx = c.Params.FindIndex(x => x.Name == "pCommandBuffers");
            if (name == "vkAllocateCommandBuffers" && device != null && buffersIdx >= 0)
            {
                post.Add("                if (rr >= 0) VulkanStandIns.NoteCommandBuffers(st, " + device + ", p1, p" + buffersIdx + "n, p" + buffersIdx + ");");
                return false;
            }

            if (name == "vkFreeCommandBuffers" && buffersIdx >= 0)
            {
                post.Add("                VulkanStandIns.ForgetCommandBuffers(st, p" + buffersIdx + "n, p" + buffersIdx + ");");
                return false;
            }

            if (commandBuffer == null)
                return false;

            switch (name)
            {
                case "vkCmdCopyBufferToImage":
                    b.Append("                if (VulkanStandIns.CopyBufferToImage(st, p0, p1, p2, p3, p4, p5)) return 0;\n");
                    return false;
                case "vkCmdCopyBufferToImage2":
                    b.Append("                if (VulkanStandIns.CopyBufferToImage2(st, p0, p1)) return 0;\n");
                    return false;
                case "vkCmdCopyImageToBuffer":
                    b.Append("                if (VulkanStandIns.CopyImageToBuffer(st, p1)) return 0;\n");
                    return false;
                case "vkCmdCopyImageToBuffer2":
                    b.Append("                if (VulkanStandIns.CopyImageToBuffer2(st, p1)) return 0;\n");
                    return false;
                case "vkCmdCopyImage":
                    b.Append("                if (VulkanStandIns.CopyImage(st, p1, p3)) return 0;\n");
                    return false;
                case "vkCmdCopyImage2":
                    b.Append("                if (VulkanStandIns.CopyImage2(st, p1)) return 0;\n");
                    return false;
                case "vkBeginCommandBuffer":
                case "vkResetCommandBuffer":
                    b.Append("                VulkanStandIns.ResetCommandBuffer(st, p0);\n");
                    return false;
                case "vkCmdBindPipeline":
                    b.Append("                p2 = VulkanStandIns.BindPipeline(st, p0, p1, p2);\n");
                    return false;
                case "vkCmdBindDescriptorSets":
                    b.Append("                VulkanStandIns.BindDescriptorSets(st, p0, p1, p2, p3, p4, p5, p6, p7);\n");
                    b.Append("                if (VulkanStandIns.TranslateBindDescriptorSets(st, p0, p1, p2, p3, p4, p5, p6, p7)) return 0;\n");
                    return false;
                case "vkCmdBindDescriptorSets2":
                    b.Append("                VulkanStandIns.BindDescriptorSets2(st, p0, p1);\n");
                    b.Append("                if (VulkanStandIns.TranslateBindDescriptorSets2(st, p0, p1)) return 0;\n");
                    return false;
                case "vkCmdPushConstants":
                    b.Append("                VulkanStandIns.PushConstants(st, p0, p1, p2, p3, p4, p5);\n");
                    return false;
                case "vkCmdPushConstants2":
                    b.Append("                VulkanStandIns.PushConstants2(st, p0, p1);\n");
                    b.Append("                if (VulkanStandIns.TranslatePushConstants2(st, p0, p1)) return 0;\n");
                    return false;
                case "vkCmdBindIndexBuffer":
                    b.Append("                p1 = VulkanStandIns.IndexBuffer(st, p0, p1, ref p2);\n");
                    return false;
                case "vkCmdBindIndexBuffer2":
                    b.Append("                p1 = VulkanStandIns.IndexBuffer(st, p0, p1, ref p2);\n");
                    b.Append("                if (VulkanStandIns.BindIndexBuffer2(st, p0, p1, p2, p4)) return 0;\n");
                    return false;
                case "vkCmdBindVertexBuffers2":
                    b.Append("                VulkanStandIns.VertexBufferSizes(st, p0, p2, p3, p4, p5);\n");
                    return false;
                case "vkCmdBeginRendering":
                    b.Append("                VulkanStandIns.BeginRendering(st, p0, p1);\n");
                    return false;
                case "vkCmdPushDescriptorSet2":
                    b.Append("                if (VulkanStandIns.TranslatePushDescriptorSet2(st, p0, p1)) return 0;\n");
                    return false;
                case "vkCmdDrawIndirect":
                case "vkCmdDrawIndexedIndirect":
                case "vkCmdDrawMeshTasksIndirectEXT":
                case "vkCmdDrawMeshTasksIndirectNV":
                    b.Append("                if (VulkanStandIns.DrawIndirect(st, p0, p1, p2, p3, p4, VulkanStandIns.IndirectKind")
                     .Append(name == "vkCmdDrawIndexedIndirect" ? "Indexed" : name == "vkCmdDrawIndirect" ? "Draw" : name == "vkCmdDrawMeshTasksIndirectEXT" ? "MeshExt" : "MeshNv")
                     .Append(")) return 0;\n");
                    return false;
                case "vkCmdDrawIndirectCount":
                case "vkCmdDrawIndexedIndirectCount":
                case "vkCmdDrawMeshTasksIndirectCountEXT":
                case "vkCmdDrawMeshTasksIndirectCountNV":
                    b.Append("                p5 = VulkanStandIns.IndirectDrawCount(st, p0, p5);\n");
                    return false;
                case "vkCmdSetPolygonModeEXT":
                    b.Append("                p1 = VulkanStandIns.SetPolygonMode(st, p0, p1);\n");
                    return false;
                case "vkCmdSetPrimitiveTopology":
                    b.Append("                VulkanStandIns.SetPrimitiveTopology(st, p0, p1);\n");
                    return false;
                case "vkCmdBeginQuery":
                case "vkCmdBeginQueryIndexedEXT":
                    b.Append("                p3 = VulkanStandIns.BeginQueryFlags(st, p0, p3);\n");
                    return false;
            }

            if (!c.Name.StartsWith("vkCmdSet", StringComparison.Ordinal))
                return false;

            for (int i = 0; i < c.Params.Count; i++)
            {
                if (c.Params[i].Name != "viewportCount" && c.Params[i].Name != "scissorCount")
                    continue;

                string first = Arg(c, c.Params[i].Name == "viewportCount" ? "firstViewport" : "firstScissor");
                b.Append("                if ((st.CommandBufferStandIns(").Append(commandBuffer).Append(") & VulkanStandIns.MultiViewportBit) != 0)\n");
                b.Append("                {\n");
                if (first != null)
                    b.Append("                    if (MultiViewport.Skip(").Append(first).Append(")) return 0;\n");
                b.Append("                    p").Append(i).Append(" = MultiViewport.Clamp(p").Append(i).Append(");\n");
                b.Append("                }\n");
                b.Append("                else\n");
                b.Append("                    st.CheckViewportRange(").Append(first ?? "0u").Append(", p").Append(i).Append(");\n");
            }

            return false;
        }

        private static void EmitWsiHooks(Command c, StringBuilder b, List<string> check, List<string> post)
        {
            string pd = Arg(c, "physicalDevice");
            string surface = Arg(c, "surface");
            string info = Arg(c, "pSurfaceInfo");

            switch (c.Name)
            {
                case "vkGetPhysicalDeviceSurfaceSupportKHR":
                case "vkGetPhysicalDeviceSurfaceFormatsKHR":
                case "vkGetPhysicalDeviceSurfacePresentModesKHR":
                    if (pd != null && surface != null)
                        post.Add("                st.Wsi.NoteSurface(" + pd + ", " + surface + ");");
                    return;

                case "vkGetPhysicalDeviceSurfaceFormats2KHR":
                    if (pd != null && info != null)
                        post.Add("                if (" + info + " != System.IntPtr.Zero) st.Wsi.NoteSurface(" + pd
                            + ", *(System.IntPtr*)(" + info + " + BrovVulkLayout.MemberOffset[\"VkPhysicalDeviceSurfaceInfo2KHR.surface\"]));");
                    return;

                case "vkGetPhysicalDeviceSurfaceCapabilitiesKHR":
                {
                    string caps = Arg(c, "pSurfaceCapabilities");
                    if (pd != null && surface != null && caps != null)
                        check.Add("                if (rr >= 0) st.Wsi.NormalizeCapabilities(" + pd + ", " + surface + ", " + caps + ");");
                    return;
                }

                case "vkGetPhysicalDeviceSurfaceCapabilities2KHR":
                {
                    string caps = Arg(c, "pSurfaceCapabilities");
                    if (pd != null && info != null && caps != null)
                        check.Add("                if (rr >= 0) st.Wsi.NormalizeCapabilities2(" + pd + ", " + info + ", " + caps + ");");
                    return;
                }

                case "vkCreateSwapchainKHR":
                {
                    string ci = Arg(c, "pCreateInfo");
                    string dev = Arg(c, "device");
                    string outp = Arg(c, "pSwapchain");
                    if (ci == null || dev == null || outp == null)
                        return;
                    b.Append("                BrovVulkWsi.SwapchainPlan wsiPlan = st.Wsi.ReconcileSwapchain(").Append(dev).Append(", ").Append(ci).Append(", st, inst);\n");
                    post.Add("                if (rr >= 0) st.Wsi.NoteSwapchain(" + outp + ", wsiPlan);");
                    return;
                }

                case "vkGetSwapchainImagesKHR":
                {
                    string swapchain = Arg(c, "swapchain");
                    int countIdx = c.Params.FindIndex(x => x.Name == "pSwapchainImageCount");
                    if (swapchain != null && countIdx >= 0)
                        post.Add("                if (rr >= 0) st.Wsi.NoteSwapchainImages(" + swapchain + ", p" + countIdx + "a, p" + countIdx + "c);");
                    return;
                }

                case "vkCreateImageView":
                {
                    string ci = Arg(c, "pCreateInfo");
                    if (ci != null)
                        b.Append("                st.Wsi.ReconcileImageView(").Append(ci).Append(");\n");
                    return;
                }

                case "vkCreateRenderPass":
                case "vkCreateRenderPass2":
                {
                    string ci = Arg(c, "pCreateInfo");
                    if (ci != null)
                        b.Append("                st.Wsi.ReconcileRenderPass(").Append(ci).Append(", ")
                         .Append(c.Name == "vkCreateRenderPass2" ? "true" : "false").Append(");\n");
                    return;
                }

                case "vkAcquireNextImageKHR":
                {
                    string swapchain = Arg(c, "swapchain");
                    if (swapchain != null)
                        check.Add("                rr = st.Wsi.FilterAcquireResult(rr, " + swapchain + ");");
                    return;
                }

                case "vkQueuePresentKHR":
                {
                    string present = Arg(c, "pPresentInfo");
                    if (present != null)
                        check.Add("                rr = st.Wsi.FilterPresentResult(rr, " + present + ");");
                    return;
                }
            }
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
                    "    if (bvk_r >= 0 && pMemory && bvk_outLen >= 8)\n" +
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
                    "    (void)pAllocator;\n" +
                    "    bvk_rq_reset();\n" +
                    "    bvk_w_u32((uint32_t)(uintptr_t)instance);\n" +
                    "    bvk_w_u64((uint64_t)(uintptr_t)(pCreateInfo ? pCreateInfo->hwnd : 0));\n" +
                    "    unsigned char bvk_out[64]; unsigned int bvk_outLen = 0;\n" +
                    "    int bvk_r = bvk_rq_send(BVK_vkCreateWin32SurfaceKHR, bvk_out, sizeof(bvk_out), &bvk_outLen);\n" +
                    "    if (bvk_r >= 0 && pSurface && bvk_outLen >= 8) { uint32_t id; memcpy(&id, bvk_out + 4, 4); *pSurface = (VkSurfaceKHR)(uintptr_t)id; }\n" +
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
                    "        if (bvk_r >= 0 && bvk_outLen >= 12) { uint64_t n; memcpy(&n, bvk_out + 4, 8); *pDataSize = (size_t)n; }\n" +
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
            int idOut = GuestIdOutIndex(m, c);
            bool guestIds = idOut >= 0;
            string ids = guestIds ? c.Params[idOut].Name : null;
            StringBuilder b = new StringBuilder();
            if (GuestWrapped.Contains(c.Name) || guestIds)
                b.Append("static ").Append(c.Ret).Append(" bvk_gen_").Append(c.Name).Append("(").Append(sig).Append(guestIds ? ", int bvk_posted" : "").Append(")\n{\n");
            else
                b.Append("VKAPI_ATTR ").Append(c.Ret).Append(" VKAPI_CALL ").Append(c.Name).Append("(").Append(sig).Append(")\n{\n");
            if (guestIds)
            {
                b.Append("    uint32_t bvk_gn = ").Append(ids).Append(" ? ").Append(StructLenGuestExpr(c.Params[idOut].Length)).Append(" : 0;\n");
                b.Append("    if (bvk_gn && !bvk_id_take(").Append(GuestParentExpr(m, c, c.Params[idOut].Type)).Append(", (uint32_t)(uintptr_t)").Append(c.Params[0].Name)
                 .Append(", bvk_gn, ").Append(ids).Append(", (int)sizeof(*").Append(ids).Append("))) return VK_ERROR_OUT_OF_HOST_MEMORY;\n");
            }
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
                int arrLen = ArrayLenIndex(c, p, out bool arrSamples);
                if (kind == "ScalarIn")
                {
                    int w = ScalarWidth(m, p.Type);
                    if (p.Type == "float" || p.Type == "double")
                        b.Append("    { uint").Append(w == 8 ? "64" : "32").Append("_t bvk_bits; memcpy(&bvk_bits, &").Append(p.Name).Append(", sizeof bvk_bits); bvk_w_u").Append(w == 8 ? "64" : "32").Append("(bvk_bits); }\n");
                    else
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
                else if (kind == "ArrayIn" && arrLen >= 0)
                {
                    string count = arrSamples ? "(((uint32_t)" + c.Params[arrLen].Name + " + 31) / 32)" : "(uint32_t)" + c.Params[arrLen].Name;
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? ").Append(count).Append(" : 0);\n");
                    b.Append("    if (").Append(p.Name).Append(") for (uint32_t k = 0; k < ").Append(count).Append("; k++) ");
                    if (m.Structs.ContainsKey(p.Type))
                        b.Append("bvk_ser_struct(").Append(StructId[p.Type]).Append(", (const unsigned char*)&").Append(p.Name).Append("[k]);\n");
                    else if (m.Handles.ContainsKey(p.Type))
                        b.Append("bvk_w_u32((uint32_t)(uintptr_t)").Append(p.Name).Append("[k]);\n");
                    else
                        b.Append("bvk_w_bytes(&").Append(p.Name).Append("[k], ").Append(ScalarWidth(m, p.Type)).Append(");\n");
                }
                else if (kind == "VoidIn" && c.Params.Any(x => x.Name == p.Length))
                {
                    string len = BlobLenExpr(c, p.Length);
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? ").Append(len).Append(" : 0);\n");
                    b.Append("    if (").Append(p.Name).Append(") bvk_w_bytes(").Append(p.Name).Append(", ").Append(len).Append(");\n");
                }
                else if (kind == "VoidOut" && c.Params.Any(x => x.Name == p.Length))
                {
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? ").Append(BlobLenExpr(c, p.Length)).Append(" : 0);\n");
                }
                else if (IsStructLenHandleArrayOut(m, p))
                {
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? ").Append(StructLenGuestExpr(p.Length)).Append(" : 0);\n");
                    if (guestIds)
                        b.Append("    if (").Append(p.Name).Append(") for (uint32_t k = 0; k < ").Append(StructLenGuestExpr(p.Length)).Append("; k++) bvk_w_u32((uint32_t)(uintptr_t)").Append(p.Name).Append("[k]);\n");
                }
                else if (kind == "ChainOut")
                {
                    b.Append("    bvk_w_u32(").Append(p.Name).Append(" ? *(const uint32_t*)").Append(p.Name).Append(" : 0);\n");
                    b.Append("    if (").Append(p.Name).Append(") { const void *bvk_pn = *(const void*const*)((const char*)").Append(p.Name).Append(" + BVK_PNEXT_OFF); while (bvk_pn) { int bvk_sd = bvk_pnext_sid(*(const uint32_t*)bvk_pn); if (bvk_sd >= 0) { bvk_w_u32(1); bvk_w_u32(*(const uint32_t*)bvk_pn); bvk_w_u32((uint32_t)bvk_sd); } bvk_pn = *(const void*const*)((const char*)bvk_pn + BVK_PNEXT_OFF); } }\n");
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
            string release = GuestIdRelease(m, c);
            if (PostedCommands.Contains(c.Name))
            {
                b.Append("    if (!bvk_post(BVK_").Append(c.Name).Append(")) { unsigned char bvk_out[32]; unsigned int bvk_outLen = 0; bvk_rq_send(BVK_").Append(c.Name).Append(", bvk_out, sizeof(bvk_out), &bvk_outLen); }\n");
                if (release != null)
                    b.Append("    ").Append(release).Append("\n");
                b.Append("}\n");
                return b.ToString();
            }
            if (guestIds)
                b.Append("    if (bvk_posted && bvk_post(BVK_").Append(c.Name).Append(")) return VK_SUCCESS;\n");
            b.Append("    unsigned char bvk_out[").Append(GuestOutSize(m, c)).Append("]; unsigned int bvk_outLen = 0;\n");
            Param waitStruct = WaitTimeoutStructParam(m, c);
            if (waitStruct != null || c.Params.Any(x => IsWaitTimeoutParam(m, x)))
            {
                b.Append("    int bvk_r;\n");
                b.Append("    uint64_t bvk_timeout = ").Append(waitStruct == null ? "timeout" : waitStruct.Name + " ? " + waitStruct.Name + "->timeout : 0").Append(";\n");
                b.Append("    uint64_t bvk_start = GetTickCount64();\n");
                b.Append("    for (;;)\n    {\n");
                b.Append("        bvk_r = bvk_rq_send(BVK_").Append(c.Name).Append(", bvk_out, sizeof(bvk_out), &bvk_outLen);\n");
                b.Append("        if (bvk_r != VK_NOT_READY || bvk_timeout == 0) break;\n");
                b.Append("        if (bvk_timeout != UINT64_MAX && (GetTickCount64() - bvk_start) * 1000000ull >= bvk_timeout)\n");
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
                    bool elemStruct = m.Structs.ContainsKey(a.Type);
                    b.Append("    if (bvk_r >= 0) { uint32_t bvk_oc = 0; if (bvk_outLen >= bvk_off + 4) { memcpy(&bvk_oc, bvk_out + bvk_off, 4); bvk_off += 4; } if (").Append(p.Name).Append(") *").Append(p.Name).Append(" = bvk_oc;\n");
                    if (elemHandle)
                        b.Append("        if (").Append(a.Name).Append(") for (uint32_t k = 0; k < bvk_oc; k++) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; ").Append(a.Name).Append("[k] = (").Append(a.Type).Append(")(uintptr_t)id; } }\n");
                    else if (elemStruct && StructId.ContainsKey(a.Type))
                        b.Append("        if (").Append(a.Name).Append(") for (uint32_t k = 0; k < bvk_oc; k++) bvk_off += bvk_deser_body(").Append(StructId[a.Type]).Append(", (unsigned char*)&").Append(a.Name).Append("[k], bvk_out + bvk_off); }\n");
                    else if (m.Structs.ContainsKey(a.Type) && StructHasPNext(m, a.Type))
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
                    b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(" && bvk_outLen >= bvk_off + ").Append(w).Append(") { bvk_r_scalar(").Append(p.Name).Append(", bvk_out + bvk_off, (int)sizeof(*").Append(p.Name).Append("), ").Append(w).Append("); bvk_off += ").Append(w).Append("; }\n");
                }
                else if (kind == "HandleOut")
                {
                    b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(" && bvk_outLen >= bvk_off + 4) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; *").Append(p.Name).Append(" = (").Append(p.Type).Append(")(uintptr_t)id; }\n");
                }
                else if (IsStructLenHandleArrayOut(m, p))
                {
                    if (!guestIds)
                        b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(") for (uint32_t k = 0; k < ").Append(StructLenGuestExpr(p.Length)).Append("; k++) { if (bvk_outLen >= bvk_off + 4) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; ").Append(p.Name).Append("[k] = (").Append(p.Type).Append(")(uintptr_t)id; } }\n");
                }
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(p.Type) && ParamLenIndex(c, p, i) >= 0)
                {
                    b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(") for (uint32_t k = 0; k < (uint32_t)").Append(p.Length).Append("; k++) { if (bvk_outLen >= bvk_off + 4) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; ").Append(p.Name).Append("[k] = (").Append(p.Type).Append(")(uintptr_t)id; } }\n");
                }
                else if (kind == "ArrayOut" && m.Handles.ContainsKey(p.Type))
                {
                    b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(" && bvk_outLen >= bvk_off + 4) { uint32_t id; memcpy(&id, bvk_out + bvk_off, 4); bvk_off += 4; ").Append(p.Name).Append("[0] = (").Append(p.Type).Append(")(uintptr_t)id; }\n");
                }
                else if (kind == "StructOut")
                {
                    if (StructId.ContainsKey(p.Type))
                        b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(") bvk_off += bvk_deser_body(").Append(StructId[p.Type]).Append(", (unsigned char*)").Append(p.Name).Append(", bvk_out + bvk_off);\n");
                    else
                        b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(") { memcpy(").Append(p.Name).Append(", bvk_out + bvk_off, sizeof(*").Append(p.Name).Append(")); bvk_off += (unsigned int)sizeof(*").Append(p.Name).Append("); }\n");
                }
                else if (kind == "ChainOut")
                {
                    int baseSid = StructId[p.Type];
                    b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(") { bvk_off += bvk_deser_body(").Append(baseSid).Append(", (unsigned char*)").Append(p.Name).Append(", bvk_out + bvk_off); void *bvk_pn = *(void**)((char*)").Append(p.Name).Append(" + BVK_PNEXT_OFF); while (bvk_pn) { int bvk_sd = bvk_pnext_sid(*(const uint32_t*)bvk_pn); if (bvk_sd >= 0) bvk_off += bvk_deser_body(bvk_sd, (unsigned char*)bvk_pn, bvk_out + bvk_off); bvk_pn = *(void**)((char*)bvk_pn + BVK_PNEXT_OFF); } }\n");
                }
                else if (kind == "VoidOut" && c.Params.Any(x => x.Name == p.Length))
                {
                    string len = BlobLenExpr(c, p.Length);
                    b.Append("    if (bvk_r >= 0 && ").Append(p.Name).Append(" && bvk_outLen >= bvk_off + ").Append(len).Append(") { memcpy(").Append(p.Name).Append(", bvk_out + bvk_off, ").Append(len).Append("); bvk_off += ").Append(len).Append("; }\n");
                }
            }
            if (guestIds)
                b.Append("    if (bvk_r < 0 && bvk_gn) { bvk_id_release_handles(").Append(ids).Append(", bvk_gn, (int)sizeof(*").Append(ids).Append(")); for (uint32_t k = 0; k < bvk_gn; k++) bvk_handle_put(")
                 .Append(ids).Append(", k, (int)sizeof(*").Append(ids).Append("), 0); }\n");
            if (release != null)
                b.Append(c.Ret == "void" ? "    " : "    if (bvk_r >= 0) ").Append(release).Append("\n");
            if (c.Name == "vkGetPhysicalDeviceMemoryProperties")
                b.Append("    if (bvk_r >= 0 && pMemoryProperties) bvk_note_memprops(pMemoryProperties);\n");
            else if (c.Name == "vkGetPhysicalDeviceMemoryProperties2")
                b.Append("    if (bvk_r >= 0 && pMemoryProperties) bvk_note_memprops(&pMemoryProperties->memoryProperties);\n");
            if (Ret64(c))
            {
                b.Append("    uint64_t bvk_rv = 0;\n");
                b.Append("    if (bvk_r >= 0 && bvk_outLen >= bvk_off + 8) memcpy(&bvk_rv, bvk_out + bvk_off, 8);\n");
                b.Append("    return (").Append(c.Ret).Append(")bvk_rv;\n");
            }
            else if (c.Ret != "void")
                b.Append("    return (").Append(c.Ret).Append(")bvk_r;\n");
            b.Append("}\n");
            if (guestIds && !GuestWrapped.Contains(c.Name))
            {
                b.Append("VKAPI_ATTR ").Append(c.Ret).Append(" VKAPI_CALL ").Append(c.Name).Append("(").Append(sig).Append(")\n{\n");
                b.Append("    return bvk_gen_").Append(c.Name).Append("(").Append(string.Join(", ", c.Params.Select(x => x.Name))).Append(", !bvk_post_disabled());\n}\n");
            }
            return b.ToString();
        }

        private static string GuestIdRelease(Model m, Command c)
        {
            HashSet<string> types = GuestIdTypes(m);
            if (types.Count == 0)
                return null;

            int destroyed = DestroyedHandleIndex(m, c);
            if (destroyed >= 0)
            {
                Param p = c.Params[destroyed];
                if (p.Type == "VkDevice")
                    return "bvk_id_release_device((uint32_t)(uintptr_t)" + p.Name + ");";
                if (types.Contains(p.Type))
                    return "bvk_id_release_handles(&" + p.Name + ", 1, (int)sizeof(" + p.Name + "));";
                if (types.Any(t => m.HandleParents.TryGetValue(t, out string parent) && parent == p.Type))
                    return "bvk_id_release_parent((uint32_t)(uintptr_t)" + p.Name + ");";
                return null;
            }

            if (c.Name.StartsWith("vkFree", StringComparison.Ordinal))
            {
                Param freed = c.Params.FirstOrDefault(x => x.IsConst && x.PtrDepth == 1 && types.Contains(x.Type) && c.Params.Any(y => y.Name == x.Length && y.PtrDepth == 0));
                if (freed != null)
                    return "bvk_id_release_handles(" + freed.Name + ", (uint32_t)" + freed.Length + ", (int)sizeof(*" + freed.Name + "));";
            }

            int reset = ResetChildrenIndex(m, c);
            return reset >= 0 ? "bvk_id_release_parent((uint32_t)(uintptr_t)" + c.Params[reset].Name + ");" : null;
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
            Dictionary<string, List<string>> promotedFrom = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            foreach (Command a in m.Commands.Values)
            {
                if (a.Alias == null)
                    continue;
                if (!promotedFrom.TryGetValue(a.Alias, out List<string> names))
                {
                    names = new List<string>();
                    promotedFrom[a.Alias] = names;
                }
                names.Add(a.Name);
            }
            foreach (List<string> names in promotedFrom.Values)
                names.Sort(StringComparer.Ordinal);

            b.AppendLine("        internal static readonly string[][] CommandAliases = new string[][]");
            b.AppendLine("        {");
            foreach (Command c in cmds)
                b.AppendLine(promotedFrom.TryGetValue(c.Name, out List<string> names)
                    ? "            new string[] { " + string.Join(", ", names.Select(n => "\"" + n + "\"")) + " },"
                    : "            null,");
            b.AppendLine("        };");
            b.AppendLine();

            for (int id = 0; id < cmds.Count; id++)
            {
                Command c = cmds[id];
                StringBuilder args = new StringBuilder();
                StringBuilder call = new StringBuilder();
                StringBuilder fnPtr = new StringBuilder("delegate* unmanaged<");
                for (int i = 0; i < c.Params.Count; i++)
                {
                    string ty = c.Params[i].ArrayLen > 1 ? "IntPtr" : CsType(m, c.Params[i].Type, c.Params[i].PtrDepth);
                    if (i > 0) { args.Append(", "); call.Append(", "); }
                    args.Append(ty).Append(" a").Append(i);
                    call.Append('a').Append(i);
                    fnPtr.Append(ty).Append(", ");
                }
                string ret = CsRet(m, c.Ret);
                fnPtr.Append(ret).Append('>');

                if (!promotedFrom.ContainsKey(c.Name) && m.CoreCommandVersion.ContainsKey(c.Name))
                {
                    b.AppendLine("        [DllImport(\"vulkan-1.dll\", EntryPoint = \"" + c.Name + "\", CallingConvention = CallingConvention.Winapi)]");
                    b.AppendLine("        internal static extern " + ret + " " + c.Name + "(" + args + ");");
                    continue;
                }

                string proc = OwnerRouted(m, c) ? "BrovVulkProc.Owned(a0, " + id + ")" : "BrovVulkProc.Global(" + id + ")";
                b.AppendLine("        internal static " + ret + " " + c.Name + "(" + args + ") => ((" + fnPtr + ")" + proc + ")(" + call + ");");
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
            lb.AppendLine();
            lb.AppendLine("    internal static class BrovVulkConstants");
            lb.AppendLine("    {");
            foreach (KeyValuePair<string, int> kv in m.Constants.OrderBy(k => k.Key, StringComparer.Ordinal))
                if (kv.Key.StartsWith("VK_", StringComparison.Ordinal))
                    lb.AppendLine("        internal const int " + kv.Key + " = " + kv.Value + ";");
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
            gh.Append("#define BVK_POSTED_ID 0x").Append(PostedBatchId.ToString("X")).Append("u\n");
            gh.Append("#define BVK_GUEST_ID_BASE 0x").Append(GuestIdBase.ToString("X")).Append("u\n");
            gh.Append("#endif\n");
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_gen.h"), gh.ToString());

            foreach (string en in ExtDenylist.Keys.Concat(ExtKnownGaps.Keys))
                if (!m.Extensions.ContainsKey(en))
                    spc.ReportDiagnostic(Diagnostic.Create(ExtGuard, Location.None, en, "not found in vk.xml"));
            foreach (string sn in KnownGapTypes)
                if (!m.Structs.ContainsKey(sn))
                    spc.ReportDiagnostic(Diagnostic.Create(ExtGuard, Location.None, sn, "not found in vk.xml"));

            PNextSet = new HashSet<string>();
            List<string> probe = ComputeNeededStructs(m, cmds, cache);
            StructId = new Dictionary<string, int>();
            for (int i = 0; i < probe.Count; i++)
                StructId[probe[i]] = i;
            Dictionary<string, bool> hostOk = new Dictionary<string, bool>(StringComparer.Ordinal);
            for (int i = 0; i < cmds.Count; i++)
                hostOk[cmds[i].Name] = EmitHostCase(m, cmds[i], i) != null;

            Dictionary<string, string> blocked = new Dictionary<string, string>(StringComparer.Ordinal);
            Advertised = new HashSet<string>(m.Extensions.Keys, StringComparer.Ordinal);
            List<Command> exported;
            HashSet<string> closure;
            while (true)
            {
                AdvertisedTypes = new HashSet<string>(StringComparer.Ordinal);
                foreach (string en in Advertised)
                    AdvertisedTypes.UnionWith(EffectiveTypes(m.Extensions[en]));
                exported = ExportedCommands(m, cmds, hostOk, cache);
                PNextSet = ComputePNextSet(m, exported, cache, out closure);
                HashSet<string> outSide = OutSideStructs(m, exported);
                bool changed = false;
                foreach (string en in Advertised.OrderBy(x => x, StringComparer.Ordinal).ToList())
                {
                    VkExtension ext = m.Extensions[en];
                    string gap = ExtensionGap(m, ext, hostOk, closure, outSide, cache);
                    if (gap == null && ext.Depends != null && !DependsSatisfied(ext.Depends, Advertised))
                        gap = "needs " + ext.Depends;
                    if (gap == null)
                        continue;
                    Advertised.Remove(en);
                    blocked[en] = gap;
                    changed = true;
                }
                if (!changed)
                    break;
            }
            List<string> needed = ComputeNeededStructs(m, exported, cache);
            StructId = new Dictionary<string, int>();
            for (int i = 0; i < needed.Count; i++)
                StructId[needed[i]] = i;
            WireShapes = new Dictionary<int, string>();
            foreach ((string Name, string Problem) bad in GuestAnswerProblems(m))
                spc.ReportDiagnostic(Diagnostic.Create(GuestAnswerGuard, Location.None, bad.Name, bad.Problem));
            foreach ((string Name, string Problem) bad in RetainedChainProblems(m))
                spc.ReportDiagnostic(Diagnostic.Create(RetainedChainGuard, Location.None, bad.Name, bad.Problem));
            HashSet<string> exportedNames = new HashSet<string>(exported.Select(x => x.Name), StringComparer.Ordinal);

            StringBuilder sm = new StringBuilder();
            sm.AppendLine("// <auto-generated> Vulkan struct member descriptors from vk.xml.");
            sm.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            sm.AppendLine("{");
            sm.AppendLine("    internal enum BvkMK : byte { Scalar, Handle, StructValue, StructPtr, StructArray, HandleArray, ScalarArray, StringZ, StringArray, PNext, Ignore, BlobPtr, SelectArray }");
            sm.AppendLine("    internal readonly struct BvkM");
            sm.AppendLine("    {");
            sm.AppendLine("        public readonly BvkMK Kind; public readonly int Offset; public readonly int Size; public readonly int Sub; public readonly int LenOffset; public readonly string HandleType; public readonly int SelOffset; public readonly uint SelMask; public readonly bool Optional; public readonly bool LenSamples; public readonly bool OptionalElements;");
            sm.AppendLine("        public BvkM(BvkMK k, int o, int s, int sub, int lo, string ht, int so, uint sm, bool opt = false, bool lenSamples = false, bool optElems = false) { Kind = k; Offset = o; Size = s; Sub = sub; LenOffset = lo; HandleType = ht; SelOffset = so; SelMask = sm; Optional = opt; LenSamples = lenSamples; OptionalElements = optElems; }");
            sm.AppendLine("    }");
            sm.AppendLine("    internal static class BrovVulkStructMeta");
            sm.AppendLine("    {");
            sm.Append("        internal static readonly int[] Sizes = { ");
            foreach (string n in needed) sm.Append(ComputeLayout(m, n, cache).Size).Append(", ");
            sm.AppendLine("};");
            sm.Append("        internal static readonly bool[] PNext = { ");
            foreach (string n in needed) sm.Append(PNextSet.Contains(n) ? "true" : "false").Append(", ");
            sm.AppendLine("};");
            sm.Append("        internal static readonly bool[] Repeatable = { ");
            foreach (string n in needed) sm.Append(m.Structs.TryGetValue(n, out VkStruct rs) && rs.AllowDuplicate ? "true" : "false").Append(", ");
            sm.AppendLine("};");
            sm.Append("        internal static readonly uint[] STypes = { ");
            foreach (string n in needed) sm.Append(STypeValue(m, n)).Append("u, ");
            sm.AppendLine("};");
            sm.AppendLine("        internal static readonly BvkM[][] Members = new BvkM[][]");
            sm.AppendLine("        {");

            StringBuilder gs = new StringBuilder();
            gs.Append("/* <auto-generated> Vulkan struct member descriptors from vk.xml. */\n");
            gs.Append("#ifndef BROVVULK_STRUCTS_H\n#define BROVVULK_STRUCTS_H\n");
            gs.Append("#include <stddef.h>\n");
            gs.Append("typedef struct { unsigned char kind; int offset; int size; int nsize; int sub; int lenOffset; int selOffset; unsigned int selMask; unsigned char lenSamples; } BvkM;\n");
            gs.Append("#define BVK_PNEXT_OFF ((int)offsetof(VkBaseInStructure, pNext))\n");
            gs.Append("#define BVK_SAME_SIZE(tag, expr, want) typedef char bvk_sz_##tag[((int)(expr) == (want)) ? 1 : -1]\n");
            StringBuilder ga = new StringBuilder();

            for (int si = 0; si < needed.Count; si++)
            {
                string n = needed[si];
                VkStruct s = m.Structs[n];
                Layout lay = ComputeLayout(m, n, cache);
                sm.Append("            new BvkM[] { ");
                gs.Append("static const BvkM bvk_s").Append(si).Append("[] = { ");
                if (s.IsUnion || StructIsFlat(m, n, new HashSet<string>()))
                {
                    sm.Append("new BvkM(BvkMK.Scalar, 0, ").Append(lay.Size).Append(", -1, -1, \"\", -1, 0u), ");
                    gs.Append("{0,0,").Append(lay.Size).Append(",(int)sizeof(").Append(n).Append("),-1,-1,-1,0,0}, ");
                    ga.Append("BVK_SAME_SIZE(u").Append(si).Append(", sizeof(").Append(n).Append("), ").Append(lay.Size).Append(");\n");
                }
                else
                {
                    foreach (Member mem in s.Members)
                    {
                        MDesc d = ClassifyMember(m, s, mem, lay.Offsets, cache);
                        int sub = d.SubName != null && StructId.ContainsKey(d.SubName) ? StructId[d.SubName] : -1;
                        if (d.Kind == "Scalar" && d.Size > 8 && d.MemName != null)
                            ga.Append("BVK_SAME_SIZE(s").Append(si).Append('_').Append(d.MemName)
                              .Append(", sizeof(((").Append(n).Append("*)0)->").Append(d.MemName).Append("), ").Append(d.Size).Append(");\n");
                        sm.Append("new BvkM(BvkMK.").Append(d.Kind).Append(", ").Append(d.Offset).Append(", ").Append(d.Size).Append(", ").Append(sub).Append(", ").Append(d.LenOffset).Append(", \"").Append(d.HandleType).Append("\", ").Append(d.SelOffset).Append(", ").Append(d.SelMask).Append("u, ").Append(d.Optional ? "true" : "false").Append(", ").Append(d.LenSamples ? "true" : "false").Append(", ").Append(d.OptionalElements ? "true" : "false").Append("), ");
                        gs.Append("{").Append(KindNum[d.Kind]).Append(",").Append(GuestOffset(n, d.MemName, d.Offset)).Append(",").Append(d.Size)
                          .Append(",").Append(GuestNativeSize(n, d))
                          .Append(",").Append(sub)
                          .Append(",").Append(GuestOffset(n, d.LenName, d.LenOffset))
                          .Append(",").Append(GuestOffset(n, d.SelName, d.SelOffset))
                          .Append(",").Append(d.SelMask).Append("u,").Append(d.LenSamples ? 1 : 0).Append("}, ");
                    }
                }
                sm.AppendLine("},");
                gs.Append("};\n");
            }
            sm.AppendLine("        };");

            // Drivers can leave raw struct padding uninitialized.
            sm.AppendLine("        internal static readonly int[][] Padding = new int[][]");
            sm.AppendLine("        {");
            foreach (string n in needed)
            {
                List<int> ranges = new List<int>();
                VkStruct s = m.Structs[n];
                Layout lay = ComputeLayout(m, n, cache);
                if (!s.IsUnion && StructIsFlat(m, n, new HashSet<string>()))
                    FlatPadding(m, n, 0, cache, ranges);
                else if (!s.IsUnion)
                {
                    foreach (Member mem in s.Members)
                    {
                        if (mem.PtrDepth != 0 || !m.Structs.ContainsKey(mem.Type) || ClassifyMember(m, s, mem, lay.Offsets, cache).Kind != "Scalar")
                            continue;
                        int esz = ComputeLayout(m, mem.Type, cache).Size;
                        for (int k = 0; k < Math.Max(1, mem.ArrayLen); k++)
                            FlatPadding(m, mem.Type, lay.Offsets[mem.Name] + k * esz, cache, ranges);
                    }
                }
                sm.Append("            ").Append(ranges.Count == 0 ? "null" : "new int[] { " + string.Join(", ", ranges) + " }").AppendLine(",");
            }
            sm.AppendLine("        };");

            int DbiSid = -1, DbiBuffer = 0, DbiOffset = 0, DbiRange = 0;
            if (StructId.TryGetValue("VkDescriptorBufferInfo", out int DbiId))
            {
                Layout DbiLay = ComputeLayout(m, "VkDescriptorBufferInfo", cache);
                if (DbiLay.Offsets.TryGetValue("buffer", out DbiBuffer)
                    && DbiLay.Offsets.TryGetValue("offset", out DbiOffset)
                    && DbiLay.Offsets.TryGetValue("range", out DbiRange))
                    DbiSid = DbiId;
            }

            sm.AppendLine("        internal const int DescriptorBufferInfoSid = " + DbiSid + ";");
            sm.AppendLine("        internal const int DescriptorBufferInfoBuffer = " + DbiBuffer + ";");
            sm.AppendLine("        internal const int DescriptorBufferInfoOffset = " + DbiOffset + ";");
            sm.AppendLine("        internal const int DescriptorBufferInfoRange = " + DbiRange + ";");
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
                foreach (string en in Advertised.OrderBy(x => x, StringComparer.Ordinal))
                    if (m.Extensions.TryGetValue(en, out VkExtension ext) && ext.Type == scope)
                        xb.AppendLine("            (\"" + en + "\", " + ext.SpecVersion + "u),");
                xb.AppendLine("        };");
            }
            xb.AppendLine("        internal static readonly string[] CpuWithheld =");
            xb.AppendLine("        {");
            Dictionary<string, bool> carries = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (string en in Advertised.OrderBy(x => x, StringComparer.Ordinal))
                if (m.Extensions.TryGetValue(en, out VkExtension ext) && ext.Type == "device" && WithheldOnCpu(m, ext, carries))
                    xb.AppendLine("            \"" + en + "\",");
            xb.AppendLine("        };");
            xb.AppendLine("    }");
            xb.AppendLine("}");
            spc.AddSource("BrovVulkExtensions.g.cs", SourceText.From(xb.ToString(), Encoding.UTF8));
            spc.AddSource("BrovVulkFormats.g.cs", SourceText.From(EmitFormats(m), Encoding.UTF8));

            gs.Append("static const BvkM* const bvk_structs[] = { ");
            for (int si = 0; si < needed.Count; si++) gs.Append("bvk_s").Append(si).Append(", ");
            gs.Append("};\n");
            gs.Append("static const int bvk_struct_counts[] = { ");
            foreach (string n in needed)
                gs.Append(m.Structs[n].IsUnion || StructIsFlat(m, n, new HashSet<string>()) ? 1 : m.Structs[n].Members.Count).Append(", ");
            gs.Append("};\n");
            gs.Append("static const int bvk_struct_nsizes[] = { ");
            foreach (string n in needed) gs.Append("(int)sizeof(").Append(n).Append("), ");
            gs.Append("};\n");
            gs.Append(ga);
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
            db.Append("        internal const uint PostedBatchId = 0x").Append(PostedBatchId.ToString("X")).AppendLine(";");
            db.Append("        internal const uint GuestIdBase = 0x").Append(GuestIdBase.ToString("X")).AppendLine(";");
            db.Append("        internal const uint MaxApiVersion = 0x").Append(MaxApiVersion.ToString("X")).AppendLine(";");
            db.AppendLine();
            db.AppendLine("        internal static int Dispatch(uint id, GenReader r, GenBuf w, GenState st, Brovan.Core.Emulation.IGuestMemory inst)");
            db.AppendLine("        {");
            db.AppendLine("            switch (id)");
            db.AppendLine("            {");
            StringBuilder cb = new StringBuilder();
            StringBuilder methodB = new StringBuilder();
            StringBuilder pb = new StringBuilder();
            StringBuilder deferB = new StringBuilder();
            StringBuilder loseB = new StringBuilder();
            StringBuilder releaseB = new StringBuilder();
            StringBuilder guestIdB = new StringBuilder();
            StringBuilder procB = new StringBuilder();
            StringBuilder defB = new StringBuilder();
            defB.Append("LIBRARY vulkan-1\nEXPORTS\n");
            foreach (string n in GuestLocal.OrderBy(x => x, StringComparer.Ordinal))
            {
                defB.Append(n).Append('\n');
                procB.Append("M(").Append(n).Append(");\n");
            }
            pb.Append("#ifndef BROVVULK_GEN_PROTOS_H\n#define BROVVULK_GEN_PROTOS_H\n");
            for (int i = 0; i < cmds.Count; i++)
            {
                Command c = cmds[i];
                if (!exportedNames.Contains(c.Name))
                    continue;
                string hostCase = EmitHostCase(m, c, i);
                if (hostCase == null)
                    continue;
                AppendHostCase(db, methodB, c.Name, i, hostCase);
                string deferredDestroy = DeferredDestroyCall(m, c);
                if (deferredDestroy != null)
                    deferB.Append("            case ").Append(i).Append("u: ").Append(deferredDestroy).Append("; return;\n");
                if (c.ErrorCodes != null && c.ErrorCodes.Split(',').Contains("VK_ERROR_DEVICE_LOST"))
                    loseB.Append(i).Append("u, ");
                if (ReleasesHandles(m, c))
                    releaseB.Append(i).Append("u, ");
                if (GuestIds.Contains(c.Name))
                    guestIdB.Append(i).Append("u, ");
                cb.Append(EmitGuestTrampoline(m, c)).Append("\n");
                if (c.Name == "vkCreateWin32SurfaceKHR")
                    pb.Append("VKAPI_ATTR VkResult VKAPI_CALL vkCreateWin32SurfaceKHR(VkInstance instance, const VkWin32SurfaceCreateInfoKHR *pCreateInfo, const VkAllocationCallbacks *pAllocator, VkSurfaceKHR *pSurface);\n");
                else
                    pb.Append("VKAPI_ATTR ").Append(c.Ret).Append(" VKAPI_CALL ").Append(c.Name).Append("(").Append(GuestSig(c)).Append(");\n");
                procB.Append("M(").Append(c.Name).Append(");\n");
                defB.Append(c.Name).Append("\n");
            }
            foreach (Command alias in m.Commands.Values)
            {
                if (alias.Alias == null || exportedNames.Contains(alias.Name)
                    || !(exportedNames.Contains(alias.Alias) || GuestLocal.Contains(alias.Alias)))
                    continue;
                procB.Append("if (strcmp(pName, \"").Append(alias.Name).Append("\") == 0) return (PFN_vkVoidFunction)")
                     .Append(alias.Alias).Append(";\n");
            }
            pb.Append("#endif\n");
            db.AppendLine("                default: return -3;");
            db.AppendLine("            }");
            db.AppendLine("        }");
            db.Append(methodB);
            db.AppendLine();
            db.Append("        internal static readonly System.Collections.Generic.HashSet<uint> MayLoseDevice = new System.Collections.Generic.HashSet<uint> { ").Append(loseB).AppendLine("};");
            db.Append("        internal static readonly System.Collections.Generic.HashSet<uint> ReleasesHandles = new System.Collections.Generic.HashSet<uint> { ").Append(releaseB).AppendLine("};");
            db.Append("        internal static readonly System.Collections.Generic.HashSet<uint> CreatesGuestIds = new System.Collections.Generic.HashSet<uint> { ").Append(guestIdB).AppendLine("};");
            db.AppendLine();
            db.AppendLine("        internal static void RunDeferredDestroy(uint id, System.IntPtr parent, System.IntPtr handle)");
            db.AppendLine("        {");
            db.AppendLine("            switch (id)");
            db.AppendLine("            {");
            db.Append(deferB);
            db.AppendLine("            }");
            db.AppendLine("        }");
            db.AppendLine("    }");
            db.AppendLine("}");
            spc.AddSource("BrovVulkGenDispatch.g.cs", SourceText.From(db.ToString(), Encoding.UTF8));

            StringBuilder wb = new StringBuilder();
            wb.AppendLine("// <auto-generated/>");
            wb.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            wb.AppendLine("{");
            wb.AppendLine("    internal static class BrovVulkWireShapes");
            wb.AppendLine("    {");
            wb.AppendLine("        internal static readonly string[] Shapes = new string[]");
            wb.AppendLine("        {");
            for (int i = 0; i < cmds.Count; i++)
                wb.AppendLine(WireShapes.TryGetValue(i, out string ws) ? "            \"" + ws + "\"," : "            null,");
            wb.AppendLine("        };");
            wb.AppendLine("    }");
            wb.AppendLine("}");
            spc.AddSource("BrovVulkWireShapes.g.cs", SourceText.From(wb.ToString(), Encoding.UTF8));

            StringBuilder rb = new StringBuilder();
            HashSet<string> outSideFinal = OutSideStructs(m, exported);
            foreach (string en in Advertised.OrderBy(x => x, StringComparer.Ordinal))
            {
                rb.Append("advertised\t").Append(en);
                if (ExtKnownGaps.TryGetValue(en, out string[] gaps))
                    rb.Append("\tnot forwarded: ").Append(string.Join(", ", gaps));
                List<string> elementChains = ElementChainGaps(m, m.Extensions[en], closure, outSideFinal);
                if (elementChains.Count > 0)
                    rb.Append("\telement chain not forwarded: ").Append(string.Join(", ", elementChains));
                rb.Append('\n');
            }
            foreach (KeyValuePair<string, string> kv in blocked.OrderBy(x => x.Key, StringComparer.Ordinal))
                rb.Append(ExtDenylist.ContainsKey(kv.Key) ? "denied\t" : "blocked\t").Append(kv.Key).Append('\t').Append(kv.Value).Append('\n');
            foreach (Command c in cmds)
            {
                if (exportedNames.Contains(c.Name) || GuestLocal.Contains(c.Name)
                    || !m.CoreCommandVersion.TryGetValue(c.Name, out double cv) || cv > MaxCoreVersion)
                    continue;
                rb.Append("core command not exported\t").Append(c.Name).Append('\t').Append(hostOk[c.Name] ? OutGap(m, c, cache) : "not forwardable").Append('\n');
            }
            foreach (string n in needed)
            {
                VkStruct s = m.Structs[n];
                if (s.IsUnion || StructIsFlat(m, n, new HashSet<string>()))
                    continue;
                Layout lay = ComputeLayout(m, n, cache);
                foreach (Member mem in s.Members)
                    if (ClassifyMember(m, s, mem, lay.Offsets, cache).Kind == "Ignore")
                        rb.Append("member not forwarded\t").Append(n).Append('.').Append(mem.Name).Append('\n');
            }
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_extensions.txt"), rb.ToString());

            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_gen.c"), cb.ToString());
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_gen_protos.h"), pb.ToString());
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "brovvulk_gen_procs.inc"), procB.ToString());
            WriteIfChanged(Path.Combine(GuestGenDir(vkXmlPath), "exports.def"), defB.ToString());
        }
    }
}
