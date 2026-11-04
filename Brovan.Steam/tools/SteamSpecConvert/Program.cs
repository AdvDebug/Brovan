using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

// Usage: SteamSpecConvert <out.xml> <header>=<Class>=<VersionString> ...
//        SteamSpecConvert --callbacks <steam_api.json> <steam.xml>
static class Program
{
    static readonly HashSet<string> Defined = new HashSet<string> { "_WIN32", "_WIN64", "WIN32", "_MSC_VER" };

    static readonly Dictionary<string, string> Scalars = new Dictionary<string, string>
    {
        ["bool"] = "bool", ["int"] = "i32", ["int32"] = "i32", ["int32_t"] = "i32", ["long"] = "i32",
        ["uint32"] = "u32", ["uint32_t"] = "u32", ["unsigned int"] = "u32", ["unsigned long"] = "u32",
        ["int64"] = "i64", ["int64_t"] = "i64", ["long long"] = "i64", ["uint64"] = "u64", ["uint64_t"] = "u64", ["unsigned long long"] = "u64",
        ["int16"] = "i16", ["short"] = "i16", ["uint16"] = "u16", ["unsigned short"] = "u16",
        ["int8"] = "i8", ["char"] = "i8", ["uint8"] = "u8", ["unsigned char"] = "u8",
        ["float"] = "f32", ["double"] = "f64", ["size_t"] = "u64",
        ["HSteamPipe"] = "i32", ["HSteamUser"] = "i32", ["AppId_t"] = "u32", ["DepotId_t"] = "u32", ["HAuthTicket"] = "u32",
        ["AccountID_t"] = "u32", ["FriendsGroupID_t"] = "i16", ["RTime32"] = "u32", ["HServerQuery"] = "i32",
        ["SNetSocket_t"] = "u32", ["SNetListenSocket_t"] = "u32", ["ScreenshotHandle"] = "u32", ["HHTTPRequest"] = "u32",
        ["HHTMLBrowser"] = "u32", ["HHTTPCookieContainer"] = "u32", ["RemotePlaySessionID_t"] = "u32", ["SteamInventoryResult_t"] = "i32",
        ["SteamItemDef_t"] = "i32", ["HSteamListenSocket"] = "u32", ["HSteamNetConnection"] = "u32", ["HSteamNetPollGroup"] = "u32",
        ["SteamNetworkingPOPID"] = "u32", ["SteamNetworkingMicroseconds"] = "i64", ["SteamAPICall_t"] = "u64", ["UGCHandle_t"] = "u64",
        ["PublishedFileId_t"] = "u64", ["PublishedFileUpdateHandle_t"] = "u64", ["UGCFileWriteStreamHandle_t"] = "u64", ["SteamLeaderboard_t"] = "u64",
        ["SteamLeaderboardEntries_t"] = "u64", ["ControllerHandle_t"] = "u64", ["ControllerActionSetHandle_t"] = "u64",
        ["ControllerDigitalActionHandle_t"] = "u64", ["ControllerAnalogActionHandle_t"] = "u64", ["InputHandle_t"] = "u64",
        ["InputActionSetHandle_t"] = "u64", ["InputDigitalActionHandle_t"] = "u64", ["InputAnalogActionHandle_t"] = "u64",
        ["ManifestId_t"] = "u64", ["SiteId_t"] = "u64", ["PartyBeaconID_t"] = "u64", ["SteamInventoryUpdateHandle_t"] = "u64",
        ["SteamItemInstanceID_t"] = "u64", ["uint64_steamid"] = "u64", ["uint64_gameid"] = "u64", ["UGCQueryHandle_t"] = "u64",
        ["UGCUpdateHandle_t"] = "u64", ["HSteamCall"] = "i32",
        ["HTTPRequestHandle"] = "u32", ["HTTPCookieContainerHandle"] = "u32", ["RemotePlayCursorID_t"] = "u32",
        ["TimelineEventHandle_t"] = "u64", ["lint64"] = "i64", ["ulint64"] = "u64",
        ["intp"] = "i64", ["uintp"] = "u64", ["intptr_t"] = "i64",
        ["HServerListRequest"] = "u64",
    };

    // By-value structs: x64 size, and whether a constructor forces a hidden-pointer return.
    static readonly Dictionary<string, (int Size, bool Ctor)> Structs = new Dictionary<string, (int, bool)>
    {
        ["CSteamID"] = (8, true), ["CGameID"] = (8, true), ["SteamIPAddress_t"] = (20, false), ["SteamNetworkingIdentity"] = (136, false),
        ["LeaderboardEntry_t"] = (32, false), ["FriendGameInfo_t"] = (24, false), ["ControllerAnalogActionData_t"] = (13, false),
        ["ControllerDigitalActionData_t"] = (2, false), ["ControllerMotionData_t"] = (40, false), ["InputAnalogActionData_t"] = (13, false),
        ["InputDigitalActionData_t"] = (2, false), ["InputMotionData_t"] = (40, false),
    };

    static readonly Dictionary<string, int> Constants = new Dictionary<string, int>
    {
        ["STEAM_CONTROLLER_MAX_COUNT"] = 16, ["STEAM_CONTROLLER_MAX_ACTIVE_LAYERS"] = 16, ["STEAM_CONTROLLER_MAX_ORIGINS"] = 8,
        ["STEAM_INPUT_MAX_COUNT"] = 16, ["STEAM_INPUT_MAX_ACTIVE_LAYERS"] = 16, ["STEAM_INPUT_MAX_ORIGINS"] = 8,
    };

    static readonly HashSet<string> FunctionPointerTypes = new HashSet<string>
    {
        "SteamAPIWarningMessageHook_t", "SteamAPI_CheckCallbackRegistered_t", "SteamAPI_PostAPIResultInProcess_t", "SteamAPI_ManualDispatch_t",
    };

    // HTML callbacks carry host pointers.
    static readonly HashSet<string> GuestOnlyInterfaces = new HashSet<string> { "ISteamHTMLSurface" };

    // steamclient uses a heap pointer as HServerListRequest.
    static readonly HashSet<string> HostPointerHandles = new HashSet<string> { "HServerListRequest" };

    // Parameters the header does not annotate and whose type alone misleads.
    static readonly Dictionary<string, (string Kind, string Count)> Overrides = new Dictionary<string, (string, string)>
    {
        ["ISteamUser::RequestEncryptedAppTicket.pDataToInclude"] = ("inbuf", "cbDataToInclude"),
        ["ISteamApps::GetInstalledDepots.pvecDepots"] = ("outarray", "cMaxDepots"),
        ["ISteamUGC::GetSubscribedItems.pvecPublishedFileID"] = ("outarray", "cMaxEntries"),
        ["ISteamUGC::GetQueryUGCChildren.pvecPublishedFileID"] = ("outarray", "cMaxEntries"),
        ["ISteamUGC::GetQueryUGCContentDescriptors.pvecDescriptors"] = ("outarray", "cMaxEntries"),
        ["ISteamUGC::GetUserContentDescriptorPreferences.pvecDescriptors"] = ("outarray", "cMaxEntries"),
        ["ISteamUGC::CreateQueryUGCDetailsRequest.pvecPublishedFileID"] = ("inarray", "unNumPublishedFileIDs"),
        ["ISteamUGC::StartPlaytimeTracking.pvecPublishedFileID"] = ("inarray", "unNumPublishedFileIDs"),
        ["ISteamUGC::StopPlaytimeTracking.pvecPublishedFileID"] = ("inarray", "unNumPublishedFileIDs"),
        ["ISteamUGC::SetItemsDisabledLocally.pvecPublishedFileIDs"] = ("inarray", "unNumPublishedFileIDs"),
        ["ISteamUGC::SetSubscriptionsLoadOrder.pvecPublishedFileIDs"] = ("inarray", "unNumPublishedFileIDs"),
        ["ISteamNetworkingUtils::GetPOPList.list"] = ("outarray", "nListSz"),
        ["ISteamUserStats::GetDownloadedLeaderboardEntry.pDetails"] = ("outarray", "cDetailsMax"),

        ["ISteamInput::SetInputActionManifestFilePath.pchInputActionManifestAbsolutePath"] = ("readpath", null),
        ["ISteamScreenshots::AddScreenshotToLibrary.pchFilename"] = ("readpath", null),
        ["ISteamScreenshots::AddScreenshotToLibrary.pchThumbnailFilename"] = ("readpath", null),
        ["ISteamScreenshots::AddVRScreenshotToLibrary.pchFilename"] = ("readpath", null),
        ["ISteamScreenshots::AddVRScreenshotToLibrary.pchVRFilename"] = ("readpath", null),
        ["ISteamUGC::SetItemContent.pszContentFolder"] = ("readpath", null),
        ["ISteamUGC::SetItemPreview.pszPreviewFile"] = ("readpath", null),
        ["ISteamUGC::AddItemPreviewFile.pszPreviewFile"] = ("readpath", null),
        ["ISteamUGC::UpdateItemPreviewFile.pszPreviewFile"] = ("readpath", null),
        ["ISteamUGC::BInitWorkshopForGameServer.pszFolder"] = ("writepath", null),
        ["ISteamUtils::CheckFileSignature.szFileName"] = ("readpath", null),
        ["ISteamRemoteStorage::UGCDownloadToLocation.pchLocation"] = ("writepath", null),
    };

    sealed class Param
    {
        public string Name, Type, Kind, Wire, Struct, Count;
        public bool Bytes;
    }

    sealed class Method
    {
        public string Name, CName, Ret, RetStruct;
        public bool Local;
        public readonly List<Param> Params = new List<Param>();
    }

    static int Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "--callbacks")
            return WriteCallbacks(args[1], args[2]);

        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: SteamSpecConvert <out.xml> <header>=<Class>=<Version> ...");
            return 2;
        }

        XElement root = new XElement("steam");
        XElement types = new XElement("types");
        foreach (KeyValuePair<string, (int Size, bool Ctor)> s in Structs)
        {
            XElement e = new XElement("struct", new XAttribute("name", s.Key), new XAttribute("size", s.Value.Size));
            if (s.Value.Ctor)
                e.Add(new XAttribute("ctor", "true"));
            types.Add(e);
        }
        root.Add(types);

        int errors = 0;
        for (int i = 1; i < args.Length; i++)
        {
            string[] parts = args[i].Split('=');
            if (parts.Length != 3)
            {
                Console.Error.WriteLine("bad argument: " + args[i]);
                return 2;
            }

            string headerText = File.ReadAllText(parts[0]);
            CollectEnumsFrom(Path.GetDirectoryName(Path.GetFullPath(parts[0])));
            List<Method> methods = Parse(headerText, parts[1], ref errors);
            XElement iface = new XElement("interface", new XAttribute("name", parts[1]), new XAttribute("version", parts[2]));
            foreach (Method m in methods)
            {
                XElement me = new XElement("method", new XAttribute("name", m.Name));
                if (m.CName != m.Name)
                    me.Add(new XAttribute("cname", m.CName));
                me.Add(new XAttribute("ret", m.Ret));
                if (m.RetStruct != null)
                    me.Add(new XAttribute("retstruct", m.RetStruct));
                if (m.Local)
                    me.Add(new XAttribute("local", "true"));
                foreach (Param p in m.Params)
                {
                    XElement pe = new XElement("param", new XAttribute("name", p.Name), new XAttribute("type", p.Type), new XAttribute("kind", p.Kind));
                    if (p.Wire != null)
                        pe.Add(new XAttribute("wire", p.Wire));
                    if (p.Struct != null)
                        pe.Add(new XAttribute("struct", p.Struct));
                    if (p.Count != null)
                        pe.Add(new XAttribute("count", p.Count));
                    if (p.Bytes)
                        pe.Add(new XAttribute("bytes", "true"));
                    me.Add(pe);
                }
                iface.Add(me);
            }
            root.Add(iface);
            Console.Error.WriteLine($"{parts[2]}: {methods.Count} methods");
        }

        if (errors != 0)
        {
            Console.Error.WriteLine($"{errors} unresolved declarations, output not written");
            return 1;
        }

        XElement callbacks = File.Exists(args[0]) ? XDocument.Load(args[0]).Root?.Element("callbacks") : null;
        if (callbacks != null)
            types.AddAfterSelf(callbacks);

        new XDocument(root).Save(args[0]);
        return 0;
    }

    sealed class CallbackTypes
    {
        public readonly Dictionary<string, string> Typedefs = new Dictionary<string, string>();
        public readonly HashSet<string> Enums = new HashSet<string>();
        public readonly Dictionary<string, List<string>> Structs = new Dictionary<string, List<string>>();
    }

    // Valve packs callbacks at 8 bytes on Windows and 4 elsewhere.
    static int WriteCallbacks(string jsonPath, string xmlPath)
    {
        using JsonDocument json = JsonDocument.Parse(File.ReadAllText(jsonPath));
        JsonElement api = json.RootElement;
        CallbackTypes t = new CallbackTypes();
        foreach (JsonElement e in api.GetProperty("typedefs").EnumerateArray())
            t.Typedefs[e.GetProperty("typedef").GetString()] = e.GetProperty("type").GetString();
        foreach (JsonElement e in api.GetProperty("enums").EnumerateArray())
            t.Enums.Add(e.GetProperty("enumname").GetString());
        foreach (JsonElement e in api.GetProperty("structs").EnumerateArray())
            t.Structs[e.GetProperty("struct").GetString()] = FieldTypes(e);

        // The JSON flattens unions and omits pack(1).
        foreach (KeyValuePair<string, (int Size, bool Ctor)> known in Structs)
        {
            if (t.Structs.TryGetValue(known.Key, out List<string> fields)
                && (!TryFieldsLayout(t, fields, 8, out int size, out _, null, 0) || size != known.Value.Size))
            {
                Console.Error.WriteLine($"  {known.Key}: json layout does not match the header, callbacks using it are skipped");
                t.Structs.Remove(known.Key);
            }
        }

        XElement callbacks = new XElement("callbacks");
        int skipped = 0;
        foreach (JsonElement cb in api.GetProperty("callback_structs").EnumerateArray())
        {
            string name = cb.GetProperty("struct").GetString();
            List<string> fields = FieldTypes(cb);
            if (!TryPadding(t, fields, 8, out int size8, out string pad8) || !TryPadding(t, fields, 4, out int size4, out string pad4))
            {
                Console.Error.WriteLine($"  {name}: layout unknown, skipped");
                skipped++;
                continue;
            }
            if (pad8.Length == 0 && pad4.Length == 0)
                continue;

            callbacks.Add(new XElement("callback",
                new XAttribute("id", cb.GetProperty("callback_id").GetInt32()), new XAttribute("name", name),
                new XAttribute("size8", size8), new XAttribute("pad8", pad8),
                new XAttribute("size4", size4), new XAttribute("pad4", pad4)));
        }

        XDocument doc = XDocument.Load(xmlPath);
        doc.Root.Element("callbacks")?.Remove();
        doc.Root.Element("types").AddAfterSelf(callbacks);
        doc.Save(xmlPath);
        Console.Error.WriteLine($"{callbacks.Elements().Count()} callbacks with padding, {skipped} skipped");
        return 0;
    }

    static List<string> FieldTypes(JsonElement s)
    {
        List<string> fields = new List<string>();
        foreach (JsonElement f in s.GetProperty("fields").EnumerateArray())
            fields.Add(f.GetProperty("fieldtype").GetString());
        return fields;
    }

    static bool TryPadding(CallbackTypes t, List<string> fields, int pack, out int size, out string padding)
    {
        padding = null;
        if (!TryFieldsLayout(t, fields, pack, out size, out _, null, 0))
            return false;

        bool[] covered = new bool[size];
        TryFieldsLayout(t, fields, pack, out _, out _, covered, 0);
        List<string> ranges = new List<string>();
        for (int i = 0; i < size; i++)
        {
            if (covered[i])
                continue;
            int start = i;
            while (i < size && !covered[i])
                i++;
            ranges.Add($"{start}:{i - start}");
        }
        padding = string.Join(",", ranges);
        return true;
    }

    static bool TryFieldsLayout(CallbackTypes t, List<string> fields, int pack, out int size, out int align, bool[] covered, int at)
    {
        int offset = 0;
        align = 1;
        size = 0;
        foreach (string f in fields)
        {
            if (!TryTypeLayout(t, f, pack, out int fieldSize, out int fieldAlign, null, 0))
                return false;
            offset = (offset + fieldAlign - 1) / fieldAlign * fieldAlign;
            if (covered != null)
                TryTypeLayout(t, f, pack, out _, out _, covered, at + offset);
            offset += fieldSize;
            align = Math.Max(align, fieldAlign);
        }
        size = Math.Max(1, (offset + align - 1) / align * align);
        return true;
    }

    static bool TryTypeLayout(CallbackTypes t, string type, int pack, out int size, out int align, bool[] covered, int at)
    {
        size = 0;
        align = 0;
        type = type.Trim();
        Match array = Regex.Match(type, @"^(.+?)\s*\[(\d+)\]$");
        if (array.Success)
        {
            int count = int.Parse(array.Groups[2].Value);
            if (!TryTypeLayout(t, array.Groups[1].Value, pack, out int element, out align, null, 0))
                return false;
            for (int k = 0; covered != null && k < count; k++)
                TryTypeLayout(t, array.Groups[1].Value, pack, out _, out _, covered, at + k * element);
            size = element * count;
            return true;
        }
        if (t.Structs.TryGetValue(type, out List<string> fields))
            return TryFieldsLayout(t, fields, pack, out size, out align, covered, at);
        if (t.Typedefs.TryGetValue(type, out string target))
            return TryTypeLayout(t, target, pack, out size, out align, covered, at);

        size = type.EndsWith("*") ? 8 : t.Enums.Contains(type) ? 4 : type switch
        {
            "bool" or "char" or "signed char" or "unsigned char" or "uint8" or "int8" => 1,
            "short" or "unsigned short" or "uint16" or "int16" => 2,
            "int" or "unsigned int" or "uint32" or "int32" or "float" => 4,
            "long long" or "unsigned long long" or "uint64" or "int64" or "double" or "CSteamID" or "CGameID" => 8,
            _ => 0,
        };
        if (size == 0)
            return false;
        align = Math.Min(size, pack);
        for (int i = at; covered != null && i < at + size && i < covered.Length; i++)
            covered[i] = true;
        return true;
    }

    static List<Method> Parse(string text, string className, ref int errors)
    {
        text = Regex.Replace(text, @"/\*.*?\*/", " ", RegexOptions.Singleline);
        string[] lines = text.Split('\n');
        Stack<(bool Active, bool ParentActive, bool Taken)> cond = new Stack<(bool, bool, bool)>();
        bool active = true;
        StringBuilder body = null;
        int depth = 0;
        List<Method> methods = new List<Method>();

        foreach (string raw in lines)
        {
            string line = raw;
            int c = line.IndexOf("//", StringComparison.Ordinal);
            if (c >= 0)
                line = line.Substring(0, c);
            string t = line.Trim();

            if (t.StartsWith("#"))
            {
                string d = t.Substring(1).Trim();
                if (d.StartsWith("ifdef"))
                {
                    bool v = Defined.Contains(d.Substring(5).Trim());
                    cond.Push((active && v, active, v));
                    active = active && v;
                }
                else if (d.StartsWith("ifndef"))
                {
                    bool v = !Defined.Contains(d.Substring(6).Trim());
                    cond.Push((active && v, active, v));
                    active = active && v;
                }
                else if (d.StartsWith("if"))
                {
                    bool v = Eval(d.Substring(2));
                    cond.Push((active && v, active, v));
                    active = active && v;
                }
                else if (d.StartsWith("elif"))
                {
                    (bool Active, bool ParentActive, bool Taken) top = cond.Pop();
                    bool v = !top.Taken && Eval(d.Substring(4));
                    cond.Push((top.ParentActive && v, top.ParentActive, top.Taken || v));
                    active = top.ParentActive && v;
                }
                else if (d.StartsWith("else"))
                {
                    (bool Active, bool ParentActive, bool Taken) top = cond.Pop();
                    bool v = !top.Taken;
                    cond.Push((top.ParentActive && v, top.ParentActive, true));
                    active = top.ParentActive && v;
                }
                else if (d.StartsWith("endif"))
                {
                    (bool Active, bool ParentActive, bool Taken) top = cond.Pop();
                    active = top.ParentActive;
                }
                continue;
            }

            if (!active)
                continue;

            if (body == null)
            {
                if (Regex.IsMatch(t, @"^class\s+" + Regex.Escape(className) + @"\s*(\{)?\s*$"))
                    body = new StringBuilder();
                continue;
            }

            // A nested enum ends with "};" too.
            if (t == "};" && depth == 0)
                break;

            if (t == "public:")
                continue;

            // A nested brace has to stay for StripInlineBodies.
            if (t == "{" && body.Length == 0)
                continue;

            depth += t.Count(c => c == '{') - t.Count(c => c == '}');
            body.Append(line).Append('\n');
        }

        if (body == null)
            throw new Exception("class " + className + " not found");

        string b = body.ToString();
        b = Regex.Replace(b, @"STEAM_PRIVATE_API\s*\(\s*((?:virtual[^;]*;\s*)+)\)", "$1");
        b = Regex.Replace(b, @"STEAM_(CALL_RESULT|CALL_BACK|METHOD_DESC|IGNOREATTR)\s*\([^)]*\)", " ");

        b = StripInlineBodies(b);

        string pendingFlat = null;
        foreach (string stmtRaw in b.Split(';'))
        {
            string stmt = Regex.Replace(stmtRaw, @"\s+", " ").Trim();
            if (stmt.Length == 0)
                continue;

            Match flat = Regex.Match(stmt, @"STEAM_FLAT_NAME\s*\(\s*(\w+)\s*\)");
            if (flat.Success)
            {
                pendingFlat = flat.Groups[1].Value;
                stmt = stmt.Remove(flat.Index, flat.Length).Trim();
            }

            if (!stmt.StartsWith("virtual"))
            {
                if (stmt.Length != 0)
                    Console.Error.WriteLine($"  skipped in {className}: {stmt}");
                continue;
            }

            // A virtual destructor owns a vtable slot.
            Match dtor = Regex.Match(stmt, @"^virtual\s+~\w+\s*\(\s*\)");
            if (dtor.Success)
            {
                methods.Add(new Method { Name = "Destructor", CName = "Destructor", Ret = "void", Local = true });
                continue;
            }

            Match m = Regex.Match(stmt, @"^virtual\s+(?<ret>.+?)\s*\b(?<name>\w+)\s*\((?<params>.*)\)\s*(const\s*)?=\s*0\s*$");
            if (!m.Success)
            {
                Console.Error.WriteLine($"  UNPARSED in {className}: {stmt}");
                errors++;
                continue;
            }

            Method method = new Method { Name = m.Groups["name"].Value, CName = pendingFlat ?? m.Groups["name"].Value };
            pendingFlat = null;
            ClassifyReturn(method, NormalizeType(m.Groups["ret"].Value));

            foreach (string p in SplitParams(m.Groups["params"].Value))
                ParseParam(method, p, className, ref errors);

            ResolveCounts(method, className, ref errors);

            if (GuestOnlyInterfaces.Contains(className))
                method.Local = true;

            if (method.Params.Any(p => HostPointerHandles.Contains(p.Type)))
            {
                Console.Error.WriteLine($"  local (host pointer handle) in {className}::{method.Name}");
                method.Local = true;
            }

            // An interface return is registered under the version string the caller passes.
            if (method.Ret == "iface" && !HasVersionParam(method))
            {
                Console.Error.WriteLine($"  local (interface return with no version) in {className}::{method.Name}");
                method.Local = true;
            }

            methods.Add(method);
        }

        return methods;
    }

    static bool Eval(string expr)
    {
        expr = Regex.Replace(expr, @"defined\s*\(\s*(\w+)\s*\)", mm => Defined.Contains(mm.Groups[1].Value) ? "1" : "0");
        expr = Regex.Replace(expr, @"defined\s+(\w+)", mm => Defined.Contains(mm.Groups[1].Value) ? "1" : "0");
        expr = Regex.Replace(expr, @"\b[A-Za-z_]\w*\b", mm => Defined.Contains(mm.Value) ? "1" : "0");
        expr = expr.Replace(" ", "");
        int pos = 0;
        return Or(expr, ref pos);
    }

    static bool Or(string e, ref int p)
    {
        bool v = And(e, ref p);
        while (p + 1 < e.Length && e[p] == '|' && e[p + 1] == '|')
        {
            p += 2;
            v |= And(e, ref p);
        }
        return v;
    }

    static bool And(string e, ref int p)
    {
        bool v = Unary(e, ref p);
        while (p + 1 < e.Length && e[p] == '&' && e[p + 1] == '&')
        {
            p += 2;
            v &= Unary(e, ref p);
        }
        return v;
    }

    static bool Unary(string e, ref int p)
    {
        if (p < e.Length && e[p] == '!')
        {
            p++;
            return !Unary(e, ref p);
        }
        if (p < e.Length && e[p] == '(')
        {
            p++;
            bool v = Or(e, ref p);
            if (p < e.Length && e[p] == ')')
                p++;
            return v;
        }
        int start = p;
        while (p < e.Length && char.IsDigit(e[p]))
            p++;
        return start != p && e.Substring(start, p - start) != "0";
    }

    static List<string> SplitParams(string s)
    {
        List<string> result = new List<string>();
        int depth = 0, start = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '(') depth++;
            else if (s[i] == ')') depth--;
            else if (s[i] == ',' && depth == 0)
            {
                result.Add(s.Substring(start, i - start));
                start = i + 1;
            }
        }
        string last = s.Substring(start).Trim();
        if (last.Length != 0 && last != "void")
            result.Add(last);
        return result;
    }

    static string NormalizeType(string t)
    {
        t = Regex.Replace(t, @"\s+", " ").Trim();
        t = Regex.Replace(t, @"\s*\*\s*", "*");
        t = Regex.Replace(t, @"\s*&\s*", "&");
        t = t.Replace("struct ", "").Replace("class ", "");
        return t;
    }

    static void ClassifyReturn(Method m, string ret)
    {
        if (ret == "void")
            m.Ret = "void";
        else if (ret == "const char*" || ret == "char*")
            m.Ret = "str";
        else if (ret == "void*" || Regex.IsMatch(ret, @"^ISteam\w+\*$"))
            m.Ret = "iface";
        else if (Scalars.TryGetValue(ret, out string w))
            m.Ret = w;
        else if (Structs.ContainsKey(ret))
        {
            m.Ret = "struct";
            m.RetStruct = ret;
        }
        else if (IsEnum(ret))
            m.Ret = "enum";
        else if (ret.EndsWith("*", StringComparison.Ordinal))
        {
            // An address in the client's own heap, which the guest cannot read.
            Console.Error.WriteLine($"  local (unmarshallable return {ret}) in {m.Name}");
            m.Ret = "iface";
            m.Local = true;
        }
        else
            throw new Exception("unknown return type " + ret + " in " + m.Name);
    }

    // A declaration with an inline body carries no ';', so the closing brace becomes one.
    static string StripInlineBodies(string text)
    {
        StringBuilder Out = new StringBuilder(text.Length);
        int Depth = 0;

        foreach (char C in text)
        {
            if (C == '{')
            {
                Depth++;
            }
            else if (C == '}')
            {
                if (Depth > 0 && --Depth == 0)
                    Out.Append(';');
            }
            else if (Depth == 0)
            {
                Out.Append(C);
            }
        }

        return Out.ToString();
    }

    static bool HasVersionParam(Method m)
    {
        foreach (Param p in m.Params)
        {
            if (p.Kind == "str" && p.Name.IndexOf("version", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }

        return false;
    }

    // Not every Steam enum is named EFoo.
    static readonly HashSet<string> KnownEnums = new HashSet<string>();

    static readonly HashSet<string> ScannedDirectories = new HashSet<string>();

    static void CollectEnumsFrom(string directory)
    {
        if (directory == null || !ScannedDirectories.Add(directory))
            return;

        foreach (string file in Directory.GetFiles(directory, "*.h"))
            CollectEnums(File.ReadAllText(file));
    }

    static void CollectEnums(string text)
    {
        foreach (Match m in Regex.Matches(text, @"\benum\s+(?:class\s+)?(\w+)"))
            KnownEnums.Add(m.Groups[1].Value);
    }

    static bool IsEnum(string t) => Regex.IsMatch(t, @"^E[A-Z]\w*$") || KnownEnums.Contains(t);

    static void ParseParam(Method m, string raw, string className, ref int errors)
    {
        string p = raw.Trim();
        string hint = null, hintArg = null;
        Match a = Regex.Match(p, @"STEAM_(OUT_STRUCT|OUT_STRING_COUNT|OUT_STRING|OUT_ARRAY_COUNT|OUT_ARRAY_CALL|ARRAY_COUNT_D|ARRAY_COUNT|OUT_BUFFER_COUNT)\s*\(([^)]*)\)");
        if (a.Success)
        {
            hint = a.Groups[1].Value;
            hintArg = a.Groups[2].Value.Split(',')[0].Trim();
            p = p.Remove(a.Index, a.Length).Trim();
        }

        int eq = p.IndexOf('=');
        if (eq >= 0)
            p = p.Substring(0, eq).Trim();

        if (p.Contains("(*)") || FunctionPointerTypes.Contains(p.Split(' ')[0]))
        {
            m.Local = true;
            m.Params.Add(new Param { Name = "hook" + m.Params.Count, Type = NormalizeType(p), Kind = "in", Wire = "u64" });
            return;
        }

        Match nm = Regex.Match(p, @"^(?<type>.+?)\s*(?<name>\w+)$");
        if (!nm.Success)
        {
            Console.Error.WriteLine($"  UNPARSED param in {className}::{m.Name}: {raw}");
            errors++;
            return;
        }

        Param param = new Param { Name = nm.Groups["name"].Value, Type = NormalizeType(nm.Groups["type"].Value) };
        string type = param.Type;
        bool isConst = type.StartsWith("const ");
        string bare = isConst ? type.Substring(6) : type;
        string elem = bare.TrimEnd('*', '&');

        if (Overrides.TryGetValue($"{className}::{m.Name}.{param.Name}", out (string Kind, string Count) ov))
        {
            param.Kind = ov.Kind;
            param.Count = ov.Count;
        }
        else if (hint == "OUT_STRUCT")
            param.Kind = "outstruct";
        else if (hint == "OUT_STRING")
            param.Kind = "outstrptr";
        else if (hint == "OUT_STRING_COUNT")
        {
            param.Kind = "outstr";
            param.Count = hintArg;
        }
        else if (hint == "OUT_ARRAY_COUNT" || hint == "OUT_ARRAY_CALL")
        {
            param.Kind = "outarray";
            param.Count = hintArg;
        }
        else if (hint == "ARRAY_COUNT" || hint == "ARRAY_COUNT_D")
        {
            param.Kind = "inarray";
            param.Count = hintArg;
        }
        else if (hint == "OUT_BUFFER_COUNT")
        {
            param.Kind = "outbuf";
            param.Count = hintArg;
        }
        else if (type == "const char*")
            param.Kind = "str";
        else if (type == "char*")
            param.Kind = "outstr";
        else if (type == "char**")
            param.Kind = "outstrptr";
        else if (bare == "void*" || bare == "uint8*" || bare == "unsigned char*")
            param.Kind = isConst ? "inbuf" : "outbuf";
        else if (bare == "SteamParamStringArray_t*")
            param.Kind = "stringarray";
        else if (type.EndsWith("&"))
            param.Kind = isConst ? "instruct" : "outstruct";
        else if (type.EndsWith("*"))
            param.Kind = isConst ? "instruct" : (Structs.ContainsKey(elem) && elem != "CSteamID" && elem != "CGameID" ? "outstruct" : "out");
        else
            param.Kind = "in";

        if (param.Kind == "instruct" || param.Kind == "outstruct")
        {
            if (Structs.ContainsKey(elem))
                param.Struct = elem;
            else if (Scalars.ContainsKey(elem) || IsEnum(elem))
                param.Kind = isConst ? "inarray" : "out";
            else
            {
                // Dropping the parameter would put the wire format out of step with the ABI.
                Console.Error.WriteLine($"  local (unrepresentable {elem}) in {className}::{m.Name}.{param.Name}");
                m.Local = true;
                param.Kind = "in";
                param.Wire = "u64";
            }
        }

        if (param.Kind == "in" || param.Kind == "out" || param.Kind == "inarray" || param.Kind == "outarray")
        {
            string e = param.Kind == "in" ? type : elem;
            if (Scalars.TryGetValue(e, out string w))
                param.Wire = w;
            else if (IsEnum(e))
                param.Wire = "enum";
            else if (e == "CSteamID" || e == "CGameID")
                param.Wire = "u64";
            else
            {
                Console.Error.WriteLine($"  local (unrepresentable {e}) in {className}::{m.Name}.{param.Name}");
                m.Local = true;
                param.Kind = "in";
                param.Wire = "u64";
            }
        }

        m.Params.Add(param);
    }

    static void ResolveCounts(Method m, string className, ref int errors)
    {
        for (int i = 0; i < m.Params.Count; i++)
        {
            Param p = m.Params[i];
            bool needsCount = p.Kind == "outstr" || p.Kind == "inbuf" || p.Kind == "outbuf" || p.Kind == "inarray" || p.Kind == "outarray";
            if (!needsCount)
                continue;

            if (p.Count == null)
            {
                for (int j = i + 1; j < m.Params.Count; j++)
                {
                    if (m.Params[j].Kind == "in" && (m.Params[j].Wire == "i32" || m.Params[j].Wire == "u32" || m.Params[j].Wire == "u16"))
                    {
                        p.Count = m.Params[j].Name;
                        break;
                    }
                }
            }

            if (p.Count == null)
            {
                Console.Error.WriteLine($"  local (no count) in {className}::{m.Name}.{p.Name}");
                m.Local = true;
                p.Kind = "in";
                p.Wire = "u64";
                continue;
            }

            if (Constants.TryGetValue(p.Count, out int fixedCount))
                p.Count = fixedCount.ToString();
            else if (!int.TryParse(p.Count, out _) && m.Params.All(q => q.Name != p.Count))
            {
                Console.Error.WriteLine($"  count {p.Count} is not a parameter of {className}::{m.Name}");
                errors++;
            }

            if ((p.Kind == "inarray" || p.Kind == "outarray") && p.Count.StartsWith("cub"))
                p.Bytes = true;
        }
    }
}
