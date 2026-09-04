using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

// Usage: SteamSpecConvert <out.xml> <header>=<Class>=<VersionString> ...
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

    // Parameters the header does not annotate and whose type alone misleads.
    static readonly Dictionary<string, (string Kind, string Count)> Overrides = new Dictionary<string, (string, string)>
    {
        ["ISteamUser::RequestEncryptedAppTicket.pDataToInclude"] = ("inbuf", "cbDataToInclude"),
        ["ISteamApps::GetInstalledDepots.pvecDepots"] = ("outarray", "cMaxDepots"),
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

            List<Method> methods = Parse(File.ReadAllText(parts[0]), parts[1], ref errors);
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

        new XDocument(root).Save(args[0]);
        return 0;
    }

    static List<Method> Parse(string text, string className, ref int errors)
    {
        text = Regex.Replace(text, @"/\*.*?\*/", " ", RegexOptions.Singleline);
        string[] lines = text.Split('\n');
        Stack<(bool Active, bool ParentActive, bool Taken)> cond = new Stack<(bool, bool, bool)>();
        bool active = true;
        StringBuilder body = null;
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

            if (t == "};")
                break;

            if (t == "{" || t == "public:")
                continue;

            body.Append(line).Append('\n');
        }

        if (body == null)
            throw new Exception("class " + className + " not found");

        string b = body.ToString();
        b = Regex.Replace(b, @"STEAM_PRIVATE_API\s*\(\s*(virtual[^;]*;)\s*\)", "$1");
        b = Regex.Replace(b, @"STEAM_(CALL_RESULT|CALL_BACK|METHOD_DESC|IGNOREATTR)\s*\([^)]*\)", " ");

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
        else
            throw new Exception("unknown return type " + ret + " in " + m.Name);
    }

    static bool IsEnum(string t) => Regex.IsMatch(t, @"^E[A-Z]\w*$");

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
                Console.Error.WriteLine($"  unknown struct {elem} in {className}::{m.Name}.{param.Name}");
                errors++;
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
                Console.Error.WriteLine($"  unknown type {e} in {className}::{m.Name}.{param.Name}");
                errors++;
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
                Console.Error.WriteLine($"  no count for {className}::{m.Name}.{p.Name}");
                errors++;
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
