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
    public sealed class SteamForwardGenerator : IIncrementalGenerator
    {
        // 1-15 belong to the steamclient exports the shim answers by hand.
        private const uint FirstMethodId = 16;

        public void Initialize(IncrementalGeneratorInitializationContext context)
        {
            IncrementalValuesProvider<(string Path, string Text)> Xml = context.AdditionalTextsProvider
                .Where(t => t.Path.EndsWith("steam.xml", StringComparison.OrdinalIgnoreCase))
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

        private static string GuestGenDir(string SpecPath)
        {
            string GenProj = Path.GetDirectoryName(SpecPath);
            string Repo = Path.GetDirectoryName(GenProj);
            return Path.Combine(Repo, "Brovan.Steam", "brovsteam-client", "obj", "generated");
        }

        private sealed class Param
        {
            public string Name;
            public string Kind;
            public string Wire;
            public string Struct;
            public string Count;
            public bool Bytes;
        }

        private sealed class Method
        {
            public string Name;
            public string CName;
            public string Ret;
            public string RetStruct;
            public bool RetByRef;
            public bool RetHasCtor;
            public bool Local;
            public int Slot;
            public uint Id;
            public readonly List<Param> Params = new List<Param>();
        }

        private sealed class Interface
        {
            public string Name;
            public string Version;
            public int Index;
            public readonly List<Method> Methods = new List<Method>();
        }

        private static readonly Dictionary<string, int> WireSize = new Dictionary<string, int>
        {
            ["bool"] = 4, ["i8"] = 4, ["u8"] = 4, ["i16"] = 4, ["u16"] = 4, ["i32"] = 4, ["u32"] = 4,
            ["enum"] = 4, ["f32"] = 4, ["i64"] = 8, ["u64"] = 8, ["f64"] = 8,
        };

        private static readonly Dictionary<string, int> ElemSize = new Dictionary<string, int>
        {
            ["bool"] = 1, ["i8"] = 1, ["u8"] = 1, ["i16"] = 2, ["u16"] = 2, ["i32"] = 4, ["u32"] = 4,
            ["enum"] = 4, ["f32"] = 4, ["i64"] = 8, ["u64"] = 8, ["f64"] = 8,
        };

        private static readonly Dictionary<string, string> CsScalar = new Dictionary<string, string>
        {
            ["bool"] = "byte", ["i8"] = "sbyte", ["u8"] = "byte", ["i16"] = "short", ["u16"] = "ushort",
            ["i32"] = "int", ["u32"] = "uint", ["enum"] = "int", ["f32"] = "float",
            ["i64"] = "long", ["u64"] = "ulong", ["f64"] = "double",
        };

        private static readonly Dictionary<string, string> CScalar = new Dictionary<string, string>
        {
            ["bool"] = "uint8_t", ["i8"] = "int8_t", ["u8"] = "uint8_t", ["i16"] = "int16_t", ["u16"] = "uint16_t",
            ["i32"] = "int32_t", ["u32"] = "uint32_t", ["enum"] = "int32_t", ["f32"] = "float",
            ["i64"] = "int64_t", ["u64"] = "uint64_t", ["f64"] = "double",
        };

        private static void Emit(SourceProductionContext spc, string SpecPath, string SpecText)
        {
            List<Interface> Interfaces;
            Dictionary<string, int> Structs;
            try
            {
                Parse(SpecText, out Interfaces, out Structs);
            }
            catch (Exception Ex)
            {
                spc.AddSource("BrovSteamGenDispatch.g.cs", "// steam.xml parse failed: " + Ex.Message.Replace("*/", "* /"));
                return;
            }

            spc.AddSource("BrovSteamGenDispatch.g.cs", SourceText.From(EmitHost(Interfaces, Structs), Encoding.UTF8));

            string Dir = GuestGenDir(SpecPath);
            WriteIfChanged(Path.Combine(Dir, "brovsteam_gen.h"), EmitGuestHeader(Interfaces));
            WriteIfChanged(Path.Combine(Dir, "brovsteam_gen.c"), EmitGuest(Interfaces, Structs));
            WriteIfChanged(Path.Combine(Dir, "exports.def"), EmitExports());
        }

        private static void Parse(string Text, out List<Interface> Interfaces, out Dictionary<string, int> Structs)
        {
            XDocument Doc = XDocument.Parse(Text);
            XElement Root = Doc.Root;

            Structs = new Dictionary<string, int>(StringComparer.Ordinal);
            HashSet<string> Ctors = new HashSet<string>(StringComparer.Ordinal);
            foreach (XElement S in Root.Element("types").Elements("struct"))
            {
                Structs[S.Attribute("name").Value] = int.Parse(S.Attribute("size").Value);
                if (S.Attribute("ctor")?.Value == "true")
                    Ctors.Add(S.Attribute("name").Value);
            }

            Interfaces = new List<Interface>();
            uint NextId = FirstMethodId;
            foreach (XElement I in Root.Elements("interface"))
            {
                Interface Iface = new Interface
                {
                    Name = I.Attribute("name").Value,
                    Version = I.Attribute("version").Value,
                    Index = Interfaces.Count,
                };

                foreach (XElement M in I.Elements("method"))
                {
                    Method Meth = new Method
                    {
                        Name = M.Attribute("name").Value,
                        CName = M.Attribute("cname")?.Value ?? M.Attribute("name").Value,
                        Ret = M.Attribute("ret").Value,
                        RetStruct = M.Attribute("retstruct")?.Value,
                        Local = M.Attribute("local")?.Value == "true",
                        Slot = Iface.Methods.Count,
                        Id = NextId++,
                    };

                    // The guest library is a Windows PE on every host, so its trampolines always take
                    // the MSVC shape. Only the host side, which calls the platform client, varies.
                    Meth.RetHasCtor = Meth.Ret == "struct" && Ctors.Contains(Meth.RetStruct);
                    Meth.RetByRef = Meth.Ret == "struct" && ReturnsByRef(Structs[Meth.RetStruct], Meth.RetHasCtor);

                    foreach (XElement P in M.Elements("param"))
                    {
                        Meth.Params.Add(new Param
                        {
                            Name = P.Attribute("name").Value,
                            Kind = P.Attribute("kind").Value,
                            Wire = P.Attribute("wire")?.Value,
                            Struct = P.Attribute("struct")?.Value,
                            Count = P.Attribute("count")?.Value,
                            Bytes = P.Attribute("bytes")?.Value == "true",
                        });
                    }

                    Iface.Methods.Add(Meth);
                }

                Interfaces.Add(Iface);
            }
        }

        private enum StructReturn
        {
            HiddenAfterSelf,
            HiddenBeforeSelf,
            Register,
            RegisterPair,
        }

        // MSVC x64 returns a user defined type in RAX only when it is 1, 2, 4 or 8 bytes and has no
        // constructor. Everything else comes back through a hidden pointer that follows this.
        private static StructReturn WindowsStructReturn(int Size, bool HasCtor)
        {
            return ReturnsByRef(Size, HasCtor) ? StructReturn.HiddenAfterSelf : StructReturn.Register;
        }

        // System V classifies by size, not by constructor, and the hidden pointer comes before this.
        // Every by value return in steam.xml has an integer field in each eightbyte, so a small one
        // lands in RAX and RDX rather than the SSE registers.
        private static StructReturn SystemVStructReturn(int Size)
        {
            if (Size > 16)
                return StructReturn.HiddenBeforeSelf;

            return Size > 8 ? StructReturn.RegisterPair : StructReturn.Register;
        }

        private static bool ReturnsByRef(int Size, bool HasCtor)
        {
            return HasCtor || (Size != 1 && Size != 2 && Size != 4 && Size != 8);
        }

        private static void EmitStructCall(StringBuilder B, string Pad, Method M, Dictionary<string, int> Structs,
            List<string> ParamArgs, List<string> ParamTypes, StructReturn Shape)
        {
            int Size = Structs[M.RetStruct];
            bool Hidden = Shape == StructReturn.HiddenAfterSelf || Shape == StructReturn.HiddenBeforeSelf;

            List<string> Args = new List<string>();
            List<string> Types = new List<string>();

            if (Hidden)
            {
                B.AppendLine($"{Pad}IntPtr RetBuf = S.Alloc({Size});");

                if (Shape == StructReturn.HiddenBeforeSelf)
                {
                    Args.Add("RetBuf");
                    Types.Add("IntPtr");
                    Args.Add("Self");
                    Types.Add("IntPtr");
                }
                else
                {
                    Args.Add("Self");
                    Types.Add("IntPtr");
                    Args.Add("RetBuf");
                    Types.Add("IntPtr");
                }
            }
            else
            {
                Args.Add("Self");
                Types.Add("IntPtr");
            }

            Args.AddRange(ParamArgs);
            Types.AddRange(ParamTypes);

            string RetCs = Hidden ? "IntPtr" : Shape == StructReturn.RegisterPair ? "SteamRetPair" : "ulong";
            Types.Add(RetCs);

            string FnType = "delegate* unmanaged<" + string.Join(", ", Types) + ">";
            B.AppendLine($"{Pad}{RetCs} Ret = (({FnType})(*(IntPtr**)Self)[{M.Slot}])({string.Join(", ", Args)});");
            B.AppendLine(Hidden
                ? $"{Pad}W.WriteBytesFrom(RetBuf, {Size});"
                : $"{Pad}W.WriteBytesFrom((IntPtr)(&Ret), {Size});");
        }

        private static string CRaxType(int Size)
        {
            switch (Size)
            {
                case 1: return "uint8_t";
                case 2: return "uint16_t";
                case 4: return "uint32_t";
                default: return "uint64_t";
            }
        }

        private static string Sanitize(string Value)
        {
            StringBuilder B = new StringBuilder(Value.Length);
            foreach (char C in Value)
                B.Append(char.IsLetterOrDigit(C) ? C : '_');
            return B.ToString();
        }

        private static int CountIndex(Method M, string Count)
        {
            for (int i = 0; i < M.Params.Count; i++)
            {
                if (M.Params[i].Name == Count)
                    return i;
            }
            return -1;
        }

        private static string EmitHost(List<Interface> Interfaces, Dictionary<string, int> Structs)
        {
            StringBuilder B = new StringBuilder(1 << 20);
            B.AppendLine("// <auto-generated> BrovSteam host dispatch from steam.xml. Do not edit.");
            B.AppendLine("#nullable disable");
            B.AppendLine("using System;");
            B.AppendLine();
            B.AppendLine("namespace Brovan.Core.Emulation.OS.Windows");
            B.AppendLine("{");
            B.AppendLine("    internal static unsafe class BrovSteamGenDispatch");
            B.AppendLine("    {");

            B.AppendLine("        internal static readonly string[] Versions =");
            B.AppendLine("        {");
            foreach (Interface I in Interfaces)
                B.AppendLine($"            \"{I.Version}\",");
            B.AppendLine("        };");
            B.AppendLine();

            B.AppendLine("        internal static int VersionIndex(string Name)");
            B.AppendLine("        {");
            B.AppendLine("            if (Name == null)");
            B.AppendLine("                return -1;");
            B.AppendLine("            for (int i = 0; i < Versions.Length; i++)");
            B.AppendLine("            {");
            B.AppendLine("                if (string.Equals(Versions[i], Name, StringComparison.Ordinal))");
            B.AppendLine("                    return i;");
            B.AppendLine("            }");
            B.AppendLine("            return -1;");
            B.AppendLine("        }");
            B.AppendLine();

            B.AppendLine("        internal static bool Dispatch(uint Id, GenReader R, GenBuf W, BrovSteamState S)");
            B.AppendLine("        {");
            B.AppendLine("            switch (Id)");
            B.AppendLine("            {");

            foreach (Interface I in Interfaces)
            {
                foreach (Method M in I.Methods)
                {
                    if (M.Local)
                        continue;

                    B.AppendLine($"                // {I.Version}::{M.CName} slot {M.Slot}");
                    B.AppendLine($"                case {M.Id}:");
                    B.AppendLine("                {");
                    EmitHostCase(B, I, M, Structs);
                    B.AppendLine("                }");
                }
            }

            B.AppendLine("                default:");
            B.AppendLine("                    return false;");
            B.AppendLine("            }");
            B.AppendLine("        }");
            B.AppendLine("    }");
            B.AppendLine("}");
            return B.ToString();
        }

        private static void EmitHostCase(StringBuilder B, Interface I, Method M, Dictionary<string, int> Structs)
        {
            const string Pad = "                    ";
            B.AppendLine($"{Pad}IntPtr Self = S.Lookup(R.ReadU32(), {I.Index});");

            List<string> CallArgs = new List<string>();
            List<string> CallTypes = new List<string>();

            for (int i = 0; i < M.Params.Count; i++)
            {
                Param P = M.Params[i];
                string V = "A" + i;
                switch (P.Kind)
                {
                    case "in":
                        {
                            string Cs = CsScalar[P.Wire];
                            if (P.Wire == "f64")
                                B.AppendLine($"{Pad}double {V} = BitConverter.Int64BitsToDouble((long)R.ReadU64());");
                            else if (P.Wire == "f32")
                                B.AppendLine($"{Pad}float {V} = BitConverter.Int32BitsToSingle((int)R.ReadU32());");
                            else if (WireSize[P.Wire] == 8)
                                B.AppendLine($"{Pad}{Cs} {V} = ({Cs})R.ReadU64();");
                            else
                                B.AppendLine($"{Pad}{Cs} {V} = ({Cs})R.ReadU32();");
                            CallArgs.Add(V);
                            CallTypes.Add(Cs);
                            break;
                        }
                    case "str":
                        B.AppendLine($"{Pad}byte* {V} = S.ReadString(R);");
                        CallArgs.Add(V);
                        CallTypes.Add("byte*");
                        break;
                    case "inbuf":
                        B.AppendLine($"{Pad}IntPtr {V} = S.ReadBlob(R);");
                        CallArgs.Add(V);
                        CallTypes.Add("IntPtr");
                        break;
                    case "inarray":
                        B.AppendLine($"{Pad}IntPtr {V} = S.ReadBlob(R);");
                        CallArgs.Add(V);
                        CallTypes.Add("IntPtr");
                        break;
                    case "instruct":
                        B.AppendLine($"{Pad}IntPtr {V} = S.ReadStruct(R, {Structs[P.Struct]});");
                        CallArgs.Add(V);
                        CallTypes.Add("IntPtr");
                        break;
                    case "stringarray":
                        B.AppendLine($"{Pad}IntPtr {V} = S.ReadStringArray(R);");
                        CallArgs.Add(V);
                        CallTypes.Add("IntPtr");
                        break;
                    case "out":
                        B.AppendLine($"{Pad}IntPtr {V} = S.ReadOutSlot(R, {ElemSize[P.Wire]});");
                        CallArgs.Add(V);
                        CallTypes.Add("IntPtr");
                        break;
                    case "outstruct":
                        B.AppendLine($"{Pad}IntPtr {V} = S.ReadOutSlot(R, {Structs[P.Struct]});");
                        CallArgs.Add(V);
                        CallTypes.Add("IntPtr");
                        break;
                    case "outstrptr":
                        B.AppendLine($"{Pad}IntPtr {V} = S.ReadOutSlot(R, 8);");
                        CallArgs.Add(V);
                        CallTypes.Add("IntPtr");
                        break;
                    case "outbuf":
                    case "outstr":
                    case "outarray":
                        B.AppendLine($"{Pad}IntPtr {V} = S.ReadOutBuffer(R, out uint {V}Cap);");
                        CallArgs.Add(V);
                        CallTypes.Add("IntPtr");
                        break;
                    default:
                        throw new InvalidOperationException("unhandled kind " + P.Kind);
                }
            }

            for (int i = 0; i < M.Params.Count; i++)
            {
                Param P = M.Params[i];
                if (P.Kind != "outbuf" && P.Kind != "outstr" && P.Kind != "outarray")
                    continue;

                string Bytes = P.Kind == "outarray"
                    ? $"({HostCount(M, P)}) * {(P.Bytes ? 1 : ElemSize[P.Wire])}L"
                    : $"({HostCount(M, P)})";

                B.AppendLine($"{Pad}BrovSteamState.CheckOutCapacity(A{i}, A{i}Cap, (long){Bytes});");
            }

            if (M.Ret == "struct")
            {
                StructReturn Win = WindowsStructReturn(Structs[M.RetStruct], M.RetHasCtor);
                StructReturn Sysv = SystemVStructReturn(Structs[M.RetStruct]);

                if (Win == Sysv)
                {
                    EmitStructCall(B, Pad, M, Structs, CallArgs, CallTypes, Win);
                }
                else
                {
                    B.AppendLine($"{Pad}if (Brovan.GeneralHelper.IsWindows)");
                    B.AppendLine($"{Pad}{{");
                    EmitStructCall(B, Pad + "    ", M, Structs, CallArgs, CallTypes, Win);
                    B.AppendLine($"{Pad}}}");
                    B.AppendLine($"{Pad}else");
                    B.AppendLine($"{Pad}{{");
                    EmitStructCall(B, Pad + "    ", M, Structs, CallArgs, CallTypes, Sysv);
                    B.AppendLine($"{Pad}}}");
                }
            }
            else
            {
                string RetCs = HostReturnType(M);
                List<string> Types = new List<string> { "IntPtr" };
                Types.AddRange(CallTypes);
                Types.Add(RetCs);

                List<string> Args = new List<string> { "Self" };
                Args.AddRange(CallArgs);

                string FnType = "delegate* unmanaged<" + string.Join(", ", Types) + ">";
                string Call = $"(({FnType})(*(IntPtr**)Self)[{M.Slot}])({string.Join(", ", Args)})";

                if (M.Ret == "void")
                    B.AppendLine($"{Pad}{Call};");
                else
                    B.AppendLine($"{Pad}{RetCs} Ret = {Call};");
            }

            switch (M.Ret)
            {
                case "void":
                    break;
                case "str":
                    B.AppendLine($"{Pad}S.WriteString(W, Ret);");
                    break;
                case "iface":
                    {
                        Param Version = M.Params.FirstOrDefault(p => p.Kind == "str" && p.Name.StartsWith("pchVersion", StringComparison.Ordinal));
                        if (Version == null)
                            throw new InvalidOperationException($"{I.Version}::{M.Name} returns an interface without a version parameter.");
                        int Index = M.Params.IndexOf(Version);
                        B.AppendLine($"{Pad}W.WriteU32(S.Register(Ret, A{Index}));");
                        break;
                    }
                case "struct":
                    break;
                case "f32":
                    B.AppendLine($"{Pad}W.WriteU32((uint)BitConverter.SingleToInt32Bits(Ret));");
                    break;
                case "f64":
                    B.AppendLine($"{Pad}W.WriteU64((ulong)BitConverter.DoubleToInt64Bits(Ret));");
                    break;
                default:
                    if (WireSize[M.Ret] == 8)
                        B.AppendLine($"{Pad}W.WriteU64((ulong)Ret);");
                    else
                        B.AppendLine($"{Pad}W.WriteU32((uint)Ret);");
                    break;
            }

            for (int i = 0; i < M.Params.Count; i++)
            {
                Param P = M.Params[i];
                string V = "A" + i;
                switch (P.Kind)
                {
                    case "out":
                        B.AppendLine($"{Pad}S.WriteOutSlot(W, {V}, {ElemSize[P.Wire]});");
                        break;
                    case "outstruct":
                        B.AppendLine($"{Pad}S.WriteOutSlot(W, {V}, {Structs[P.Struct]});");
                        break;
                    case "outstrptr":
                        B.AppendLine($"{Pad}S.WriteOutString(W, {V});");
                        break;
                    case "outbuf":
                    case "outstr":
                    case "outarray":
                        B.AppendLine($"{Pad}S.WriteOutBuffer(W, {V}, {V}Cap);");
                        break;
                }
            }

            B.AppendLine($"{Pad}return true;");
        }

        // A struct return picks its own shape per ABI in EmitStructCall and never reaches here.
        private static string HostReturnType(Method M)
        {
            switch (M.Ret)
            {
                case "void": return "void";
                case "str": return "IntPtr";
                case "iface": return "IntPtr";
                default: return CsScalar[M.Ret];
            }
        }

        private static string HostCount(Method M, Param P)
        {
            if (int.TryParse(P.Count, out int Fixed))
                return Fixed.ToString();

            int Index = CountIndex(M, P.Count);
            if (Index < 0)
                throw new InvalidOperationException($"{M.Name}: count {P.Count} is not a parameter.");

            return "A" + Index;
        }

        private static string EmitGuestHeader(List<Interface> Interfaces)
        {
            StringBuilder B = new StringBuilder(1 << 16);
            B.AppendLine("/* <auto-generated> BrovSteam method ids from steam.xml. Do not edit. */");
            B.AppendLine("#ifndef BROVSTEAM_GEN_H");
            B.AppendLine("#define BROVSTEAM_GEN_H");
            B.AppendLine();
            B.AppendLine($"#define BS_VERSION_COUNT {Interfaces.Count}");
            B.AppendLine();
            foreach (Interface I in Interfaces)
                B.AppendLine($"#define BS_VER_{Sanitize(I.Version)} {I.Index}");
            B.AppendLine();
            B.AppendLine("const void** bs_vtable_for(const char* version);");
            B.AppendLine("int bs_version_index(const char* version);");
            B.AppendLine();
            B.AppendLine("#endif");
            return B.ToString();
        }

        private static string EmitGuest(List<Interface> Interfaces, Dictionary<string, int> Structs)
        {
            StringBuilder B = new StringBuilder(1 << 20);
            B.AppendLine("/* <auto-generated> BrovSteam guest trampolines from steam.xml. Do not edit. */");
            B.AppendLine();

            foreach (Interface I in Interfaces)
            {
                foreach (Method M in I.Methods)
                    EmitGuestMethod(B, I, M, Structs);
            }

            foreach (Interface I in Interfaces)
            {
                B.AppendLine($"static const void* bs_vt_{Sanitize(I.Version)}[] =");
                B.AppendLine("{");
                foreach (Method M in I.Methods)
                    B.AppendLine($"    (const void*)bs_{Sanitize(I.Version)}_{M.Slot}_{Sanitize(M.CName)},");
                B.AppendLine("};");
                B.AppendLine();
            }

            B.AppendLine("static const struct { const char* name; const void** vt; } bs_versions[] =");
            B.AppendLine("{");
            foreach (Interface I in Interfaces)
                B.AppendLine($"    {{ \"{I.Version}\", bs_vt_{Sanitize(I.Version)} }},");
            B.AppendLine("};");
            B.AppendLine();

            B.AppendLine("int bs_version_index(const char* version)");
            B.AppendLine("{");
            B.AppendLine("    if (!version)");
            B.AppendLine("        return -1;");
            B.AppendLine("    for (int i = 0; i < BS_VERSION_COUNT; i++)");
            B.AppendLine("        if (strcmp(bs_versions[i].name, version) == 0)");
            B.AppendLine("            return i;");
            B.AppendLine("    return -1;");
            B.AppendLine("}");
            B.AppendLine();
            B.AppendLine("const void** bs_vtable_for(const char* version)");
            B.AppendLine("{");
            B.AppendLine("    int i = bs_version_index(version);");
            B.AppendLine("    return i < 0 ? 0 : bs_versions[i].vt;");
            B.AppendLine("}");
            return B.ToString();
        }

        private static void EmitGuestMethod(StringBuilder B, Interface I, Method M, Dictionary<string, int> Structs)
        {
            string Name = $"bs_{Sanitize(I.Version)}_{M.Slot}_{Sanitize(M.CName)}";
            List<string> Sig = new List<string> { "void* self" };
            if (M.RetByRef)
                Sig.Add("void* bsret");

            for (int i = 0; i < M.Params.Count; i++)
            {
                Param P = M.Params[i];
                Sig.Add(GuestParamType(P) + " p" + i);
            }

            string Ret = GuestReturnType(M, Structs);
            B.AppendLine($"static {Ret} {Name}({string.Join(", ", Sig)})");
            B.AppendLine("{");

            if (M.Local)
            {
                for (int i = 0; i < M.Params.Count; i++)
                    B.AppendLine($"    (void)p{i};");
                B.AppendLine("    (void)self;");
                EmitGuestFail(B, M, Structs);
                B.AppendLine("}");
                B.AppendLine();
                return;
            }

            B.AppendLine("    bs_rq_reset();");
            B.AppendLine("    bs_w_u32(((BsObj*)self)->id);");

            List<string> Need = new List<string> { "64" };

            for (int i = 0; i < M.Params.Count; i++)
            {
                Param P = M.Params[i];
                string V = "p" + i;
                switch (P.Kind)
                {
                    case "in":
                        if (WireSize[P.Wire] == 8)
                            B.AppendLine(P.Wire == "f64" ? $"    bs_w_f64({V});" : $"    bs_w_u64((uint64_t){V});");
                        else if (P.Wire == "f32")
                            B.AppendLine($"    bs_w_f32({V});");
                        else
                            B.AppendLine($"    bs_w_u32((uint32_t){V});");
                        break;
                    case "str":
                        B.AppendLine($"    bs_w_str({V});");
                        break;
                    case "inbuf":
                        B.AppendLine($"    bs_w_blob({V}, (uint32_t)({GuestCount(M, P)}));");
                        break;
                    case "inarray":
                        B.AppendLine($"    bs_w_blob({V}, (uint32_t)({GuestCount(M, P)}) * {(P.Bytes ? 1 : ElemSize[P.Wire])}u);");
                        break;
                    case "instruct":
                        B.AppendLine($"    bs_w_blob({V}, {Structs[P.Struct]}u);");
                        break;
                    case "stringarray":
                        B.AppendLine($"    bs_w_strarray((const BsStringArray*){V});");
                        break;
                    case "out":
                    case "outstruct":
                    case "outstrptr":
                        B.AppendLine($"    bs_w_u32({V} ? 1u : 0u);");
                        Need.Add(P.Kind == "outstruct" ? (Structs[P.Struct] + 8).ToString() : "16");
                        break;
                    case "outbuf":
                    case "outstr":
                        B.AppendLine($"    bs_w_out({V}, (uint32_t)({GuestCount(M, P)}));");
                        Need.Add($"(uint32_t)({GuestCount(M, P)}) + 8u");
                        break;
                    case "outarray":
                        B.AppendLine($"    bs_w_out({V}, (uint32_t)({GuestCount(M, P)}) * {(P.Bytes ? 1 : ElemSize[P.Wire])}u);");
                        Need.Add($"(uint32_t)({GuestCount(M, P)}) * {(P.Bytes ? 1 : ElemSize[P.Wire])}u + 8u");
                        break;
                }
            }

            if (M.Ret == "str")
                Need.Add("BS_RING_SLOT");
            else if (M.Ret == "struct")
                Need.Add(Structs[M.RetStruct].ToString());

            B.AppendLine($"    if (bs_call({M.Id}u, {string.Join(" + ", Need)}) != 0)");
            B.AppendLine("    {");
            EmitGuestFail(B, M, Structs);
            B.AppendLine("    }");
            B.AppendLine();

            string RetVar = null;
            switch (M.Ret)
            {
                case "void":
                    break;
                case "str":
                    B.AppendLine("    const char* bsr = bs_r_ring();");
                    RetVar = "bsr";
                    break;
                case "iface":
                    {
                        Param Version = M.Params.FirstOrDefault(p => p.Kind == "str" && p.Name.StartsWith("pchVersion", StringComparison.Ordinal));
                        int Index = M.Params.IndexOf(Version);
                        B.AppendLine($"    void* bsr = bs_wrap(bs_r_u32(), p{Index});");
                        RetVar = "bsr";
                        break;
                    }
                case "struct":
                    if (M.RetByRef)
                    {
                        B.AppendLine($"    bs_r_bytes(bsret, {Structs[M.RetStruct]}u);");
                        RetVar = "bsret";
                    }
                    else
                    {
                        B.AppendLine($"    {CRaxType(Structs[M.RetStruct])} bsr = 0;");
                        B.AppendLine($"    bs_r_bytes(&bsr, {Structs[M.RetStruct]}u);");
                        RetVar = "bsr";
                    }
                    break;
                case "f32":
                    B.AppendLine("    float bsr = bs_r_f32();");
                    RetVar = "bsr";
                    break;
                case "f64":
                    B.AppendLine("    double bsr = bs_r_f64();");
                    RetVar = "bsr";
                    break;
                default:
                    B.AppendLine(WireSize[M.Ret] == 8
                        ? $"    {CScalar[M.Ret]} bsr = ({CScalar[M.Ret]})bs_r_u64();"
                        : $"    {CScalar[M.Ret]} bsr = ({CScalar[M.Ret]})bs_r_u32();");
                    RetVar = "bsr";
                    break;
            }

            for (int i = 0; i < M.Params.Count; i++)
            {
                Param P = M.Params[i];
                string V = "p" + i;
                switch (P.Kind)
                {
                    case "out":
                        B.AppendLine($"    bs_r_out({V}, {ElemSize[P.Wire]}u);");
                        break;
                    case "outstruct":
                        B.AppendLine($"    bs_r_out({V}, {Structs[P.Struct]}u);");
                        break;
                    case "outstrptr":
                        B.AppendLine($"    bs_r_outstrptr((char**){V});");
                        break;
                    case "outbuf":
                    case "outstr":
                        B.AppendLine($"    bs_r_outbuf({V}, (uint32_t)({GuestCount(M, P)}));");
                        break;
                    case "outarray":
                        B.AppendLine($"    bs_r_outbuf({V}, (uint32_t)({GuestCount(M, P)}) * {(P.Bytes ? 1 : ElemSize[P.Wire])}u);");
                        break;
                }
            }

            if (RetVar != null)
                B.AppendLine($"    return {RetVar};");

            B.AppendLine("}");
            B.AppendLine();
        }

        private static void EmitGuestFail(StringBuilder B, Method M, Dictionary<string, int> Structs)
        {
            switch (M.Ret)
            {
                case "void":
                    B.AppendLine("        return;");
                    break;
                case "str":
                    B.AppendLine("        return \"\";");
                    break;
                case "iface":
                    B.AppendLine("        return 0;");
                    break;
                case "struct":
                    if (M.RetByRef)
                    {
                        B.AppendLine($"        memset(bsret, 0, {Structs[M.RetStruct]});");
                        B.AppendLine("        return bsret;");
                    }
                    else
                    {
                        B.AppendLine("        return 0;");
                    }
                    break;
                default:
                    B.AppendLine("        return 0;");
                    break;
            }
        }

        private static string GuestCount(Method M, Param P)
        {
            if (int.TryParse(P.Count, out int Fixed))
                return Fixed.ToString();

            int Index = CountIndex(M, P.Count);
            if (Index < 0)
                throw new InvalidOperationException($"{M.Name}: count {P.Count} is not a parameter.");

            return "p" + Index;
        }

        private static string GuestParamType(Param P)
        {
            switch (P.Kind)
            {
                case "in": return CScalar[P.Wire];
                case "str": return "const char*";
                case "inbuf": return "const void*";
                case "inarray": return "const void*";
                case "instruct": return "const void*";
                case "stringarray": return "const void*";
                case "out": return "void*";
                case "outstruct": return "void*";
                case "outstrptr": return "void*";
                case "outbuf": return "void*";
                case "outstr": return "char*";
                case "outarray": return "void*";
                default: throw new InvalidOperationException("unhandled kind " + P.Kind);
            }
        }

        private static string GuestReturnType(Method M, Dictionary<string, int> Structs)
        {
            switch (M.Ret)
            {
                case "void": return "void";
                case "str": return "const char*";
                case "iface": return "void*";
                case "struct": return M.RetByRef ? "void*" : CRaxType(Structs[M.RetStruct]);
                default: return CScalar[M.Ret];
            }
        }

        private static string EmitExports()
        {
            StringBuilder B = new StringBuilder();
            B.AppendLine("LIBRARY steamclient64");
            B.AppendLine("EXPORTS");
            foreach (string Name in new[]
            {
                "CreateInterface",
                "Steam_BGetCallback",
                "Steam_FreeLastCallback",
                "Steam_GetAPICallResult",
                "Steam_ReleaseThreadLocalMemory",
                "Steam_IsKnownInterface",
                "Steam_NotifyMissingInterface",
                "Breakpad_SteamMiniDumpInit",
                "Breakpad_SteamSetAppID",
                "Breakpad_SteamSetSteamID",
                "Breakpad_SteamWriteMiniDumpSetComment",
                "Breakpad_SteamWriteMiniDumpUsingExceptionInfoWithBuildId",
                "Breakpad_SteamSendMiniDump",
            })
            {
                B.AppendLine(Name);
            }
            return B.ToString();
        }
    }
}
