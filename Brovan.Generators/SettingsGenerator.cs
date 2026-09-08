using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Brovan.Generators
{
    [Generator(LanguageNames.CSharp)]
    public sealed class SettingsGenerator : IIncrementalGenerator
    {
        private const string AttributeName = "Brovan.Core.Settings.SettingAttribute";
        private const string SettingsTypeName = "Brovan.Core.Settings.BrovanSettings";

        private sealed class Entry
        {
            public string Key = string.Empty;
            public string Property = string.Empty;
            public string Category = string.Empty;
            public string Scope = "Program";
            public string Applies = "Boot";
            public string Platforms = "All";
            public string Help = string.Empty;
            public string Cli = string.Empty;
            public string CliShort = string.Empty;
            public string CliNegated = string.Empty;
            public string CliValueSets = string.Empty;
            public bool Repeatable;
            public double Min = double.NaN;
            public double Max = double.NaN;

            public string TypeName = string.Empty;
            public ValueShape Shape;
            public List<string> EnumMembers = new List<string>();
            public string DefaultText = string.Empty;
        }

        private enum ValueShape
        {
            Boolean,
            Integer,
            Real,
            String,
            StringArray,
            Enum,
        }

        public void Initialize(IncrementalGeneratorInitializationContext context)
        {
            IncrementalValuesProvider<INamedTypeSymbol?> Candidates =
                context.SyntaxProvider.CreateSyntaxProvider(IsCandidate, GetSymbol);

            context.RegisterSourceOutput(context.CompilationProvider.Combine(Candidates.Collect()), Execute);
        }

        private static bool IsCandidate(SyntaxNode Node, CancellationToken Token)
        {
            return Node is ClassDeclarationSyntax ClassNode && ClassNode.Members.Count > 0;
        }

        private static INamedTypeSymbol? GetSymbol(GeneratorSyntaxContext Context, CancellationToken Token)
        {
            return Context.SemanticModel.GetDeclaredSymbol(Context.Node) as INamedTypeSymbol;
        }

        private static void Execute(SourceProductionContext Context,
            (Compilation Compilation, ImmutableArray<INamedTypeSymbol?> Classes) Source)
        {
            INamedTypeSymbol? Attribute = Source.Compilation.GetTypeByMetadataName(AttributeName);
            if (Attribute == null)
                return;

            INamedTypeSymbol? Settings = null;
            for (int i = 0; i < Source.Classes.Length; i++)
            {
                INamedTypeSymbol? Candidate = Source.Classes[i];
                if (Candidate != null && Candidate.ToDisplayString() == SettingsTypeName)
                {
                    Settings = Candidate;
                    break;
                }
            }

            if (Settings == null)
                return;

            List<Entry> Entries = new List<Entry>();
            foreach (ISymbol Member in Settings.GetMembers())
            {
                if (Member is not IPropertySymbol Property)
                    continue;

                Entry? Parsed = ReadEntry(Property, Attribute);
                if (Parsed != null)
                    Entries.Add(Parsed);
            }

            if (Entries.Count == 0)
                return;

            Context.AddSource("BrovanSettings.Generated.cs", BuildSource(Entries));
        }

        private static Entry? ReadEntry(IPropertySymbol Property, INamedTypeSymbol Attribute)
        {
            AttributeData? Data = null;
            foreach (AttributeData Candidate in Property.GetAttributes())
            {
                if (SymbolEqualityComparer.Default.Equals(Candidate.AttributeClass, Attribute))
                {
                    Data = Candidate;
                    break;
                }
            }

            if (Data == null || Data.ConstructorArguments.Length < 2)
                return null;

            Entry Result = new Entry
            {
                Property = Property.Name,
                Key = Data.ConstructorArguments[0].Value as string ?? string.Empty,

                // An enum argument arrives boxed as its underlying integer, never as the enum type.
                Category = EnumMemberName(Data.ConstructorArguments[1]),
            };

            foreach (KeyValuePair<string, TypedConstant> Named in Data.NamedArguments)
            {
                switch (Named.Key)
                {
                    case "Scope": Result.Scope = EnumMemberName(Named.Value); break;
                    case "Applies": Result.Applies = EnumMemberName(Named.Value); break;
                    case "Platforms": Result.Platforms = EnumMemberName(Named.Value); break;
                    case "Help": Result.Help = Named.Value.Value as string ?? string.Empty; break;
                    case "Cli": Result.Cli = Named.Value.Value as string ?? string.Empty; break;
                    case "CliShort": Result.CliShort = Named.Value.Value as string ?? string.Empty; break;
                    case "CliNegated": Result.CliNegated = Named.Value.Value as string ?? string.Empty; break;
                    case "CliValueSets": Result.CliValueSets = Named.Value.Value as string ?? string.Empty; break;
                    case "Repeatable": Result.Repeatable = Named.Value.Value is bool Flag && Flag; break;
                    case "Min": Result.Min = ToDouble(Named.Value); break;
                    case "Max": Result.Max = ToDouble(Named.Value); break;
                }
            }

            ITypeSymbol Type = Property.Type;
            Result.TypeName = Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

            if (Type.TypeKind == TypeKind.Enum)
            {
                Result.Shape = ValueShape.Enum;
                foreach (ISymbol Member in Type.GetMembers())
                {
                    if (Member is IFieldSymbol Field && Field.HasConstantValue)
                        Result.EnumMembers.Add(Field.Name);
                }
            }
            else
            {
                switch (Type.SpecialType)
                {
                    case SpecialType.System_Boolean: Result.Shape = ValueShape.Boolean; break;
                    case SpecialType.System_Int32: Result.Shape = ValueShape.Integer; break;
                    case SpecialType.System_Single:
                    case SpecialType.System_Double: Result.Shape = ValueShape.Real; break;
                    case SpecialType.System_String: Result.Shape = ValueShape.String; break;
                    default:
                        if (Type is IArrayTypeSymbol Array && Array.ElementType.SpecialType == SpecialType.System_String)
                            Result.Shape = ValueShape.StringArray;
                        else
                            return null;
                        break;
                }
            }

            Result.DefaultText = ReadDefaultText(Property, Result);
            return Result;
        }

        // The property initialiser is the only place a default lives, so it is read from the syntax.
        private static string ReadDefaultText(IPropertySymbol Property, Entry Result)
        {
            foreach (SyntaxReference Reference in Property.DeclaringSyntaxReferences)
            {
                if (Reference.GetSyntax() is not PropertyDeclarationSyntax Declaration || Declaration.Initializer == null)
                    continue;

                string Text = Declaration.Initializer.Value.ToString();
                int Dot = Text.LastIndexOf('.');
                if (Result.Shape == ValueShape.Enum && Dot >= 0)
                    Text = Text.Substring(Dot + 1);

                if (Text == "string.Empty" || Text.StartsWith("Array.Empty", StringComparison.Ordinal))
                    return string.Empty;

                return Text.Trim('"');
            }

            return Result.Shape switch
            {
                ValueShape.Boolean => "false",
                ValueShape.Integer => "0",
                ValueShape.Real => "0",
                _ => string.Empty,
            };
        }

        private static string EnumMemberName(TypedConstant Constant)
        {
            if (Constant.Type is not INamedTypeSymbol Type || Constant.Value == null)
                return string.Empty;

            string Raw = Constant.Value.ToString() ?? string.Empty;
            foreach (ISymbol Member in Type.GetMembers())
            {
                if (Member is IFieldSymbol Field && Field.HasConstantValue &&
                    string.Equals(Field.ConstantValue?.ToString(), Raw, StringComparison.Ordinal))
                {
                    return Field.Name;
                }
            }

            return Raw;
        }

        private static double ToDouble(TypedConstant Constant)
        {
            return Constant.Value switch
            {
                double Value => Value,
                float Value => Value,
                int Value => Value,
                long Value => Value,
                _ => double.NaN,
            };
        }

        private static string BuildSource(List<Entry> Entries)
        {
            StringBuilder Builder = new StringBuilder();
            Builder.AppendLine("// <auto-generated />");
            Builder.AppendLine("#nullable enable");
            Builder.AppendLine("using System;");
            Builder.AppendLine("using System.Globalization;");
            Builder.AppendLine();
            Builder.AppendLine("namespace Brovan.Core.Settings");
            Builder.AppendLine("{");
            Builder.AppendLine("    public sealed partial class BrovanSettings");
            Builder.AppendLine("    {");

            AppendDescriptors(Builder, Entries);
            AppendApply(Builder, Entries);

            Builder.AppendLine("    }");
            Builder.AppendLine("}");
            return Builder.ToString();
        }

        private static void AppendDescriptors(StringBuilder Builder, List<Entry> Entries)
        {
            Builder.AppendLine("        public static readonly SettingDescriptor[] Descriptors = new SettingDescriptor[]");
            Builder.AppendLine("        {");

            foreach (Entry Item in Entries)
            {
                Builder.AppendLine("            new SettingDescriptor");
                Builder.AppendLine("            {");
                Builder.AppendLine($"                Key = {Quote(Item.Key)},");
                Builder.AppendLine($"                Cli = {Quote(Item.Cli)},");
                Builder.AppendLine($"                CliShort = {Quote(Item.CliShort)},");
                Builder.AppendLine($"                CliNegated = {Quote(Item.CliNegated)},");
                Builder.AppendLine($"                CliValueSets = {Quote(Item.CliValueSets)},");
                Builder.AppendLine($"                Help = {Quote(Item.Help)},");
                Builder.AppendLine($"                DefaultText = {Quote(Item.DefaultText)},");
                Builder.AppendLine($"                DefaultJson = {Quote(DefaultJson(Item))},");
                Builder.AppendLine($"                AllowedValues = {AllowedValues(Item)},");
                Builder.AppendLine($"                Category = SettingCategory.{Item.Category},");
                Builder.AppendLine($"                Scope = SettingScope.{Item.Scope},");
                Builder.AppendLine($"                Applies = SettingApplies.{Item.Applies},");
                Builder.AppendLine($"                Platforms = SettingPlatforms.{Item.Platforms},");
                Builder.AppendLine($"                IsBoolean = {(Item.Shape == ValueShape.Boolean ? "true" : "false")},");
                Builder.AppendLine($"                Repeatable = {(Item.Repeatable ? "true" : "false")},");
                Builder.AppendLine($"                Min = {Number(Item.Min)},");
                Builder.AppendLine($"                Max = {Number(Item.Max)},");
                Builder.AppendLine("            },");
            }

            Builder.AppendLine("        };");
            Builder.AppendLine();
        }

        private static string DefaultJson(Entry Item)
        {
            switch (Item.Shape)
            {
                case ValueShape.Boolean:
                    return Item.DefaultText == "true" ? "true" : "false";

                case ValueShape.Integer:
                case ValueShape.Real:
                    return Item.DefaultText.Length == 0 ? "0" : Item.DefaultText;

                case ValueShape.StringArray:
                    return "[]";

                case ValueShape.Enum:
                    return "\"" + Item.DefaultText.ToLowerInvariant() + "\"";

                default:
                    return "\"" + Item.DefaultText.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
            }
        }

        private static string AllowedValues(Entry Item)
        {
            if (Item.Shape == ValueShape.Boolean)
                return "new string[] { \"true\", \"false\" }";

            if (Item.Shape != ValueShape.Enum || Item.EnumMembers.Count == 0)
                return "Array.Empty<string>()";

            StringBuilder Builder = new StringBuilder("new string[] { ");
            for (int i = 0; i < Item.EnumMembers.Count; i++)
            {
                if (i != 0)
                    Builder.Append(", ");

                Builder.Append(Quote(Item.EnumMembers[i].ToLowerInvariant()));
            }

            Builder.Append(" }");
            return Builder.ToString();
        }

        private static void AppendApply(StringBuilder Builder, List<Entry> Entries)
        {
            Builder.AppendLine("        public bool TryApply(string key, string value, out string error)");
            Builder.AppendLine("        {");
            Builder.AppendLine("            error = string.Empty;");
            Builder.AppendLine("            switch (key)");
            Builder.AppendLine("            {");

            foreach (Entry Item in Entries)
            {
                Builder.AppendLine($"                case {Quote(Item.Key)}:");
                AppendApplyBody(Builder, Item);
            }

            Builder.AppendLine("                default:");
            Builder.AppendLine("                    error = \"unknown setting\";");
            Builder.AppendLine("                    return false;");
            Builder.AppendLine("            }");
            Builder.AppendLine("        }");
            Builder.AppendLine();
        }

        private static void AppendApplyBody(StringBuilder Builder, Entry Item)
        {
            switch (Item.Shape)
            {
                case ValueShape.Boolean:
                    Builder.AppendLine("                    if (!SettingValue.TryParseBoolean(value, out bool " + Item.Property + "Parsed))");
                    Builder.AppendLine("                    {");
                    Builder.AppendLine("                        error = \"expected true or false\";");
                    Builder.AppendLine("                        return false;");
                    Builder.AppendLine("                    }");
                    Builder.AppendLine($"                    {Item.Property} = {Item.Property}Parsed;");
                    Builder.AppendLine("                    return true;");
                    return;

                case ValueShape.Integer:
                    Builder.AppendLine("                    if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int " + Item.Property + "Parsed))");
                    Builder.AppendLine("                    {");
                    Builder.AppendLine("                        error = \"expected a whole number\";");
                    Builder.AppendLine("                        return false;");
                    Builder.AppendLine("                    }");
                    AppendRangeCheck(Builder, Item, Item.Property + "Parsed");
                    Builder.AppendLine($"                    {Item.Property} = {Item.Property}Parsed;");
                    Builder.AppendLine("                    return true;");
                    return;

                case ValueShape.Real:
                    Builder.AppendLine("                    if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out double " + Item.Property + "Parsed))");
                    Builder.AppendLine("                    {");
                    Builder.AppendLine("                        error = \"expected a number\";");
                    Builder.AppendLine("                        return false;");
                    Builder.AppendLine("                    }");
                    AppendRangeCheck(Builder, Item, Item.Property + "Parsed");
                    Builder.AppendLine($"                    {Item.Property} = ({Item.TypeName}){Item.Property}Parsed;");
                    Builder.AppendLine("                    return true;");
                    return;

                case ValueShape.String:
                    Builder.AppendLine($"                    {Item.Property} = value;");
                    Builder.AppendLine("                    return true;");
                    return;

                case ValueShape.StringArray:
                    Builder.AppendLine($"                    {Item.Property} = SettingValue.SplitList(value);");
                    Builder.AppendLine("                    return true;");
                    return;

                case ValueShape.Enum:
                    Builder.AppendLine($"                    switch (value.Trim().ToLowerInvariant())");
                    Builder.AppendLine("                    {");
                    foreach (string Member in Item.EnumMembers)
                    {
                        Builder.AppendLine($"                        case {Quote(Member.ToLowerInvariant())}:");
                        Builder.AppendLine($"                            {Item.Property} = {Item.TypeName}.{Member};");
                        Builder.AppendLine("                            return true;");
                    }

                    Builder.AppendLine("                        default:");
                    Builder.AppendLine($"                            error = \"expected one of {string.Join(", ", Lowered(Item.EnumMembers))}\";");
                    Builder.AppendLine("                            return false;");
                    Builder.AppendLine("                    }");
                    return;
            }
        }

        private static void AppendRangeCheck(StringBuilder Builder, Entry Item, string Variable)
        {
            if (!double.IsNaN(Item.Min))
            {
                Builder.AppendLine($"                    if ({Variable} < {Number(Item.Min)})");
                Builder.AppendLine("                    {");
                Builder.AppendLine($"                        error = \"below the smallest accepted value {Number(Item.Min)}\";");
                Builder.AppendLine("                        return false;");
                Builder.AppendLine("                    }");
            }

            if (!double.IsNaN(Item.Max))
            {
                Builder.AppendLine($"                    if ({Variable} > {Number(Item.Max)})");
                Builder.AppendLine("                    {");
                Builder.AppendLine($"                        error = \"above the largest accepted value {Number(Item.Max)}\";");
                Builder.AppendLine("                        return false;");
                Builder.AppendLine("                    }");
            }
        }

        private static IEnumerable<string> Lowered(List<string> Values)
        {
            foreach (string Value in Values)
                yield return Value.ToLowerInvariant();
        }

        private static string Quote(string Value)
        {
            return "\"" + Value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        }

        private static string Number(double Value)
        {
            return double.IsNaN(Value) ? "double.NaN" : Value.ToString("R", CultureInfo.InvariantCulture);
        }
    }
}
