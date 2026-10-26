using Brovan.WinFacts.Readers;
using Brovan.WinFacts.Sources;
using Iced.Intel;

namespace Brovan.WinFacts
{
    internal static class Program
    {
        private const string Usage =
            "usage:\n" +
            "  Brovan.WinFacts update --unicorn <library> [--root <repository>] [--group <name>] [--versions <build.revision,...>]\n" +
            "                         [--store <symbol store>] [--cache <directory>] [--report <file>] [--write subset]\n" +
            "  Brovan.WinFacts groups\n" +
            "  Brovan.WinFacts dis <image> <pdb> <symbol prefix>\n" +
            "  Brovan.WinFacts probe <image> <pdb> [symbol prefix ...]";

        private static int Main(string[] Args)
        {
            switch (Args.Length == 0 ? null : Args[0])
            {
                case "update":
                    return Mitigations.RunWithoutControlFlowGuard() ?? Update(Args);
                case "groups":
                    foreach (Rules.FactGroup Group in Rules.FactGroup.All)
                        Console.WriteLine($"{Group.Name} {Group.OutputPath}");

                    return 0;
                case "dis" when Args.Length == 4:
                    return Disassemble(Args);
                case "probe" when Args.Length >= 3:
                    return Probe(Args);
                default:
                    Console.Error.WriteLine(Usage);
                    return 2;
            }
        }

        private static int Update(string[] Args)
        {
            Dictionary<string, string> Options = new(StringComparer.Ordinal);
            for (int i = 1; i < Args.Length; i += 2)
            {
                if (!Args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= Args.Length)
                {
                    Console.Error.WriteLine(Usage);
                    return 2;
                }

                Options[Args[i].Substring(2)] = Args[i + 1];
            }

            if (!Options.TryGetValue("unicorn", out string Unicorn))
            {
                Console.Error.WriteLine(Usage);
                return 2;
            }

            Machine.UseLibrary(Path.GetFullPath(Unicorn));
            HashSet<string> Versions = Options.TryGetValue("versions", out string List) ? new HashSet<string>(List.Split(','), StringComparer.Ordinal) : null;
            bool Write = Options.GetValueOrDefault("write") == "subset";
            return Engine.Update(new UpdateOptions(Options.GetValueOrDefault("group"), Options.GetValueOrDefault("root", "."),
                Options.GetValueOrDefault("store"), Options.GetValueOrDefault("cache"), Options.GetValueOrDefault("report"), Versions, Write));
        }

        private static int Probe(string[] Args)
        {
            PeImage Image = PeImage.Open(new LocalFile(Args[1]));
            PdbPublics Publics = PdbPublics.Open(new LocalFile(Args[2]), Image);
            Console.WriteLine($"image base 0x{Image.ImageBase:X} size 0x{Image.SizeOfImage:X} pdb {Image.PdbName} {Image.PdbGuid:N}{Image.PdbAge:X} version {Image.FileVersion()}");
            Console.WriteLine($"publics {Publics.Count}");
            for (int i = 3; i < Args.Length; i++)
            {
                foreach ((string Name, uint Rva) in Publics.NamesStartingWith(Args[i]).OrderBy(Symbol => Symbol.Rva))
                    Console.WriteLine($"0x{Rva:X} {Name}");
            }

            return 0;
        }

        private static int Disassemble(string[] Args)
        {
            PeImage Image = PeImage.Open(new LocalFile(Args[1]));
            PdbPublics Publics = PdbPublics.Open(new LocalFile(Args[2]), Image);
            Function Function = Function.Decode(Image, Publics, Publics.Find(Args[3]));
            IntelFormatter Formatter = new(new PublicsResolver(Image, Publics));
            StringOutput Output = new();
            HashSet<ulong> CaseTargets = new();
            foreach (JumpTable Table in Function.Tables)
            {
                Console.WriteLine($"table at 0x{Table.Jump - Image.ImageBase:X} on {Table.Case}: {Table.Targets.Count} entries");
                for (int i = 0; i < Table.Targets.Count; i++)
                    Console.WriteLine($"  case {i} -> 0x{Table.Targets[i] - Image.ImageBase:X}");

                CaseTargets.UnionWith(Table.Targets);
            }

            foreach (Instruction Instruction in Function.Instructions)
            {
                Formatter.Format(Instruction, Output);
                Console.WriteLine($"{(CaseTargets.Contains(Instruction.IP) ? "*" : " ")}{Instruction.IP - Image.ImageBase:X8}  {Output.ToStringAndReset()}");
            }

            return 0;
        }

        private sealed class PublicsResolver : ISymbolResolver
        {
            private readonly PeImage Image;
            private readonly PdbPublics Publics;

            internal PublicsResolver(PeImage Image, PdbPublics Publics)
            {
                this.Image = Image;
                this.Publics = Publics;
            }

            public bool TryGetSymbol(in Instruction Instruction, int Operand, int InstructionOperand, ulong Address, int AddressSize, out SymbolResult Symbol)
            {
                string Name = Address >= Image.ImageBase && Address - Image.ImageBase < Image.SizeOfImage ? Publics.NameAt((uint)(Address - Image.ImageBase)) : null;
                Symbol = Name != null ? new SymbolResult(Address, Name) : default;
                return Name != null;
            }
        }
    }
}
