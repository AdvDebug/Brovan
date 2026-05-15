using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;
using System.Reflection.PortableExecutable;
using System.Globalization;
using Iced.Intel;
using System.Runtime.CompilerServices;
using Brovan.Core;

namespace Brovan.Analysis
{
    /// <summary>
    /// Simple representation of a decoded x86 instruction.
    /// </summary>
    public struct X86Instruction
    {
        public ulong Address;
        public string Mnemonic;
        public string Operand;
        public ReadOnlyMemory<byte> Bytes { get; set; }
        public uint BytesLength;
    }

    /// <summary>
    /// Architecture mode for disassembly.
    /// </summary>
    public enum X86DisassembleMode
    {
        Bit32,
        Bit64
    }

    /// <summary>
    /// Speed mode for disassembling.
    /// </summary>
    public enum X86DisassemblerFormat
    {
        NasmFormat,
        FastFormat
    }

    public class BinaryAnalyzer
    {
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void AnalyzeBinary(AnalyzationSettings Settings, BinaryFile Binary)
        {
            if (Binary == null || Binary.Functions == null || Binary.Functions.Length == 0)
                return;

            if (Binary.PE.DotNetStatus != DotNetStatus.None)
                return;

            if (Binary.FileFormat != BinaryFormat.PE && Binary.FileFormat != BinaryFormat.ELF)
                return;

            byte[] BinaryData = Binary.GetBinaryData().ToArray();
            if (BinaryData.Length == 0)
                return;

            bool IsPE = Binary.FileFormat == BinaryFormat.PE;
            ulong ImageBase = IsPE ? Binary.PE.ImageBase : 0;

            int FunctionCount = Binary.Functions.Length;
            bool UseParallel = Settings.EnableParallelDisassembly && FunctionCount >= Settings.ParallelMinFunctionCount;

            FunctionResolver Resolver = new FunctionResolver(Binary, ImageBase);

            IcedX86Disassembler Disassembler = new IcedX86Disassembler(Binary, X86DisassemblerFormat.FastFormat);

            if (!UseParallel)
            {
                IcedX86Disassembler.DisassembleContext Context = new IcedX86Disassembler.DisassembleContext();
                for (int i = 0; i < FunctionCount; i++)
                    AnalyzeOneFunction(Binary, Disassembler, Context, Resolver, BinaryData, ImageBase, i);
                return;
            }

            int Cpu = Environment.ProcessorCount;
            int MaxDegree = Cpu <= 1 ? 1 : Cpu - 1;

            ParallelOptions Options = new ParallelOptions { MaxDegreeOfParallelism = MaxDegree };

            ThreadLocal<IcedX86Disassembler.DisassembleContext> ContextLocal =
                new ThreadLocal<IcedX86Disassembler.DisassembleContext>(() => new IcedX86Disassembler.DisassembleContext());

            Parallel.For(0, FunctionCount, Options, i =>
            {
                AnalyzeOneFunction(Binary, Disassembler, ContextLocal.Value!, Resolver, BinaryData, ImageBase, i);
            });

            ContextLocal.Dispose();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AnalyzeOneFunction(BinaryFile Binary, IcedX86Disassembler Disassembler, IcedX86Disassembler.DisassembleContext Context, FunctionResolver Resolver, byte[] BinaryData, ulong ImageBase, int Index)
        {
            ref var Function = ref Binary.Functions[Index];

            ulong StartOffset = Function.Offset;
            ulong EndOffset = Function.EndOffset;

            if (EndOffset <= StartOffset)
                return;

            ulong Size = EndOffset - StartOffset;
            ulong DataLength = (ulong)BinaryData.Length;

            if (StartOffset >= DataLength)
                return;

            if (Size > DataLength - StartOffset)
                return;

            if (StartOffset > int.MaxValue || Size > int.MaxValue)
                return;

            int FunctionStart = (int)StartOffset;
            int FunctionSize = (int)Size;

            ulong RuntimeAddress = ImageBase + StartOffset;

            Disassembler.DisassembleFunction(BinaryData, FunctionStart, FunctionSize, RuntimeAddress, Binary, false, Resolver, Context, out X86Instruction[] Instructions, out string DisasmText, out ulong DecodedSize);

            if (Instructions == null || Instructions.Length == 0)
                return;

            Function.Code = Instructions;
            Function.DisassembledCode = DisasmText;
            Function.EndAddress = Function.Address + DecodedSize;
        }

        /// <summary>
        /// Calculate the entropy for the specified data.
        /// </summary>
        /// <param name="Data">Data to calculate it's entropy.</param>
        /// <returns>return the data's entropy.</returns>
        public static double CalculateEntropy(ReadOnlySpan<byte> Data)
        {
            if (Data.Length == 0)
                return 0.0;

            Span<int> Counts = stackalloc int[256];
            Counts.Clear(); // 'Counts' is not guaranteed to be zero-initialized

            for (int i = 0; i < Data.Length; i++)
                Counts[Data[i]]++;

            double Entropy = 0.0;
            int DataLength = Data.Length;

            for (int i = 0; i < 256; i++)
            {
                int Count = Counts[i];
                if (Count == 0)
                    continue;

                double p = (double)Count / DataLength;
                Entropy -= p * Math.Log2(p);
            }

            return Entropy;
        }

        /// <summary>
        /// Check whether the binary is likely packed or not (entropy based).
        /// </summary>
        /// <param name="Binary">Binary to check.</param>
        /// <returns>returns true if packed, otherwise false.</returns>
        public static bool IsBinaryPacked(BinaryFile Binary)
        {
            ReadOnlySpan<byte> Data = Binary.GetBinaryData();

            if (Binary.FileFormat == BinaryFormat.PE)
            {
                foreach (PortableBinarySection Section in Binary.PE.Sections)
                {
                    if (!IsCodeSection(Section.Characteristics))
                        continue;

                    if (Section.RawSize <= 0 || Section.RawSize > int.MaxValue)
                        continue;

                    long RawOffsetLong = Section.RawOffset;
                    if (RawOffsetLong < 0 || RawOffsetLong >= Data.Length)
                        continue;

                    int RawOffset = (int)RawOffsetLong;
                    int RawSize = (int)Section.RawSize;

                    int MaxReadable = Data.Length - RawOffset;
                    int BytesToRead = RawSize;
                    if (BytesToRead > MaxReadable)
                        BytesToRead = MaxReadable;

                    if (BytesToRead == 0)
                        continue;

                    ReadOnlySpan<byte> SectionSpan = Data.Slice(RawOffset, BytesToRead);
                    if (CalculateEntropy(SectionSpan) > 6.6)
                        return true;
                }

                return false;
            }

            if (Binary.FileFormat == BinaryFormat.ELF)
            {
                foreach (ElfBinarySection Section in Binary.ELF.Sections)
                {
                    if (!IsCodeSection(Section.Characteristics))
                        continue;

                    if (Section.RawSize <= 0 || Section.RawSize > int.MaxValue)
                        continue;

                    long RawOffsetLong = Section.RawOffset;
                    if (RawOffsetLong < 0 || RawOffsetLong >= Data.Length)
                        continue;

                    int RawOffset = (int)RawOffsetLong;
                    int RawSize = (int)Section.RawSize;

                    int MaxReadable = Data.Length - RawOffset;
                    int BytesToRead = RawSize;
                    if (BytesToRead > MaxReadable)
                        BytesToRead = MaxReadable;

                    if (BytesToRead == 0)
                        continue;

                    ReadOnlySpan<byte> SectionSpan = Data.Slice(RawOffset, BytesToRead);
                    if (CalculateEntropy(SectionSpan) > 6.6)
                        return true;
                }

                return false;
            }

            return false;
        }

        /// <summary>
        /// Section search options.
        /// </summary>
        public enum SearchSection
        {
            /// <summary>
            /// Search for the pattern anywhere in the file.
            /// </summary>
            All = 0,

            /// <summary>
            /// Search for the pattern inside the code (.text for example) section.
            /// </summary>
            CodeSection = 1,

            /// <summary>
            /// Search for the pattern inside the data section.
            /// </summary>
            DataSection = 2
        }

        /// <summary>
        /// Searches for all occurrences of a byte pattern within a binary array.
        /// </summary>
        /// <param name="Binary">The source binary array to search within.</param>
        /// <param name="Pattern">The byte pattern to search for.</param>
        /// <returns>A List of integers containing all indexes where the pattern was found.</returns>
        public static List<int> IndexOf(byte[] Binary, byte[] Pattern)
        {
            if (Binary == null)
                throw new ArgumentNullException(nameof(Binary));

            if (Pattern == null)
                throw new ArgumentNullException(nameof(Pattern));

            var Matches = new List<int>();

            if (Pattern.Length == 0 || Binary.Length < Pattern.Length)
                return Matches;

            ReadOnlySpan<byte> BinarySpan = Binary;
            ReadOnlySpan<byte> PatternSpan = Pattern;

            byte FirstByte = PatternSpan[0];
            int SearchStart = 0;

            while (SearchStart <= BinarySpan.Length - PatternSpan.Length)
            {
                int RelativeIndex = BinarySpan.Slice(SearchStart).IndexOf(FirstByte);
                if (RelativeIndex < 0)
                    break;

                int Index = SearchStart + RelativeIndex;

                if (Index + PatternSpan.Length <= BinarySpan.Length && BinarySpan.Slice(Index, PatternSpan.Length).SequenceEqual(PatternSpan))
                {
                    Matches.Add(Index);
                    SearchStart = Index + 1;
                    continue;
                }

                SearchStart = Index + 1;
            }

            return Matches;
        }

        /// <summary>
        /// Check if the PE Section is executable.
        /// </summary>
        /// <param name="Characteristics">Characteristics of the Section.</param>
        /// <returns>returns true if the section is a code section, otherwise false.</returns>
        public static bool IsCodeSection(SectionCharacteristics Characteristics)
        {
            return (Characteristics & SectionCharacteristics.ContainsCode) != 0 || ((Characteristics & SectionCharacteristics.MemExecute) != 0 && (Characteristics & SectionCharacteristics.MemRead) != 0);
        }

        /// <summary>
        /// Check if the PE Section is the data section.
        /// </summary>
        /// <param name="Characteristics">Characteristics of the Section.</param>
        /// <returns>returns true if the section is a data section, otherwise false.</returns>
        public static bool IsDataSection(SectionCharacteristics Characteristics)
        {
            return (Characteristics & SectionCharacteristics.ContainsInitializedData) != 0 || (Characteristics & SectionCharacteristics.ContainsUninitializedData) != 0;
        }

        /// <summary>
        /// Checks if the ELF Section is an executable section.
        /// </summary>
        /// <param name="Characteristics">Characteristics of the Section.</param>
        /// <returns>returns true if the section is a code section, otherwise false.</returns>
        public static bool IsCodeSection(ElfSectionCharacteristics Characteristics)
        {
            return (Characteristics & ElfSectionCharacteristics.ExecInstr) != 0 && (Characteristics & ElfSectionCharacteristics.Alloc) != 0;
        }

        /// <summary>
        /// Checks if an ELF Section is a data section.
        /// </summary>
        /// <param name="Characteristics">Characteristics of the Section.</param>
        /// <returns>returns true if the section is a data section, otherwise false.</returns>
        public static bool IsDataSection(ElfSectionCharacteristics Characteristics)
        {
            return (Characteristics & ElfSectionCharacteristics.Alloc) != 0 && (Characteristics & ElfSectionCharacteristics.ExecInstr) == 0;
        }

        /// <summary>
        /// Search for a pattern in a PE Section.
        /// </summary>
        /// <param name="Data">The Binary Data.</param>
        /// <param name="Pattern">The Pattern to search for.</param>
        /// <param name="Section">The Section to search in.</param>
        /// <param name="Results">The Result in which the Binary Search will be stored.</param>
        /// <param name="ImageBase">The Image Base of the Binary.</param>
        public static void SearchInSection(byte[] Data, byte[] Pattern, PortableBinarySection Section, List<BinarySearch> Results, ulong ImageBase)
        {
            byte[] SectionData = new byte[Section.RawSize];
            Array.Copy(Data, Section.RawOffset, SectionData, 0, Section.RawSize);

            List<int> Indexes = IndexOf(SectionData, Pattern);
            foreach (int Index in Indexes)
            {
                Results.Add(new BinarySearch
                {
                    Match = Pattern,
                    Address = (ulong)(ImageBase + Section.VirtualAddress + (uint)Index),
                    Offset = Section.RawOffset + (uint)Index
                });
            }
        }

        /// <summary>
        /// Search for a pattern in an ELF Section.
        /// </summary>
        /// <param name="Data">The ELF Binary Data.</param>
        /// <param name="Pattern">The Pattern to search for.</param>
        /// <param name="Section">The ELF Section to search in.</param>
        /// <param name="Results">The Result in which the Binary Search will be stored.</param>
        public static void SearchInSection(byte[] Data, byte[] Pattern, ElfBinarySection Section, List<BinarySearch> Results)
        {
            byte[] SectionData = new byte[Section.RawSize];
            Array.Copy(Data, Section.RawOffset, SectionData, 0, Section.RawSize);

            List<int> Indexes = IndexOf(SectionData, Pattern);
            foreach (int Index in Indexes)
            {
                Results.Add(new BinarySearch
                {
                    Match = Pattern,
                    Address = Section.VirtualAddress + (uint)Index,
                    Offset = Section.RawOffset + (uint)Index
                });
            }
        }

        /// <summary>
        /// Search for a pattern in the Binary file.
        /// </summary>
        /// <param name="Binary">The Binary Data.</param>
        /// <param name="Search">The Search option.</param>
        /// <param name="Pattern">The Pattern to search for.</param>
        /// <returns>returns BinarySearch struct array containing all the patterns with their information.</returns>
        public static BinarySearch[] SearchPatterns(BinaryFile Binary, SearchSection Search, byte[] Pattern)
        {
            List<BinarySearch> Results = new List<BinarySearch>();
            byte[] Data = Binary.GetBinaryData().ToArray();

            if (Search == SearchSection.All)
            {
                List<int> Indexes = IndexOf(Data, Pattern);
                foreach (int Index in Indexes)
                {
                    Results.Add(new BinarySearch
                    {
                        Match = Pattern,
                        Address = (uint)Index,
                        Offset = (uint)Index
                    });
                }
                return Results.ToArray();
            }

            if (Binary.FileFormat == BinaryFormat.PE)
            {
                if (Search.HasFlag(SearchSection.CodeSection))
                {
                    var CodeSections = Binary.PE.Sections.Where(s => IsCodeSection(s.Characteristics));
                    foreach (PortableBinarySection Section in CodeSections)
                    {
                        SearchInSection(Data, Pattern, Section, Results, Binary.PE.ImageBase);
                    }
                }

                if (Search.HasFlag(SearchSection.DataSection))
                {
                    var DataSections = Binary.PE.Sections.Where(s => IsDataSection(s.Characteristics));
                    foreach (PortableBinarySection Section in DataSections)
                    {
                        SearchInSection(Data, Pattern, Section, Results, Binary.PE.ImageBase);
                    }
                }
            }
            else if (Binary.FileFormat == BinaryFormat.ELF)
            {
                if (Search.HasFlag(SearchSection.CodeSection))
                {
                    var CodeSections = Binary.ELF.Sections.Where(s => IsCodeSection(s.Characteristics));
                    foreach (ElfBinarySection Section in CodeSections)
                    {
                        SearchInSection(Data, Pattern, Section, Results);
                    }
                }

                if (Search.HasFlag(SearchSection.DataSection))
                {
                    var DataSections = Binary.ELF.Sections.Where(s => IsDataSection(s.Characteristics));
                    foreach (ElfBinarySection Section in DataSections)
                    {
                        SearchInSection(Data, Pattern, Section, Results);
                    }
                }
            }

            return Results.ToArray();
        }

        /// <summary>
        /// Get an address from a jmp/call.
        /// </summary>
        /// <param name="Instruction">Instruction to extract the address from.</param>
        /// <param name="Binary">The binary that contains the instruction.</param>
        /// <returns>returns the target address, if fails it returns 0.</returns>
        public static ulong GetAddressFromOperand(X86Instruction Instruction, BinaryFile Binary)
        {
            if (Instruction.Bytes.Length == 0 || Binary == null)
                return 0;

            ReadOnlySpan<byte> InstructionBytes = Instruction.Bytes.Span;
            if (InstructionBytes.Length == 0)
                return 0;

            ulong TargetAddress = 0;

            if (InstructionBytes.Length >= 6 && InstructionBytes[0] == 0xFF && (InstructionBytes[1] == 0x15 || InstructionBytes[1] == 0x25))
            {
                uint Displacement = BitConverter.ToUInt32(InstructionBytes.Slice(2, 4));

                if (Binary.Architecture == BinaryArchitecture.x64)
                {
                    ulong NextInstructionAddress = Instruction.Address + (ulong)InstructionBytes.Length;
                    TargetAddress = NextInstructionAddress + Displacement;
                }
                else
                {
                    TargetAddress = Displacement;
                }

                return TargetAddress;
            }

            if (InstructionBytes.Length >= 5 && (InstructionBytes[0] == 0xE8 || InstructionBytes[0] == 0xE9))
            {
                int RelativeOffset = BitConverter.ToInt32(InstructionBytes.Slice(1, 4));
                ulong NextInstructionAddress = Instruction.Address + (ulong)InstructionBytes.Length;
                TargetAddress = (ulong)((long)NextInstructionAddress + RelativeOffset);
                return TargetAddress;
            }

            if (string.IsNullOrEmpty(Instruction.Operand))
                return 0;

            string CleanedOperand = Instruction.Operand.Trim();

            if (CleanedOperand.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                CleanedOperand = CleanedOperand.Substring(0, CleanedOperand.Length - 1);

            if (CleanedOperand.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                CleanedOperand = CleanedOperand.Substring(2);

            CleanedOperand = CleanedOperand.TrimStart('0');
            if (CleanedOperand.Length == 0)
                CleanedOperand = "0";

            if (!ulong.TryParse(CleanedOperand, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong ParsedAddress))
                return 0;

            TargetAddress = ParsedAddress;

            if (Binary.FileFormat == BinaryFormat.PE && !Instruction.Operand.Contains("ptr", StringComparison.OrdinalIgnoreCase))
            {
                ulong NextInstructionAddress = Instruction.Address + (ulong)InstructionBytes.Length;
                TargetAddress = NextInstructionAddress + ParsedAddress;

                if (!Instruction.Operand.TrimStart().StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    TargetAddress = Binary.PE.ImageBase + TargetAddress;
            }

            return TargetAddress;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong GetAddressFast(ulong Address, uint Length, ReadOnlySpan<byte> Bytes, BinaryFile Binary)
        {
            if (Bytes.Length >= 5 && (Bytes[0] == 0xE8 || Bytes[0] == 0xE9))
            {
                int Rel = BitConverter.ToInt32(Bytes.Slice(1, 4));
                ulong Next = Address + Length;
                return (ulong)((long)Next + Rel);
            }

            if (Bytes.Length >= 6 && Bytes[0] == 0xFF && (Bytes[1] == 0x15 || Bytes[1] == 0x25))
            {
                uint Disp = BitConverter.ToUInt32(Bytes.Slice(2, 4));
                if (Binary.Architecture == BinaryArchitecture.x64)
                {
                    ulong Next = Address + Length;
                    return Next + Disp;
                }
                return Disp;
            }

            return 0;
        }

        /// <summary>
        /// Get a function name from an operand (call/jmp).
        /// </summary>
        /// <param name="Instruction">Instruction to extract the function from.</param>
        /// <param name="Binary">The binary that contains the instruction.</param>
        /// <returns>The resolved function name, an unresolved placeholder, or "fun_unknown" on failure.</returns>
        public static string GetFunctionFromOperand(X86Instruction Instruction, BinaryFile Binary, bool Emu)
        {
            if (Binary == null && Emu)
                return Instruction.Operand;
            else if (Binary == null)
                return "fun_unknown";

            ulong TargetAddress = GetAddressFromOperand(Instruction, Binary);

            // Try to resolve the function name
            if (TargetAddress != 0)
            {
                Dictionary<ulong, string> FunctionMap = Binary.GetFunctionsMap(true, true, true);
                if (FunctionMap != null)
                {
                    // Try with current address
                    if (FunctionMap.TryGetValue(TargetAddress, out string FunctionName))
                    {
                        return FunctionName;
                    }

                    // Try without ImageBase for PE files
                    if (Binary.FileFormat == BinaryFormat.PE)
                    {
                        uint AddressWithoutBase = (uint)(TargetAddress - Binary.PE.ImageBase);
                        if (FunctionMap.TryGetValue(AddressWithoutBase, out FunctionName))
                        {
                            return FunctionName;
                        }
                        else
                        {
                            if (Emu)
                                return Instruction.Operand;
                            return $"fun_{TargetAddress:X}h (unresolved)";
                        }
                    }
                    if (Emu)
                        return Instruction.Operand;
                    else
                        return $"fun_{TargetAddress:X}h";
                }
            }

            if (Emu)
                return Instruction.Operand;
            else
                return "fun_unknown";
        }
    }

    public sealed class FunctionResolver
    {
        private readonly Dictionary<ulong, string> NameByAddress;

        public FunctionResolver(BinaryFile Binary, ulong ImageBase)
        {
            NameByAddress = new Dictionary<ulong, string>(Binary.Functions.Length);

            for (int i = 0; i < Binary.Functions.Length; i++)
            {
                var Fn = Binary.Functions[i];

                ulong Address = Fn.Address;
                if (Address == 0)
                    Address = ImageBase + Fn.Offset;

                if (!NameByAddress.ContainsKey(Address))
                    NameByAddress.Add(Address, Fn.FunctionName ?? string.Empty);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool TryResolveName(ulong Address, out string Name) => NameByAddress.TryGetValue(Address, out Name);
    }

    public sealed class IcedX86Disassembler : IDisposable
    {
        private readonly int Bitness;
        private readonly X86DisassemblerFormat Format;

        private readonly ThreadLocal<DisassembleContext> ContextLocal;

        private static readonly string[] MnemonicLower = BuildMnemonicLower();

        public IcedX86Disassembler(X86DisassembleMode Mode, X86DisassemblerFormat Speed = X86DisassemblerFormat.NasmFormat)
        {
            Bitness = Mode == X86DisassembleMode.Bit64 ? 64 : 32;
            this.Format = Speed;
            ContextLocal = new ThreadLocal<DisassembleContext>(() => new DisassembleContext());
        }

        public IcedX86Disassembler(BinaryFile Binary, X86DisassemblerFormat Speed = X86DisassemblerFormat.NasmFormat)
        {
            Bitness = Binary.Architecture == BinaryArchitecture.x64 ? 64 : 32;
            this.Format = Speed;
            ContextLocal = new ThreadLocal<DisassembleContext>(() => new DisassembleContext());
        }

        public void Dispose()
        {
            ContextLocal.Dispose();
        }

        private DisassembleContext GetContext() => ContextLocal.Value!;

        public sealed class DisassembleContext
        {
            public readonly FastFormatter FastFormatter;
            public readonly FastStringOutput FastOutput;

            public readonly NasmFormatter NasmFormatter;
            public readonly StringOutput NasmOutput;

            public List<X86Instruction> Instructions;
            public StringBuilder Text;
            public char[] TempChars;

            public DisassembleContext()
            {
                FastFormatter = new FastFormatter();
                FastOutput = new FastStringOutput(160);

                NasmFormatter = new NasmFormatter();
                NasmOutput = new StringOutput();

                Instructions = new List<X86Instruction>(4096);
                Text = new StringBuilder(8192);
                TempChars = new char[256];
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void ResetLists()
            {
                Instructions.Clear();

                if (Instructions.Capacity > 65536)
                    Instructions = new List<X86Instruction>(4096);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void ResetText()
            {
                Text.Clear();

                if (Text.Capacity > 1_000_000)
                    Text = new StringBuilder(8192);

                if (TempChars.Length > 1_000_000)
                    TempChars = new char[256];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public X86Instruction[] DisassembleBinary(byte[] Code, ulong BaseOffset = 0, BinaryFile Binary = null, int MaxInstructions = 0, bool Emulator = false)
        {
            if (Code == null || Code.Length == 0)
                throw new NullReferenceException("The code byte array cannot be null or empty.");

            DisassembleContext Context = GetContext();
            Context.ResetLists();

            ByteArrayCodeReader Reader = new ByteArrayCodeReader(Code);
            Iced.Intel.Decoder Decoder = Iced.Intel.Decoder.Create(Bitness, Reader);
            Decoder.IP = BaseOffset;

            int Count = 0;

            if (Format == X86DisassemblerFormat.FastFormat)
            {
                while (Reader.CanReadByte)
                {
                    if (MaxInstructions > 0 && Count >= MaxInstructions)
                        break;

                    ulong Address = Decoder.IP;
                    Instruction Instr = Decoder.Decode();
                    if (Instr.IsInvalid)
                        break;

                    int Length = Instr.Length;
                    if (Length <= 0)
                        break;

                    int Offset = (int)(Address - BaseOffset);
                    if ((uint)(Offset + Length) > (uint)Code.Length)
                        break;

                    ReadOnlyMemory<byte> Bytes = new ReadOnlyMemory<byte>(Code, Offset, Length);

                    string Mnemonic = MnemonicLower[(int)Instr.Mnemonic];
                    string Operands = string.Empty;

                    if (Instr.OpCount != 0)
                        Operands = ExtractOperandsFast(Context, Instr);

                    if (Binary != null && (Mnemonic == "call" || Mnemonic == "jmp"))
                    {
                        Operands = BinaryAnalyzer.GetFunctionFromOperand(new X86Instruction
                        {
                            Address = Address,
                            Mnemonic = Mnemonic,
                            Operand = Operands,
                            Bytes = Bytes,
                            BytesLength = (uint)Length
                        }, Binary, Emulator);
                    }

                    Context.Instructions.Add(new X86Instruction
                    {
                        Address = Address,
                        Mnemonic = Mnemonic,
                        Operand = Operands,
                        Bytes = Bytes,
                        BytesLength = (uint)Length
                    });

                    Count++;
                }

                return Context.Instructions.Count == 0 ? Array.Empty<X86Instruction>() : Context.Instructions.ToArray();
            }

            while (Reader.CanReadByte)
            {
                if (MaxInstructions > 0 && Count >= MaxInstructions)
                    break;

                ulong Address = Decoder.IP;
                Instruction Instr = Decoder.Decode();
                if (Instr.IsInvalid)
                    break;

                int Length = Instr.Length;
                if (Length <= 0)
                    break;

                int Offset = (int)(Address - BaseOffset);
                if ((uint)(Offset + Length) > (uint)Code.Length)
                    break;

                ReadOnlyMemory<byte> Bytes = new ReadOnlyMemory<byte>(Code, Offset, Length);

                Context.NasmOutput.Reset();
                Context.NasmFormatter.Format(Instr, Context.NasmOutput);

                string Mnemonic = MnemonicLower[(int)Instr.Mnemonic];
                string Operands = ExtractOperandsFromFormatted(Context.NasmOutput.ToString());

                if (Binary != null && (Mnemonic == "call" || Mnemonic == "jmp"))
                {
                    Operands = BinaryAnalyzer.GetFunctionFromOperand(new X86Instruction
                    {
                        Address = Address,
                        Mnemonic = Mnemonic,
                        Operand = Operands,
                        Bytes = Bytes,
                        BytesLength = (uint)Length
                    }, Binary, Emulator);
                }

                Context.Instructions.Add(new X86Instruction
                {
                    Address = Address,
                    Mnemonic = Mnemonic,
                    Operand = Operands,
                    Bytes = Bytes,
                    BytesLength = (uint)Length
                });

                Count++;
            }

            return Context.Instructions.Count == 0 ? Array.Empty<X86Instruction>() : Context.Instructions.ToArray();
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public X86Instruction[] Disassemble(byte[] Code, ulong BaseOffset = 0, int MaxInstructions = 0)
        {
            return DisassembleBinary(Code, BaseOffset, null, MaxInstructions, false);
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public string DisassembleToString(byte[] Code, ulong BaseOffset = 0, BinaryFile Binary = null, int MaxInstructions = 0, bool ShowOffset = true)
        {
            if (Code == null || Code.Length == 0)
                throw new NullReferenceException("The code byte array cannot be null or empty.");

            DisassembleContext Context = GetContext();
            Context.ResetText();

            ByteArrayCodeReader Reader = new ByteArrayCodeReader(Code);
            Iced.Intel.Decoder Decoder = Iced.Intel.Decoder.Create(Bitness, Reader);
            Decoder.IP = BaseOffset;

            int Count = 0;

            if (Format == X86DisassemblerFormat.FastFormat)
            {
                while (Reader.CanReadByte)
                {
                    if (MaxInstructions > 0 && Count >= MaxInstructions)
                        break;

                    ulong Address = Decoder.IP;
                    Instruction Instr = Decoder.Decode();
                    if (Instr.IsInvalid)
                        break;

                    if (ShowOffset)
                    {
                        Context.Text.Append("0x");
                        AppendHex(Context.Text, Address);
                        Context.Text.Append(": ");
                    }

                    Context.FastOutput.Clear();
                    Context.FastFormatter.Format(Instr, Context.FastOutput);
                    AppendFastOutput(Context.Text, Context.FastOutput, ref Context.TempChars);
                    Context.Text.AppendLine();

                    Count++;
                }

                return Context.Text.ToString();
            }

            while (Reader.CanReadByte)
            {
                if (MaxInstructions > 0 && Count >= MaxInstructions)
                    break;

                ulong Address = Decoder.IP;
                Instruction Instr = Decoder.Decode();
                if (Instr.IsInvalid)
                    break;

                if (ShowOffset)
                {
                    Context.Text.Append("0x");
                    AppendHex(Context.Text, Address);
                    Context.Text.Append(": ");
                }

                Context.NasmOutput.Reset();
                Context.NasmFormatter.Format(Instr, Context.NasmOutput);
                Context.Text.Append(Context.NasmOutput.ToString());
                Context.Text.AppendLine();

                Count++;
            }

            return Context.Text.ToString();
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public string DisassembleToStringEmu(byte[] Code, ulong BaseOffset = 0, BinaryFile Binary = null, int MaxInstructions = 0, bool ShowOffset = true)
        {
            return DisassembleToString(Code, BaseOffset, Binary, MaxInstructions, ShowOffset);
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public string DisassembleToString(X86Instruction[] Instructions, bool ShowOffset = true)
        {
            if (Instructions == null || Instructions.Length == 0)
                throw new NullReferenceException("The Instructions cannot be null or empty.");

            StringBuilder Output = new StringBuilder(Instructions.Length * 32);

            for (int i = 0; i < Instructions.Length; i++)
            {
                X86Instruction Instruction = Instructions[i];

                if (ShowOffset)
                    Output.Append("0x").Append(Instruction.Address.ToString("X")).Append(": ");

                Output.Append(Instruction.Mnemonic);

                if (!string.IsNullOrEmpty(Instruction.Operand))
                    Output.Append(' ').Append(Instruction.Operand);

                Output.AppendLine();
            }

            return Output.ToString();
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public void DisassembleFunction(byte[] BinaryData, int Start, int Size, ulong BaseOffset, BinaryFile Binary, bool Emulator, FunctionResolver Resolver, DisassembleContext Context, out X86Instruction[] Instructions, out string DisassembledCode, out ulong DecodedSize)
        {
            if (BinaryData == null || BinaryData.Length == 0 || Size <= 0 || (uint)Start > (uint)BinaryData.Length || Start + Size > BinaryData.Length)
            {
                Instructions = Array.Empty<X86Instruction>();
                DisassembledCode = string.Empty;
                DecodedSize = 0;
                return;
            }

            Context.ResetLists();
            Context.ResetText();

            SliceByteArrayCodeReader Reader = new SliceByteArrayCodeReader(BinaryData, Start, Size);
            Iced.Intel.Decoder Decoder = Iced.Intel.Decoder.Create(Bitness, Reader);
            Decoder.IP = BaseOffset;

            ulong Sum = 0;

            while (Reader.CanReadByte)
            {
                int LocalOffset = Reader.Offset;

                ulong Address = Decoder.IP;
                Instruction Instr = Decoder.Decode();
                if (Instr.IsInvalid)
                    break;

                int Length = Instr.Length;
                if (Length <= 0)
                    break;

                int AbsoluteOffset = Start + LocalOffset;
                if ((uint)(AbsoluteOffset + Length) > (uint)BinaryData.Length)
                    break;

                ReadOnlyMemory<byte> Bytes = new ReadOnlyMemory<byte>(BinaryData, AbsoluteOffset, Length);

                string Mnemonic = MnemonicLower[(int)Instr.Mnemonic];
                string Operand = string.Empty;

                if (Mnemonic == "call" || Mnemonic == "jmp")
                {
                    ulong Target = BinaryAnalyzer.GetAddressFromOperand(new X86Instruction { Address = Address, Mnemonic = Mnemonic, Operand = string.Empty, Bytes = Bytes, BytesLength = (uint)Length }, Binary);
                    if (Target != 0 && Resolver.TryResolveName(Target, out string Name) && Name.Length != 0)
                        Operand = Name;
                }

                Context.Instructions.Add(new X86Instruction
                {
                    Address = Address,
                    Mnemonic = Mnemonic,
                    Operand = Operand,
                    Bytes = Bytes,
                    BytesLength = (uint)Length
                });

                Context.Text.Append("0x");
                AppendHex(Context.Text, Address);
                Context.Text.Append(": ");

                Context.FastOutput.Clear();
                Context.FastFormatter.Format(Instr, Context.FastOutput);
                AppendFastOutput(Context.Text, Context.FastOutput, ref Context.TempChars);
                Context.Text.AppendLine();

                Sum += (uint)Length;
            }

            Instructions = Context.Instructions.Count == 0 ? Array.Empty<X86Instruction>() : Context.Instructions.ToArray();
            DisassembledCode = Context.Text.Length == 0 ? string.Empty : Context.Text.ToString();
            DecodedSize = Sum;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static string ExtractOperandsFast(DisassembleContext Context, Instruction Instr)
        {
            Context.FastOutput.Clear();
            Context.FastFormatter.Format(Instr, Context.FastOutput);

            int Len = Context.FastOutput.Length;
            if (Len <= 0)
                return string.Empty;

            if (Context.TempChars.Length < Len)
                Context.TempChars = new char[Math.Max(Len, Context.TempChars.Length * 2)];

            Context.FastOutput.CopyTo(Context.TempChars, 0);

            int Space = -1;
            for (int i = 0; i < Len; i++)
            {
                char c = Context.TempChars[i];
                if (c == ' ' || c == '\t')
                {
                    Space = i;
                    break;
                }
            }

            if (Space < 0)
                return string.Empty;

            int Start = Space;
            while (Start < Len && (Context.TempChars[Start] == ' ' || Context.TempChars[Start] == '\t'))
                Start++;

            if (Start >= Len)
                return string.Empty;

            return new string(Context.TempChars, Start, Len - Start);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AppendFastOutput(StringBuilder Sb, FastStringOutput Output, ref char[] TempChars)
        {
            int Len = Output.Length;
            if (Len <= 0)
                return;

            if (TempChars.Length < Len)
                TempChars = new char[Math.Max(Len, TempChars.Length * 2)];

            Output.CopyTo(TempChars, 0);
            Sb.Append(TempChars, 0, Len);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static string ExtractOperandsFromFormatted(string Formatted)
        {
            if (string.IsNullOrEmpty(Formatted))
                return string.Empty;

            int Len = Formatted.Length;

            int Space = -1;
            for (int i = 0; i < Len; i++)
            {
                char c = Formatted[i];
                if (c == ' ' || c == '\t')
                {
                    Space = i;
                    break;
                }
            }

            if (Space < 0)
                return string.Empty;

            int Start = Space;
            while (Start < Len && (Formatted[Start] == ' ' || Formatted[Start] == '\t'))
                Start++;

            if (Start >= Len)
                return string.Empty;

            return Formatted.Substring(Start);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AppendHex(StringBuilder Sb, ulong Value)
        {
            Span<char> Buffer = stackalloc char[16];
            int Pos = 16;

            do
            {
                int Digit = (int)(Value & 0xF);
                Buffer[--Pos] = (char)(Digit < 10 ? ('0' + Digit) : ('A' + (Digit - 10)));
                Value >>= 4;
            }
            while (Value != 0);

            Sb.Append(Buffer.Slice(Pos, 16 - Pos));
        }

        private sealed class SliceByteArrayCodeReader : CodeReader
        {
            private readonly byte[] Data;
            private readonly int End;
            private int Index;
            private int OffsetFromStart;

            public SliceByteArrayCodeReader(byte[] Data, int Start, int Length)
            {
                this.Data = Data;
                Index = Start;
                End = Start + Length;
                OffsetFromStart = 0;
            }

            public bool CanReadByte => Index < End;
            public int Offset => OffsetFromStart;

            public override int ReadByte()
            {
                if (Index >= End)
                    return -1;

                OffsetFromStart++;
                return Data[Index++];
            }
        }

        private static string[] BuildMnemonicLower()
        {
            Array Values = Enum.GetValues(typeof(Mnemonic));
            string[] Table = new string[Values.Length];
            foreach (Mnemonic M in Values)
                Table[(int)M] = M.ToString().ToLowerInvariant();
            return Table;
        }
    }
}