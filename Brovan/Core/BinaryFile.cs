using System.Text;
using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.BinaryHelpers;
using System.Reflection.PortableExecutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using Brovan.Core.Helpers;
using Brovan.Analysis;
using System.Runtime.CompilerServices;
using System.Runtime;
using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Concurrent;

namespace Brovan.Core
{
    /// <summary>
    /// BinaryFile class which parses PE, ELF, and .NET binaries.
    /// </summary>
    public class BinaryFile : IDisposable
    {
        // public variables (results of analysis)

        /// <summary>
        /// Binary format.
        /// </summary>
        public BinaryFormat FileFormat;

        /// <summary>
        /// Binary size.
        /// </summary>
        public int BinarySize = 0;

        /// <summary>
        /// Binary Architecture.
        /// </summary>
        public BinaryArchitecture Architecture;

        /// <summary>
        /// Entry point of the binary.
        /// </summary>
        public uint EntryPoint = 0;

        /// <summary>
        /// Binary location.
        /// </summary>
        public string Location = string.Empty;

        /// <summary>
        /// Structure to be used for PE files.
        /// </summary>
        public PortableExecutable PE { get; private set; }

        /// <summary>
        /// Structure to be used for .NET files.
        /// </summary>
        public DotNet DotNet { get; private set; }

        /// <summary>
        /// Structure to be used for ELF files.
        /// </summary>
        public ELF ELF { get; private set; }

        /// <summary>
        /// Functions that exist in the binary (doesn't get filled if the binary is a .NET Binary).
        /// </summary>
        public BinaryFunction[] Functions { get; private set; } = Array.Empty<BinaryFunction>();

        /// <summary>
        /// Exported functions from the binary.
        /// </summary>
        public BinaryFunction[] ExportFunctions { get; private set; } = Array.Empty<BinaryFunction>();

        private MappedMemoryBytes Data;
        private ReadOnlySpan<byte> DataSpan => Data.AsSpan();

        public bool IsDisposed { get; private set; }
        private bool Quick = false;

        private readonly SectionLookupCache<PortableBinarySection> PeSectionCache = new SectionLookupCache<PortableBinarySection>(GetPeSectionVa, GetPeSectionSize);
        private readonly SectionLookupCache<ElfBinarySection> ElfSectionCache = new SectionLookupCache<ElfBinarySection>(GetElfSectionVa, GetElfSectionSize);

        private Dictionary<uint, uint> RvaToFileOffsetCache;

        /// <summary>
        /// Executable Formats Magic Number.
        /// </summary>
        private static readonly Dictionary<BinaryFormat, byte[]> BinaryMagicNumbers = new()
        {
            { BinaryFormat.PE, new byte[] { 0x4D, 0x5A } },
            { BinaryFormat.ELF, new byte[] { 0x7F, 0x45, 0x4C, 0x46 } },
        };

        private IcedX86Disassembler Disassembler;

        /// <summary>
        /// Reads an unmanaged structure from a byte array.
        /// </summary>
        /// <typeparam name="T">Unmanaged struct.</typeparam>
        /// <param name="Data">Data to get the struct from.</param>
        /// <param name="Offset">Offset of the struct.</param>
        /// <returns>The structure read from the supplied data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public T ReadStruct<T>(byte[] Data, int Offset) where T : unmanaged
        {
            if (Data == null || Data.Length == 0)
                throw new ArgumentNullException(nameof(Data), $"The parameter \"{nameof(Data)}\" byte array cannot be null or empty when reading a struct.");

            if (Offset < 0)
                throw new ArgumentOutOfRangeException(nameof(Offset), "Offset cannot be negative when reading a struct.");

            unsafe
            {
                int Size = sizeof(T);

                if ((long)Offset + Size > Data.Length)
                    throw new ArgumentOutOfRangeException(nameof(Offset), "Not enough data in the byte array to read the struct.");

                fixed (byte* Ptr = &Data[Offset])
                {
                    return Unsafe.ReadUnaligned<T>(Ptr)!;
                }
            }
        }

        /// <summary>
        /// Reads an unmanaged structure from a byte span.
        /// </summary>
        /// <typeparam name="T">Unmanaged struct.</typeparam>
        /// <param name="Data">Data to get the struct from.</param>
        /// <param name="Offset">Offset of the struct.</param>
        /// <returns>The structure read from the supplied data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public T ReadStruct<T>(ReadOnlySpan<byte> Data, int Offset) where T : unmanaged
        {
            if (Data.IsEmpty || Data.Length == 0)
                throw new ArgumentNullException(nameof(Data), $"The parameter \"{nameof(Data)}\" byte array cannot be null or empty when reading a struct.");

            if (Offset < 0)
                throw new ArgumentOutOfRangeException(nameof(Offset), "Offset cannot be negative when reading a struct.");

            unsafe
            {
                int Size = sizeof(T);

                if ((long)Offset + Size > Data.Length)
                    throw new ArgumentOutOfRangeException(nameof(Offset), "Not enough data in the byte array to read the struct.");

                fixed (byte* Ptr = &Data[Offset])
                {
                    return Unsafe.ReadUnaligned<T>(Ptr)!;
                }
            }
        }

        /// <summary>
        /// Read Executable Section Name.
        /// </summary>
        /// <param name="NameBytes">Name in bytes.</param>
        /// <returns>The section name as a string.</returns>
        private static string ReadSectionName(ReadOnlySpan<byte> NameBytes)
        {
            int NameLength = NameBytes.IndexOf((byte)0);
            if (NameLength < 0) NameLength = NameBytes.Length;
            return Encoding.ASCII.GetString(NameBytes.Slice(0, NameLength));
        }

        /// <summary>
        /// Gets the Binary Data.
        /// </summary>
        /// <returns>returns a byte array containing the whole Binary.</returns>
        public ReadOnlySpan<byte> GetBinaryData()
        {
            return DataSpan;
        }

        /// <summary>
        /// Disposes and nulls the mapped binary data.
        /// </summary>
        public void DisposeBinaryData()
        {
            MappedMemoryBytes Old = Data;
            if (Old == null)
                return;

            Data = null;
            Old.Dispose();
        }

        /// <summary>
        /// Reads a single byte from an offset.
        /// </summary>
        /// <param name="Offset">Offset of the data.</param>
        /// <returns>returns a byte from the chosen offset.</returns>
        public byte ReadOffset(int Offset)
        {
            if (Offset < 0 || Offset >= Data.Length)
                throw new ArgumentOutOfRangeException(nameof(Offset));
            return Data[Offset];
        }

        /// <summary>
        /// Parses, analyzes, and sets values for the Binary File based on it's format.
        /// </summary>
        /// <param name="Data">Binary file data.</param>
        /// <exception cref="IndexOutOfRangeException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="OverflowException"></exception>
        public void ParseBinary(byte[] Data)
        {
            ParseBinary((ReadOnlySpan<byte>)Data);
        }

        /// <summary>
        /// Parses, analyzes, and sets values for the Binary File based on it's format.
        /// </summary>
        /// <param name="Data">Binary file data.</param>
        /// <exception cref="IndexOutOfRangeException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="OverflowException"></exception>
        private void ParseBinary(ReadOnlySpan<byte> Data)
        {
            bool FormatFound = false;
            foreach (var BinaryMagicNumber in BinaryMagicNumbers)
            {
                byte[] MagicBytes = BinaryMagicNumber.Value;
                if (Data.Length >= MagicBytes.Length)
                {
                    bool Valid = true;
                    for (int i = 0; i < MagicBytes.Length; i++)
                    {
                        if (MagicBytes[i] != Data[i])
                        {
                            Valid = false;
                            break;
                        }
                    }

                    if (Valid)
                    {
                        FormatFound = true;
                        FileFormat = BinaryMagicNumber.Key;
                        break;
                    }
                }
            }

            if (!FormatFound)
            {
                FileFormat = BinaryFormat.Unknown;
                BinarySize = Data.Length;
                return;
            }

            if (FileFormat == BinaryFormat.PE)
            {
                // Read PE Dos Header
                IMAGE_DOS_HEADER DosHeader = ReadStruct<IMAGE_DOS_HEADER>(Data, 0);

                // Check for magic number again, to be sure.
                if (DosHeader.e_magic != 0x5A4D)
                {
                    FileFormat = BinaryFormat.Unknown;
                    return;
                }

                uint PESignature = ReadStruct<uint>(Data, DosHeader.e_lfanew);

                // do a check to ensure it's a valid PE file.
                if (PESignature != 0x00004550) // (check for "PE\0\0" which should be available for valid PE binaries)
                {
                    FileFormat = BinaryFormat.Unknown;
                    return;
                }

                IMAGE_FILE_HEADER FileHeader = ReadStruct<IMAGE_FILE_HEADER>(Data, DosHeader.e_lfanew + 4);
                PE.FileHeader = FileHeader;
                bool Is64Bit = false;

                // Determine binary type.
                switch (FileHeader.Machine)
                {
                    case 0x014C:
                        Architecture = BinaryArchitecture.x86;
                        Disassembler = new IcedX86Disassembler(X86DisassembleMode.Bit32, X86DisassemblerFormat.FastFormat);
                        break;
                    case 0x8664:
                        Architecture = BinaryArchitecture.x64;
                        Is64Bit = true;
                        Disassembler = new IcedX86Disassembler(X86DisassembleMode.Bit64, X86DisassemblerFormat.FastFormat);
                        break;
                    default:
                        Architecture = BinaryArchitecture.Unknown;
                        break;
                }

                if (Architecture == BinaryArchitecture.Unknown)
                    throw new BadImageFormatException("Unsupported binary architecture.");

                PE.Characteristics = (Characteristics)FileHeader.Characteristics;

                bool IsDotNet = false;
                uint ComDescriptorRva = 0;
                dynamic Header;
                if (Is64Bit)
                {
                    IMAGE_OPTIONAL_HEADER64 OptionalHeader = ReadStruct<IMAGE_OPTIONAL_HEADER64>(Data, DosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>());
                    PE.Subsystem = (Subsystem)OptionalHeader.Subsystem;
                    PE.CheckSum = OptionalHeader.CheckSum;
                    EntryPoint = OptionalHeader.AddressOfEntryPoint;
                    PE.DllCharacteristics = (BinaryHelpers.DllCharacteristics)OptionalHeader.DllCharacteristics;
                    PE.ImageBase = OptionalHeader.ImageBase;
                    if (OptionalHeader.DataDirectory[14].VirtualAddress != 0)
                    {
                        ComDescriptorRva = OptionalHeader.DataDirectory[14].VirtualAddress;
                        IsDotNet = true;
                        PE.DotNetStatus = DotNetStatus.DotNet;
                    }
                    PE.SizeOfImage = OptionalHeader.SizeOfImage;
                    PE.SizeOfHeaders = OptionalHeader.SizeOfHeaders;
                    PE.BaseOfCode = OptionalHeader.BaseOfCode;
                    PE.FileAlignment = OptionalHeader.FileAlignment;
                    PE.SectionAlignment = OptionalHeader.SectionAlignment;
                    PE.OptionalHeader64 = OptionalHeader;
                    Header = OptionalHeader;
                }
                else
                {
                    IMAGE_OPTIONAL_HEADER32 OptionalHeader = ReadStruct<IMAGE_OPTIONAL_HEADER32>(Data, DosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>());
                    PE.Subsystem = (Subsystem)OptionalHeader.Subsystem;
                    PE.CheckSum = OptionalHeader.CheckSum;
                    EntryPoint = OptionalHeader.AddressOfEntryPoint;
                    PE.DllCharacteristics = (BinaryHelpers.DllCharacteristics)OptionalHeader.DllCharacteristics;
                    PE.ImageBase = OptionalHeader.ImageBase;
                    if (OptionalHeader.DataDirectory[14].VirtualAddress != 0)
                    {
                        ComDescriptorRva = OptionalHeader.DataDirectory[14].VirtualAddress;
                        IsDotNet = true;
                        PE.DotNetStatus = DotNetStatus.DotNet;
                    }
                    PE.SizeOfImage = OptionalHeader.SizeOfImage;
                    PE.SizeOfHeaders = OptionalHeader.SizeOfHeaders;
                    PE.BaseOfCode = OptionalHeader.BaseOfCode;
                    PE.FileAlignment = OptionalHeader.FileAlignment;
                    PE.SectionAlignment = OptionalHeader.SectionAlignment;
                    PE.OptionalHeader32 = OptionalHeader;
                    Header = OptionalHeader;
                }

                // Get the offset of the PE sections.
                int SectionOffset = (DosHeader.e_lfanew + 4) + (Marshal.SizeOf<IMAGE_FILE_HEADER>() + FileHeader.SizeOfOptionalHeader);

                PE.Sections = new PortableBinarySection[FileHeader.NumberOfSections];

                // Get PE Sections.
                for (int i = 0; i < FileHeader.NumberOfSections; i++)
                {
                    if (SectionOffset + Marshal.SizeOf<IMAGE_SECTION_HEADER>() > Data.Length)
                        break;
                    IMAGE_SECTION_HEADER SectionHeader = ReadStruct<IMAGE_SECTION_HEADER>(Data, SectionOffset);
                    PE.Sections[i] = new PortableBinarySection
                    {
                        SectionName = ReadSectionName(SectionHeader.Name),
                        VirtualSize = SectionHeader.VirtualSize,
                        VirtualAddress = SectionHeader.VirtualAddress,
                        RawSize = SectionHeader.SizeOfRawData,
                        RawOffset = SectionHeader.PointerToRawData,
                        Characteristics = (SectionCharacteristics)SectionHeader.Characteristics
                    };
                    SectionOffset += Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                }

                BuildPESectionLookupCache();

                if (!IsDotNet)
                {
                    ParsePEExportFunctions(DosHeader, FileHeader, Is64Bit);
                    if (!Quick)
                        ParsePEFunctions(DosHeader, FileHeader, Is64Bit);
                }
                else
                {
                    int FileOffset = (int)RvaToFileOffset(ComDescriptorRva, PE.Sections);
                    IMAGE_COR20_HEADER CoreHeader = ReadStruct<IMAGE_COR20_HEADER>(Data, FileOffset);
                    int MetaDataOffset = (int)RvaToFileOffset(CoreHeader.MetaData.VirtualAddress, PE.Sections);
                    if (MetaDataOffset < 0 || MetaDataOffset > Data.Length - 4)
                        throw new IndexOutOfRangeException("Metadata signature offset of .NET is outside the binary length.");

                    ReadOnlySpan<byte> Signature = Data.Slice(MetaDataOffset, 4);
                    if (!(Signature[0] == (byte)'B' && Signature[1] == (byte)'S' && Signature[2] == (byte)'J' && Signature[3] == (byte)'B'))
                    {
                        PE.DotNetStatus = DotNetStatus.ModifiedDotNet;
                    }
                    if (!Quick)
                        ParseDotNetFunctions();
                }
                ParsePEImports(DosHeader, FileHeader, Is64Bit);
            }
            else if (FileFormat == BinaryFormat.ELF)
            {
                // Determine Architecture first which is located at the offset (0x4)
                byte ElfClass = Data[4];
                bool Is64Bit = ElfClass == 2;
                if (Is64Bit)
                {
                    ELF64_HEADER ElfHeader = ReadStruct<ELF64_HEADER>(Data, 0);

                    switch (ElfHeader.e_machine)
                    {
                        case 0x03:
                            Architecture = BinaryArchitecture.x86;
                            Disassembler = new IcedX86Disassembler(X86DisassembleMode.Bit32, X86DisassemblerFormat.FastFormat);
                            break;
                        case 0x3E:
                            Architecture = BinaryArchitecture.x64;
                            Disassembler = new IcedX86Disassembler(X86DisassembleMode.Bit64, X86DisassemblerFormat.FastFormat);
                            break;
                        default:
                            Architecture = BinaryArchitecture.Unknown;
                            return;
                    }

                    if (Architecture == BinaryArchitecture.Unknown)
                        throw new BadImageFormatException("Unsupported binary architecture.");

                    int SectionCount = ElfHeader.e_shnum;

                    // Set ELF Information.
                    EntryPoint = (uint)ElfHeader.e_entry;
                    ELF.Type = ElfHeader.e_type;
                    ELF.Version = ElfHeader.e_version;
                    ELF.Flags = ElfHeader.e_flags;
                    ELF.HeaderSize = ElfHeader.e_ehsize;
                    ELF.ProgramHeaderSize = ElfHeader.e_phentsize;
                    ELF.ProgramHeaderCount = ElfHeader.e_phnum;
                    ELF.SectionHeaderSize = ElfHeader.e_shentsize;
                    ELF.SectionHeaderCount = ElfHeader.e_shnum;
                    ELF.SectionNameIndex = ElfHeader.e_shstrndx;
                    ELF.Sections = new ElfBinarySection[SectionCount];

                    // Read the sections and set it's information.
                    ELF64_SECTION_HEADER StringTableHeader = ReadStruct<ELF64_SECTION_HEADER>(Data, (int)(ElfHeader.e_shoff + ((ulong)ElfHeader.e_shstrndx * (ulong)ElfHeader.e_shentsize)));
                    if (StringTableHeader.sh_size > (ulong)Array.MaxLength || StringTableHeader.sh_size < 0)
                        throw new ArgumentOutOfRangeException(nameof(StringTableHeader.sh_size), "sh_size is out-of-range for a byte array.");
                    int ShOffset = (int)StringTableHeader.sh_offset;
                    long EndPos = ShOffset + (long)StringTableHeader.sh_size;
                    if ((ShOffset > Data.Length) || (ShOffset < 0 || EndPos > Data.Length))
                        throw new IndexOutOfRangeException("sh_offset or size is larger than the binary data length.");
                    ReadOnlySpan<byte> StringTable = Data.Slice(ShOffset, (int)StringTableHeader.sh_size);
                    int SectionHeaderSize = ElfHeader.e_shentsize;
                    long SectionHeadersBase = (long)ElfHeader.e_shoff;
                    for (int i = 0; i < SectionCount; i++)
                    {
                        int SectionHeaderOffset = (int)(SectionHeadersBase + (i * SectionHeaderSize));
                        ELF64_SECTION_HEADER SectionHeader = ReadStruct<ELF64_SECTION_HEADER>(Data, SectionHeaderOffset);

                        string SectionName = null;
                        if (SectionHeader.sh_name != 0)
                        {
                            int NameOffset = (int)SectionHeader.sh_name;
                            if (NameOffset < 0 || NameOffset >= StringTable.Length)
                                throw new IndexOutOfRangeException("Section name offset is outside the string-table size.");

                            ReadOnlySpan<byte> NameSlice = StringTable.Slice(NameOffset);
                            int EndOffset = NameSlice.IndexOf((byte)0);
                            if (EndOffset < 0)
                                EndOffset = NameSlice.Length;

                            SectionName = Encoding.ASCII.GetString(NameSlice.Slice(0, EndOffset));
                        }

                        ELF.Sections[i] = new ElfBinarySection
                        {
                            SectionName = SectionName,
                            VirtualSize = (uint)SectionHeader.sh_size,
                            VirtualAddress = (uint)SectionHeader.sh_addr,
                            RawSize = (uint)SectionHeader.sh_size,
                            RawOffset = (uint)SectionHeader.sh_offset,
                            Characteristics = (ElfSectionCharacteristics)SectionHeader.sh_flags
                        };
                    }
                }
                else
                {
                    ELF32_HEADER ElfHeader = ReadStruct<ELF32_HEADER>(Data, 0);

                    switch (ElfHeader.e_machine)
                    {
                        case 0x03:
                            Architecture = BinaryArchitecture.x86;
                            Disassembler = new IcedX86Disassembler(X86DisassembleMode.Bit32, X86DisassemblerFormat.FastFormat);
                            break;
                        case 0x3E:
                            Architecture = BinaryArchitecture.x64;
                            Disassembler = new IcedX86Disassembler(X86DisassembleMode.Bit64, X86DisassemblerFormat.FastFormat);
                            break;
                        default:
                            Architecture = BinaryArchitecture.Unknown;
                            return;
                    }

                    if (Architecture == BinaryArchitecture.Unknown)
                        throw new BadImageFormatException("Unsupported binary architecture.");

                    int SectionCount = ElfHeader.e_shnum;

                    // Set ELF Information.
                    EntryPoint = ElfHeader.e_entry;
                    ELF.Type = ElfHeader.e_type;
                    ELF.Version = ElfHeader.e_version;
                    ELF.Flags = ElfHeader.e_flags;
                    ELF.HeaderSize = ElfHeader.e_ehsize;
                    ELF.ProgramHeaderSize = ElfHeader.e_phentsize;
                    ELF.ProgramHeaderCount = ElfHeader.e_phnum;
                    ELF.SectionHeaderSize = ElfHeader.e_shentsize;
                    ELF.SectionHeaderCount = ElfHeader.e_shnum;
                    ELF.SectionNameIndex = ElfHeader.e_shstrndx;
                    ELF.Sections = new ElfBinarySection[SectionCount];

                    // Read the sections and set it's information.
                    ELF32_SECTION_HEADER StringTableHeader = ReadStruct<ELF32_SECTION_HEADER>(Data, (int)(ElfHeader.e_shoff + (ElfHeader.e_shstrndx * ElfHeader.e_shentsize)));
                    if (StringTableHeader.sh_size > Array.MaxLength || StringTableHeader.sh_size < 0)
                        throw new OverflowException("sh_size is out-of-range for a byte array.");
                    int ShOffset = (int)StringTableHeader.sh_offset;
                    long EndPos = ShOffset + StringTableHeader.sh_size;
                    if ((ShOffset > Data.Length) || (ShOffset < 0 || EndPos > Data.Length))
                        throw new IndexOutOfRangeException("sh_offset or size is larger than the binary data length.");
                    ReadOnlySpan<byte> StringTable = Data.Slice(ShOffset, (int)StringTableHeader.sh_size);
                    int SectionHeaderSize = ElfHeader.e_shentsize;
                    int SectionHeadersBase = (int)ElfHeader.e_shoff;

                    for (int i = 0; i < SectionCount; i++)
                    {
                        int SectionHeaderOffset = SectionHeadersBase + (i * SectionHeaderSize);
                        ELF32_SECTION_HEADER SectionHeader = ReadStruct<ELF32_SECTION_HEADER>(Data, SectionHeaderOffset);

                        string SectionName = null;

                        if (SectionHeader.sh_name != 0)
                        {
                            int NameOffset = (int)SectionHeader.sh_name;
                            if (NameOffset < 0 || NameOffset >= StringTable.Length)
                                throw new IndexOutOfRangeException("Section name offset is outside the string-table size.");

                            ReadOnlySpan<byte> NameSlice = StringTable.Slice(NameOffset);
                            int EndOffset = NameSlice.IndexOf((byte)0);
                            if (EndOffset < 0)
                                EndOffset = NameSlice.Length;

                            SectionName = Encoding.ASCII.GetString(NameSlice.Slice(0, EndOffset));
                        }

                        ELF.Sections[i] = new ElfBinarySection
                        {
                            SectionName = SectionName,
                            VirtualSize = SectionHeader.sh_size,
                            VirtualAddress = SectionHeader.sh_addr,
                            RawSize = SectionHeader.sh_size,
                            RawOffset = SectionHeader.sh_offset,
                            Characteristics = (ElfSectionCharacteristics)SectionHeader.sh_flags
                        };
                    }
                }

                BuildELFSectionLookupCache();

                // Parse functions and imports
                ParseELFFunctions();
                ParseELFImports(Is64Bit);
            }
            BinarySize = Data.Length;
        }

        /// <summary>
        /// Parse and extract function names from the PE export directory and code sections.
        /// </summary>
        /// <param name="DosHeader">DOS Header of the PE file.</param>
        /// <param name="FileHeader">File Header of the PE file.</param>
        /// <param name="Is64Bit">Indicates if the PE is 64-bit.</param>
        private void ParsePEFunctions(IMAGE_DOS_HEADER DosHeader, IMAGE_FILE_HEADER FileHeader, bool Is64Bit)
        {
            // Parse .pdata section for runtime function information
            var PDataSection = PE.Sections.FirstOrDefault(s => s.SectionName == ".pdata");
            if (PDataSection.SectionName != null)
            {
                try
                {
                    int ExistingCount = Functions.Length;

                    List<BinaryFunction> FunctionList = new List<BinaryFunction>(ExistingCount + 128);
                    FunctionList.AddRange(Functions);

                    HashSet<uint> ExistingOffsets = new HashSet<uint>(ExistingCount);
                    for (int i = 0; i < ExistingCount; i++)
                        ExistingOffsets.Add(Functions[i].Offset);

                    if (PDataSection.RawOffset > (uint)Data.Length || PDataSection.RawSize > (uint)Data.Length - PDataSection.RawOffset)
                        throw new IndexOutOfRangeException("pdata section is out of the binary length range.");

                    int EntrySize = 12;
                    int EntryCount = (int)(PDataSection.RawSize / (uint)EntrySize);

                    int Base = (int)PDataSection.RawOffset;
                    int Max = Base + (int)PDataSection.RawSize;

                    for (int i = 0; i < EntryCount; i++)
                    {
                        int Entry = Base + (i * EntrySize);

                        if (Entry + 8 > Max)
                            break;

                        uint BeginRva = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(Data.AsSpan(Entry, 4));
                        uint EndRva = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(Data.AsSpan(Entry + 4, 4));

                        if (BeginRva == 0 || EndRva == 0)
                            continue;

                        if (!TryRvaToFileOffset(BeginRva, out uint FunctionOffset))
                            continue;

                        if (!TryRvaToFileOffset(EndRva, out uint EndOffset))
                            continue;

                        if (!ExistingOffsets.Add(FunctionOffset))
                            continue;

                        FunctionList.Add(new BinaryFunction
                        {
                            FunctionName = $"fun_{FunctionOffset:X}",
                            Address = PE.ImageBase + BeginRva,
                            Offset = FunctionOffset,
                            EndOffset = EndOffset
                        });
                    }

                    Functions = FunctionList.ToArray();
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[PE Parser] Error parsing functions using the pdata section: {ex.Message}");
                }
            }

            // Parse remaining functions using signature scanning
            ParsePEFunctions();

            // Add entry point as before
            if (Is64Bit)
            {
                IMAGE_OPTIONAL_HEADER64 OptionalHeader = ReadStruct<IMAGE_OPTIONAL_HEADER64>(DataSpan, DosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>());
                uint EntryRva = OptionalHeader.AddressOfEntryPoint;

                if (TryFindPESectionByRvaFast(EntryRva, out PortableBinarySection EntrySection))
                {
                    if (EntrySection.SectionName != null)
                    {
                        uint EntryOffset = RvaToFileOffset(EntryRva, PE.Sections);
                        List<BinaryFunction> FunctionList = Functions.ToList();

                        int ExistingIndex = -1;
                        for (int i = 0; i < FunctionList.Count; i++)
                        {
                            if (FunctionList[i].Offset == EntryOffset)
                            {
                                ExistingIndex = i;
                                break;
                            }
                        }

                        if (ExistingIndex == -1)
                        {
                            FunctionList.Add(new BinaryFunction
                            {
                                FunctionName = "start",
                                Address = PE.ImageBase + EntryRva,
                                Offset = EntryOffset,
                                EndOffset = GetFunctionEndOffset(EntryOffset)
                            });
                        }
                        else
                        {
                            BinaryFunction Existing = FunctionList[ExistingIndex];

                            if (string.IsNullOrEmpty(Existing.FunctionName))
                                Existing.FunctionName = "start";

                            Existing.Address = PE.ImageBase + EntryRva;
                            Existing.Offset = EntryOffset;

                            if (Existing.EndOffset == 0)
                                Existing.EndOffset = GetFunctionEndOffset(EntryOffset);

                            FunctionList[ExistingIndex] = Existing;
                        }
                    }
                }
            }
            else
            {
                IMAGE_OPTIONAL_HEADER32 OptionalHeader = ReadStruct<IMAGE_OPTIONAL_HEADER32>(DataSpan, DosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>());
                uint EntryRva = OptionalHeader.AddressOfEntryPoint;

                // Find the section containing the entry point
                if (TryFindPESectionByRvaFast(EntryRva, out PortableBinarySection EntrySection))
                {
                    if (EntrySection.SectionName != null)
                    {
                        // Calculate file offset
                        if (TryRvaToFileOffset(EntryRva, out uint EntryOffset))
                        {
                            if (!Functions.Any(f => f.Offset == EntryOffset))
                            {
                                List<BinaryFunction> FunctionList = Functions.ToList();
                                FunctionList.Add(new BinaryFunction
                                {
                                    FunctionName = "start",
                                    Address = PE.ImageBase + EntryRva,
                                    Offset = EntryOffset
                                });
                                Functions = FunctionList.ToArray();
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Try to locate the PE section that contains the specified file offset by scanning section raw ranges.
        /// </summary>
        /// <param name="FileOffset">The file offset to resolve.</param>
        /// <param name="Section">Receives the containing section when found.</param>
        /// <returns>returns true if the file offset maps to a section, otherwise false.</returns>
        private bool TryFindPESectionByFileOffset(uint FileOffset, out PortableBinarySection Section)
        {
            Section = default;

            for (int i = 0; i < PE.Sections.Length; i++)
            {
                PortableBinarySection Sec = PE.Sections[i];

                uint Start = Sec.RawOffset;
                uint End = Sec.RawOffset + Sec.RawSize;

                if (End < Start)
                    continue;

                if (FileOffset >= Start && FileOffset < End)
                {
                    Section = Sec;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determine the end offset of a function starting at the specified file offset by scanning forward for common epilogues or padding.
        /// </summary>
        /// <param name="StartOffset">The file offset where the function begins.</param>
        /// <returns>The file offset where the function is considered to end.</returns>
        private uint GetFunctionEndOffset(uint StartOffset)
        {
            if (StartOffset >= (uint)Data.Length)
                return StartOffset;

            if (!TryFindPESectionByFileOffset(StartOffset, out PortableBinarySection Section))
                return StartOffset;

            uint SectionStart = Section.RawOffset;
            uint SectionEnd = Section.RawOffset + Section.RawSize;

            if (SectionEnd > (uint)Data.Length)
                SectionEnd = (uint)Data.Length;

            if (StartOffset < SectionStart || StartOffset >= SectionEnd)
                return StartOffset;

            uint MaxEnd = StartOffset + 4096;
            if (MaxEnd > SectionEnd)
                MaxEnd = SectionEnd;

            uint EndOffset = StartOffset;
            byte[] ChunkData = GC.AllocateUninitializedArray<byte>(16);
            for (uint EndSearch = StartOffset; EndSearch < MaxEnd; EndSearch++)
            {
                if (EndSearch + 16 > (uint)Data.Length)
                    break;

                // Disassemble a chunk of code at the current position
                DataSpan.Slice((int)EndSearch, 16).CopyTo(ChunkData);

                X86Instruction[] Instructions = Disassembler.Disassemble(ChunkData, EndSearch);

                if (Instructions.Length < 1)
                    continue;

                // Check for common epilogues
                if (IsEpilogue(Instructions))
                {
                    EndOffset = EndSearch + (uint)Instructions[Instructions.Length - 1].Bytes.Length;
                    break;
                }

                // Check for proper INT3 padding
                if (IsInt3Padding(Instructions))
                {
                    bool IsInt3Sequence = true;

                    int Limit = Instructions.Length;
                    if (Limit > 4)
                        Limit = 4;

                    for (int i = 0; i < Limit; i++)
                    {
                        if (!IsInt3Padding(Instructions[i]))
                        {
                            IsInt3Sequence = false;
                            break;
                        }
                    }

                    if (IsInt3Sequence)
                    {
                        EndOffset = EndSearch;
                        break;
                    }
                }
            }

            return EndOffset;
        }

        private bool IsFunctionAlreadyDefined(uint StartOffset, uint EndOffset, List<BinaryFunction> FunctionList)
        {
            if (FunctionList == null || FunctionList.Count == 0)
                return false;

            if (EndOffset <= StartOffset)
                return true;

            for (int i = 0; i < FunctionList.Count; i++)
            {
                BinaryFunction F = FunctionList[i];

                uint A0 = F.Offset;
                uint A1 = F.EndOffset;

                if (A1 <= A0)
                    continue;

                // Overlap test
                if (StartOffset < A1 && EndOffset > A0)
                    return true;
            }

            return false;
        }

        private static uint GetPeSectionVa(PortableBinarySection Section) => Section.VirtualAddress;

        private static uint GetPeSectionSize(PortableBinarySection Section)
        {
            uint Size = Section.VirtualSize;
            return Size == 0 ? Section.RawSize : Size;
        }

        private static uint GetElfSectionVa(ElfBinarySection Section) => Section.VirtualAddress;

        private static uint GetElfSectionSize(ElfBinarySection Section) => Section.VirtualSize;

        private sealed class SectionLookupCache<TSection> where TSection : struct
        {
            private readonly Func<TSection, uint> GetVa;
            private readonly Func<TSection, uint> GetSize;

            private TSection[]? SortedByVa;
            private uint[]? VaStart;
            private uint[]? VaEnd;
            private bool HasLast;
            private TSection Last;

            public SectionLookupCache(Func<TSection, uint> GetVa, Func<TSection, uint> GetSize)
            {
                this.GetVa = GetVa ?? throw new ArgumentNullException(nameof(GetVa));
                this.GetSize = GetSize ?? throw new ArgumentNullException(nameof(GetSize));
            }

            public void Build(TSection[] Sections)
            {
                if (Sections == null || Sections.Length == 0)
                {
                    SortedByVa = null;
                    VaStart = null;
                    VaEnd = null;
                    HasLast = false;
                    return;
                }

                SortedByVa = (TSection[])Sections.Clone();
                Array.Sort(SortedByVa, (Left, Right) =>
                {
                    uint LeftVa = GetVa(Left);
                    uint RightVa = GetVa(Right);

                    if (LeftVa < RightVa)
                        return -1;

                    if (LeftVa > RightVa)
                        return 1;

                    return 0;
                });

                int Count = SortedByVa.Length;

                VaStart = new uint[Count];
                VaEnd = new uint[Count];

                for (int i = 0; i < Count; i++)
                {
                    TSection Section = SortedByVa[i];
                    uint Va = GetVa(Section);
                    uint Size = GetSize(Section);

                    VaStart[i] = Va;
                    VaEnd[i] = Va + Size;
                }

                HasLast = false;
            }

            public bool TryFindByVa(ulong VirtualAddress, out TSection Section)
            {
                Section = default;

                if (SortedByVa == null || VaStart == null || VaEnd == null)
                    return false;

                if (VirtualAddress > uint.MaxValue)
                    return false;

                uint Va = (uint)VirtualAddress;

                if (HasLast)
                {
                    uint Start = GetVa(Last);
                    uint End = Start + GetSize(Last);

                    if (Va >= Start && Va < End)
                    {
                        Section = Last;
                        return true;
                    }
                }

                int Lo = 0;
                int Hi = SortedByVa.Length - 1;

                while (Lo <= Hi)
                {
                    int Mid = Lo + ((Hi - Lo) >> 1);

                    uint Start = VaStart[Mid];
                    uint End = VaEnd[Mid];

                    if (Va < Start)
                    {
                        Hi = Mid - 1;
                        continue;
                    }

                    if (Va >= End)
                    {
                        Lo = Mid + 1;
                        continue;
                    }

                    Section = SortedByVa[Mid];
                    HasLast = true;
                    Last = Section;
                    return true;
                }

                return false;
            }
        }

        /// <summary>
        /// Builds internal lookup structures for PE sections, enabling fast resolution of RVAs to sections and file offsets.
        /// Must be called after Sections inside <see cref="PE"/> is populated.
        /// </summary>
        private void BuildPESectionLookupCache()
        {
            if (PE.Sections == null || PE.Sections.Length == 0)
                return;

            PeSectionCache.Build(PE.Sections);
            RvaToFileOffsetCache = new Dictionary<uint, uint>(4096);
        }

        /// <summary>
        /// Builds internal lookup structures for ELF sections, enabling fast resolution of VAs to sections.
        /// </summary>
        private void BuildELFSectionLookupCache()
        {
            if (ELF.Sections == null || ELF.Sections.Length == 0)
                return;

            ElfSectionCache.Build(ELF.Sections);
        }

        /// <summary>
        /// Try to locate the PE section that contains the specified RVA using a binary search over sorted section ranges.
        /// </summary>
        /// <param name="Rva">The RVA to resolve.</param>
        /// <param name="Section">Receives the containing section when found.</param>
        /// <returns>returns true if the RVA maps to a section, otherwise false.</returns>
        private bool TryFindPESectionByRva(uint Rva, out PortableBinarySection Section)
        {
            return PeSectionCache.TryFindByVa(Rva, out Section);
        }

        /// <summary>
        /// Try to locate the PE section that contains the specified RVA using a small cache for sequential access.
        /// </summary>
        /// <param name="Rva">The RVA to resolve.</param>
        /// <param name="Section">Receives the containing section when found.</param>
        /// <returns>returns true if the RVA maps to a section, otherwise false.</returns>
        private bool TryFindPESectionByRvaFast(uint Rva, out PortableBinarySection Section)
        {
            return PeSectionCache.TryFindByVa(Rva, out Section);
        }

        /// <summary>
        /// Try to locate the ELF section that contains the specified virtual address using a small cache for sequential access.
        /// </summary>
        private bool TryFindELFSectionByVaFast(ulong VirtualAddress, out ElfBinarySection Section)
        {
            return ElfSectionCache.TryFindByVa(VirtualAddress, out Section);
        }

        /// <summary>
        /// Convert an RVA to a file offset using cached section lookup.
        /// </summary>
        /// <param name="Rva">The RVA to convert.</param>
        /// <param name="FileOffset">Receives the file offset when conversion succeeds.</param>
        /// <returns>True if the RVA could be converted; otherwise, false.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool TryRvaToFileOffset(uint Rva, out uint FileOffset)
        {
            if (RvaToFileOffsetCache != null &&
                RvaToFileOffsetCache.TryGetValue(Rva, out FileOffset))
            {
                return true;
            }

            if (!TryFindPESectionByRvaFast(Rva, out PortableBinarySection Sec))
            {
                FileOffset = 0;
                return false;
            }

            uint Delta = Rva - Sec.VirtualAddress;
            FileOffset = Sec.RawOffset + Delta;

            if (RvaToFileOffsetCache != null)
                RvaToFileOffsetCache[Rva] = FileOffset;

            return true;
        }

        private static readonly byte[][] X86FunctionSignatures = new[]
        {
            new byte[] { 0x55, 0x89, 0xE5 }, // push ebp; mov ebp, esp
            new byte[] { 0x53, 0x56, 0x57 }, // push ebx; push esi; push edi
            new byte[] { 0x83, 0xEC }, // sub esp, XX
            new byte[] { 0x56, 0x8B, 0xF1 }, // push esi; mov esi, ecx (common C++ method prologue)
            new byte[] { 0x57, 0x8B, 0xF9 }, // push edi; mov edi, ecx (common C++ method prologue)
            new byte[] { 0x55, 0x8B, 0xEC }, // push ebp; mov ebp, esp (MSVC style)
            new byte[] { 0x53, 0x8B, 0xDC }, // push ebx; mov ebx, esp
        };

        private static readonly byte[][] X64FunctionSignatures = new[]
        {
            new byte[] { 0x55, 0x48, 0x89, 0xE5 }, // push rbp; mov rbp, rsp
            new byte[] { 0x48, 0x83, 0xEC }, // sub rsp, XX
            new byte[] { 0x40, 0x53 }, // push rbx
            new byte[] { 0x40, 0x55 }, // push rbp
            new byte[] { 0x40, 0x56 }, // push rsi
            new byte[] { 0x40, 0x57 }, // push rdi
            new byte[] { 0x48, 0x89, 0x5C, 0x24 }, // mov [rsp+XX], rbx
            new byte[] { 0x48, 0x89, 0x6C, 0x24 }, // mov [rsp+XX], rbp
            new byte[] { 0x48, 0x89, 0x74, 0x24 }, // mov [rsp+XX], rsi
            new byte[] { 0x48, 0x89, 0x7C, 0x24 }, // mov [rsp+XX], rdi
            new byte[] { 0x4C, 0x89, 0x44, 0x24 }, // mov [rsp+XX], r8
            new byte[] { 0x4C, 0x89, 0x4C, 0x24 }, // mov [rsp+XX], r9
        };

        private static readonly Dictionary<byte, byte[][]> X86FunctionSignatureLookup = BuildFunctionSignatureLookup(X86FunctionSignatures);
        private static readonly Dictionary<byte, byte[][]> X64FunctionSignatureLookup = BuildFunctionSignatureLookup(X64FunctionSignatures);
        private static readonly byte[] X86FunctionSignatureFirstBytes = X86FunctionSignatureLookup.Keys.OrderBy(b => b).ToArray();
        private static readonly byte[] X64FunctionSignatureFirstBytes = X64FunctionSignatureLookup.Keys.OrderBy(b => b).ToArray();
        private static readonly SearchValues<byte> X86FunctionSignatureFirstByteSearchValues = SearchValues.Create(X86FunctionSignatureFirstBytes);
        private static readonly SearchValues<byte> X64FunctionSignatureFirstByteSearchValues = SearchValues.Create(X64FunctionSignatureFirstBytes);

        /// <summary>
        /// Group function signatures by their first byte so we only test plausible candidates.
        /// </summary>
        private static Dictionary<byte, byte[][]> BuildFunctionSignatureLookup(byte[][] Signatures)
        {
            Dictionary<byte, List<byte[]>> GroupedSignatures = new Dictionary<byte, List<byte[]>>();

            foreach (byte[] Signature in Signatures)
            {
                if (Signature == null || Signature.Length == 0)
                    continue;

                byte FirstByte = Signature[0];
                if (!GroupedSignatures.TryGetValue(FirstByte, out List<byte[]> bucket))
                {
                    bucket = new List<byte[]>();
                    GroupedSignatures[FirstByte] = bucket;
                }

                bucket.Add(Signature);
            }

            Dictionary<byte, byte[][]> Lookup = new Dictionary<byte, byte[][]>(GroupedSignatures.Count);
            foreach ((byte FirstByte, List<byte[]> bucket) in GroupedSignatures)
                Lookup[FirstByte] = bucket.OrderByDescending(sig => sig.Length).ToArray();

            return Lookup;
        }

        /// <summary>
        /// Find the next offset whose first byte matches one of the known function signatures.
        /// </summary>
        private static int FindNextFunctionSignatureCandidate(ReadOnlySpan<byte> SectionData, int StartOffset, SearchValues<byte> CandidateFirstBytes)
        {
            if ((uint)StartOffset >= (uint)SectionData.Length)
                return -1;

            int relative = SectionData.Slice(StartOffset).IndexOfAny(CandidateFirstBytes);
            return relative < 0 ? -1 : StartOffset + relative;
        }

        private IcedX86Disassembler CreateDisassemblerForArchitecture()
        {
            return Architecture switch
            {
                BinaryArchitecture.x86 => new IcedX86Disassembler(X86DisassembleMode.Bit32, X86DisassemblerFormat.FastFormat),
                BinaryArchitecture.x64 => new IcedX86Disassembler(X86DisassembleMode.Bit64, X86DisassemblerFormat.FastFormat),
                _ => throw new BadImageFormatException("Unsupported binary architecture.")
            };
        }

        /// <summary>
        /// Parse and identify non-exported functions by scanning code sections for common function prologues.
        /// </summary>
        private void ParsePEFunctions()
        {
            FrozenSet<uint> ExistingOffsets = Functions.Select(f => f.Offset).ToFrozenSet();

            Dictionary<byte, byte[][]> FunctionSignatureLookup = Architecture == BinaryArchitecture.x64 ? X64FunctionSignatureLookup : X86FunctionSignatureLookup;

            SearchValues<byte> FunctionSignatureFirstBytes = Architecture == BinaryArchitecture.x64 ? X64FunctionSignatureFirstByteSearchValues : X86FunctionSignatureFirstByteSearchValues;

            ConcurrentBag<List<BinaryFunction>> AllChunkResults = new ConcurrentBag<List<BinaryFunction>>();

            const int MinChunkSize = 256 * 1024;

            for (int s = 0; s < PE.Sections.Length; s++)
            {
                PortableBinarySection Section = PE.Sections[s];

                if ((Section.Characteristics & SectionCharacteristics.ContainsCode) == 0)
                    continue;

                ulong SectionEnd = (ulong)Section.RawOffset + Section.RawSize;
                if (SectionEnd > (ulong)Data.Length)
                    throw new IndexOutOfRangeException("Section raw size / raw offset is larger than the binary data itself.");

                int SectionRawOffset = (int)Section.RawOffset;
                int SectionLength = (int)Section.RawSize;
                if (SectionLength < 2)
                    continue;

                int WorkerCount = Math.Min(Environment.ProcessorCount, Math.Max(1, SectionLength / MinChunkSize));
                if (WorkerCount <= 1)
                    WorkerCount = 1;

                int ChunkSize = (SectionLength + WorkerCount - 1) / WorkerCount;

                Parallel.For(0, WorkerCount, WorkerIndex =>
                {
                    ReadOnlySpan<byte> SectionData = DataSpan.Slice(SectionRawOffset, SectionLength);
                    int ChunkStart = WorkerIndex * ChunkSize;
                    int ChunkEnd = Math.Min(SectionLength, ChunkStart + ChunkSize);

                    if (ChunkStart >= ChunkEnd)
                        return;

                    List<BinaryFunction> LocalResults = new List<BinaryFunction>(64);
                    HashSet<uint> LocalOffsets = new HashSet<uint>();
                    byte[] DisasmBuffer = GC.AllocateUninitializedArray<byte>(16);
                    IcedX86Disassembler LocalDisassembler = CreateDisassemblerForArchitecture();

                    for (int i = ChunkStart; i < ChunkEnd;)
                    {
                        i = FindNextFunctionSignatureCandidate(SectionData, i, FunctionSignatureFirstBytes);
                        if (i < 0 || i >= ChunkEnd)
                            break;

                        if (!FunctionSignatureLookup.TryGetValue(SectionData[i], out byte[][] CandidateSignatures))
                        {
                            i++;
                            continue;
                        }

                        bool FoundMatch = false;

                        foreach (byte[] Signature in CandidateSignatures)
                        {
                            int SigLength = Signature.Length;
                            if (i + SigLength > SectionLength)
                                continue;

                            if (!SectionData.Slice(i, SigLength).SequenceEqual(Signature))
                                continue;

                            FoundMatch = true;

                            uint OffsetInSection = (uint)i;
                            uint FunctionRva = Section.VirtualAddress + OffsetInSection;
                            uint FunctionFileOffset = Section.RawOffset + OffsetInSection;

                            if (ExistingOffsets.Contains(FunctionFileOffset) || !LocalOffsets.Add(FunctionFileOffset))
                            {
                                i += SigLength;
                                break;
                            }

                            uint EndOffset = FunctionFileOffset;
                            uint MaxSearch = Math.Min(OffsetInSection + 4096, (uint)SectionLength - 1);

                            for (uint Search = OffsetInSection + (uint)SigLength; Search < MaxSearch;)
                            {
                                int ChunkBytes = Math.Min(16, SectionLength - (int)Search);
                                if (ChunkBytes <= 0)
                                    break;

                                SectionData.Slice((int)Search, ChunkBytes).CopyTo(DisasmBuffer);

                                if (ChunkBytes < DisasmBuffer.Length)
                                    Array.Clear(DisasmBuffer, ChunkBytes, DisasmBuffer.Length - ChunkBytes);

                                X86Instruction[] Instructions = LocalDisassembler.Disassemble(DisasmBuffer, Search);

                                if (Instructions.Length == 0)
                                {
                                    Search++;
                                    continue;
                                }

                                if (IsEpilogue(Instructions))
                                {
                                    EndOffset = Section.RawOffset + Search + (uint)Instructions[^1].Bytes.Length;
                                    break;
                                }

                                if (IsInt3Padding(Instructions))
                                {
                                    bool Int3Sequence = true;
                                    uint CheckCount = Math.Min(4u, (uint)(SectionLength - (int)Search));

                                    for (uint k = 0; k < CheckCount; k++)
                                    {
                                        if (SectionData[(int)Search + (int)k] != 0xCC)
                                        {
                                            Int3Sequence = false;
                                            break;
                                        }
                                    }

                                    if (Int3Sequence)
                                    {
                                        EndOffset = Section.RawOffset + Search;
                                        break;
                                    }
                                }

                                Search += (uint)Instructions[0].Bytes.Length;
                            }

                            LocalResults.Add(new BinaryFunction
                            {
                                FunctionName = $"fun_{FunctionFileOffset:X}",
                                Address = PE.ImageBase + FunctionRva,
                                Offset = FunctionFileOffset,
                                EndOffset = EndOffset
                            });

                            i += SigLength;
                            break;
                        }

                        if (!FoundMatch)
                            i++;
                    }

                    if (LocalResults.Count > 0)
                        AllChunkResults.Add(LocalResults);
                });
            }

            if (AllChunkResults.IsEmpty)
                return;

            List<BinaryFunction> Candidates = new List<BinaryFunction>(256);
            foreach (List<BinaryFunction> ChunkList in AllChunkResults)
                Candidates.AddRange(ChunkList);

            if (Candidates.Count == 0)
                return;

            Candidates.Sort((A, B) => A.Offset.CompareTo(B.Offset));

            var ExistingRanges = Functions.Where(f => f.EndOffset > f.Offset).Select(f => (Start: f.Offset, End: f.EndOffset)).OrderBy(r => r.Start).ToArray();

            List<BinaryFunction> FinalFunctions = new List<BinaryFunction>(Functions.Length + Candidates.Count);
            FinalFunctions.AddRange(Functions);

            HashSet<uint> FinalOffsets = new HashSet<uint>(Functions.Length);
            for (int i = 0; i < Functions.Length; i++)
                FinalOffsets.Add(Functions[i].Offset);

            int ExistingIndex = 0;
            bool HasLastAccepted = false;
            uint LastAcceptedEnd = 0;

            for (int i = 0; i < Candidates.Count; i++)
            {
                BinaryFunction Candidate = Candidates[i];

                if (!FinalOffsets.Add(Candidate.Offset))
                    continue;

                if (Candidate.EndOffset <= Candidate.Offset)
                    continue;

                while (ExistingIndex < ExistingRanges.Length && ExistingRanges[ExistingIndex].End <= Candidate.Offset)
                    ExistingIndex++;

                if (ExistingIndex < ExistingRanges.Length)
                {
                    var Range = ExistingRanges[ExistingIndex];
                    if (Candidate.Offset < Range.End && Candidate.EndOffset > Range.Start)
                        continue;
                }

                if (HasLastAccepted && Candidate.Offset < LastAcceptedEnd)
                    continue;

                FinalFunctions.Add(Candidate);
                HasLastAccepted = true;
                LastAcceptedEnd = Candidate.EndOffset;
            }

            Functions = FinalFunctions.ToArray();
        }

        /// <summary>
        /// Check whether the instruction represents a one-byte INT3 padding instruction.
        /// </summary>
        /// <param name="Inst">The instruction to examine.</param>
        /// <returns>returns true if the instruction is a one-byte INT3, otherwise false.</returns>
        private bool IsInt3Padding(X86Instruction Inst)
        {
            return Inst.Mnemonic == "int3" && Inst.Bytes.Length == 1 && Inst.Bytes.Span[0] == 0xCC;
        }

        /// <summary>
        /// Check whether the first instruction in the sequence represents INT3 padding.
        /// </summary>
        /// <param name="Instructions">Decoded instructions to examine.</param>
        /// <returns>returns true if the first instruction is a one-byte INT3, otherwise false.</returns>
        private bool IsInt3Padding(X86Instruction[] Instructions)
        {
            if (Instructions == null || Instructions.Length == 0)
                return false;

            return IsInt3Padding(Instructions[0]);
        }

        /// <summary>
        /// Check whether the instruction represents a stack-frame teardown move.
        /// </summary>
        private bool IsMovSpBp(X86Instruction Inst)
        {
            string Op = Inst.Operand;
            if (string.IsNullOrEmpty(Op))
                return false;

            return Op == "esp, ebp" || Op == "rsp, rbp";
        }

        /// <summary>
        /// Check whether the provided instruction sequence matches a function epilogue pattern.
        /// </summary>
        /// <param name="Instructions">Decoded instructions to examine.</param>
        /// <returns>returns true if an epilogue pattern is detected, otherwise false.</returns>
        private bool IsEpilogue(X86Instruction[] Instructions)
        {
            if (Instructions == null || Instructions.Length == 0)
                return false;

            X86Instruction I0 = Instructions[0];

            if (I0.Mnemonic == "leave")
            {
                if (Instructions.Length >= 2 && Instructions[1].Mnemonic == "ret")
                    return true;

                return false;
            }

            if (I0.Mnemonic == "ret")
                return true;

            if (I0.Mnemonic == "pop")
            {
                if (Instructions.Length >= 2 && Instructions[1].Mnemonic == "ret")
                    return true;

                return false;
            }

            if (I0.Mnemonic == "add")
            {
                if (Instructions.Length < 2)
                    return false;

                if (Instructions[1].Mnemonic != "ret")
                    return false;

                string Op = I0.Operand;
                if (Op == null || Op.Length < 3)
                    return false;

                char c0 = Op[0];
                if ((c0 == 'e' || c0 == 'r') && Op[1] == 's' && Op[2] == 'p')
                    return true;

                return false;
            }

            if (I0.Mnemonic == "mov")
            {
                if (Instructions.Length < 3)
                    return false;

                if (Instructions[1].Mnemonic != "pop")
                    return false;

                if (Instructions[2].Mnemonic != "ret")
                    return false;

                if (!IsMovSpBp(I0))
                    return false;

                string PopOp = Instructions[1].Operand;
                if (PopOp == "ebp" || PopOp == "rbp")
                    return true;

                return false;
            }

            return false;
        }

        /// <summary>
        /// Try to calculate a table entry file offset while checking for malformed export table bounds.
        /// </summary>
        /// <param name="BaseOffset">File offset of the table.</param>
        /// <param name="Index">Entry index inside the table.</param>
        /// <param name="EntrySize">Entry size in bytes.</param>
        /// <param name="DataLength">Binary data length.</param>
        /// <param name="Offset">Receives the calculated file offset.</param>
        /// <returns>returns true if the table entry is fully inside the binary data.</returns>
        private static bool TryGetExportTableEntryOffset(uint BaseOffset, uint Index, uint EntrySize, int DataLength, out int Offset)
        {
            Offset = 0;

            ulong Computed = (ulong)BaseOffset + ((ulong)Index * EntrySize);
            if (Computed + EntrySize > (ulong)DataLength)
                return false;

            Offset = (int)Computed;
            return true;
        }

        /// <summary>
        /// Find a conservative end offset for an exported function by scanning a small code window for common terminators.
        /// </summary>
        /// <param name="Data">Binary data.</param>
        /// <param name="FunctionFileOffset">Function file offset.</param>
        /// <returns>The discovered end offset, or the original function offset when no terminator is found.</returns>
        private static uint FindExportFunctionEndOffset(ReadOnlySpan<byte> Data, uint FunctionFileOffset)
        {
            if (FunctionFileOffset >= (uint)Data.Length)
                return FunctionFileOffset;

            int Start = (int)FunctionFileOffset;
            int Length = Data.Length - Start;
            if (Length > 4096)
                Length = 4096;

            if (Length <= 0)
                return FunctionFileOffset;

            ReadOnlySpan<byte> Code = Data.Slice(Start, Length);

            for (int i = 0; i < Code.Length; i++)
            {
                byte Current = Code[i];

                if (Current == 0xCC)
                    return (uint)(Start + i);

                if (i + 1 < Code.Length && Current == 0xC9 && Code[i + 1] == 0xC3)
                    return (uint)(Start + i + 2);

                if (i + 1 < Code.Length && Current >= 0x58 && Current <= 0x5F && Code[i + 1] == 0xC3)
                    return (uint)(Start + i + 2);

                if (i + 2 < Code.Length && Current == 0xC2)
                    return (uint)(Start + i + 3);
            }

            return FunctionFileOffset;
        }

        /// <summary>
        /// Parse and extract function names from the PE export directory.
        /// </summary>
        /// <param name="DosHeader">DOS Header of the PE file.</param>
        /// <param name="FileHeader">File Header of the PE file.</param>
        /// <param name="Is64Bit">Indicates if the PE is 64-bit.</param>
        /// <exception cref="IndexOutOfRangeException"></exception>
        private void ParsePEExportFunctions(IMAGE_DOS_HEADER DosHeader, IMAGE_FILE_HEADER FileHeader, bool Is64Bit)
        {
            ReadOnlySpan<byte> BinaryData = DataSpan;
            int BinaryLength = BinaryData.Length;
            uint ExportTableRva = 0;

            if (Is64Bit)
            {
                IMAGE_OPTIONAL_HEADER64 OptionalHeader64 = ReadStruct<IMAGE_OPTIONAL_HEADER64>(BinaryData, DosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>());

                ExportTableRva = OptionalHeader64.ExportTable.VirtualAddress;
            }
            else
            {
                IMAGE_OPTIONAL_HEADER32 OptionalHeader32 = ReadStruct<IMAGE_OPTIONAL_HEADER32>(BinaryData, DosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>());

                ExportTableRva = OptionalHeader32.ExportTable.VirtualAddress;
            }

            if (ExportTableRva == 0)
                return;

            if (!TryFindPESectionByRvaFast(ExportTableRva, out PortableBinarySection ExportSection))
                return;

            uint ExportTableOffset = ExportSection.RawOffset + (ExportTableRva - ExportSection.VirtualAddress);
            if (ExportTableOffset > int.MaxValue)
                throw new IndexOutOfRangeException("Invalid PE export directory offset.");

            IMAGE_EXPORT_DIRECTORY ExportDirectory = ReadStruct<IMAGE_EXPORT_DIRECTORY>(BinaryData, (int)ExportTableOffset);

            uint NameTableRva = ExportDirectory.AddressOfNames;
            uint AddressTableRva = ExportDirectory.AddressOfFunctions;
            uint OrdinalTableRva = ExportDirectory.AddressOfNameOrdinals;

            if (AddressTableRva == 0 || ExportDirectory.NumberOfFunctions == 0)
                return;

            if (!TryFindPESectionByRvaFast(AddressTableRva, out PortableBinarySection AddressSection))
                return;

            uint AddressTableOffset = AddressSection.RawOffset + (AddressTableRva - AddressSection.VirtualAddress);

            uint NameTableOffset = 0;
            uint OrdinalTableOffset = 0;
            bool HasNamedExports = NameTableRva != 0 && OrdinalTableRva != 0 && ExportDirectory.NumberOfNames != 0;

            if (HasNamedExports)
            {
                if (!TryFindPESectionByRvaFast(NameTableRva, out PortableBinarySection NameSection))
                    return;

                if (!TryFindPESectionByRvaFast(OrdinalTableRva, out PortableBinarySection OrdinalSection))
                    return;

                NameTableOffset = NameSection.RawOffset + (NameTableRva - NameSection.VirtualAddress);
                OrdinalTableOffset = OrdinalSection.RawOffset + (OrdinalTableRva - OrdinalSection.VirtualAddress);
            }

            ulong TotalExports = (ulong)ExportDirectory.NumberOfNames + ExportDirectory.NumberOfFunctions;
            int EstimatedExportCount = (int)Math.Min(TotalExports, 8192UL);
            List<BinaryFunction> FunctionList = new List<BinaryFunction>(EstimatedExportCount);
            HashSet<uint> ExistingOffsets = new HashSet<uint>(Functions.Length + EstimatedExportCount);

            for (int i = 0; i < Functions.Length; i++)
                ExistingOffsets.Add(Functions[i].Offset);

            if (HasNamedExports)
            {
                for (uint i = 0; i < ExportDirectory.NumberOfNames; i++)
                {
                    if (!TryGetExportTableEntryOffset(NameTableOffset, i, sizeof(uint), BinaryLength, out int NameTable))
                        throw new IndexOutOfRangeException("Invalid offsets to get exports.");

                    if (!TryGetExportTableEntryOffset(OrdinalTableOffset, i, sizeof(ushort), BinaryLength, out int OrdinalTable))
                        throw new IndexOutOfRangeException("Invalid offsets to get exports.");

                    uint NameRva = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(BinaryData.Slice(NameTable, sizeof(uint)));
                    ushort Ordinal = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(BinaryData.Slice(OrdinalTable, sizeof(ushort)));

                    if (Ordinal >= ExportDirectory.NumberOfFunctions)
                        continue;

                    if (!TryGetExportTableEntryOffset(AddressTableOffset, Ordinal, sizeof(uint), BinaryLength, out int AddressTable))
                        throw new IndexOutOfRangeException("Invalid offsets to get exports.");

                    uint FunctionRva = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(BinaryData.Slice(AddressTable, sizeof(uint)));
                    if (FunctionRva == 0)
                        continue;

                    if (!TryRvaToFileOffset(FunctionRva, out uint FunctionFileOffset))
                        continue;

                    if (FunctionFileOffset >= (uint)BinaryLength)
                        continue;

                    if (ExistingOffsets.Contains(FunctionFileOffset))
                        continue;

                    if (!TryRvaToFileOffset(NameRva, out uint NameOffset))
                        continue;

                    if (NameOffset >= (uint)BinaryLength)
                        continue;

                    string FunctionName = ReadNullTerminatedString(BinaryData, (int)NameOffset);

                    if (string.IsNullOrEmpty(FunctionName))
                        continue;

                    uint EndOffset = FindExportFunctionEndOffset(BinaryData, FunctionFileOffset);

                    FunctionList.Add(new BinaryFunction
                    {
                        FunctionName = FunctionName,
                        Address = PE.ImageBase + FunctionRva,
                        Offset = FunctionFileOffset,
                        EndOffset = EndOffset
                    });

                    ExistingOffsets.Add(FunctionFileOffset);
                }
            }

            for (uint i = 0; i < ExportDirectory.NumberOfFunctions; i++)
            {
                if (!TryGetExportTableEntryOffset(AddressTableOffset, i, sizeof(uint), BinaryLength, out int AddressTable))
                    throw new IndexOutOfRangeException("Invalid offset for the address table.");

                uint FunctionRva = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(BinaryData.Slice(AddressTable, sizeof(uint)));
                if (FunctionRva == 0)
                    continue;

                if (!TryRvaToFileOffset(FunctionRva, out uint FunctionFileOffset))
                    continue;

                if (FunctionFileOffset >= (uint)BinaryLength)
                    continue;

                if (!ExistingOffsets.Add(FunctionFileOffset))
                    continue;

                uint EndOffset = FindExportFunctionEndOffset(BinaryData, FunctionFileOffset);
                uint Ordinal = unchecked(i + ExportDirectory.Base);

                FunctionList.Add(new BinaryFunction
                {
                    FunctionName = $"Ordinal_{Ordinal:X}",
                    Address = PE.ImageBase + FunctionRva,
                    Offset = FunctionFileOffset,
                    EndOffset = EndOffset
                });
            }

            ExportFunctions = FunctionList.ToArray();
        }

        /// <summary>
        /// Parse and read .NET Binary information.
        /// </summary>
        private unsafe void ParseDotNetFunctions()
        {
            List<DotNetFunction> DotNetFunctionList = new List<DotNetFunction>();
            List<DotNetProperty> DotNetPropertyList = new List<DotNetProperty>();
            List<DotNetField> DotNetFieldList = new List<DotNetField>();
            List<DotNetType> DotNetTypeList = new List<DotNetType>();
            List<DotNetMember> DotNetMemberList = new List<DotNetMember>();
            MetadataReader MetadataReader = null;
            try
            {
                // Gonna use PEReader (no manual parsing for now)
                PEReader PEReader = new PEReader(Data.BasePtr, Data.Length, true);
                MetadataReader = PEReader.GetMetadataReader();
                foreach (TypeDefinitionHandle TypeHandle in MetadataReader.TypeDefinitions)
                {
                    TypeDefinition TypeDef = MetadataReader.GetTypeDefinition(TypeHandle);
                    string TypeNamespace = TypeDef.Namespace.IsNil ? "" : MetadataReader.GetString(TypeDef.Namespace);
                    string TypeName = MetadataReader.GetString(TypeDef.Name);
                    AssemblyDefinition AsmDef = MetadataReader.GetAssemblyDefinition();
                    string AssemblyName = MetadataReader.GetString(AsmDef.Name);
                    foreach (MethodDefinitionHandle MethodHandle in TypeDef.GetMethods())
                    {
                        MethodDefinition MethodDef = MetadataReader.GetMethodDefinition(MethodHandle);
                        string MethodName = MetadataReader.GetString(MethodDef.Name);

                        if (MethodDef.RelativeVirtualAddress == 0)
                            continue;

                        uint RVA = (uint)MethodDef.RelativeVirtualAddress;
                        uint FileOffset = RvaToFileOffset(RVA, PE.Sections);
                        if (FileOffset == 0 || FileOffset >= Data.Length - 1)
                            continue;

                        byte HeaderByte = Data[FileOffset];
                        bool IsTiny = (HeaderByte & 0x03) == 0x02;
                        uint CodeSize;

                        if (IsTiny)
                        {
                            CodeSize = (uint)(HeaderByte >> 2);
                            FileOffset += 1;
                        }
                        else
                        {
                            if (FileOffset + 12 > Data.Length)
                                continue;

                            ushort Flags_Size = ReadStruct<ushort>(DataSpan, (int)FileOffset);
                            CodeSize = ReadStruct<uint>(DataSpan, (int)FileOffset + 4);
                            FileOffset += 12;

                            if (CodeSize > 1024 * 1024)
                                continue;
                        }

                        if (CodeSize == 0 || FileOffset + CodeSize > Data.Length)
                            continue;

                        ReadOnlySpan<byte> ILCode = DataSpan.Slice((int)FileOffset, (int)CodeSize);

                        int ParameterCount = 0;
                        foreach (ParameterHandle ParamHandle in MethodDef.GetParameters())
                        {
                            ParameterCount++;
                        }

                        BlobReader SignatureReader = MetadataReader.GetBlobReader(MethodDef.Signature);
                        byte Convention = SignatureReader.ReadByte();
                        bool IsInstance = (Convention & 0x20) != 0;
                        int Token = MetadataTokens.GetToken(MethodHandle);
                        if (!string.IsNullOrEmpty(MethodName))
                        {
                            int LocalsCount = 0;
                            if (ILCode != null)
                            {
                                MethodBodyBlock MethodBody = PEReader.GetMethodBody(MethodDef.RelativeVirtualAddress);
                                if (!MethodBody.LocalSignature.IsNil)
                                {
                                    StandaloneSignature LocalSignature = MetadataReader.GetStandaloneSignature(MethodBody.LocalSignature);

                                    // Get the signature blob reader to read the local variables count
                                    BlobReader LocalSignatureReader = MetadataReader.GetBlobReader(LocalSignature.Signature);
                                    SignatureHeader SigHeader = LocalSignatureReader.ReadSignatureHeader();
                                    if (SigHeader.Kind == SignatureKind.LocalVariables)
                                    {
                                        LocalsCount = LocalSignatureReader.ReadCompressedInteger();
                                    }
                                }
                            }

                            DotNetFunctionList.Add(new DotNetFunction
                            {
                                FunctionName = MethodName,
                                TypeName = TypeName,
                                RVA = RVA,
                                FileOffset = FileOffset,
                                CodeSize = CodeSize,
                                Flags = (ushort)MethodDef.Attributes,
                                Token = Token,
                                ParameterCount = ParameterCount,
                                LocalsCount = LocalsCount,
                                ImplFlags = (MethodImplementations)MethodDef.ImplAttributes,
                                ILCode = ILCode.ToArray(),
                                IsInstance = IsInstance,
                                DeclaringType = TypeNamespace + "." + TypeName,
                                AssemblyName = AssemblyName
                            });
                        }
                    }

                    foreach (PropertyDefinitionHandle PropertyHandle in TypeDef.GetProperties())
                    {
                        PropertyDefinition PropertyDef = MetadataReader.GetPropertyDefinition(PropertyHandle);
                        int Token = MetadataTokens.GetToken(PropertyHandle);
                        DotNetPropertyList.Add(new DotNetProperty
                        {
                            PropertyName = MetadataReader.GetString(PropertyDef.Name),
                            Token = Token
                        });
                    }

                    foreach (FieldDefinitionHandle FieldHandle in TypeDef.GetFields())
                    {
                        FieldDefinition FieldDef = MetadataReader.GetFieldDefinition(FieldHandle);
                        int Token = MetadataTokens.GetToken(FieldHandle);
                        DotNetFieldList.Add(new DotNetField()
                        {
                            FieldName = MetadataReader.GetString(FieldDef.Name),
                            Token = Token
                        });
                    }

                    DotNetTypeList.Add(new DotNetType
                    {
                        TypeName = TypeName,
                        Token = MetadataReader.GetToken(TypeHandle)
                    });
                }

                foreach (MemberReferenceHandle MemberHandle in MetadataReader.MemberReferences)
                {
                    MemberReference MemberRef = MetadataReader.GetMemberReference(MemberHandle);
                    string MemberName = MetadataReader.GetString(MemberRef.Name);
                    int Token = MetadataTokens.GetToken(MemberHandle);

                    string TypeNameMember = string.Empty;
                    string DeclaringType = string.Empty;
                    string AssemblyNameMember = string.Empty;

                    EntityHandle ParentHandle = MemberRef.Parent;
                    if (ParentHandle.Kind == HandleKind.TypeReference)
                    {
                        TypeReference TypeRef = MetadataReader.GetTypeReference((TypeReferenceHandle)ParentHandle);
                        TypeNameMember = MetadataReader.GetString(TypeRef.Name);
                        DeclaringType = MetadataReader.GetString(TypeRef.Namespace) + "." + TypeNameMember;

                        EntityHandle Scope = TypeRef.ResolutionScope;
                        if (Scope.Kind == HandleKind.AssemblyReference)
                        {
                            AssemblyReference AsmRef = MetadataReader.GetAssemblyReference((AssemblyReferenceHandle)Scope);
                            AssemblyNameMember = MetadataReader.GetString(AsmRef.Name);
                        }
                    }
                    else if (ParentHandle.Kind == HandleKind.TypeDefinition)
                    {
                        TypeDefinition TypeDefMember = MetadataReader.GetTypeDefinition((TypeDefinitionHandle)ParentHandle);
                        DeclaringType = MetadataReader.GetString(TypeDefMember.Namespace) + "." + MetadataReader.GetString(TypeDefMember.Name);

                        AssemblyDefinition AsmDefMember = MetadataReader.GetAssemblyDefinition();
                        AssemblyNameMember = MetadataReader.GetString(AsmDefMember.Name);
                    }
                    else
                    {
                        DeclaringType = ParentHandle.ToString();
                    }

                    // Read method signature blob
                    bool IsInstance = false;
                    BlobReader SignatureReader = MetadataReader.GetBlobReader(MemberRef.Signature);
                    SignatureHeader SignatureHeader = SignatureReader.ReadSignatureHeader();
                    IsInstance = SignatureHeader.IsInstance;

                    DotNetMemberList.Add(new DotNetMember
                    {
                        MemberName = MemberName,
                        Token = Token,
                        TypeName = TypeNameMember,
                        DeclaringType = DeclaringType,
                        AssemblyName = AssemblyNameMember,
                        IsInstance = IsInstance
                    });
                }
            }
            catch (Exception ex)
            {
                Utils.LogError($"[.NET Parser] Failed Parsing a .NET file: {ex.Message} (.NET Status: {(PE.DotNetStatus == DotNetStatus.DotNet ? "\".NET\"" : "\"Modified/Corrupted .NET\"")})");
            }

            DotNet.DotNetFunctions = DotNetFunctionList.ToArray();
            DotNet.DotNetProperties = DotNetPropertyList.ToArray();
            DotNet.DotNetFields = DotNetFieldList.ToArray();
            DotNet.DotNetTypes = DotNetTypeList.ToArray();
            DotNet.DotNetMembers = DotNetMemberList.ToArray();
            DotNet.MetaReader = MetadataReader;
        }

        /// <summary>
        /// Parse the PE import directory to extract imported functions.
        /// </summary>
        /// <param name="DosHeader">DOS Header of the PE file.</param>
        /// <param name="FileHeader">File Header of the PE file.</param>
        /// <param name="Is64Bit">Indicates if the PE is 64-bit.</param>
        private void ParsePEImports(IMAGE_DOS_HEADER DosHeader, IMAGE_FILE_HEADER FileHeader, bool Is64Bit)
        {
            uint ImportTableRva = 0;

            if (Is64Bit)
            {
                IMAGE_OPTIONAL_HEADER64 OptionalHeader64 = ReadStruct<IMAGE_OPTIONAL_HEADER64>(DataSpan, DosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>());

                ImportTableRva = OptionalHeader64.DataDirectory[1].VirtualAddress;
            }
            else
            {
                IMAGE_OPTIONAL_HEADER32 OptionalHeader32 = ReadStruct<IMAGE_OPTIONAL_HEADER32>(DataSpan, DosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>());

                ImportTableRva = OptionalHeader32.DataDirectory[1].VirtualAddress;
            }

            if (ImportTableRva == 0)
                return;

            if (!TryRvaToFileOffset(ImportTableRva, out uint ImportTableOffset))
                return;

            uint DescriptorSize = (uint)Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
            uint PointerSize = (uint)(Is64Bit ? 8 : 4);

            while (true)
            {
                if (ImportTableOffset + DescriptorSize > Data.Length)
                    break;

                IMAGE_IMPORT_DESCRIPTOR ImportDescriptor = ReadStruct<IMAGE_IMPORT_DESCRIPTOR>(DataSpan, (int)ImportTableOffset);

                // Check for end of import descriptors (null entry)
                if (ImportDescriptor.Name == 0 && ImportDescriptor.FirstThunk == 0 && ImportDescriptor.OriginalFirstThunk == 0)
                    break;

                // Get DLL name
                if (!TryRvaToFileOffset(ImportDescriptor.Name, out uint NameOffset))
                {
                    ImportTableOffset += DescriptorSize;
                    continue;
                }

                string DllName = ReadNullTerminatedString(DataSpan, (int)NameOffset);

                uint ThunkRva = ImportDescriptor.OriginalFirstThunk != 0 ? ImportDescriptor.OriginalFirstThunk : ImportDescriptor.FirstThunk;

                if (!TryRvaToFileOffset(ThunkRva, out uint ThunkOffset))
                {
                    ImportTableOffset += DescriptorSize;
                    continue;
                }

                if (!TryRvaToFileOffset(ImportDescriptor.FirstThunk, out uint IATOffset))
                {
                    ImportTableOffset += DescriptorSize;
                    continue;
                }

                int i = 0;

                while (true)
                {
                    uint ThunkEntryOffset = ThunkOffset + (uint)(i * PointerSize);
                    uint IATEntryOffset = IATOffset + (uint)(i * PointerSize);

                    ulong ThunkValue;
                    bool IsOrdinal;
                    string FunctionName;

                    ulong ImportAddressRVA = ImportDescriptor.FirstThunk + (uint)(i * PointerSize);

                    if (Is64Bit)
                    {
                        if (ThunkEntryOffset + 8 > Data.Length)
                            break;

                        ThunkValue = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(Data.AsSpan((int)ThunkEntryOffset, 8));

                        if (ThunkValue == 0)
                            break;

                        IsOrdinal = (ThunkValue & 0x8000000000000000) != 0;

                        if (IsOrdinal)
                        {
                            ushort Ordinal = (ushort)(ThunkValue & 0xFFFF);
                            FunctionName = $"Ordinal_{Ordinal:X}";
                        }
                        else
                        {
                            uint NameRva = (uint)(ThunkValue & 0x7FFFFFFFFFFFFFFF);

                            if (TryRvaToFileOffset(NameRva, out uint StringOffset))
                            {
                                if (StringOffset + 2 < Data.Length)
                                {
                                    ushort Hint = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan((int)StringOffset, 2));

                                    FunctionName = ReadNullTerminatedString(DataSpan, (int)StringOffset + 2);
                                }
                                else
                                {
                                    FunctionName = $"InvalidImport_{NameRva:X}";
                                }
                            }
                            else
                            {
                                FunctionName = $"UnknownImport_{NameRva:X}";
                            }
                        }
                    }
                    else
                    {
                        if (ThunkEntryOffset + 4 > Data.Length)
                            break;

                        uint ThunkValue32 = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(Data.AsSpan((int)ThunkEntryOffset, 4));

                        if (ThunkValue32 == 0)
                            break;

                        ThunkValue = ThunkValue32;
                        IsOrdinal = (ThunkValue32 & 0x80000000) != 0;

                        if (IsOrdinal)
                        {
                            ushort Ordinal = (ushort)(ThunkValue32 & 0xFFFF);
                            FunctionName = $"Ordinal_{Ordinal:X}";
                        }
                        else
                        {
                            uint NameRva = ThunkValue32 & 0x7FFFFFFF;

                            if (TryRvaToFileOffset(NameRva, out uint StringOffset))
                            {
                                if (StringOffset + 2 < Data.Length)
                                {
                                    ushort Hint = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan((int)StringOffset, 2));

                                    FunctionName = ReadNullTerminatedString(DataSpan, (int)StringOffset + 2);
                                }
                                else
                                {
                                    FunctionName = $"InvalidImport_{NameRva:X}";
                                }
                            }
                            else
                            {
                                FunctionName = $"UnknownImport_{NameRva:X}";
                            }
                        }
                    }

                    PE.ImportFunctions[ImportAddressRVA] = new PEImportFunction
                    {
                        LibraryName = DllName,
                        FunctionName = FunctionName,
                        ImportAddressRVA = ImportAddressRVA,
                        ImportLookupRVA = ((ThunkRva + (uint)(i * PointerSize))),
                        Offset = IATEntryOffset,
                        IsOrdinal = IsOrdinal,
                        Ordinal = IsOrdinal ? (ushort)(ThunkValue & 0xFFFF) : (ushort)0
                    };

                    i++;
                }

                ImportTableOffset += DescriptorSize;
            }
        }

        /// <summary>
        /// Scan forward from a function start offset and attempt to locate a termination boundary using epilogue patterns or INT3 padding.
        /// </summary>
        /// <param name="StartOffset">The file offset where the function begins.</param>
        /// <returns>The file offset where the function is considered to end.</returns>
        private uint FindFunctionEnd(uint StartOffset)
        {
            uint EndOffset = StartOffset;

            if (StartOffset >= (uint)Data.Length)
                return EndOffset;

            uint MaxSearch = StartOffset + 4096;
            uint MaxAllowed = (uint)Data.Length;

            if (MaxSearch > MaxAllowed)
                MaxSearch = MaxAllowed;

            byte[] InstructionBytes = new byte[16];

            for (uint EndSearch = StartOffset; EndSearch < MaxSearch; EndSearch++)
            {
                int Remaining = Data.Length - (int)EndSearch;
                if (Remaining <= 0)
                    break;

                int MaxLength = Remaining < 16 ? Remaining : 16;

                DataSpan.Slice((int)EndSearch, MaxLength).CopyTo(InstructionBytes);

                X86Instruction[] Instructions = Disassembler.Disassemble(InstructionBytes, EndSearch);
                if (Instructions.Length == 0)
                    continue;

                if (IsEpilogue(Instructions))
                {
                    EndOffset = EndSearch + (uint)Instructions[Instructions.Length - 1].Bytes.Length;
                    break;
                }

                if (IsInt3Padding(Instructions))
                {
                    bool IsInt3Sequence = true;

                    int Limit = Instructions.Length;
                    if (Limit > 4)
                        Limit = 4;

                    for (int i = 0; i < Limit; i++)
                    {
                        if (!IsInt3Padding(Instructions[i]))
                        {
                            IsInt3Sequence = false;
                            break;
                        }
                    }

                    if (IsInt3Sequence)
                    {
                        EndOffset = EndSearch;
                        break;
                    }
                }
            }

            return EndOffset;
        }

        /// <summary>
        /// Parse the ELF function names from the symbol table.
        /// </summary>
        private void ParseELFFunctions()
        {
            List<BinaryFunction> FunctionList = new List<BinaryFunction>();
            HashSet<uint> KnownOffsets = new HashSet<uint>();

            ulong EntryPoint = Architecture == BinaryArchitecture.x64 ? ReadStruct<ELF64_HEADER>(DataSpan, 0).e_entry : ReadStruct<ELF32_HEADER>(DataSpan, 0).e_entry;

            if (TryFindELFSectionByVaFast(EntryPoint, out ElfBinarySection EntrySection) && EntrySection.SectionName != null)
            {
                uint EntryOffset = EntrySection.RawOffset + (uint)(EntryPoint - EntrySection.VirtualAddress);
                uint EndOffset = FindFunctionEnd(EntryOffset);

                FunctionList.Add(new BinaryFunction
                {
                    FunctionName = "start",
                    Address = FileOffsetToRva(EntryOffset, ELF.Sections),
                    Offset = EntryOffset,
                    EndOffset = EndOffset
                });

                KnownOffsets.Add(EntryOffset);
            }

            foreach (ElfBinarySection Section in ELF.Sections)
            {
                if (Section.SectionName != ".symtab")
                    continue;

                ElfBinarySection StrTab = ELF.Sections.FirstOrDefault(s => s.SectionName == ".strtab");
                if (StrTab.SectionName == null)
                    continue;

                int SymbolSize = Architecture == BinaryArchitecture.x64 ? 24 : 16;
                int SymbolCount = (int)(Section.RawSize / SymbolSize);

                for (int i = 0; i < SymbolCount; i++)
                {
                    ulong SymbolValue;
                    uint SymbolSizeValue;
                    uint SymbolName;
                    byte SymbolInfo;

                    if (Architecture == BinaryArchitecture.x64)
                    {
                        ELF64_SYMBOL Symbol = ReadStruct<ELF64_SYMBOL>(DataSpan, (int)(Section.RawOffset + i * SymbolSize));
                        SymbolValue = Symbol.st_value;
                        SymbolSizeValue = (uint)Symbol.st_size;
                        SymbolName = Symbol.st_name;
                        SymbolInfo = Symbol.st_info;
                    }
                    else
                    {
                        ELF32_SYMBOL Symbol = ReadStruct<ELF32_SYMBOL>(DataSpan, (int)(Section.RawOffset + i * SymbolSize));
                        SymbolValue = Symbol.st_value;
                        SymbolSizeValue = Symbol.st_size;
                        SymbolName = Symbol.st_name;
                        SymbolInfo = Symbol.st_info;
                    }

                    if (SymbolInfo != 0x12 || SymbolName == 0)
                        continue;

                    if (!TryFindELFSectionByVaFast(SymbolValue, out ElfBinarySection SymbolSection) || SymbolSection.SectionName == null)
                        continue;

                    uint FileOffset = SymbolSection.RawOffset + (uint)(SymbolValue - SymbolSection.VirtualAddress);
                    if (KnownOffsets.Contains(FileOffset))
                        continue;

                    uint EndOffset = SymbolSizeValue > 0 && FileOffset + SymbolSizeValue < Data.Length ? FileOffset + SymbolSizeValue : FindFunctionEnd(FileOffset);

                    string Name = ReadNullTerminatedString(DataSpan, (int)(StrTab.RawOffset + SymbolName));
                    if (string.IsNullOrEmpty(Name))
                        continue;

                    FunctionList.Add(new BinaryFunction
                    {
                        FunctionName = Name,
                        Address = FileOffsetToRva(FileOffset, ELF.Sections),
                        Offset = FileOffset,
                        EndOffset = EndOffset
                    });

                    KnownOffsets.Add(FileOffset);
                }
            }

            int Count = FunctionList.Count;
            BinaryFunction[] Result = new BinaryFunction[Count];

            for (int i = 0; i < Count; i++)
            {
                Result[i] = FunctionList[i];
            }

            Functions = Result;
        }

        /// <summary>
        /// Parse the ELF import jumps from the PLT and GOT sections.
        /// </summary>
        /// <param name="Is64Bit">Indicates if the ELF is 64-bit.</param>
        private void ParseELFImports(bool Is64Bit)
        {

            // Find .plt, .got.plt, and .rela.plt or .rel.plt sections
            var PltSection = ELF.Sections.FirstOrDefault(s => s.SectionName == ".plt");
            var GotPltSection = ELF.Sections.FirstOrDefault(s => s.SectionName == ".got.plt");
            var RelaPltSection = ELF.Sections.FirstOrDefault(s =>
                s.SectionName == ".rela.plt" || s.SectionName == ".rel.plt");
            var DynSymSection = ELF.Sections.FirstOrDefault(s => s.SectionName == ".dynsym");
            var DynStrSection = ELF.Sections.FirstOrDefault(s => s.SectionName == ".dynstr");

            if (PltSection.SectionName == null || GotPltSection.SectionName == null ||
                RelaPltSection.SectionName == null || DynSymSection.SectionName == null ||
                DynStrSection.SectionName == null)
                return;

            // Read dynamic string table
            if (DynStrSection.RawOffset > Data.Length || DynStrSection.RawSize < 0)
                throw new IndexOutOfRangeException("Invalid .dynstr data.");

            long RawOffsetLong = DynStrSection.RawOffset;
            if (RawOffsetLong < 0 || RawOffsetLong >= Data.Length)
                throw new IndexOutOfRangeException("RawOffset is out of range.");

            int RawOffset = (int)RawOffsetLong;
            int RawSize = (int)DynStrSection.RawSize;

            int MaxReadable = Data.Length - RawOffset;
            int BytesToCopy = RawSize;
            if (BytesToCopy > MaxReadable)
                BytesToCopy = MaxReadable;

            ReadOnlySpan<byte> DynStr = DataSpan.Slice(RawOffset, BytesToCopy);

            // Create a map of symbol index to name
            int SymbolSize = Is64Bit ? 24 : 16; // if 64-bit arch, set to 24 (Elf64_Sym) and if not then use 16 (Elf32_Sym)
            int SymbolCount = (int)(DynSymSection.RawSize / SymbolSize);
            Dictionary<uint, string> SymbolNames = new Dictionary<uint, string>(SymbolCount);

            for (int i = 0; i < SymbolCount; i++)
            {
                if (Is64Bit)
                {
                    ELF64_SYMBOL Symbol = ReadStruct<ELF64_SYMBOL>(DataSpan, (int)DynSymSection.RawOffset + i * SymbolSize);
                    if (Symbol.st_name != 0)
                    {
                        ReadOnlySpan<byte> NameSlice = DynStr.Slice((int)Symbol.st_name);
                        int EndOff = NameSlice.IndexOf((byte)0);
                        if (EndOff != -1)
                        {
                            string Name = Encoding.ASCII.GetString(NameSlice.Slice(0, EndOff));
                            SymbolNames[(uint)i] = Name;
                        }
                    }
                }
                else
                {
                    ELF32_SYMBOL Symbol = ReadStruct<ELF32_SYMBOL>(DataSpan, (int)DynSymSection.RawOffset + i * SymbolSize);
                    if (Symbol.st_name != 0)
                    {
                        ReadOnlySpan<byte> NameSlice = DynStr.Slice((int)Symbol.st_name);
                        int EndOff = NameSlice.IndexOf((byte)0);
                        if (EndOff != -1)
                        {
                            string Name = Encoding.ASCII.GetString(NameSlice.Slice(0, EndOff));
                            SymbolNames[(uint)i] = Name;
                        }
                    }
                }
            }

            // Parse relocation entries
            int RelSize = Is64Bit ? 24 : 8;
            int RelCount = (int)(RelaPltSection.RawSize / RelSize);

            for (int i = 0; i < RelCount; i++)
            {
                uint SymbolIndex;
                uint Offset;

                if (Is64Bit)
                {
                    ELF64_RELA Rela = ReadStruct<ELF64_RELA>(DataSpan, (int)RelaPltSection.RawOffset + i * RelSize);
                    SymbolIndex = (uint)(Rela.r_info >> 32);
                    Offset = (uint)Rela.r_offset;
                }
                else
                {
                    ELF32_REL Rel = ReadStruct<ELF32_REL>(DataSpan, (int)RelaPltSection.RawOffset + i * RelSize);
                    SymbolIndex = Rel.r_info >> 8;
                    Offset = Rel.r_offset;
                }

                if (SymbolNames.TryGetValue(SymbolIndex, out string SymbolName))
                {
                    // PLT entry is 16 bytes on both 32-bit and 64-bit
                    uint VirtualAddress = PltSection.VirtualAddress + 16 + (uint)(i * 16);
                    ulong PltOffset = VirtualAddressToFileOffset(VirtualAddress, PltSection);
                    ELF.ImportFunctions[PltOffset] = new ELFImportFunction
                    {
                        FunctionName = $"plt_{SymbolName}",
                        JumpOffset = (uint)PltOffset,
                        ImportedFunction = SymbolName,
                        GotEntry = Offset
                    };
                }
            }
        }

        /// <summary>
        /// Get Functions Map which contains the function offset with its name.
        /// </summary>
        /// <returns>Returns a dictionary containing the offset and function name.</returns>
        public Dictionary<ulong, string> GetFunctionsMap(bool IncludeImports, bool IncludeExports, bool ImageBaseIncluded)
        {
            if (this.FileFormat == BinaryFormat.PE)
            {
                if (Functions != null)
                {
                    Dictionary<ulong, string> FunctionMap = this.Functions
                        .Where(f => f.FunctionName != null)
                        .GroupBy(f => (ulong)f.Offset)
                        .ToDictionary(
                            g => g.Key,
                            g => g.First().FunctionName
                        );

                    if (IncludeImports && PE.ImportFunctions != null)
                    {
                        foreach (PEImportFunction Import in this.PE.ImportFunctions.Values)
                        {
                            ulong IATEntryPoint = ImageBaseIncluded ? PE.ImageBase + Import.ImportAddressRVA : Import.ImportAddressRVA;
                            if (!FunctionMap.ContainsKey(IATEntryPoint))
                            {
                                FunctionMap.Add(IATEntryPoint, Import.FunctionName);
                            }
                        }
                    }

                    if (IncludeExports && ExportFunctions != null)
                    {
                        foreach (BinaryFunction Export in this.ExportFunctions)
                        {
                            ulong Offset = ImageBaseIncluded ? PE.ImageBase + (ulong)Export.Offset : Export.Offset;
                            if (!FunctionMap.ContainsKey(Offset))
                            {
                                FunctionMap.Add(Offset, Export.FunctionName);
                            }
                        }
                    }

                    return FunctionMap;
                }
            }
            else if (this.FileFormat == BinaryFormat.ELF)
            {
                if (Functions != null)
                {
                    Dictionary<ulong, string> FunctionMap = this.Functions
                        .Where(f => f.FunctionName != null)
                        .GroupBy(f => (ulong)f.Offset)
                        .ToDictionary(
                            g => g.Key,
                            g => g.First().FunctionName
                        );

                    if (IncludeImports && ELF.ImportFunctions != null)
                    {
                        foreach (var PLTEntry in this.ELF.ImportFunctions.Values)
                        {
                            ulong JumpOffset = (ulong)PLTEntry.JumpOffset;
                            if (!FunctionMap.ContainsKey(JumpOffset))
                            {
                                FunctionMap.Add(JumpOffset, PLTEntry.ImportedFunction);
                            }
                        }
                    }

                    return FunctionMap;
                }
            }

            return null;
        }


        /// <summary>
        /// Checks whether the binary has obvious structural corruption.
        /// </summary>
        /// <returns>The binary corruption status, or <see cref="BinaryCorruptionStatus.Unknown"/> when the binary format could not be determined.</returns>
        /// <remarks>
        /// <para>
        /// </para>
        /// <para>
        /// Run this after loading a binary so later components can assume the core binary metadata is usable.
        /// </para>
        /// </remarks>
        public BinaryCorruptionStatus IsCorruptedBinary(out string Reason)
        {
            Reason = null;
            try
            {
                if (FileFormat == BinaryFormat.PE)
                {
                    if (Architecture == BinaryArchitecture.Unknown)
                    {
                        Reason = "Unsupported architecture";
                        return BinaryCorruptionStatus.Corrupted;
                    }

                    if (PE.Sections == null || PE.Sections.Length == 0)
                    {
                        Reason = "No sections found";
                        return BinaryCorruptionStatus.Corrupted;
                    }

                    if (PE.SizeOfHeaders <= 0 || PE.SizeOfImage <= 0)
                    {
                        Reason = "Invalid size of headers or SizeOfImage";
                        return BinaryCorruptionStatus.Corrupted;
                    }

                    if (PE.DotNetStatus == DotNetStatus.DotNet)
                        return BinaryCorruptionStatus.Clean;

                    if (EntryPoint <= 0 || EntryPoint >= PE.SizeOfImage)
                    {
                        Reason = "EntryPoint outside binary range.";
                        return BinaryCorruptionStatus.Corrupted;
                    }

                    if (!Quick)
                    {
                        if (Functions == null || Functions.Length == 0)
                        {
                            Reason = "No function found or parsed.";
                            return BinaryCorruptionStatus.Corrupted;
                        }
                    }

                    bool CodeSection = false;
                    bool MainCodeSection = false;

                    foreach (PortableBinarySection Section in PE.Sections)
                    {
                        if (Section.VirtualAddress < 0 || Section.VirtualSize < 0 || Section.RawSize < 0 || Section.RawOffset < 0 || Section.RawOffset > Data.Length)
                            return BinaryCorruptionStatus.Corrupted;

                        if (Section.Characteristics.HasFlag(SectionCharacteristics.ContainsCode) || Section.Characteristics.HasFlag(SectionCharacteristics.MemExecute))
                        {
                            CodeSection = true;

                            if (EntryPoint >= Section.VirtualAddress && EntryPoint < Section.VirtualAddress + Math.Max(Section.VirtualSize, Section.RawSize))
                            {
                                MainCodeSection = true;

                                if (Section.VirtualSize == 0 || Section.RawSize == 0)
                                    return BinaryCorruptionStatus.Corrupted;
                            }
                        }
                    }

                    if (!CodeSection || !MainCodeSection)
                    {
                        Reason = $"{(!CodeSection ? "No Code Section available in the binary" : "The section containing the EntryPoint is not found")}.";
                        return BinaryCorruptionStatus.Corrupted;
                    }

                    if (PE.SectionAlignment < 0x200 || PE.FileAlignment < 0x200)
                    {
                        Reason = "The section alignment looks unusual.";
                        return BinaryCorruptionStatus.Corrupted;
                    }

                    return BinaryCorruptionStatus.Clean;
                }
                else if (FileFormat == BinaryFormat.ELF)
                {
                    if (Architecture == BinaryArchitecture.Unknown)
                        return BinaryCorruptionStatus.Corrupted;

                    if (ELF.Sections == null || ELF.Sections.Length == 0)
                        return BinaryCorruptionStatus.Corrupted;

                    if (EntryPoint <= 0)
                        return BinaryCorruptionStatus.Corrupted;

                    if (Functions == null || Functions.Length == 0)
                        return BinaryCorruptionStatus.Corrupted;

                    bool CodeSection = false;
                    bool MainCodeSection = false;

                    foreach (ElfBinarySection Section in ELF.Sections)
                    {
                        if (Section.VirtualAddress < 0 || Section.VirtualSize < 0 || Section.RawSize < 0 || Section.RawOffset < 0 || Section.RawOffset > Data.Length)
                            return BinaryCorruptionStatus.Corrupted;

                        if (Section.Characteristics.HasFlag(ElfSectionCharacteristics.ExecInstr))
                        {
                            CodeSection = true;

                            if (EntryPoint >= Section.VirtualAddress && EntryPoint < Section.VirtualAddress + Math.Max(Section.VirtualSize, Section.RawSize))
                            {
                                MainCodeSection = true;

                                if (Section.VirtualSize == 0 || Section.RawSize == 0)
                                    return BinaryCorruptionStatus.Corrupted;
                            }
                        }
                    }

                    if (!CodeSection || !MainCodeSection)
                        return BinaryCorruptionStatus.Corrupted;

                    return BinaryCorruptionStatus.Clean;
                }
            }
            catch
            {
                // most likely corrupted if it reaches here
                return BinaryCorruptionStatus.Corrupted;
            }

            return BinaryCorruptionStatus.Unknown;
        }

        /// <summary>
        /// Get the format of a binary.
        /// </summary>
        /// <param name="Data">Data of the binary.</param>
        /// <returns>returns the binary format.</returns>
        /// <remarks>Primarily used to be a lightweight alternative to full parsing to inspect binaries quickly.</remarks>
        public static BinaryFormat GetBinaryFormat(byte[] Data)
        {
            foreach (var BinaryMagicNumber in BinaryMagicNumbers)
            {
                byte[] MagicBytes = BinaryMagicNumber.Value;
                if (Data.Length >= MagicBytes.Length)
                {
                    bool Valid = true;
                    for (int i = 0; i < MagicBytes.Length; i++)
                    {
                        if (MagicBytes[i] != Data[i])
                        {
                            Valid = false;
                            break;
                        }
                    }

                    if (Valid)
                    {
                        return BinaryMagicNumber.Key;
                    }
                }
            }
            return BinaryFormat.Unknown;
        }

        /// <summary>
        /// Get the architecture of a binary.
        /// </summary>
        /// <param name="Data">Data of the binary.</param>
        /// <param name="Format">The format of the binary.</param>
        /// <returns>returns the binary format.</returns>
        /// <remarks>Primarily used to be a lightweight alternative to full parsing to inspect binaries quickly.</remarks>
        public static BinaryArchitecture GetBinaryArch(byte[] Data, BinaryFormat Format)
        {
            if (Format != BinaryFormat.Unknown)
            {
                if (Format == BinaryFormat.PE)
                {
                    if (Data.Length < 0x40)
                        return BinaryArchitecture.Unknown;

                    int PEHeaderOffset = BitConverter.ToInt32(Data, 0x3C);
                    if (PEHeaderOffset + 6 >= Data.Length)
                        return BinaryArchitecture.Unknown;

                    ushort Machine = BitConverter.ToUInt16(Data, PEHeaderOffset + 4);
                    if (Machine == 0x014C)
                    {
                        return BinaryArchitecture.x86;
                    }
                    else if (Machine == 0x8664)
                    {
                        return BinaryArchitecture.x64;
                    }
                }
                else if (Format == BinaryFormat.ELF)
                {
                    if (Data.Length < 4)
                        return BinaryArchitecture.Unknown;

                    byte ElfClass = Data[4];
                    bool Is64Bit = ElfClass == 2;
                    if (Is64Bit)
                        return BinaryArchitecture.x64;
                    else
                        return BinaryArchitecture.x86;
                }
            }
            return BinaryArchitecture.Unknown;
        }

        /// <summary>
        /// Clone the current BinaryFile class with all it's information.
        /// </summary>
        /// <returns>returns a cloned copy of the BinaryFile class.</returns>
        public BinaryFile Clone()
        {
            return new BinaryFile(this);
        }

        /// <summary>
        /// Initialize the Binary File instance with a file path.
        /// </summary>
        /// <param name="BinaryPath">The Path of the Binary to be parsed.</param>
        /// <exception cref="FileNotFoundException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="IndexOutOfRangeException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="OverflowException"></exception>
        public BinaryFile(string BinaryPath, bool Quick)
        {
            PE = new PortableExecutable();
            ELF = new ELF();
            DotNet = new DotNet();
            if (!File.Exists(BinaryPath))
                throw new FileNotFoundException($"The binary file \"{BinaryPath}\" couldn't be found in the path.");
            Data = new MappedMemoryBytes(BinaryPath);
            this.Quick = Quick;
            ParseBinary(Data.AsSpan());
            this.Location = Path.GetFullPath(BinaryPath);
            this.RvaToFileOffsetCache?.Clear();
            this.RvaToFileOffsetCache = null;
        }

        /// <summary>
        /// Initialize the Binary File instance with a byte array.
        /// </summary>
        /// <param name="BinaryData">The byte array of the binary to be parsed.</param>
        /// <exception cref="NullReferenceException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="IndexOutOfRangeException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="OverflowException"></exception>
        public BinaryFile(byte[] BinaryData, bool Quick)
        {
            if (BinaryData == null || BinaryData.Length == 0)
                throw new NullReferenceException("Binary data cannot be null or empty.");
            PE = new PortableExecutable();
            ELF = new ELF();
            DotNet = new DotNet();
            Data = new MappedMemoryBytes(BinaryData);
            this.Quick = Quick;
            ParseBinary(Data.AsSpan());
            this.Location = null;
        }

        /// <summary>
        /// Initialize the Binary File instance with a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        /// <param name="BinaryData">The span of the binary to be parsed.</param>
        /// <exception cref="NullReferenceException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="IndexOutOfRangeException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="OverflowException"></exception>
        public BinaryFile(ReadOnlySpan<byte> BinaryData, bool Quick)
        {
            if (BinaryData == null || BinaryData.Length == 0)
                throw new NullReferenceException("Binary data cannot be null or empty.");
            PE = new PortableExecutable();
            ELF = new ELF();
            DotNet = new DotNet();
            Data = new MappedMemoryBytes(BinaryData);
            this.Quick = Quick;
            ParseBinary(Data.AsSpan());
            this.Location = null;
        }

        /// <summary>
        /// Copy constructor for BinaryFile, used by Clone().
        /// </summary>
        /// <param name="Copy">The original BinaryFile to clone.</param>
        private BinaryFile(BinaryFile Copy)
        {
            if (Copy == null)
                throw new ArgumentNullException(nameof(Copy));

            this.FileFormat = Copy.FileFormat;
            this.BinarySize = Copy.BinarySize;
            this.Architecture = Copy.Architecture;
            this.EntryPoint = Copy.EntryPoint;
            this.Location = Copy.Location;

            if (Copy.Functions != null && Copy.Functions.Length > 0)
            {
                BinaryFunction[] Functions = new BinaryFunction[Copy.Functions.Length];
                for (int i = 0; i < Copy.Functions.Length; i++)
                {
                    BinaryFunction Original = Copy.Functions[i];
                    BinaryFunction BinFunction = new BinaryFunction();

                    BinFunction.Arguments = Original.Arguments?.ToArray();
                    BinFunction.FunctionName = Original.FunctionName;
                    BinFunction.Locals = Original.Locals?.ToArray();
                    BinFunction.EndOffset = Original.EndOffset;
                    BinFunction.Address = Original.Address;
                    BinFunction.EndAddress = Original.EndAddress;
                    BinFunction.Code = Original.Code?.ToArray();
                    BinFunction.DisassembledCode = Original.DisassembledCode;
                    BinFunction.RegisterArguments = Original.RegisterArguments?.ToArray();

                    Functions[i] = BinFunction;
                }
                this.Functions = Functions;
            }
            else
            {
                this.Functions = Array.Empty<BinaryFunction>();
            }

            if (Copy.ExportFunctions != null && Copy.ExportFunctions.Length > 0)
            {
                BinaryFunction[] ExportFunctions = new BinaryFunction[Copy.ExportFunctions.Length];
                for (int i = 0; i < Copy.ExportFunctions.Length; i++)
                {
                    BinaryFunction Original = Copy.ExportFunctions[i];
                    BinaryFunction BinFunction = new BinaryFunction();

                    BinFunction.Arguments = Original.Arguments?.ToArray();
                    BinFunction.FunctionName = Original.FunctionName;
                    BinFunction.Locals = Original.Locals?.ToArray();
                    BinFunction.EndOffset = Original.EndOffset;
                    BinFunction.Address = Original.Address;
                    BinFunction.EndAddress = Original.EndAddress;
                    BinFunction.Code = Original.Code?.ToArray();
                    BinFunction.DisassembledCode = Original.DisassembledCode;
                    BinFunction.RegisterArguments = Original.RegisterArguments?.ToArray();

                    ExportFunctions[i] = BinFunction;
                }
                this.ExportFunctions = ExportFunctions;
            }
            else
            {
                this.ExportFunctions = Array.Empty<BinaryFunction>();
            }

            if (Copy.PE != null)
            {
                this.PE = new PortableExecutable()
                {
                    Subsystem = Copy.PE.Subsystem,
                    CheckSum = Copy.PE.CheckSum,
                    ImageBase = Copy.PE.ImageBase,
                    SizeOfImage = Copy.PE.SizeOfImage,
                    SizeOfHeaders = Copy.PE.SizeOfHeaders,
                    BaseOfCode = Copy.PE.BaseOfCode,
                    FileAlignment = Copy.PE.FileAlignment,
                    SectionAlignment = Copy.PE.SectionAlignment,
                    Characteristics = Copy.PE.Characteristics,
                    DllCharacteristics = Copy.PE.DllCharacteristics,
                    DotNetStatus = Copy.PE.DotNetStatus,
                    Sections = Copy.PE.Sections?.Select(s => new PortableBinarySection
                    {
                        SectionName = s.SectionName,
                        VirtualAddress = s.VirtualAddress,
                        VirtualSize = s.VirtualSize,
                        RawOffset = s.RawOffset,
                        RawSize = s.RawSize,
                        Characteristics = s.Characteristics
                    }).ToArray() ?? Array.Empty<PortableBinarySection>(),
                    ImportFunctions = Copy.PE.ImportFunctions != null
                        ? new Dictionary<ulong, PEImportFunction>(
                            Copy.PE.ImportFunctions.ToDictionary(kvp => kvp.Key, kvp => new PEImportFunction
                            {
                                FunctionName = kvp.Value.FunctionName,
                                ImportAddressRVA = kvp.Value.ImportAddressRVA,
                                ImportLookupRVA = kvp.Value.ImportLookupRVA,
                                IsOrdinal = kvp.Value.IsOrdinal,
                                LibraryName = kvp.Value.LibraryName,
                                Offset = kvp.Value.Offset,
                                Ordinal = kvp.Value.Ordinal
                            }))
                        : new Dictionary<ulong, PEImportFunction>()
                };
            }

            if (Copy.DotNet != null)
            {
                this.DotNet = new DotNet()
                {
                    DotNetFunctions = Copy.DotNet.DotNetFunctions?.Select(f => new DotNetFunction
                    {
                        FunctionName = f.FunctionName,
                        ParameterCount = f.ParameterCount,
                        FileOffset = f.FileOffset,
                        Flags = f.Flags,
                        ImplFlags = f.ImplFlags,
                        AssemblyName = f.AssemblyName,
                        RVA = f.RVA,
                        CodeSize = f.CodeSize,
                        DeclaringType = f.DeclaringType,
                        ILCode = f.ILCode?.ToArray(),
                        ILString = f.ILString,
                        Instance = f.Instance,
                        IsInstance = f.IsInstance,
                        LocalsCount = f.LocalsCount,
                        Token = f.Token,
                        TypeName = f.TypeName
                    }).ToArray() ?? Array.Empty<DotNetFunction>(),

                    DotNetProperties = Copy.DotNet.DotNetProperties?.Select(p => new DotNetProperty
                    {
                        PropertyName = p.PropertyName,
                        Token = p.Token,
                    }).ToArray() ?? Array.Empty<DotNetProperty>(),

                    DotNetFields = Copy.DotNet.DotNetFields?.Select(f => new DotNetField
                    {
                        FieldName = f.FieldName,
                        Token = f.Token
                    }).ToArray() ?? Array.Empty<DotNetField>(),

                    DotNetTypes = Copy.DotNet.DotNetTypes?.Select(t => new DotNetType
                    {
                        TypeName = t.TypeName,
                        Token = t.Token
                    }).ToArray() ?? Array.Empty<DotNetType>(),

                    DotNetMembers = Copy.DotNet.DotNetMembers?.Select(m => new DotNetMember
                    {
                        MemberName = m.MemberName,
                        Token = m.Token,
                        AssemblyName = m.AssemblyName,
                        DeclaringType = m.DeclaringType,
                        IsInstance = m.IsInstance,
                        TypeName = m.TypeName
                    }).ToArray() ?? Array.Empty<DotNetMember>(),

                    MetaReader = null
                };
            }

            if (Copy.ELF != null)
            {
                this.ELF = new ELF()
                {
                    Type = Copy.ELF.Type,
                    Version = Copy.ELF.Version,
                    Flags = Copy.ELF.Flags,
                    HeaderSize = Copy.ELF.HeaderSize,
                    ProgramHeaderSize = Copy.ELF.ProgramHeaderSize,
                    ProgramHeaderCount = Copy.ELF.ProgramHeaderCount,
                    SectionHeaderSize = Copy.ELF.SectionHeaderSize,
                    SectionHeaderCount = Copy.ELF.SectionHeaderCount,
                    SectionNameIndex = Copy.ELF.SectionNameIndex,
                    Sections = Copy.ELF.Sections?.Select(s => new ElfBinarySection
                    {
                        SectionName = s.SectionName,
                        RawOffset = s.RawOffset,
                        RawSize = s.RawSize,
                        Characteristics = s.Characteristics,
                        VirtualSize = s.VirtualSize,
                        VirtualAddress = s.VirtualAddress
                    }).ToArray() ?? Array.Empty<ElfBinarySection>(),

                    ImportFunctions = Copy.ELF.ImportFunctions != null
                ? new Dictionary<ulong, ELFImportFunction>(
                    Copy.ELF.ImportFunctions.ToDictionary(kvp => kvp.Key, kvp => new ELFImportFunction
                    {
                        FunctionName = kvp.Value.FunctionName,
                        VirtualAddress = kvp.Value.VirtualAddress,
                        GotEntry = kvp.Value.GotEntry,
                        ImportedFunction = kvp.Value.ImportedFunction,
                        JumpOffset = kvp.Value.JumpOffset
                    }))
                : new Dictionary<ulong, ELFImportFunction>()
                };
            }

            this.IsDisposed = false;
        }

        /// <summary>
        /// Clear a byte array after checking for it's availability.
        /// </summary>
        /// <param name="array">Array to clear.</param>
        private void ClearArray(Array array)
        {
            if (array != null)
            {
                Array.Clear(array);
                array = null;
            }
        }

        /// <summary>
        /// Dispose resources in the class (PE/ELF/DotNet information, exports, imports, etc).
        /// </summary>
        public void Dispose()
        {
            if (IsDisposed)
                return;

            // Dispose collected binary information
            ELF.ImportFunctions?.Clear();
            PE.ImportFunctions?.Clear();
            ClearArray(Functions);
            ClearArray(ExportFunctions);
            ClearArray(PE.Sections);
            ClearArray(ELF.Sections);
            ClearArray(DotNet.DotNetFunctions);
            ClearArray(DotNet.DotNetProperties);
            ClearArray(DotNet.DotNetFields);
            ClearArray(DotNet.DotNetTypes);
            ClearArray(DotNet.DotNetMembers);

            // Set objects to null
            PE = null;
            ELF = null;
            DotNet = null;
            if (Data != null)
            {
                Data.Dispose();
                Data = null;
            }

            IsDisposed = true;
            GC.SuppressFinalize(this);
        }

        ~BinaryFile() => Dispose();
    }
}
