using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Brovan.Analysis;
using Microsoft.Win32.SafeHandles;
using static System.Collections.Specialized.BitVector32;

namespace Brovan.Core.Helpers
{
    public class BinaryHelpers
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;

            public fixed ushort e_res1[4];

            public ushort e_oemid;
            public ushort e_oeminfo;

            public fixed ushort e_res2[10];

            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct IMAGE_NT_HEADERS32
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            private fixed uint _DataDirectory[16 * 2];

            public unsafe ReadOnlySpan<IMAGE_DATA_DIRECTORY> DataDirectory
            {
                get
                {
                    fixed (uint* DataDirPtr = _DataDirectory)
                    {
                        return new ReadOnlySpan<IMAGE_DATA_DIRECTORY>(DataDirPtr, 16);
                    }
                }
            }

            public IMAGE_DATA_DIRECTORY ExportTable
            {
                get { return DataDirectory[0]; }
            }

            public IMAGE_DATA_DIRECTORY ImportTable
            {
                get { return DataDirectory[1]; }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            private fixed uint _DataDirectory[16 * 2];
            public unsafe ReadOnlySpan<IMAGE_DATA_DIRECTORY> DataDirectory
            {
                get
                {
                    fixed (uint* DataDirPtr = _DataDirectory)
                    {
                        return new ReadOnlySpan<IMAGE_DATA_DIRECTORY>(DataDirPtr, 16);
                    }
                }
            }

            public IMAGE_DATA_DIRECTORY ExportTable
            {
                get { return DataDirectory[0]; }
            }

            public IMAGE_DATA_DIRECTORY ImportTable
            {
                get { return DataDirectory[1]; }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_COR20_HEADER
        {
            public uint cb;
            public ushort MajorRuntimeVersion;
            public ushort MinorRuntimeVersion;
            public IMAGE_DATA_DIRECTORY MetaData;
            public uint Flags;
            public uint EntryPointToken;
            public IMAGE_DATA_DIRECTORY Resources;
            public IMAGE_DATA_DIRECTORY StrongNameSignature;
            public IMAGE_DATA_DIRECTORY CodeManagerTable;
            public IMAGE_DATA_DIRECTORY VTableFixups;
            public IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
            public IMAGE_DATA_DIRECTORY ManagedNativeHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public unsafe struct IMAGE_SECTION_HEADER
        {
            private fixed byte _Name[8];

            public ReadOnlySpan<byte> Name
            {
                get
                {
                    fixed (byte* p = _Name)
                    {
                        return new ReadOnlySpan<byte>(p, 8);
                    }
                }
            }

            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct ELF32_HEADER
        {
            public fixed byte e_ident[16];
            public ushort e_type;
            public ushort e_machine;
            public uint e_version;
            public uint e_entry;
            public uint e_phoff;
            public uint e_shoff;
            public uint e_flags;
            public ushort e_ehsize;
            public ushort e_phentsize;
            public ushort e_phnum;
            public ushort e_shentsize;
            public ushort e_shnum;
            public ushort e_shstrndx;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ELF32_PROGRAM_HEADER
        {
            public uint p_type;
            public uint p_offset;
            public uint p_vaddr;
            public uint p_paddr;
            public uint p_filesz;
            public uint p_memsz;
            public uint p_flags;
            public uint p_align;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ELF32_SECTION_HEADER
        {
            public uint sh_name;
            public uint sh_type;
            public uint sh_flags;
            public uint sh_addr;
            public uint sh_offset;
            public uint sh_size;
            public uint sh_link;
            public uint sh_info;
            public uint sh_addralign;
            public uint sh_entsize;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct ELF64_HEADER
        {
            public fixed byte e_ident[16];
            public ushort e_type;
            public ushort e_machine;
            public uint e_version;
            public ulong e_entry;
            public ulong e_phoff;
            public ulong e_shoff;
            public uint e_flags;
            public ushort e_ehsize;
            public ushort e_phentsize;
            public ushort e_phnum;
            public ushort e_shentsize;
            public ushort e_shnum;
            public ushort e_shstrndx;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ELF64_SECTION_HEADER
        {
            public uint sh_name;
            public uint sh_type;
            public ulong sh_flags;
            public ulong sh_addr;
            public ulong sh_offset;
            public ulong sh_size;
            public uint sh_link;
            public uint sh_info;
            public ulong sh_addralign;
            public ulong sh_entsize;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ELF64_PROGRAM_HEADER
        {
            public uint p_type;
            public uint p_flags;
            public ulong p_offset;
            public ulong p_vaddr;
            public ulong p_paddr;
            public ulong p_filesz;
            public ulong p_memsz;
            public ulong p_align;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ELF32_SYMBOL
        {
            public uint st_name;
            public uint st_value;
            public uint st_size;
            public byte st_info;
            public byte st_other;
            public ushort st_shndx;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ELF64_SYMBOL
        {
            public uint st_name;
            public byte st_info;
            public byte st_other;
            public ushort st_shndx;
            public ulong st_value;
            public ulong st_size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ELF64_RELA
        {
            public ulong r_offset;
            public ulong r_info;
            public long r_addend;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ELF32_REL
        {
            public uint r_offset;
            public uint r_info;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        public enum BinaryFormat
        {
            Unknown = 1,
            PE = 2,
            ELF = 3,
        }

        public enum BinaryArchitecture
        {
            Unknown = 0,
            x86 = 1,
            x64 = 2,
        }

        public struct PortableBinarySection
        {
            public string SectionName;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint RawSize;
            public uint RawOffset;
            public SectionCharacteristics Characteristics;
        }

        public struct ElfBinarySection
        {
            public string SectionName;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint RawSize;
            public uint RawOffset;
            public ElfSectionCharacteristics Characteristics;
        }

        public struct ImportedFunction
        {
            public string LibraryName;
            public string FunctionName;
            public uint RVA;
        }

        [Flags]
        public enum DllCharacteristics : uint
        {
            None = 0x0,
            HighEntropy = 0x0020,
            DynamicBase = 0x0040,
            ForceIntegrity = 0x0080,
            NxCompat = 0x0100,
            NoIsolation = 0x0200,
            NoSeh = 0x0400,
            NoBind = 0x0800,
            WdmDriver = 0x2000,
            ControlFlowGuard = 0x4000,
            TerminalServerAware = 0x8000,
        }

        [Flags]
        public enum ElfSectionCharacteristics : uint
        {
            Write = 0x1,
            Alloc = 0x2,
            ExecInstr = 0x4,
        }

        /// <summary>
        /// Binary Function.
        /// </summary>
        public struct BinaryFunction
        {
            /// <summary>
            /// The function name.
            /// </summary>
            public string FunctionName;

            /// <summary>
            /// Virtual address of the function.
            /// </summary>
            public ulong Address;

            /// <summary>
            /// End of the virtual address of the function.
            /// </summary>
            public ulong EndAddress;

            /// <summary>
            /// The offset of the function in the binary.
            /// </summary>
            public uint Offset;

            /// <summary>
            /// The offset that indicates the end of the function.
            /// </summary>
            public uint EndOffset;

            /// <summary>
            /// The code of the function (only gets set if analyzing the binary, not parsing).
            /// </summary>
            public X86Instruction[] Code;

            /// <summary>
            /// The disassembled code of the function (only gets set if analyzing the binary, not parsing).
            /// </summary>
            public string DisassembledCode;

            /// <summary>
            /// Discovered local stack variables (may be empty if stack analysis not performed).
            /// </summary>
            public StackVariable[] Locals;

            /// <summary>
            /// Discovered stack-passed arguments (heuristic; for x64 only stack spill / >4th args appear here).
            /// </summary>
            public StackVariable[] Arguments;

            /// <summary>
            /// Discovered register-based arguments (x64: rcx, rdx, r8, r9) or fastcall/thiscall candidates on x86.
            /// </summary>
            public StackVariable[] RegisterArguments;
        }

        /// <summary>
        /// Represents a stack variable (local or argument) discovered by analysis.
        /// </summary>
        public struct StackVariable
        {
            /// <summary>
            /// Variable name (auto-generated, e.g., local_20h, arg_18h).
            /// </summary>
            public string Name;

            /// <summary>
            /// Stack offset relative to frame pointer (rbp/ebp). Locals are negative, arguments positive.
            /// </summary>
            public int Offset;

            /// <summary>
            /// Inferred size in bytes (from access width hints). 0 if unknown.
            /// </summary>
            public int Size;
        }

        public struct AnalyzationSettings
        {
            /// <summary>
            /// Resolve IAT/Import stubs.
            /// </summary>
            public bool ResolveStubs;

            /// <summary>
            /// Resolve push + ret as a jmp.
            /// </summary>
            public bool ResolvePushRet;

            /// <summary>
            /// When true, only transform push+ret thunks if no stack pointer modifications or other instructions (besides NOPs) occur between them and the operand is a simple reg/imm/mem not referencing rsp/esp.
            /// </summary>
            public bool StrictPushRetValidation;

            /// <summary>
            /// Analyze stack variables.
            /// </summary>
            public bool AnalyzeStack;

            /// <summary>
            /// Enable parallel disassembly to disassemble functions faster.
            /// </summary>
            public bool EnableParallelDisassembly;

            /// <summary>
            /// The minimum functions to have to use parallel disassembly.
            /// </summary>
            public int ParallelMinFunctionCount;
        }

        public enum MethodImplementations
        {
            IL = 0,
            Managed = 0,
            Native = 1,
            OPTIL = 2,
            CodeTypeMask = 3,
            Runtime = 3,
            ManagedMask = 4,
            Unmanaged = 4,
            NoInlining = 8,
            ForwardRef = 16,
            Synchronized = 32,
            NoOptimization = 64,
            PreserveSig = 128,
            AggressiveInlining = 256,
            AggressiveOptimization = 512,
            InternalCall = 4096,
            MaxMethodImplVal = 65535
        }

        public struct DotNetFunction
        {
            /// <summary>
            /// The function name.
            /// </summary>
            public string FunctionName;

            /// <summary>
            /// The type name of the function.
            /// </summary>
            public string TypeName;
            
            /// <summary>
            /// The RVA (Relative Virtual Address) of the method.
            /// </summary>
            public uint RVA;
            
            /// <summary>
            /// The file offset of the method.
            /// </summary>
            public uint FileOffset;
            
            /// <summary>
            /// The IL code size of the method.
            /// </summary>
            public uint CodeSize;
            
            /// <summary>
            /// The method flags.
            /// </summary>
            public ushort Flags;

            /// <summary>
            /// The method token.
            /// </summary>
            public int Token;

            /// <summary>
            /// Parameter count of the method.
            /// </summary>
            public int ParameterCount;
            
            /// <summary>
            /// The method implementation flags.
            /// </summary>
            public MethodImplementations ImplFlags;
            
            /// <summary>
            /// The raw IL code bytes of the method.
            /// </summary>
            public byte[] ILCode;

            /// <summary>
            /// The raw IL code string of the method.
            /// </summary>
            public string ILString;

            /// <summary>
            /// An indicator to whether the method is an instance or not.
            /// </summary>
            public bool IsInstance;

            /// <summary>
            /// The number of locals for the method.
            /// </summary>
            public int LocalsCount;

            /// <summary>
            /// Instance of the method.
            /// </summary>
            public Type Instance;

            /// <summary>
            /// Declaring type.
            /// </summary>
            public string DeclaringType;

            /// <summary>
            /// Assembly name.
            /// </summary>
            public string AssemblyName;
        }

        public struct DotNetProperty
        {
            /// <summary>
            /// Name of the property.
            /// </summary>
            public string PropertyName;

            /// <summary>
            /// Token of the property.
            /// </summary>
            public int Token;
        }

        public struct DotNetField
        {
            /// <summary>
            /// Name of the field.
            /// </summary>
            public string FieldName;
            
            /// <summary>
            /// Token of the field.
            /// </summary>
            public int Token;
        }

        public struct DotNetType
        {
            /// <summary>
            /// Name of the type.
            /// </summary>
            public string TypeName;

            /// <summary>
            /// Token of the type.
            /// </summary>
            public int Token;
        }

        public struct DotNetMember
        {
            /// <summary>
            /// Name of the member.
            /// </summary>
            public string MemberName;

            /// <summary>
            /// Token of the member.
            /// </summary>
            public int Token;

            /// <summary>
            /// Declaring type.
            /// </summary>
            public string DeclaringType;

            /// <summary>
            /// Type name.
            /// </summary>
            public string TypeName;

            /// <summary>
            /// Assembly name.
            /// </summary>
            public string AssemblyName;

            /// <summary>
            /// Determines if the member is an instance or not.
            /// </summary>
            public bool IsInstance;
        }

        /// <summary>
        /// Import Jump Function structure.
        /// </summary>
        public struct ELFImportFunction
        {
            /// <summary>
            /// The PLT function name (with plt_ prefix).
            /// </summary>
            public string FunctionName;

            /// <summary>
            /// The virtual address of the PLT entry.
            /// </summary>
            public uint VirtualAddress;

            /// <summary>
            /// The offset of the PLT entry.
            /// </summary>
            public uint JumpOffset;

            /// <summary>
            /// The original imported function name.
            /// </summary>
            public string ImportedFunction;

            /// <summary>
            /// The GOT entry address.
            /// </summary>
            public uint GotEntry;
        }

        /// <summary>
        /// PE Import Function structure.
        /// </summary>
        public struct PEImportFunction
        {
            /// <summary>
            /// The name of the imported DLL.
            /// </summary>
            public string LibraryName;

            /// <summary>
            /// The name of the imported function.
            /// </summary>
            public string FunctionName;

            /// <summary>
            /// The RVA of the import address table entry.
            /// </summary>
            public ulong ImportAddressRVA;

            /// <summary>
            /// The RVA of the import lookup table entry.
            /// </summary>
            public uint ImportLookupRVA;

            /// <summary>
            /// The file offset of the import address table entry.
            /// </summary>
            public uint Offset;

            /// <summary>
            /// True if imported by ordinal.
            /// </summary>
            public bool IsOrdinal;

            /// <summary>
            /// The ordinal value if imported by ordinal.
            /// </summary>
            public ushort Ordinal;
        }

        public enum DotNetStatus
        {
            /// <summary>
            /// The PE file is not a .NET file.
            /// </summary>
            None = 0,
            
            /// <summary>
            /// The PE file is a valid .NET file.
            /// </summary>
            DotNet = 1,

            /// <summary>
            /// The PE file is a modified/corrupted .NET file.
            /// </summary>
            ModifiedDotNet = 2
        }

        /// <summary>
        /// PE Specific class.
        /// </summary>
        public class PortableExecutable
        {
            /// <summary>
            /// Subsystem of the PE Binary.
            /// </summary>
            public Subsystem Subsystem;

            /// <summary>
            /// The checksum of the PE Binary.
            /// </summary>
            public uint CheckSum;

            /// <summary>
            /// ImageBase of the PE.
            /// </summary>
            public ulong ImageBase;

            /// <summary>
            /// Size of the PE image.
            /// </summary>
            public ulong SizeOfImage;

            /// <summary>
            /// Size of the PE headers.
            /// </summary>
            public ulong SizeOfHeaders;

            /// <summary>
            /// Base of code.
            /// </summary>
            public ulong BaseOfCode;

            /// <summary>
            /// File Alignment.
            /// </summary>
            public ulong FileAlignment;

            /// <summary>
            /// Alignment of sections.
            /// </summary>
            public ulong SectionAlignment;

            /// <summary>
            /// PE Characteristics.
            /// </summary>
            public Characteristics Characteristics;

            /// <summary>
            /// Dll Characteristics of the PE File.
            /// </summary>
            public DllCharacteristics DllCharacteristics;

            /// <summary>
            /// PE Sections with all their information.
            /// </summary>
            public PortableBinarySection[] Sections = Array.Empty<PortableBinarySection>();

            public IMAGE_OPTIONAL_HEADER32 OptionalHeader32;

            public IMAGE_OPTIONAL_HEADER64 OptionalHeader64;

            public IMAGE_FILE_HEADER FileHeader;

            /// <summary>
            /// Import functions for the PE File (IAT).
            /// </summary>
            public Dictionary<ulong, PEImportFunction> ImportFunctions = new();

            /// <summary>
            /// Indicates if the PE File is a .NET File.
            /// </summary>
            public DotNetStatus DotNetStatus;
        }

        public class DotNet
        {
            /// <summary>
            /// .NET Functions that exist inside the binary.
            /// </summary>
            public DotNetFunction[] DotNetFunctions = Array.Empty<DotNetFunction>();

            /// <summary>
            /// .NET Properties that exist inside the binary.
            /// </summary>
            public DotNetProperty[] DotNetProperties = Array.Empty<DotNetProperty>();

            /// <summary>
            /// .NET Fields that exist inside the binary.
            /// </summary>
            public DotNetField[] DotNetFields = Array.Empty<DotNetField>();

            /// <summary>
            /// .NET Types that exist inside the binary.
            /// </summary>
            public DotNetType[] DotNetTypes = Array.Empty<DotNetType>();

            /// <summary>
            /// .NET Members.
            /// </summary>
            public DotNetMember[] DotNetMembers = Array.Empty<DotNetMember>();

            /// <summary>
            /// Metadata reader for the .NET assembly.
            /// </summary>
            public MetadataReader MetaReader;
        }

        /// <summary>
        /// ELF Specific class.
        /// </summary>
        public class ELF
        {
            public uint Type;
            public uint Version;
            public uint Flags;
            public uint HeaderSize;
            public uint ProgramHeaderSize;
            public uint ProgramHeaderCount;
            public uint SectionHeaderSize;
            public uint SectionHeaderCount;
            public uint SectionNameIndex;
            public ElfBinarySection[] Sections = Array.Empty<ElfBinarySection>();
            public Dictionary<ulong, ELFImportFunction> ImportFunctions = new();
        }

        /// <summary>
        /// Binary search result.
        /// </summary>
        public struct BinarySearch
        {
            /// <summary>
            /// Matching bytes.
            /// </summary>
            public byte[] Match;

            /// <summary>
            /// The virtual address of the matching bytes where it is found.
            /// </summary>
            public ulong Address;

            /// <summary>
            /// The offset of the matching bytes where it is found.
            /// </summary>
            public uint Offset;
        }

        public enum BinaryCorruptionStatus
        {
            Unknown = 0,
            Clean = 1,
            Suspicious = 2,
            Corrupted = 3,
        }

        /// <summary>
        /// Read a null-terminated string inside the binary file in an offset.
        /// </summary>
        /// <param name="Data">Binary file.</param>
        /// <param name="Offset">Offset to read from.</param>
        /// <returns>Reads a null-terminated string from the binary in a specific offset.</returns>
        /// <exception cref="IndexOutOfRangeException"></exception>
        public static string ReadNullTerminatedString(byte[] Data, int Offset)
        {
            if (Offset > Data.Length)
                throw new IndexOutOfRangeException("Offset is larger than the binary data length.");
            if (Offset < 0)
                throw new IndexOutOfRangeException("Offset is less than zero.");
            int End = Array.IndexOf<byte>(Data, 0, Offset);
            return End < 0 ? string.Empty : Encoding.ASCII.GetString(Data, Offset, End - Offset);
        }

        /// <summary>
        /// Read a null-terminated string inside the binary file at an offset.
        /// </summary>
        /// <param name="Data">Binary file data.</param>
        /// <param name="Offset">Offset to read from.</param>
        /// <returns>Reads a null-terminated ASCII string.</returns>
        /// <exception cref="IndexOutOfRangeException"></exception>
        public static string ReadNullTerminatedString(ReadOnlySpan<byte> Data, int Offset)
        {
            if ((uint)Offset >= (uint)Data.Length)
                throw new IndexOutOfRangeException("Offset is out of range.");

            ReadOnlySpan<byte> Slice = Data.Slice(Offset);
            int End = Slice.IndexOf((byte)0);

            if (End < 0)
                return string.Empty;

            return Encoding.ASCII.GetString(Slice.Slice(0, End));
        }

        /// <summary>
        /// Converts a Relative Virtual Address (RVA) to a file offset using section information.
        /// </summary>
        /// <param name="Rva">The RVA to convert.</param>
        /// <param name="Section">The section containing the RVA.</param>
        /// <returns>The file offset corresponding to the RVA.</returns>
        public static uint RvaToFileOffset(uint Rva, PortableBinarySection[] Sections)
        {
            foreach (PortableBinarySection Section in Sections)
            {
                if (Rva >= Section.VirtualAddress && Rva < Section.VirtualAddress + Section.VirtualSize)
                    return Rva - Section.VirtualAddress + Section.RawOffset;
            }
            return 0;
        }

        /// <summary>
        /// Convert a virtual address to an offset.
        /// </summary>
        /// <param name="VirtualAddress">Virtual Address to convert.</param>
        /// <param name="Section">Section containing the virtual address.</param>
        /// <returns>returns the offset.</returns>
        public static ulong VirtualAddressToFileOffset(ulong VirtualAddress, ElfBinarySection Section)
        {
            if (VirtualAddress >= Section.VirtualAddress &&
                VirtualAddress < Section.VirtualAddress + Section.VirtualSize)
            {
                return VirtualAddress - Section.VirtualAddress + Section.RawOffset;
            }
            return 0;
        }

        /// <summary>
        /// Convert a virtual address to an offset.
        /// </summary>
        /// <param name="VirtualAddress">Virtual Address to convert.</param>
        /// <param name="Sections">Sections to search for the virtual address.</param>
        /// <returns>returns the offset.</returns>
        public static ulong VirtualAddressToFileOffset(ulong VirtualAddress, ElfBinarySection[] Sections)
        {
            foreach (ElfBinarySection Section in Sections)
            {
                if (VirtualAddress >= Section.VirtualAddress &&
                    VirtualAddress < Section.VirtualAddress + Section.VirtualSize)
                {
                    return VirtualAddress - Section.VirtualAddress + Section.RawOffset;
                }
            }
            return 0;
        }

        /// <summary>
        /// Convert the file offset in an ELF section to an RVA.
        /// </summary>
        /// <param name="FileOffset">File offset.</param>
        /// <param name="Sections">Sections to search in.</param>
        /// <returns>The RVA.</returns>
        public static ulong FileOffsetToRva(uint FileOffset, ElfBinarySection[] Sections)
        {
            foreach (ElfBinarySection Section in Sections)
            {
                if (FileOffset >= Section.RawOffset && FileOffset < Section.RawOffset + Section.RawSize)
                    return FileOffset - Section.RawOffset + Section.VirtualAddress;
            }
            return 0;
        }

        public static bool IsExecutableSection(PortableBinarySection Section)
        {
            return (Section.Characteristics & SectionCharacteristics.MemExecute) != 0;
        }

        public static bool IsExecutableSection(ElfBinarySection Section)
        {
            return (Section.Characteristics & ElfSectionCharacteristics.ExecInstr) != 0;
        }
    }

    public sealed unsafe class MappedMemoryBytes : IDisposable
    {
        private byte[] ManagedData;

        private MemoryMappedFile Mmf;
        private MemoryMappedViewAccessor View;
        private SafeMemoryMappedViewHandle Handle;
        public byte* BasePtr;

        public int Length { get; private set; }
        public bool IsMemoryMapped => ManagedData == null;

        public MappedMemoryBytes(byte[] Data)
        {
            if (Data == null || Data.Length == 0)
                throw new ArgumentNullException(nameof(Data));
            ManagedData = Data ?? Array.Empty<byte>();
            Length = ManagedData.Length;
        }

        public MappedMemoryBytes(Span<byte> Data)
        {
            if (Data.IsEmpty || Data.Length == 0)
                throw new ArgumentNullException(nameof(Data));
            BasePtr = (byte*)&Data;
            Length = Data.Length;
        }

        public MappedMemoryBytes(ReadOnlySpan<byte> Data)
        {
            if (Data.IsEmpty || Data.Length == 0)
                throw new ArgumentNullException(nameof(Data));
            BasePtr = (byte*)&Data;
            Length = Data.Length;
        }

        public MappedMemoryBytes(string Path)
        {
            FileStream Stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            try
            {
                long StreamLength = Stream.Length;
                if (StreamLength > int.MaxValue)
                    throw new NotSupportedException("Files > 2GB are not supported.");

                Length = (int)StreamLength;

                Mmf = MemoryMappedFile.CreateFromFile(Stream, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: false);
                Stream = null;
                View = Mmf.CreateViewAccessor(0, StreamLength, MemoryMappedFileAccess.Read);

                Handle = View.SafeMemoryMappedViewHandle;

                byte* Ptr = null;
                Handle.AcquirePointer(ref Ptr);
                BasePtr = Ptr + View.PointerOffset;
            }
            finally
            {
                Stream?.Dispose();
            }
        }

        public byte this[int Offset]
        {
            get
            {
                if ((uint)Offset >= (uint)Length)
                    throw new ArgumentOutOfRangeException(nameof(Offset));

                if (ManagedData != null)
                    return ManagedData[Offset];

                return BasePtr[Offset];
            }
        }

        public byte this[uint Offset]
        {
            get
            {
                if ((uint)Offset >= (uint)Length)
                    throw new ArgumentOutOfRangeException(nameof(Offset));

                if (ManagedData != null)
                    return ManagedData[Offset];

                return BasePtr[Offset];
            }
        }

        public ReadOnlySpan<byte> AsSpan(int Offset, int Size)
        {
            if (Offset < 0 || Size < 0 || (long)Offset + Size > Length)
                throw new ArgumentOutOfRangeException();

            if (ManagedData != null)
                return new ReadOnlySpan<byte>(ManagedData, Offset, Size);

            return new ReadOnlySpan<byte>(BasePtr + Offset, Size);
        }

        public ReadOnlySpan<byte> AsSpan()
        {
            return AsSpan(0, Length);
        }

        public byte[] ToArray()
        {
            if (ManagedData != null)
                return ManagedData;

            byte[] Buffer = new byte[Length];
            AsSpan(0, Length).CopyTo(Buffer);
            return Buffer;
        }

        public void CopyTo(byte[] Destination)
        {
            if (Destination == null)
                return;
            AsSpan().CopyTo(Destination);
        }

        public void Dispose()
        {
            // If we're backed by a managed array, nothing to release.
            if (ManagedData != null)
            {
                ManagedData = null;
                Length = 0;
                return;
            }

            if (Handle != null && !Handle.IsClosed)
                Handle.ReleasePointer();

            View?.Dispose();
            Mmf?.Dispose();

            BasePtr = null;
            Length = 0;
        }
    }
}
