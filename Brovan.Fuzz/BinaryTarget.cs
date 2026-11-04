using System.Buffers.Binary;
using System.Text;
using Brovan.Core;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.OS.Windows;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Fuzz;

internal static class BinaryTarget
{
    private static readonly InputFile Input = new();

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 3)
            return;

        string path = Input.Write(data[1..]);
        try
        {
            using BinaryFile image = new(path, (data[0] & 1) == 0);
            if (image.FileFormat == BinaryFormat.PE)
                ReadImage(image, path);
        }
        catch (Exception e) when (Rejects(e))
        {
        }

        try
        {
            ImageResources.TryReadFileVersion(path, out _, out _);
        }
        catch (Exception e) when (Rejects(e))
        {
        }
    }

    private static bool Rejects(Exception e) => Oracle.Rejects(e) || e is BadImageFormatException or NotSupportedException;

    private static void ReadImage(BinaryFile image, string path)
    {
        ulong imageSize = BinaryEmulator.GetPeImageSize(image);
        foreach (BinaryEmulator.PeImageExtent extent in BinaryEmulator.GetPeImageExtents(image, imageSize))
        {
            // The PE writer assumes every extent fits the mapping.
            if (!extent.FitsIn(imageSize))
                Oracle.Fail($"extent at 0x{extent.Rva:X} of 0x{extent.Size:X} bytes leaves the 0x{imageSize:X} byte image");
        }

        BinaryEmulator.IsDynamicallyRelocatable(image);
        byte[]? manifest = WinSxS.ReadImageManifest(image, path);
        if (manifest != null)
            WinSxS.ReadCompatibility(manifest, out _, out _);
    }

    public static string Dictionary()
    {
        StringBuilder sb = new();
        foreach (string token in Tokens)
            sb.AppendLine($"\"{token}\"");
        return sb.ToString();
    }

    private static readonly string[] Tokens =
    {
        "MZ", "PE\\x00\\x00", "\\x0b\\x01", "\\x0b\\x02", "\\x4c\\x01", "\\x64\\x86", "\\x7fELF", "BSJB",
        ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc",
        ".symtab", ".strtab", ".dynsym", ".dynstr", ".plt", ".got.plt", ".rela.plt", ".rel.plt",
        "\\xbd\\x04\\xef\\xfe", "V\\x00S\\x00_\\x00V\\x00E\\x00R\\x00S\\x00I\\x00O\\x00N\\x00_\\x00I\\x00N\\x00F\\x00O\\x00",
        "<assembly", "<compatibility", "<application", "<supportedOS", "<maxversiontested", "Id=\\x22",
        "urn:schemas-microsoft-com:asm.v1", "urn:schemas-microsoft-com:compatibility.v1",
    };

    public static IEnumerable<byte[]> Seeds()
    {
        foreach (bool wide in new[] { false, true })
        {
            foreach (byte[] image in new[] { Pe(wide, false), Pe(wide, true), Elf(wide) })
            {
                foreach (byte mode in new byte[] { 0, 1 })
                {
                    byte[] input = new byte[1 + image.Length];
                    input[0] = mode;
                    image.CopyTo(input, 1);
                    yield return input;
                }
            }
        }
    }

    private const uint HeaderBytes = 0x400;
    private const ulong ImageBase64 = 0x180000000;
    private const uint ImageBase32 = 0x10000000;

    private static readonly byte[] Code64 =
    {
        0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3,
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3,
    };

    private static readonly byte[] Code32 =
    {
        0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0xA1, 0x00, 0x10, 0x00, 0x10, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC,
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x8B, 0xE5, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    };

    private const string Manifest =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        + "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
        + "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application>"
        + "<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><maxversiontested Id=\"10.0.26100.0\"/>"
        + "</application></compatibility></assembly>";

    private static byte[] Pe(bool wide, bool clr)
    {
        (string Name, uint Rva, uint Size, uint Flags)[] all =
        {
            (".text", 0x1000, 0x200, 0x60000020),
            (".rdata", 0x2000, 0x400, 0x40000040),
            (".rsrc", 0x3000, 0x400, 0x40000040),
            (".reloc", 0x4000, 0x200, 0x42000040),
            (".pdata", 0x5000, 0x200, 0x40000040),
        };
        var sections = wide ? all : all[..4];

        uint[] raws = new uint[sections.Length];
        uint fileBytes = HeaderBytes;
        for (int i = 0; i < sections.Length; i++)
        {
            raws[i] = fileBytes;
            fileBytes += sections[i].Size;
        }
        byte[] b = new byte[fileBytes];

        int At(uint rva)
        {
            for (int i = 0; i < sections.Length; i++)
            {
                if (rva >= sections[i].Rva && rva < sections[i].Rva + sections[i].Size)
                    return (int)(raws[i] + rva - sections[i].Rva);
            }
            throw new ArgumentOutOfRangeException(nameof(rva));
        }

        const int NtHeaders = 0x40;
        const int Opt = NtHeaders + 4 + 20;
        Ascii(b, 0, "MZ");
        U32(b, 0x3C, NtHeaders);
        Ascii(b, NtHeaders, "PE");
        U16(b, NtHeaders + 4, wide ? 0x8664 : 0x14C);
        U16(b, NtHeaders + 6, sections.Length);
        U16(b, NtHeaders + 20, wide ? 0xF0 : 0xE0);
        U16(b, NtHeaders + 22, wide ? 0x2022 : 0x2102);

        U16(b, Opt, wide ? 0x20B : 0x10B);
        b[Opt + 2] = 14;
        U32(b, Opt + 4, 0x200);
        U32(b, Opt + 8, 0x800);
        U32(b, Opt + 16, 0x1000);
        U32(b, Opt + 20, 0x1000);
        if (wide)
            U64(b, Opt + 24, ImageBase64);
        else
        {
            U32(b, Opt + 24, 0x2000);
            U32(b, Opt + 28, ImageBase32);
        }
        U32(b, Opt + 32, 0x1000);
        U32(b, Opt + 36, 0x200);
        U16(b, Opt + 40, 6);
        U16(b, Opt + 48, 6);
        U32(b, Opt + 56, sections[^1].Rva + 0x1000);
        U32(b, Opt + 60, HeaderBytes);
        U16(b, Opt + 68, 3);
        U16(b, Opt + 70, wide ? 0x160 : 0x140);
        if (wide)
        {
            U64(b, Opt + 72, 0x100000);
            U64(b, Opt + 80, 0x1000);
            U64(b, Opt + 88, 0x100000);
            U64(b, Opt + 96, 0x1000);
        }
        else
        {
            U32(b, Opt + 72, 0x100000);
            U32(b, Opt + 76, 0x1000);
            U32(b, Opt + 80, 0x100000);
            U32(b, Opt + 84, 0x1000);
        }
        U32(b, Opt + (wide ? 108 : 92), 16);
        int dirs = Opt + (wide ? 112 : 96);
        void Dir(int index, uint rva, uint size)
        {
            U32(b, dirs + index * 8, rva);
            U32(b, dirs + index * 8 + 4, size);
        }

        int header = Opt + (wide ? 0xF0 : 0xE0);
        for (int i = 0; i < sections.Length; i++, header += 40)
        {
            Ascii(b, header, sections[i].Name);
            U32(b, header + 8, sections[i].Size);
            U32(b, header + 12, sections[i].Rva);
            U32(b, header + 16, sections[i].Size);
            U32(b, header + 20, raws[i]);
            U32(b, header + 36, sections[i].Flags);
        }

        (wide ? Code64 : Code32).CopyTo(b, At(0x1000));

        int exports = At(0x2000);
        U32(b, exports + 12, 0x2100);
        U32(b, exports + 16, 1);
        U32(b, exports + 20, 2);
        U32(b, exports + 24, 2);
        U32(b, exports + 28, 0x2040);
        U32(b, exports + 32, 0x2048);
        U32(b, exports + 36, 0x2050);
        U32(b, At(0x2040), 0x1000);
        U32(b, At(0x2044), 0x1010);
        U32(b, At(0x2048), 0x2110);
        U32(b, At(0x204C), 0x2118);
        U16(b, At(0x2052), 1);
        Dir(0, 0x2000, 0x60);

        int imports = At(0x2060);
        U32(b, imports, 0x2090);
        U32(b, imports + 12, 0x2120);
        U32(b, imports + 16, 0x20B0);
        Dir(1, 0x2060, 40);
        uint pointer = wide ? 8u : 4u;
        foreach (uint table in new uint[] { 0x2090, 0x20B0 })
        {
            if (wide)
            {
                U64(b, At(table), 0x2130);
                U64(b, At(table + 8), 0x8000000000000005);
            }
            else
            {
                U32(b, At(table), 0x2130);
                U32(b, At(table + 4), 0x80000005);
            }
        }
        Dir(12, 0x20B0, 3 * pointer);

        Ascii(b, At(0x2100), "seed.dll");
        Ascii(b, At(0x2110), "Open");
        Ascii(b, At(0x2118), "Close");
        Ascii(b, At(0x2120), "kernel32.dll");
        U16(b, At(0x2130), 0x10);
        Ascii(b, At(0x2132), "ExitProcess");

        if (wide)
        {
            new byte[] { 0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00 }.CopyTo(b, At(0x2150));
            int pdata = At(0x5000);
            U32(b, pdata, 0x1000);
            U32(b, pdata + 4, 0x1010);
            U32(b, pdata + 8, 0x2150);
            U32(b, pdata + 12, 0x1010);
            U32(b, pdata + 16, 0x1020);
            U32(b, pdata + 20, 0x2150);
            Dir(3, 0x5000, 24);
        }

        if (clr)
        {
            int cor = At(0x2160);
            U32(b, cor, 72);
            U16(b, cor + 4, 2);
            U16(b, cor + 6, 5);
            U32(b, cor + 8, 0x2200);
            U32(b, cor + 12, 0x20);
            U32(b, cor + 16, 1);
            U32(b, cor + 20, 0x06000001);
            Dir(14, 0x2160, 72);

            int metadata = At(0x2200);
            Ascii(b, metadata, "BSJB");
            U16(b, metadata + 4, 1);
            U16(b, metadata + 6, 1);
            U32(b, metadata + 12, 12);
            Ascii(b, metadata + 16, "v4.0.30319");
        }

        if (wide)
            U64(b, At(0x21F0), ImageBase64 + 0x1000);
        else
            U32(b, At(0x21F0), ImageBase32 + 0x1000);
        int relocs = At(0x4000);
        U32(b, relocs, 0x2000);
        U32(b, relocs + 4, 12);
        U16(b, relocs + 8, (wide ? 10 : 3) << 12 | 0x1F0);
        Dir(5, 0x4000, 12);

        int resources = At(0x3000);
        WriteDirectory(b, resources, (16, 0x80000020), (24, 0x80000050));
        WriteDirectory(b, resources + 0x20, (1, 0x80000038));
        WriteDirectory(b, resources + 0x38, (0x409, 0x80));
        WriteDirectory(b, resources + 0x50, (1, 0x80000068));
        WriteDirectory(b, resources + 0x68, (0x409, 0x90));

        U32(b, resources + 0x80, 0x3100);
        U32(b, resources + 0x84, 92);
        int version = At(0x3100);
        U16(b, version, 92);
        U16(b, version + 2, 52);
        Encoding.Unicode.GetBytes("VS_VERSION_INFO", b.AsSpan(version + 6));
        U32(b, version + 40, 0xFEEF04BD);
        U32(b, version + 44, 0x00010000);
        U32(b, version + 48, 0x000A0000);
        U32(b, version + 52, 26100u << 16 | 1);
        U32(b, version + 56, 0x000A0000);
        U32(b, version + 60, 26100u << 16 | 1);

        U32(b, resources + 0x90, 0x3200);
        U32(b, resources + 0x94, (uint)Manifest.Length);
        Ascii(b, At(0x3200), Manifest);
        Dir(2, 0x3000, 0x400);

        return b;
    }

    private static void WriteDirectory(byte[] b, int at, params (uint Id, uint Offset)[] entries)
    {
        U16(b, at + 14, entries.Length);
        for (int i = 0; i < entries.Length; i++)
        {
            U32(b, at + 16 + i * 8, entries[i].Id);
            U32(b, at + 20 + i * 8, entries[i].Offset);
        }
    }

    private static byte[] Elf(bool wide)
    {
        const int SectionTable = 0x400;
        string relocations = wide ? ".rela.plt" : ".rel.plt";
        string names = $"\0.shstrtab\0.text\0.symtab\0.strtab\0.dynsym\0.dynstr\0.plt\0.got.plt\0{relocations}\0";
        int symbolBytes = wide ? 24 : 16;
        int relocationBytes = wide ? 24 : 8;

        (string Name, uint Type, uint Flags, uint Address, uint Offset, uint Size, uint Link, uint Info, uint EntrySize)[] sections =
        {
            ("", 0, 0, 0, 0, 0, 0, 0, 0),
            (".shstrtab", 3, 0, 0, 0x100, (uint)names.Length, 0, 0, 0),
            (".text", 1, 6, 0x1000, 0x200, 0x40, 0, 0, 0),
            (".symtab", 2, 0, 0, 0x280, (uint)(2 * symbolBytes), 4, 1, (uint)symbolBytes),
            (".strtab", 3, 0, 0, 0x2C0, 6, 0, 0, 0),
            (".dynsym", 11, 2, 0, 0x300, (uint)(2 * symbolBytes), 6, 1, (uint)symbolBytes),
            (".dynstr", 3, 2, 0, 0x340, 16, 0, 0, 0),
            (".plt", 1, 6, 0x2000, 0x380, 0x20, 0, 0, 16),
            (".got.plt", 1, 3, 0x3000, 0x3A0, 0x20, 0, 0, 0),
            (relocations, wide ? 4u : 9u, 2, 0, 0x3C0, (uint)relocationBytes, 5, 8, (uint)relocationBytes),
        };

        int headerBytes = wide ? 64 : 40;
        byte[] b = new byte[SectionTable + sections.Length * headerBytes];

        b[0] = 0x7F;
        Ascii(b, 1, "ELF");
        b[4] = (byte)(wide ? 2 : 1);
        b[5] = 1;
        b[6] = 1;
        U16(b, 16, 3);
        U16(b, 18, wide ? 0x3E : 0x03);
        U32(b, 20, 1);
        if (wide)
        {
            U64(b, 24, 0x1000);
            U64(b, 40, SectionTable);
            U16(b, 52, 64);
            U16(b, 54, 56);
            U16(b, 58, headerBytes);
            U16(b, 60, sections.Length);
            U16(b, 62, 1);
        }
        else
        {
            U32(b, 24, 0x1000);
            U32(b, 32, SectionTable);
            U16(b, 40, 52);
            U16(b, 42, 32);
            U16(b, 46, headerBytes);
            U16(b, 48, sections.Length);
            U16(b, 50, 1);
        }

        Ascii(b, 0x100, names);
        (wide ? Code64 : Code32).CopyTo(b, 0x200);
        Symbol(b, 0x280 + symbolBytes, wide, 1, 0x1010, 0x10, 2);
        Ascii(b, 0x2C1, "main");
        Symbol(b, 0x300 + symbolBytes, wide, 1, 0, 0, 0);
        Ascii(b, 0x341, "puts");
        Ascii(b, 0x346, "libc.so.6");
        new byte[] { 0xFF, 0x25, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0xE9, 0xE0, 0xFF, 0xFF, 0xFF }.CopyTo(b, 0x390);
        if (wide)
        {
            U64(b, 0x3C0, 0x3018);
            U64(b, 0x3C8, 1UL << 32 | 7);
        }
        else
        {
            U32(b, 0x3C0, 0x300C);
            U32(b, 0x3C4, 1u << 8 | 7);
        }

        for (int i = 0; i < sections.Length; i++)
        {
            var s = sections[i];
            int at = SectionTable + i * headerBytes;
            uint name = i == 0 ? 0u : (uint)names.IndexOf($"\0{s.Name}\0", StringComparison.Ordinal) + 1;
            U32(b, at, name);
            U32(b, at + 4, s.Type);
            if (wide)
            {
                U64(b, at + 8, s.Flags);
                U64(b, at + 16, s.Address);
                U64(b, at + 24, s.Offset);
                U64(b, at + 32, s.Size);
                U32(b, at + 40, s.Link);
                U32(b, at + 44, s.Info);
                U64(b, at + 56, s.EntrySize);
            }
            else
            {
                U32(b, at + 8, s.Flags);
                U32(b, at + 12, s.Address);
                U32(b, at + 16, s.Offset);
                U32(b, at + 20, s.Size);
                U32(b, at + 24, s.Link);
                U32(b, at + 28, s.Info);
                U32(b, at + 36, s.EntrySize);
            }
        }

        return b;
    }

    private static void Symbol(byte[] b, int at, bool wide, uint name, uint value, uint size, int section)
    {
        const byte GlobalFunction = 0x12;
        U32(b, at, name);
        if (wide)
        {
            b[at + 4] = GlobalFunction;
            U16(b, at + 6, section);
            U64(b, at + 8, value);
            U64(b, at + 16, size);
        }
        else
        {
            U32(b, at + 4, value);
            U32(b, at + 8, size);
            b[at + 12] = GlobalFunction;
            U16(b, at + 14, section);
        }
    }

    private static void U16(byte[] b, int at, int v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at), (ushort)v);

    private static void U32(byte[] b, int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), v);

    private static void U64(byte[] b, int at, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(at), v);

    private static void Ascii(byte[] b, int at, string s) => Encoding.ASCII.GetBytes(s, b.AsSpan(at));
}
