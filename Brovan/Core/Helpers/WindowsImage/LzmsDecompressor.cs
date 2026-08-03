using System;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal sealed class LzmsDecompressor
    {
        private const int ProbabilityBits = 6;
        private const int ProbabilityDenominator = 1 << ProbabilityBits;
        private const int InitialProbability = 48;
        private const ulong InitialRecentBits = 0x0000000055555555;

        private const int NumMainProbs = 16;
        private const int NumMatchProbs = 32;
        private const int NumLzProbs = 64;
        private const int NumLzRepProbs = 64;
        private const int NumDeltaProbs = 64;
        private const int NumDeltaRepProbs = 64;

        private const int NumLiteralSyms = 256;
        private const int NumLengthSyms = 54;
        private const int NumDeltaPowerSyms = 8;
        private const int MaxNumOffsetSyms = 799;
        private const int MaxCodewordLength = 15;

        private const int LiteralRebuildFreq = 1024;
        private const int LzOffsetRebuildFreq = 1024;
        private const int LengthRebuildFreq = 512;
        private const int DeltaOffsetRebuildFreq = 1024;
        private const int DeltaPowerRebuildFreq = 512;

        private const int X86IdWindowSize = 65535;
        private const int X86MaxTranslationOffset = 1023;

        private static readonly uint[] OffsetSlotBase =
        {
            0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007, 0x00000008,
            0x00000009, 0x0000000D, 0x00000011, 0x00000015, 0x00000019, 0x0000001D, 0x00000021, 0x00000025,
            0x00000029, 0x0000002D, 0x00000035, 0x0000003D, 0x00000045, 0x0000004D, 0x00000055, 0x0000005D,
            0x00000065, 0x00000075, 0x00000085, 0x00000095, 0x000000A5, 0x000000B5, 0x000000C5, 0x000000D5,
            0x000000E5, 0x000000F5, 0x00000105, 0x00000125, 0x00000145, 0x00000165, 0x00000185, 0x000001A5,
            0x000001C5, 0x000001E5, 0x00000205, 0x00000225, 0x00000245, 0x00000265, 0x00000285, 0x000002A5,
            0x000002C5, 0x000002E5, 0x00000325, 0x00000365, 0x000003A5, 0x000003E5, 0x00000425, 0x00000465,
            0x000004A5, 0x000004E5, 0x00000525, 0x00000565, 0x000005A5, 0x000005E5, 0x00000625, 0x00000665,
            0x000006A5, 0x00000725, 0x000007A5, 0x00000825, 0x000008A5, 0x00000925, 0x000009A5, 0x00000A25,
            0x00000AA5, 0x00000B25, 0x00000BA5, 0x00000C25, 0x00000CA5, 0x00000D25, 0x00000DA5, 0x00000E25,
            0x00000EA5, 0x00000F25, 0x00000FA5, 0x00001025, 0x000010A5, 0x000011A5, 0x000012A5, 0x000013A5,
            0x000014A5, 0x000015A5, 0x000016A5, 0x000017A5, 0x000018A5, 0x000019A5, 0x00001AA5, 0x00001BA5,
            0x00001CA5, 0x00001DA5, 0x00001EA5, 0x00001FA5, 0x000020A5, 0x000021A5, 0x000022A5, 0x000023A5,
            0x000024A5, 0x000026A5, 0x000028A5, 0x00002AA5, 0x00002CA5, 0x00002EA5, 0x000030A5, 0x000032A5,
            0x000034A5, 0x000036A5, 0x000038A5, 0x00003AA5, 0x00003CA5, 0x00003EA5, 0x000040A5, 0x000042A5,
            0x000044A5, 0x000046A5, 0x000048A5, 0x00004AA5, 0x00004CA5, 0x00004EA5, 0x000050A5, 0x000052A5,
            0x000054A5, 0x000056A5, 0x000058A5, 0x00005AA5, 0x00005CA5, 0x00005EA5, 0x000060A5, 0x000064A5,
            0x000068A5, 0x00006CA5, 0x000070A5, 0x000074A5, 0x000078A5, 0x00007CA5, 0x000080A5, 0x000084A5,
            0x000088A5, 0x00008CA5, 0x000090A5, 0x000094A5, 0x000098A5, 0x00009CA5, 0x0000A0A5, 0x0000A4A5,
            0x0000A8A5, 0x0000ACA5, 0x0000B0A5, 0x0000B4A5, 0x0000B8A5, 0x0000BCA5, 0x0000C0A5, 0x0000C4A5,
            0x0000C8A5, 0x0000CCA5, 0x0000D0A5, 0x0000D4A5, 0x0000D8A5, 0x0000DCA5, 0x0000E0A5, 0x0000E4A5,
            0x0000ECA5, 0x0000F4A5, 0x0000FCA5, 0x000104A5, 0x00010CA5, 0x000114A5, 0x00011CA5, 0x000124A5,
            0x00012CA5, 0x000134A5, 0x00013CA5, 0x000144A5, 0x00014CA5, 0x000154A5, 0x00015CA5, 0x000164A5,
            0x00016CA5, 0x000174A5, 0x00017CA5, 0x000184A5, 0x00018CA5, 0x000194A5, 0x00019CA5, 0x0001A4A5,
            0x0001ACA5, 0x0001B4A5, 0x0001BCA5, 0x0001C4A5, 0x0001CCA5, 0x0001D4A5, 0x0001DCA5, 0x0001E4A5,
            0x0001ECA5, 0x0001F4A5, 0x0001FCA5, 0x000204A5, 0x00020CA5, 0x000214A5, 0x00021CA5, 0x000224A5,
            0x000234A5, 0x000244A5, 0x000254A5, 0x000264A5, 0x000274A5, 0x000284A5, 0x000294A5, 0x0002A4A5,
            0x0002B4A5, 0x0002C4A5, 0x0002D4A5, 0x0002E4A5, 0x0002F4A5, 0x000304A5, 0x000314A5, 0x000324A5,
            0x000334A5, 0x000344A5, 0x000354A5, 0x000364A5, 0x000374A5, 0x000384A5, 0x000394A5, 0x0003A4A5,
            0x0003B4A5, 0x0003C4A5, 0x0003D4A5, 0x0003E4A5, 0x0003F4A5, 0x000404A5, 0x000414A5, 0x000424A5,
            0x000434A5, 0x000444A5, 0x000454A5, 0x000464A5, 0x000474A5, 0x000484A5, 0x000494A5, 0x0004A4A5,
            0x0004B4A5, 0x0004C4A5, 0x0004E4A5, 0x000504A5, 0x000524A5, 0x000544A5, 0x000564A5, 0x000584A5,
            0x0005A4A5, 0x0005C4A5, 0x0005E4A5, 0x000604A5, 0x000624A5, 0x000644A5, 0x000664A5, 0x000684A5,
            0x0006A4A5, 0x0006C4A5, 0x0006E4A5, 0x000704A5, 0x000724A5, 0x000744A5, 0x000764A5, 0x000784A5,
            0x0007A4A5, 0x0007C4A5, 0x0007E4A5, 0x000804A5, 0x000824A5, 0x000844A5, 0x000864A5, 0x000884A5,
            0x0008A4A5, 0x0008C4A5, 0x0008E4A5, 0x000904A5, 0x000924A5, 0x000944A5, 0x000964A5, 0x000984A5,
            0x0009A4A5, 0x0009C4A5, 0x0009E4A5, 0x000A04A5, 0x000A24A5, 0x000A44A5, 0x000A64A5, 0x000AA4A5,
            0x000AE4A5, 0x000B24A5, 0x000B64A5, 0x000BA4A5, 0x000BE4A5, 0x000C24A5, 0x000C64A5, 0x000CA4A5,
            0x000CE4A5, 0x000D24A5, 0x000D64A5, 0x000DA4A5, 0x000DE4A5, 0x000E24A5, 0x000E64A5, 0x000EA4A5,
            0x000EE4A5, 0x000F24A5, 0x000F64A5, 0x000FA4A5, 0x000FE4A5, 0x001024A5, 0x001064A5, 0x0010A4A5,
            0x0010E4A5, 0x001124A5, 0x001164A5, 0x0011A4A5, 0x0011E4A5, 0x001224A5, 0x001264A5, 0x0012A4A5,
            0x0012E4A5, 0x001324A5, 0x001364A5, 0x0013A4A5, 0x0013E4A5, 0x001424A5, 0x001464A5, 0x0014A4A5,
            0x0014E4A5, 0x001524A5, 0x001564A5, 0x0015A4A5, 0x0015E4A5, 0x001624A5, 0x001664A5, 0x0016A4A5,
            0x0016E4A5, 0x001724A5, 0x001764A5, 0x0017A4A5, 0x0017E4A5, 0x001824A5, 0x001864A5, 0x0018A4A5,
            0x0018E4A5, 0x001924A5, 0x001964A5, 0x0019E4A5, 0x001A64A5, 0x001AE4A5, 0x001B64A5, 0x001BE4A5,
            0x001C64A5, 0x001CE4A5, 0x001D64A5, 0x001DE4A5, 0x001E64A5, 0x001EE4A5, 0x001F64A5, 0x001FE4A5,
            0x002064A5, 0x0020E4A5, 0x002164A5, 0x0021E4A5, 0x002264A5, 0x0022E4A5, 0x002364A5, 0x0023E4A5,
            0x002464A5, 0x0024E4A5, 0x002564A5, 0x0025E4A5, 0x002664A5, 0x0026E4A5, 0x002764A5, 0x0027E4A5,
            0x002864A5, 0x0028E4A5, 0x002964A5, 0x0029E4A5, 0x002A64A5, 0x002AE4A5, 0x002B64A5, 0x002BE4A5,
            0x002C64A5, 0x002CE4A5, 0x002D64A5, 0x002DE4A5, 0x002E64A5, 0x002EE4A5, 0x002F64A5, 0x002FE4A5,
            0x003064A5, 0x0030E4A5, 0x003164A5, 0x0031E4A5, 0x003264A5, 0x0032E4A5, 0x003364A5, 0x0033E4A5,
            0x003464A5, 0x0034E4A5, 0x003564A5, 0x0035E4A5, 0x003664A5, 0x0036E4A5, 0x003764A5, 0x0037E4A5,
            0x003864A5, 0x0038E4A5, 0x003964A5, 0x0039E4A5, 0x003A64A5, 0x003AE4A5, 0x003B64A5, 0x003BE4A5,
            0x003C64A5, 0x003CE4A5, 0x003D64A5, 0x003DE4A5, 0x003EE4A5, 0x003FE4A5, 0x0040E4A5, 0x0041E4A5,
            0x0042E4A5, 0x0043E4A5, 0x0044E4A5, 0x0045E4A5, 0x0046E4A5, 0x0047E4A5, 0x0048E4A5, 0x0049E4A5,
            0x004AE4A5, 0x004BE4A5, 0x004CE4A5, 0x004DE4A5, 0x004EE4A5, 0x004FE4A5, 0x0050E4A5, 0x0051E4A5,
            0x0052E4A5, 0x0053E4A5, 0x0054E4A5, 0x0055E4A5, 0x0056E4A5, 0x0057E4A5, 0x0058E4A5, 0x0059E4A5,
            0x005AE4A5, 0x005BE4A5, 0x005CE4A5, 0x005DE4A5, 0x005EE4A5, 0x005FE4A5, 0x0060E4A5, 0x0061E4A5,
            0x0062E4A5, 0x0063E4A5, 0x0064E4A5, 0x0065E4A5, 0x0066E4A5, 0x0067E4A5, 0x0068E4A5, 0x0069E4A5,
            0x006AE4A5, 0x006BE4A5, 0x006CE4A5, 0x006DE4A5, 0x006EE4A5, 0x006FE4A5, 0x0070E4A5, 0x0071E4A5,
            0x0072E4A5, 0x0073E4A5, 0x0074E4A5, 0x0075E4A5, 0x0076E4A5, 0x0077E4A5, 0x0078E4A5, 0x0079E4A5,
            0x007AE4A5, 0x007BE4A5, 0x007CE4A5, 0x007DE4A5, 0x007EE4A5, 0x007FE4A5, 0x0080E4A5, 0x0081E4A5,
            0x0082E4A5, 0x0083E4A5, 0x0084E4A5, 0x0085E4A5, 0x0086E4A5, 0x0087E4A5, 0x0088E4A5, 0x0089E4A5,
            0x008AE4A5, 0x008BE4A5, 0x008CE4A5, 0x008DE4A5, 0x008FE4A5, 0x0091E4A5, 0x0093E4A5, 0x0095E4A5,
            0x0097E4A5, 0x0099E4A5, 0x009BE4A5, 0x009DE4A5, 0x009FE4A5, 0x00A1E4A5, 0x00A3E4A5, 0x00A5E4A5,
            0x00A7E4A5, 0x00A9E4A5, 0x00ABE4A5, 0x00ADE4A5, 0x00AFE4A5, 0x00B1E4A5, 0x00B3E4A5, 0x00B5E4A5,
            0x00B7E4A5, 0x00B9E4A5, 0x00BBE4A5, 0x00BDE4A5, 0x00BFE4A5, 0x00C1E4A5, 0x00C3E4A5, 0x00C5E4A5,
            0x00C7E4A5, 0x00C9E4A5, 0x00CBE4A5, 0x00CDE4A5, 0x00CFE4A5, 0x00D1E4A5, 0x00D3E4A5, 0x00D5E4A5,
            0x00D7E4A5, 0x00D9E4A5, 0x00DBE4A5, 0x00DDE4A5, 0x00DFE4A5, 0x00E1E4A5, 0x00E3E4A5, 0x00E5E4A5,
            0x00E7E4A5, 0x00E9E4A5, 0x00EBE4A5, 0x00EDE4A5, 0x00EFE4A5, 0x00F1E4A5, 0x00F3E4A5, 0x00F5E4A5,
            0x00F7E4A5, 0x00F9E4A5, 0x00FBE4A5, 0x00FDE4A5, 0x00FFE4A5, 0x0101E4A5, 0x0103E4A5, 0x0105E4A5,
            0x0107E4A5, 0x0109E4A5, 0x010BE4A5, 0x010DE4A5, 0x010FE4A5, 0x0111E4A5, 0x0113E4A5, 0x0115E4A5,
            0x0117E4A5, 0x0119E4A5, 0x011BE4A5, 0x011DE4A5, 0x011FE4A5, 0x0121E4A5, 0x0123E4A5, 0x0125E4A5,
            0x0127E4A5, 0x0129E4A5, 0x012BE4A5, 0x012DE4A5, 0x012FE4A5, 0x0131E4A5, 0x0133E4A5, 0x0135E4A5,
            0x0137E4A5, 0x013BE4A5, 0x013FE4A5, 0x0143E4A5, 0x0147E4A5, 0x014BE4A5, 0x014FE4A5, 0x0153E4A5,
            0x0157E4A5, 0x015BE4A5, 0x015FE4A5, 0x0163E4A5, 0x0167E4A5, 0x016BE4A5, 0x016FE4A5, 0x0173E4A5,
            0x0177E4A5, 0x017BE4A5, 0x017FE4A5, 0x0183E4A5, 0x0187E4A5, 0x018BE4A5, 0x018FE4A5, 0x0193E4A5,
            0x0197E4A5, 0x019BE4A5, 0x019FE4A5, 0x01A3E4A5, 0x01A7E4A5, 0x01ABE4A5, 0x01AFE4A5, 0x01B3E4A5,
            0x01B7E4A5, 0x01BBE4A5, 0x01BFE4A5, 0x01C3E4A5, 0x01C7E4A5, 0x01CBE4A5, 0x01CFE4A5, 0x01D3E4A5,
            0x01D7E4A5, 0x01DBE4A5, 0x01DFE4A5, 0x01E3E4A5, 0x01E7E4A5, 0x01EBE4A5, 0x01EFE4A5, 0x01F3E4A5,
            0x01F7E4A5, 0x01FBE4A5, 0x01FFE4A5, 0x0203E4A5, 0x0207E4A5, 0x020BE4A5, 0x020FE4A5, 0x0213E4A5,
            0x0217E4A5, 0x021BE4A5, 0x021FE4A5, 0x0223E4A5, 0x0227E4A5, 0x022BE4A5, 0x022FE4A5, 0x0233E4A5,
            0x0237E4A5, 0x023BE4A5, 0x023FE4A5, 0x0243E4A5, 0x0247E4A5, 0x024BE4A5, 0x024FE4A5, 0x0253E4A5,
            0x0257E4A5, 0x025BE4A5, 0x025FE4A5, 0x0263E4A5, 0x0267E4A5, 0x026BE4A5, 0x026FE4A5, 0x0273E4A5,
            0x0277E4A5, 0x027BE4A5, 0x027FE4A5, 0x0283E4A5, 0x0287E4A5, 0x028BE4A5, 0x028FE4A5, 0x0293E4A5,
            0x0297E4A5, 0x029BE4A5, 0x029FE4A5, 0x02A3E4A5, 0x02A7E4A5, 0x02ABE4A5, 0x02AFE4A5, 0x02B3E4A5,
            0x02BBE4A5, 0x02C3E4A5, 0x02CBE4A5, 0x02D3E4A5, 0x02DBE4A5, 0x02E3E4A5, 0x02EBE4A5, 0x02F3E4A5,
            0x02FBE4A5, 0x0303E4A5, 0x030BE4A5, 0x0313E4A5, 0x031BE4A5, 0x0323E4A5, 0x032BE4A5, 0x0333E4A5,
            0x033BE4A5, 0x0343E4A5, 0x034BE4A5, 0x0353E4A5, 0x035BE4A5, 0x0363E4A5, 0x036BE4A5, 0x0373E4A5,
            0x037BE4A5, 0x0383E4A5, 0x038BE4A5, 0x0393E4A5, 0x039BE4A5, 0x03A3E4A5, 0x03ABE4A5, 0x03B3E4A5,
            0x03BBE4A5, 0x03C3E4A5, 0x03CBE4A5, 0x03D3E4A5, 0x03DBE4A5, 0x03E3E4A5, 0x03EBE4A5, 0x03F3E4A5,
            0x03FBE4A5, 0x0403E4A5, 0x040BE4A5, 0x0413E4A5, 0x041BE4A5, 0x0423E4A5, 0x042BE4A5, 0x0433E4A5,
            0x043BE4A5, 0x0443E4A5, 0x044BE4A5, 0x0453E4A5, 0x045BE4A5, 0x0463E4A5, 0x046BE4A5, 0x0473E4A5,
            0x047BE4A5, 0x0483E4A5, 0x048BE4A5, 0x0493E4A5, 0x049BE4A5, 0x04A3E4A5, 0x04ABE4A5, 0x04B3E4A5,
            0x04BBE4A5, 0x04C3E4A5, 0x04CBE4A5, 0x04D3E4A5, 0x04DBE4A5, 0x04E3E4A5, 0x04EBE4A5, 0x04F3E4A5,
            0x04FBE4A5, 0x0503E4A5, 0x050BE4A5, 0x0513E4A5, 0x051BE4A5, 0x0523E4A5, 0x052BE4A5, 0x0533E4A5,
            0x053BE4A5, 0x0543E4A5, 0x054BE4A5, 0x0553E4A5, 0x055BE4A5, 0x0563E4A5, 0x056BE4A5, 0x0573E4A5,
            0x057BE4A5, 0x0583E4A5, 0x058BE4A5, 0x0593E4A5, 0x059BE4A5, 0x05A3E4A5, 0x05ABE4A5, 0x05B3E4A5,
            0x05BBE4A5, 0x05C3E4A5, 0x05CBE4A5, 0x05D3E4A5, 0x05DBE4A5, 0x05E3E4A5, 0x05EBE4A5, 0x05F3E4A5,
            0x05FBE4A5, 0x060BE4A5, 0x061BE4A5, 0x062BE4A5, 0x063BE4A5, 0x064BE4A5, 0x065BE4A5, 0x465BE4A5,
        };

        private static readonly uint[] LengthSlotBase =
        {
            0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007, 0x00000008,
            0x00000009, 0x0000000A, 0x0000000B, 0x0000000C, 0x0000000D, 0x0000000E, 0x0000000F, 0x00000010,
            0x00000011, 0x00000012, 0x00000013, 0x00000014, 0x00000015, 0x00000016, 0x00000017, 0x00000018,
            0x00000019, 0x0000001A, 0x0000001B, 0x0000001D, 0x0000001F, 0x00000021, 0x00000023, 0x00000027,
            0x0000002B, 0x0000002F, 0x00000033, 0x00000037, 0x0000003B, 0x00000043, 0x0000004B, 0x00000053,
            0x0000005B, 0x0000006B, 0x0000007B, 0x0000008B, 0x0000009B, 0x000000AB, 0x000000CB, 0x000000EB,
            0x0000012B, 0x000001AB, 0x000002AB, 0x000004AB, 0x000008AB, 0x000108AB, 0x400108AB,
        };

        private static readonly byte[] ExtraOffsetBits = DeriveExtraBits(OffsetSlotBase, MaxNumOffsetSyms);
        private static readonly byte[] ExtraLengthBits = DeriveExtraBits(LengthSlotBase, NumLengthSyms);

        private readonly ProbabilityContext Main = new ProbabilityContext(NumMainProbs);
        private readonly ProbabilityContext Match = new ProbabilityContext(NumMatchProbs);
        private readonly ProbabilityContext Lz = new ProbabilityContext(NumLzProbs);
        private readonly ProbabilityContext Delta = new ProbabilityContext(NumDeltaProbs);
        private readonly ProbabilityContext[] LzRep = { new ProbabilityContext(NumLzRepProbs), new ProbabilityContext(NumLzRepProbs) };
        private readonly ProbabilityContext[] DeltaRep = { new ProbabilityContext(NumDeltaRepProbs), new ProbabilityContext(NumDeltaRepProbs) };

        private readonly HuffmanCode LiteralCode = new HuffmanCode(NumLiteralSyms, 9);
        private readonly HuffmanCode LzOffsetCode = new HuffmanCode(MaxNumOffsetSyms, 10);
        private readonly HuffmanCode LengthCode = new HuffmanCode(NumLengthSyms, 7);
        private readonly HuffmanCode DeltaOffsetCode = new HuffmanCode(MaxNumOffsetSyms, 10);
        private readonly HuffmanCode DeltaPowerCode = new HuffmanCode(NumDeltaPowerSyms, 4);

        private readonly int[] LastTargetUsages = new int[65536];

        private readonly uint[] RecentLzOffsets = new uint[4];
        private readonly ulong[] RecentDeltaPairs = new ulong[4];

        private static byte[] DeriveExtraBits(uint[] Base, int Count)
        {
            byte[] Bits = new byte[Count];

            for (int Slot = 0; Slot < Count; Slot++)
            {
                uint Gap = Base[Slot + 1] - Base[Slot];
                int Length = 0;

                while ((1u << Length) < Gap)
                    Length++;

                Bits[Slot] = (byte)Length;
            }

            return Bits;
        }

        private static int GetSlot(uint Value, uint[] Base, int Count)
        {
            int Low = 0;
            int High = Count;

            while (Low < High - 1)
            {
                int Middle = (Low + High) / 2;

                if (Value >= Base[Middle])
                    Low = Middle;
                else
                    High = Middle;
            }

            return Low;
        }

        private static int GetNumOffsetSlots(int UncompressedSize)
        {
            if (UncompressedSize < 2)
                return 0;

            return 1 + GetSlot((uint)(UncompressedSize - 1), OffsetSlotBase, MaxNumOffsetSyms);
        }

        public bool Decompress(ReadOnlySpan<byte> Input, Span<byte> Output)
        {
            if ((Input.Length & 1) != 0 || Input.Length < 4)
                return false;

            int OffsetSlots = GetNumOffsetSlots(Output.Length);
            if (OffsetSlots == 0)
                return false;

            Main.Reset();
            Match.Reset();
            Lz.Reset();
            Delta.Reset();
            LzRep[0].Reset();
            LzRep[1].Reset();
            DeltaRep[0].Reset();
            DeltaRep[1].Reset();

            LiteralCode.Init(NumLiteralSyms, LiteralRebuildFreq);
            LzOffsetCode.Init(OffsetSlots, LzOffsetRebuildFreq);
            LengthCode.Init(NumLengthSyms, LengthRebuildFreq);
            DeltaOffsetCode.Init(OffsetSlots, DeltaOffsetRebuildFreq);
            DeltaPowerCode.Init(NumDeltaPowerSyms, DeltaPowerRebuildFreq);

            for (int i = 0; i < RecentLzOffsets.Length; i++)
            {
                RecentLzOffsets[i] = (uint)(i + 1);
                RecentDeltaPairs[i] = (ulong)(i + 1);
            }

            LzmsRangeDecoder Range = new LzmsRangeDecoder(Input);
            LzmsBitStream Bits = new LzmsBitStream(Input);

            uint MainState = 0;
            uint MatchState = 0;
            uint LzState = 0;
            uint DeltaState = 0;
            uint LzRepState0 = 0;
            uint LzRepState1 = 0;
            uint DeltaRepState0 = 0;
            uint DeltaRepState1 = 0;

            int PreviousItem = 0;
            int Position = 0;

            while (Position < Output.Length)
            {
                if (Range.DecodeBit(ref MainState, NumMainProbs, Main) == 0)
                {
                    int Symbol = LiteralCode.Decode(ref Bits);
                    if (Symbol < 0)
                        return false;

                    Output[Position++] = (byte)Symbol;
                    PreviousItem = 0;
                    continue;
                }

                if (Range.DecodeBit(ref MatchState, NumMatchProbs, Match) == 0)
                {
                    uint Offset;

                    if (Range.DecodeBit(ref LzState, NumLzProbs, Lz) == 0)
                    {
                        int Slot = LzOffsetCode.Decode(ref Bits);
                        if (Slot < 0 || Slot >= OffsetSlots)
                            return false;

                        Offset = OffsetSlotBase[Slot] + Bits.ReadBits(ExtraOffsetBits[Slot]);

                        RecentLzOffsets[3] = RecentLzOffsets[2];
                        RecentLzOffsets[2] = RecentLzOffsets[1];
                        RecentLzOffsets[1] = RecentLzOffsets[0];
                    }
                    else
                    {
                        int Shift = PreviousItem & 1;

                        if (Range.DecodeBit(ref LzRepState0, NumLzRepProbs, LzRep[0]) == 0)
                        {
                            Offset = RecentLzOffsets[Shift];
                            RecentLzOffsets[Shift] = RecentLzOffsets[0];
                        }
                        else if (Range.DecodeBit(ref LzRepState1, NumLzRepProbs, LzRep[1]) == 0)
                        {
                            Offset = RecentLzOffsets[1 + Shift];
                            RecentLzOffsets[1 + Shift] = RecentLzOffsets[1];
                            RecentLzOffsets[1] = RecentLzOffsets[0];
                        }
                        else
                        {
                            Offset = RecentLzOffsets[2 + Shift];
                            RecentLzOffsets[2 + Shift] = RecentLzOffsets[2];
                            RecentLzOffsets[2] = RecentLzOffsets[1];
                            RecentLzOffsets[1] = RecentLzOffsets[0];
                        }
                    }

                    RecentLzOffsets[0] = Offset;
                    PreviousItem = 1;

                    int Length = DecodeLength(ref Bits);
                    if (Length <= 0)
                        return false;

                    if (Offset > (uint)Position || Length > Output.Length - Position)
                        return false;

                    LzOutput.CopyMatch(Output, Position, (int)Offset, Length);
                    Position += Length;
                    continue;
                }

                {
                    ulong Pair;

                    if (Range.DecodeBit(ref DeltaState, NumDeltaProbs, Delta) == 0)
                    {
                        int PowerSymbol = DeltaPowerCode.Decode(ref Bits);
                        if (PowerSymbol < 0)
                            return false;

                        int Slot = DeltaOffsetCode.Decode(ref Bits);
                        if (Slot < 0 || Slot >= OffsetSlots)
                            return false;

                        uint ExplicitOffset = OffsetSlotBase[Slot] + Bits.ReadBits(ExtraOffsetBits[Slot]);

                        Pair = ((ulong)(uint)PowerSymbol << 32) | ExplicitOffset;
                        RecentDeltaPairs[3] = RecentDeltaPairs[2];
                        RecentDeltaPairs[2] = RecentDeltaPairs[1];
                        RecentDeltaPairs[1] = RecentDeltaPairs[0];
                    }
                    else
                    {
                        int Shift = PreviousItem >> 1;

                        if (Range.DecodeBit(ref DeltaRepState0, NumDeltaRepProbs, DeltaRep[0]) == 0)
                        {
                            Pair = RecentDeltaPairs[Shift];
                            RecentDeltaPairs[Shift] = RecentDeltaPairs[0];
                        }
                        else if (Range.DecodeBit(ref DeltaRepState1, NumDeltaRepProbs, DeltaRep[1]) == 0)
                        {
                            Pair = RecentDeltaPairs[1 + Shift];
                            RecentDeltaPairs[1 + Shift] = RecentDeltaPairs[1];
                            RecentDeltaPairs[1] = RecentDeltaPairs[0];
                        }
                        else
                        {
                            Pair = RecentDeltaPairs[2 + Shift];
                            RecentDeltaPairs[2 + Shift] = RecentDeltaPairs[2];
                            RecentDeltaPairs[2] = RecentDeltaPairs[1];
                            RecentDeltaPairs[1] = RecentDeltaPairs[0];
                        }
                    }

                    RecentDeltaPairs[0] = Pair;
                    PreviousItem = 2;

                    int Length = DecodeLength(ref Bits);
                    if (Length <= 0)
                        return false;

                    int Power = (int)(Pair >> 32);
                    uint RawOffset = (uint)Pair;

                    long Span = 1L << Power;
                    long Offset = (long)RawOffset << Power;

                    if (Power >= 32 || Offset + Span > Position || Length > Output.Length - Position)
                        return false;

                    int Source = Position - (int)Offset;
                    int Step = (int)Span;

                    for (int i = 0; i < Length; i++)
                    {
                        Output[Position] = (byte)(Output[Source] + Output[Position - Step] - Output[Source - Step]);
                        Position++;
                        Source++;
                    }
                }
            }

            UndoX86Filter(Output);
            return true;
        }

        private int DecodeLength(ref LzmsBitStream Bits)
        {
            int Slot = LengthCode.Decode(ref Bits);
            if (Slot < 0 || Slot >= NumLengthSyms)
                return -1;

            uint Length = LengthSlotBase[Slot];
            int Extra = ExtraLengthBits[Slot];

            if (Extra != 0)
                Length += Bits.ReadBits(Extra);

            return Length > int.MaxValue ? -1 : (int)Length;
        }

        /// <summary>
        /// Reverses the x86 filter the compressor applied. It is not driven by the bitstream. the same heuristic that
        /// decided which call and RIP relative operands to rewrite is replayed over the decoded output.
        /// </summary>
        private void UndoX86Filter(Span<byte> Data)
        {
            if (Data.Length <= 17)
                return;

            for (int i = 0; i < LastTargetUsages.Length; i++)
                LastTargetUsages[i] = -X86IdWindowSize - 1;

            int LastX86Position = -X86MaxTranslationOffset - 1;
            int Position = 1;
            int Tail = Data.Length - 16;

            while (Position < Tail)
            {
                byte Opcode = Data[Position];

                if (Opcode != 0x48 && Opcode != 0x4C && Opcode != 0xE8 && Opcode != 0xE9 && Opcode != 0xF0 && Opcode != 0xFF)
                {
                    Position++;
                    continue;
                }

                Position = Translate(Data, Position, ref LastX86Position);
            }
        }

        private int Translate(Span<byte> Data, int Position, ref int LastX86Position)
        {
            int MaxTranslationOffset = X86MaxTranslationOffset;
            int OpcodeBytes;

            byte Opcode = Data[Position];

            if (Opcode >= 0xF0)
            {
                if ((Opcode & 0x0F) != 0)
                {
                    if (Data[Position + 1] != 0x15)
                        return Position + 1;

                    OpcodeBytes = 2;
                }
                else
                {
                    if (Data[Position + 1] != 0x83 || Data[Position + 2] != 0x05)
                        return Position + 1;

                    OpcodeBytes = 3;
                }
            }
            else if (Opcode <= 0x4C)
            {
                if ((Data[Position + 2] & 0x07) != 0x05)
                    return Position + 1;

                if (Data[Position + 1] != 0x8D &&
                    !(Data[Position + 1] == 0x8B && (Opcode & 0x04) == 0 && (Data[Position + 2] & 0xF0) == 0))
                    return Position + 1;

                OpcodeBytes = 3;
            }
            else if ((Opcode & 0x01) != 0)
            {
                return Position + 5;
            }
            else
            {
                OpcodeBytes = 1;
                MaxTranslationOffset >>= 1;
            }

            int Start = Position;
            Position += OpcodeBytes;

            if (Start - LastX86Position <= MaxTranslationOffset)
            {
                uint Value = (uint)(Data[Position] | (Data[Position + 1] << 8) | (Data[Position + 2] << 16) | (Data[Position + 3] << 24));
                Value -= (uint)Start;

                Data[Position] = (byte)Value;
                Data[Position + 1] = (byte)(Value >> 8);
                Data[Position + 2] = (byte)(Value >> 16);
                Data[Position + 3] = (byte)(Value >> 24);
            }

            ushort Target = (ushort)(Start + (Data[Position] | (Data[Position + 1] << 8)));

            Start += OpcodeBytes + 3;

            if (Start - LastTargetUsages[Target] <= X86IdWindowSize)
                LastX86Position = Start;

            LastTargetUsages[Target] = Start;
            return Position + 4;
        }

        private sealed class ProbabilityContext
        {
            public readonly ulong[] RecentBits;
            public readonly int[] ZeroCounts;

            public ProbabilityContext(int Count)
            {
                RecentBits = new ulong[Count];
                ZeroCounts = new int[Count];
            }

            public void Reset()
            {
                for (int i = 0; i < RecentBits.Length; i++)
                {
                    RecentBits[i] = InitialRecentBits;
                    ZeroCounts[i] = InitialProbability;
                }
            }
        }

        private ref struct LzmsRangeDecoder
        {
            private readonly ReadOnlySpan<byte> Data;
            private uint Range;
            private uint Code;
            private int Next;

            public LzmsRangeDecoder(ReadOnlySpan<byte> Data)
            {
                this.Data = Data;
                Range = 0xFFFFFFFF;
                Code = (uint)(((Data[0] | (Data[1] << 8)) << 16) | (Data[2] | (Data[3] << 8)));
                Next = 4;
            }

            public int DecodeBit(ref uint State, int NumStates, ProbabilityContext Context)
            {
                int Index = (int)State;
                State = (State << 1) & (uint)(NumStates - 1);

                uint Probability = (uint)Context.ZeroCounts[Index];
                Probability += (Probability - 1) >> 31;
                Probability -= Probability >> ProbabilityBits;

                if ((Range & 0xFFFF0000) == 0)
                {
                    Range <<= 16;
                    Code <<= 16;

                    if (Next < Data.Length)
                    {
                        Code |= (uint)(Data[Next] | (Data[Next + 1] << 8));
                        Next += 2;
                    }
                }

                uint Bound = (Range >> ProbabilityBits) * Probability;
                int Bit;

                if (Code < Bound)
                {
                    Range = Bound;
                    Bit = 0;
                }
                else
                {
                    Range -= Bound;
                    Code -= Bound;
                    State |= 1;
                    Bit = 1;
                }

                ulong Recent = Context.RecentBits[Index];
                Context.ZeroCounts[Index] += (int)(Recent >> (ProbabilityDenominator - 1)) - Bit;
                Context.RecentBits[Index] = (Recent << 1) | (uint)Bit;
                return Bit;
            }
        }

        internal ref struct LzmsBitStream
        {
            private readonly ReadOnlySpan<byte> Data;
            private int Next;
            private ulong Buffer;
            private int Count;

            public LzmsBitStream(ReadOnlySpan<byte> Data)
            {
                this.Data = Data;
                Next = Data.Length;
                Buffer = 0;
                Count = 0;
            }

            public void Ensure(int Bits)
            {
                if (Count >= Bits)
                    return;

                int Available = 64 - Count;

                if (Next != 0)
                {
                    Next -= 2;
                    Buffer |= (ulong)(Data[Next] | (Data[Next + 1] << 8)) << (Available - 16);
                }

                if (Next != 0)
                {
                    Next -= 2;
                    Buffer |= (ulong)(Data[Next] | (Data[Next + 1] << 8)) << (Available - 32);
                }

                Count += 32;
            }

            public readonly uint Peek(int Bits)
            {
                return (uint)((Buffer >> 1) >> (63 - Bits));
            }

            public void Remove(int Bits)
            {
                Buffer <<= Bits;
                Count -= Bits;
            }

            public uint ReadBits(int Bits)
            {
                if (Bits == 0)
                    return 0;

                Ensure(Bits);
                uint Value = Peek(Bits);
                Remove(Bits);
                return Value;
            }
        }

        private sealed class HuffmanCode
        {
            private const int SymbolBits = 10;
            private const uint SymbolMask = (1 << SymbolBits) - 1;

            private readonly uint[] Frequencies;
            private readonly byte[] Lengths;
            private readonly uint[] Work;
            private readonly int[] Counters;
            private readonly int[] LengthCounts = new int[MaxCodewordLength + 2];
            private readonly HuffmanDecodeTable Table;

            private int SymbolCount;
            private int RebuildFrequency;
            private int Remaining;

            public HuffmanCode(int MaxSymbols, int TableBits)
            {
                Frequencies = new uint[MaxSymbols];
                Lengths = new byte[MaxSymbols];
                Work = new uint[MaxSymbols];
                Counters = new int[MaxSymbols];
                Table = new HuffmanDecodeTable(MaxSymbols, TableBits);
            }

            public void Init(int SymbolCount, int RebuildFrequency)
            {
                this.SymbolCount = SymbolCount;
                this.RebuildFrequency = RebuildFrequency;

                for (int i = 0; i < SymbolCount; i++)
                    Frequencies[i] = 1;

                Build();
            }

            public int Decode(ref LzmsBitStream Bits)
            {
                int Symbol = Table.Decode(ref Bits);
                if (Symbol < 0 || Symbol >= SymbolCount)
                    return -1;

                Frequencies[Symbol]++;

                if (--Remaining == 0)
                {
                    Build();

                    for (int i = 0; i < SymbolCount; i++)
                        Frequencies[i] = (Frequencies[i] >> 1) + 1;
                }

                return Symbol;
            }

            private void Build()
            {
                int Used = SortSymbols();

                if (Used == 1)
                {
                    int Symbol = (int)(Work[0] & SymbolMask);
                    int Other = Symbol != 0 ? Symbol : 1;

                    Lengths[0] = 1;
                    Lengths[Other] = 1;
                }
                else if (Used >= 2)
                {
                    BuildTree(Used);
                    ComputeLengthCounts(Used - 2);
                    AssignLengths();
                }

                Table.Build(Lengths.AsSpan(0, SymbolCount));
                Remaining = RebuildFrequency;
            }

            private int SortSymbols()
            {
                Array.Clear(Counters, 0, SymbolCount);

                for (int Symbol = 0; Symbol < SymbolCount; Symbol++)
                    Counters[(int)Math.Min(Frequencies[Symbol], (uint)(SymbolCount - 1))]++;

                int Used = 0;

                for (int i = 1; i < SymbolCount; i++)
                {
                    int Count = Counters[i];
                    Counters[i] = Used;
                    Used += Count;
                }

                for (int Symbol = 0; Symbol < SymbolCount; Symbol++)
                {
                    uint Frequency = Frequencies[Symbol];

                    if (Frequency != 0)
                        Work[Counters[(int)Math.Min(Frequency, (uint)(SymbolCount - 1))]++] = (uint)Symbol | (Frequency << SymbolBits);
                    else
                        Lengths[Symbol] = 0;
                }

                int Start = Counters[SymbolCount - 2];
                int End = Counters[SymbolCount - 1];

                // The last counter is a catch-all bucket for every frequency at or above it, so only that bucket is
                // left unsorted by the counting pass. Packed values are unique, so any ascending sort matches.
                if (End > Start)
                    Array.Sort(Work, Start, End - Start);

                return Used;
            }

            private void BuildTree(int Count)
            {
                int Last = Count - 1;
                int i = 0;
                int b = 0;
                int e = 0;

                do
                {
                    uint Frequency;

                    if (i + 1 <= Last && (b == e || (Work[i + 1] >> SymbolBits) <= (Work[b] >> SymbolBits)))
                    {
                        Frequency = (Work[i] >> SymbolBits) + (Work[i + 1] >> SymbolBits);
                        i += 2;
                    }
                    else if (b + 2 <= e && (i > Last || (Work[b + 1] >> SymbolBits) < (Work[i] >> SymbolBits)))
                    {
                        Frequency = (Work[b] >> SymbolBits) + (Work[b + 1] >> SymbolBits);
                        Work[b] = ((uint)e << SymbolBits) | (Work[b] & SymbolMask);
                        Work[b + 1] = ((uint)e << SymbolBits) | (Work[b + 1] & SymbolMask);
                        b += 2;
                    }
                    else
                    {
                        Frequency = (Work[i] >> SymbolBits) + (Work[b] >> SymbolBits);
                        Work[b] = ((uint)e << SymbolBits) | (Work[b] & SymbolMask);
                        i++;
                        b++;
                    }

                    Work[e] = (Frequency << SymbolBits) | (Work[e] & SymbolMask);
                }
                while (++e < Last);
            }

            private void ComputeLengthCounts(int RootIndex)
            {
                Array.Clear(LengthCounts);
                LengthCounts[1] = 2;

                Work[RootIndex] &= SymbolMask;

                for (int Node = RootIndex - 1; Node >= 0; Node--)
                {
                    int Parent = (int)(Work[Node] >> SymbolBits);
                    int Depth = (int)(Work[Parent] >> SymbolBits) + 1;
                    int Length = Depth;

                    Work[Node] = (Work[Node] & SymbolMask) | ((uint)Depth << SymbolBits);

                    if (Length >= MaxCodewordLength)
                    {
                        Length = MaxCodewordLength;

                        do
                        {
                            Length--;
                        }
                        while (LengthCounts[Length] == 0);
                    }

                    LengthCounts[Length]--;
                    LengthCounts[Length + 1] += 2;
                }
            }

            private void AssignLengths()
            {
                int Index = 0;

                for (int Length = MaxCodewordLength; Length >= 1; Length--)
                {
                    for (int Count = LengthCounts[Length]; Count > 0; Count--)
                        Lengths[Work[Index++] & SymbolMask] = (byte)Length;
                }
            }
        }
    }
}
