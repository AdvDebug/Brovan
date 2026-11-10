using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class TokenTransfer
    {
        private const ushort Version = 1;

        internal const int MaxFormBytes = 0x10000;
        private const int MaxCapabilities = 256;
        private const int MaxAttributes = 64;
        private const int MaxValues = 64;
        private const int MaxStringBytes = 0x7FFE;

        private const byte EffectiveOnlyFlag = 0x1;
        private const byte RestrictedFlag = 0x2;

        // Null for a form the reader would refuse, so a writer never sends one.
        internal static byte[] Write(WinToken Token)
        {
            Writer Out = new Writer();
            Out.UInt16(Version);
            Out.Byte((byte)Token.User);
            Out.Byte((byte)Token.Type);
            Out.Byte((byte)Token.ImpersonationLevel);
            Out.Byte((byte)((Token.EffectiveOnly ? EffectiveOnlyFlag : 0) | (Token.IsRestricted ? RestrictedFlag : 0)));
            Out.UInt32(Token.SessionId);
            Out.UInt64(Token.TokenId);
            Out.UInt64(Token.ModifiedId);
            Out.UInt32(Token.AppContainerNumber);
            Out.Bytes(Token.IsAppContainer ? Token.AppContainerSid.AsSpan() : default);

            Out.UInt16((ushort)Token.CapabilitySids.Length);
            foreach (ImmutableArray<byte> Capability in Token.CapabilitySids)
                Out.Bytes(Capability.AsSpan());

            Out.UInt16((ushort)Token.SecurityAttributes.Length);
            foreach (WinTokenSecurityAttribute Attribute in Token.SecurityAttributes)
            {
                Out.String(Attribute.Name);
                Out.UInt16(Attribute.ValueType);
                Out.UInt32(Attribute.Flags);
                Out.UInt16((ushort)Attribute.ValueCount);
                if (Attribute.ValueType == WinTokenSecurityAttribute.TypeString)
                {
                    foreach (string Value in Attribute.StringValues)
                        Out.String(Value);
                }
                else
                {
                    foreach (ulong Value in Attribute.UInt64Values)
                        Out.UInt64(Value);
                }
            }

            byte[] Form = Out.ToArray();
            return TryRead(Form, 0, out _) ? Form : null;
        }

        // Form must be a private host copy, never memory that another process can still write.
        internal static bool TryRead(ReadOnlySpan<byte> Form, ulong OwningProcessId, out WinToken Token)
        {
            Token = null;
            if (Form.Length > MaxFormBytes)
                return false;

            Reader In = new Reader(Form);
            if (!In.UInt16(out ushort FormVersion) || FormVersion != Version)
                return false;

            if (!In.Byte(out byte UserValue) || !In.Byte(out byte TypeValue) || !In.Byte(out byte LevelValue) || !In.Byte(out byte Flags)
                || !In.UInt32(out uint SessionId) || !In.UInt64(out ulong TokenId) || !In.UInt64(out ulong ModifiedId)
                || !In.UInt32(out uint AppContainerNumber))
                return false;

            User User = (User)UserValue;
            TokenType Type = (TokenType)TypeValue;
            SecurityImpersonationLevel Level = (SecurityImpersonationLevel)LevelValue;
            if (User > User.Anonymous || Type > TokenType.Impersonation || Level > SecurityImpersonationLevel.SecurityDelegation
                || (Flags & ~(EffectiveOnlyFlag | RestrictedFlag)) != 0)
                return false;

            // Brovan's anonymous token has session 0, and every other token it makes lives in the interactive session.
            if (SessionId != WinToken.InteractiveSessionId && !(User == User.Anonymous && SessionId == 0))
                return false;

            if (TokenId < SessionIds.FirstLuid || ModifiedId < SessionIds.FirstLuid)
                return false;

            if (!In.Bytes(out ReadOnlySpan<byte> AppContainer))
                return false;
            if (AppContainer.IsEmpty ? AppContainerNumber != 0 : !NtQueryInformationToken.IsValidSid(AppContainer))
                return false;

            if (!In.UInt16(out ushort CapabilityCount) || CapabilityCount > MaxCapabilities)
                return false;

            ImmutableArray<ImmutableArray<byte>>.Builder Capabilities = ImmutableArray.CreateBuilder<ImmutableArray<byte>>(CapabilityCount);
            for (int Index = 0; Index < CapabilityCount; Index++)
            {
                if (!In.Bytes(out ReadOnlySpan<byte> Sid) || !NtQueryInformationToken.IsValidSid(Sid))
                    return false;
                Capabilities.Add(ImmutableArray.Create(Sid));
            }

            if (!In.UInt16(out ushort AttributeCount) || AttributeCount > MaxAttributes)
                return false;

            ImmutableArray<WinTokenSecurityAttribute>.Builder Attributes = ImmutableArray.CreateBuilder<WinTokenSecurityAttribute>(AttributeCount);
            HashSet<string> Names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int Index = 0; Index < AttributeCount; Index++)
            {
                if (!In.String(out string Name) || Name.Length == 0 || !Names.Add(Name)
                    || !In.UInt16(out ushort ValueType) || !In.UInt32(out uint AttributeFlags)
                    || !In.UInt16(out ushort ValueCount) || ValueCount == 0 || ValueCount > MaxValues)
                    return false;

                if (ValueType == WinTokenSecurityAttribute.TypeString)
                {
                    ImmutableArray<string>.Builder Values = ImmutableArray.CreateBuilder<string>(ValueCount);
                    for (int Value = 0; Value < ValueCount; Value++)
                    {
                        if (!In.String(out string Text))
                            return false;
                        Values.Add(Text);
                    }

                    Attributes.Add(new WinTokenSecurityAttribute { Name = Name, ValueType = ValueType, Flags = AttributeFlags, StringValues = Values.MoveToImmutable() });
                }
                else if (ValueType == WinTokenSecurityAttribute.TypeUInt64)
                {
                    ImmutableArray<ulong>.Builder Values = ImmutableArray.CreateBuilder<ulong>(ValueCount);
                    for (int Value = 0; Value < ValueCount; Value++)
                    {
                        if (!In.UInt64(out ulong Number))
                            return false;
                        Values.Add(Number);
                    }

                    Attributes.Add(new WinTokenSecurityAttribute { Name = Name, ValueType = ValueType, Flags = AttributeFlags, UInt64Values = Values.MoveToImmutable() });
                }
                else
                {
                    return false;
                }
            }

            if (!In.AtEnd)
                return false;

            Token = new WinToken(TokenId, ModifiedId)
            {
                Type = Type,
                User = User,
                SessionId = SessionId,
                IsRestricted = (Flags & RestrictedFlag) != 0,
                EffectiveOnly = (Flags & EffectiveOnlyFlag) != 0,
                ImpersonationLevel = Level,
                OwningProcessId = OwningProcessId,
                AppContainerSid = AppContainer.IsEmpty ? default : ImmutableArray.Create(AppContainer),
                AppContainerNumber = AppContainerNumber,
                CapabilitySids = Capabilities.MoveToImmutable(),
                SecurityAttributes = Attributes.MoveToImmutable(),
            };
            return true;
        }

        private sealed class Writer
        {
            private readonly ArrayBufferWriter<byte> Data = new ArrayBufferWriter<byte>(256);

            internal void Byte(byte Value)
            {
                Data.GetSpan(1)[0] = Value;
                Data.Advance(1);
            }

            internal void UInt16(ushort Value)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(Data.GetSpan(2), Value);
                Data.Advance(2);
            }

            internal void UInt32(uint Value)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Data.GetSpan(4), Value);
                Data.Advance(4);
            }

            internal void UInt64(ulong Value)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Data.GetSpan(8), Value);
                Data.Advance(8);
            }

            internal void Bytes(ReadOnlySpan<byte> Value)
            {
                UInt16((ushort)Value.Length);
                Data.Write(Value);
            }

            internal void String(string Value) => Bytes(MemoryMarshal.AsBytes(Value.AsSpan()));

            internal byte[] ToArray() => Data.WrittenSpan.ToArray();
        }

        private ref struct Reader
        {
            private readonly ReadOnlySpan<byte> Data;
            private int Position;

            internal Reader(ReadOnlySpan<byte> Data)
            {
                this.Data = Data;
                Position = 0;
            }

            internal bool AtEnd => Position == Data.Length;

            internal bool Byte(out byte Value)
            {
                Value = 0;
                if (Data.Length - Position < 1)
                    return false;
                Value = Data[Position++];
                return true;
            }

            internal bool UInt16(out ushort Value)
            {
                Value = 0;
                if (Data.Length - Position < 2)
                    return false;
                Value = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(Position));
                Position += 2;
                return true;
            }

            internal bool UInt32(out uint Value)
            {
                Value = 0;
                if (Data.Length - Position < 4)
                    return false;
                Value = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(Position));
                Position += 4;
                return true;
            }

            internal bool UInt64(out ulong Value)
            {
                Value = 0;
                if (Data.Length - Position < 8)
                    return false;
                Value = BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(Position));
                Position += 8;
                return true;
            }

            internal bool Bytes(out ReadOnlySpan<byte> Value)
            {
                Value = default;
                if (!UInt16(out ushort Length) || Length > MaxStringBytes || Data.Length - Position < Length)
                    return false;
                Value = Data.Slice(Position, Length);
                Position += Length;
                return true;
            }

            internal bool String(out string Value)
            {
                Value = null;
                if (!Bytes(out ReadOnlySpan<byte> Raw) || (Raw.Length & 1) != 0)
                    return false;
                Value = new string(MemoryMarshal.Cast<byte, char>(Raw));
                return true;
            }
        }
    }
}
