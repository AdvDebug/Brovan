using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed unsafe class BrovSteamDevice : IWinDevice
    {
        private const uint IOCTL_BROVSTEAM_CALL = 0x80002400;
        private const uint MaxPayload = 1u << 20;
        private const uint MaxCallResult = 1u << 16;

        private const uint CmdCreateInterface = 1;
        private const uint CmdBGetCallback = 2;
        private const uint CmdGetApiCallResult = 3;
        private const uint CmdNotifyMissingInterface = 6;

        private readonly object Lock = new object();
        private readonly BrovSteamState State = new BrovSteamState();
        private readonly GenReader Reader = new GenReader();
        private readonly GenBuf Writer = new GenBuf();

        public string DeviceName => "\\Device\\BrovSteam";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = HandleIoctl;

            if (Instance.WinHelper.Steam == null || !Instance.WinHelper.Steam.Enabled)
            {
                InternalPath = null;
                Handler = null;
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS HandleIoctl(uint Ioctl, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Ioctl != IOCTL_BROVSTEAM_CALL)
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[BrovSteam] unknown IOCTL 0x{Ioctl:X}.", LogFlags.Issues);

                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            byte[] Input = Data.InputBuffer;
            // InputBuffer can be pooled, so only InputLength bounds the guest data.
            uint InputLength = Input == null ? 0 : Math.Min(Data.InputLength, (uint)Input.Length);
            if (Input == null || InputLength < 8)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Id = BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(0, 4));
            uint PayloadLength = BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(4, 4));
            if (PayloadLength > InputLength - 8 || PayloadLength > MaxPayload)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            byte[] Output;
            lock (Lock)
            {
                Reader.Reset(Input, 8, (int)PayloadLength);
                Writer.Reset();
                uint Status = 0;

                try
                {
                    if (!HandleExport(Id, Instance) && !BrovSteamGenDispatch.Dispatch(Id, Reader, Writer, State))
                    {
                        if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                            Instance.TriggerEventMessage($"[BrovSteam] unknown command {Id}.", LogFlags.Issues);

                        Status = 1;
                    }
                }
                catch (Exception Ex)
                {
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[!] BrovSteam: {Ex.Message}", LogFlags.Issues);

                    Writer.Reset();
                    Status = 1;
                }
                finally
                {
                    State.FreeCallAllocs();
                }

                Output = Writer.Finish((int)Status);
            }

            Data.OutputBuffer = Output;
            Data.Information = (ulong)Output.Length;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private bool HandleExport(uint Id, BinaryEmulator Instance)
        {
            switch (Id)
            {
                case CmdCreateInterface:
                    {
                        byte* Version = State.ReadString(Reader);
                        if (Version == null)
                            throw new InvalidOperationException("BrovSteam: CreateInterface without a version string.");

                        int ReturnCode = 0;
                        IntPtr Interface = NativeSteamClient.CreateInterface(Version, &ReturnCode);
                        if (Interface == IntPtr.Zero && (Instance.Settings.Flags & LogFlags.Issues) != 0)
                            Instance.TriggerEventMessage($"[BrovSteam] the client has no {Marshal.PtrToStringAnsi((IntPtr)Version)}.", LogFlags.Issues);

                        Writer.WriteU32(State.Register(Interface, Version));
                        return true;
                    }
                case CmdBGetCallback:
                    {
                        int Pipe = (int)Reader.ReadU32();
                        // CallbackMsg_t: hSteamUser@0, iCallback@4, pubParam@8, cubParam@16.
                        byte* Message = stackalloc byte[24];
                        int Call = 0;
                        if (NativeSteamClient.BGetCallback(Pipe, Message, &Call) == 0)
                        {
                            Writer.WriteU32(0);
                            return true;
                        }

                        uint Length = *(uint*)(Message + 16);
                        IntPtr Parameter = *(IntPtr*)(Message + 8);
                        if (Length > MaxCallResult || Parameter == IntPtr.Zero)
                            Length = 0;

                        Writer.WriteU32(1);
                        Writer.WriteU32(*(uint*)Message);
                        Writer.WriteU32(*(uint*)(Message + 4));
                        Writer.WriteU32(Length);
                        if (Length != 0)
                            Writer.WriteBytesFrom(Parameter, Length);

                        NativeSteamClient.FreeLastCallback(Pipe);
                        return true;
                    }
                case CmdGetApiCallResult:
                    {
                        int Pipe = (int)Reader.ReadU32();
                        ulong Call = Reader.ReadU64();
                        uint Size = Reader.ReadU32();
                        int Expected = (int)Reader.ReadU32();
                        if (Size > MaxCallResult)
                            throw new InvalidOperationException($"BrovSteam: call result of {Size} bytes exceeds the cap.");

                        IntPtr Buffer = State.Alloc((int)(Size == 0 ? 1 : Size));
                        byte Failed = 0;
                        byte Result = NativeSteamClient.GetApiCallResult(Pipe, Call, (void*)Buffer, (int)Size, Expected, &Failed);

                        Writer.WriteU32(Result);
                        Writer.WriteU32(Failed);
                        Writer.WriteU32(Size);
                        if (Size != 0)
                            Writer.WriteBytesFrom(Buffer, Size);
                        return true;
                    }
                case CmdNotifyMissingInterface:
                    {
                        int Pipe = (int)Reader.ReadU32();
                        byte* Version = State.ReadString(Reader);
                        if (Version == null)
                            throw new InvalidOperationException("BrovSteam: missing interface report without a version string.");

                        Instance.TriggerEventMessage($"[BrovSteam] the guest asked for {Marshal.PtrToStringAnsi((IntPtr)Version)}, which is not in steam.xml.", LogFlags.Issues);
                        NativeSteamClient.NotifyMissingInterface(Pipe, Version);
                        return true;
                    }
                default:
                    return false;
            }
        }
    }
}
