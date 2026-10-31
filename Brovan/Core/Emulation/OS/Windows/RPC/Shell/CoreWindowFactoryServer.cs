using System;
using System.Buffers.Binary;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Shell
{
    // NT: the app's handler, CoreWindowFactoryProxy, creates the CoreWindow from the data after the OBJREF and calls
    // this object for the rest.
    internal sealed class CoreWindowFactoryServer : HostObject
    {
        private static readonly Guid HandlerClassId = new Guid("b243a9fd-c57a-4d3e-a7cf-21caed64cb5a");

        private static readonly Guid ConfigureWindowFactoryInterface = new Guid("601d51e3-801e-49c9-bbfa-fe29a662aead");
        private static readonly Guid PrivateInterface = new Guid("087ca5a4-8cfc-4264-b39d-da2bb2583a11");

        // The interfaces of CoreWindowFactory::QueryInterface, less those COM itself asks for.
        private static readonly Guid[] Interfaces =
        {
            Orpc.IUnknownId,
            Orpc.IInspectableId,
            new Guid("cd292360-2763-4085-8a9f-74b224a29175"),
            ConfigureWindowFactoryInterface,
            new Guid("4208d435-b020-4346-ae40-2a4796084296"),
            PrivateInterface,
            new Guid("067382b1-acdd-434b-9ca2-75e2fff108bf"),
            new Guid("dbcc81cc-d31a-4e70-9632-fc3fdd4325c0"),
            new Guid("6851041d-eae8-43bd-a60d-ef6cb304c639"),
            new Guid("118b4ce1-ee64-4f90-b4c2-45280afbf38b"),
        };

        private const uint ProcCreateSplashScreen = 5;
        private const uint ProcSetAppWindow = 3;

        private const string ViewIdProperty = "Microsoft.Windows.WindowFactory.ViewId";
        private const string ActivationIdProperty = "Microsoft.Windows.WindowFactory.ActivationId";

        // The fixed fields of the configuration, without the three strings (CoreWindowFactory::v_GetAdditionalDataSizeMax).
        private const int FixedConfigurationSize = 91;

        private readonly PendingViewActivation View;

        internal CoreWindowFactoryServer(PendingViewActivation View) => this.View = View;

        internal override bool Supports(Guid Interface) => Array.IndexOf(Interfaces, Interface) >= 0;

        internal override bool TryCall(HostCall Call, Guid Interface, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub)
        {
            Stub = null;
            if (Interface == PrivateInterface && ProcNumber == ProcSetAppWindow)
                Stub = SetAppWindow(Call.Instance, Parameters);
            else if (Interface == ConfigureWindowFactoryInterface && ProcNumber == ProcCreateSplashScreen)
                Stub = CreateSplashScreen(Parameters);
            else
                return false;

            return true;
        }

        internal override Guid? HandlerClass => HandlerClassId;

        // NT: the factory aggregates its standard marshaler (CoGetStdMarshalEx with SMEXF_SERVER).
        internal override Guid UnmarshalClass => Orpc.AggregatedStandardMarshal;

        // The layout follows CoreWindowFactory::v_MarshalAdditionalData. Only the view is set, so the app's window covers
        // the screen.
        internal override byte[] GetMarshalData(Guid Interface, in StdObjRef Std)
        {
            const byte AllowReuse = 0;
            const uint WindowAttributes = 0;
            const uint SplashScreenColor = 0;
            const string SplashScreenImage = "";
            const uint Orientation = 0;
            const uint ViewActivationFlags = 0;
            const int PositionAndMonitorSize = 16 + sizeof(ulong);
            const string ExperienceId = "";
            const int UserDataSize = 2 * sizeof(ulong);

            int Size = FixedConfigurationSize + (SplashScreenImage.Length + View.ContractId.Length + ExperienceId.Length) * sizeof(char);
            Ndr20Writer Writer = new Ndr20Writer(StandardObjRefSize + sizeof(uint) + Size);
            WriteStandardObjRef(Writer.Take(StandardObjRefSize), Interface, Std);
            Writer.WriteUInt32((uint)Size);
            Writer.WriteByte(AllowReuse);
            Writer.WriteUInt32(WindowAttributes);
            Writer.WriteUInt32(View.ViewId);
            Writer.WriteUInt32(SplashScreenColor);
            WriteString(ref Writer, SplashScreenImage);
            Writer.WriteUInt32(Orientation);
            Writer.WriteUInt32(ViewActivationFlags);
            Writer.WriteZeros(PositionAndMonitorSize);
            View.Request.TryWriteBytes(Writer.Take(16));
            BinaryPrimitives.WriteUInt64LittleEndian(Writer.Take(sizeof(ulong)), View.HostId);
            WriteString(ref Writer, View.ContractId);
            WriteString(ref Writer, ExperienceId);
            Writer.WriteZeros(UserDataSize);
            return Writer.ToArray();
        }

        private static void WriteString(ref Ndr20Writer Writer, string Value)
        {
            Writer.WriteUInt16((ushort)Value.Length);
            Writer.WriteUtf16(Value);
        }

        // NT answers S_OK whether or not the properties are set. It also tells the activation manager's sink, which keeps
        // nothing the guest sees.
        private byte[] SetAppWindow(BinaryEmulator Instance, ReadOnlySpan<byte> Parameters)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Reader.TryReadUInt32(out uint Hwnd))
                return null;

            // NT: user32's SetPropW passes a string name to NtUserSetProp2.
            WinWindow Window = Instance.WinHelper.GetWindow((ulong)(long)(int)Hwnd);
            if (Window != null)
            {
                Window.AtomProperties[Instance.WinHelper.RegisterWindowMessageAtom(ViewIdProperty)] = View.ViewId;
                if ((uint)View.ActivationId != 0)
                    Window.AtomProperties[Instance.WinHelper.RegisterWindowMessageAtom(ActivationIdProperty)] = (uint)View.ActivationId;
            }

            return SuccessResult;
        }

        // The app ignores a failure here and makes its own splash screen events.
        private static byte[] CreateSplashScreen(ReadOnlySpan<byte> Parameters)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Reader.TryReadUInt32(out _))
                return null;

            Utils.LogError("[-] Shell: the window factory has no splash screen to give.");
            Ndr20Writer Writer = new Ndr20Writer(0x40);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Orpc.ENotImpl);
            return Writer.ToArray();
        }
    }
}
