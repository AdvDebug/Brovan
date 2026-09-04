using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static unsafe class NativeSteamClient
    {
        private static delegate* unmanaged<byte*, int*, IntPtr> CreateInterfaceFn;
        private static delegate* unmanaged<int, void*, int*, byte> BGetCallbackFn;
        private static delegate* unmanaged<int, byte> FreeLastCallbackFn;
        private static delegate* unmanaged<int, ulong, void*, int, int, byte*, byte> GetApiCallResultFn;
        private static delegate* unmanaged<int, byte*, void> NotifyMissingInterfaceFn;

        private static bool Attempted;

        public static bool Ready { get; private set; }

        public static string Directory { get; private set; }

        public static bool TryStart(uint AppId, out string Error)
        {
            Error = null;
            if (Ready)
            {
                // The client reads the app id once, at load, so a later run cannot rebind it.
                if (AccountAppId != 0 && AccountAppId != AppId)
                {
                    Error = $"the Steam client in this process is already serving app {AccountAppId}";
                    return false;
                }

                return true;
            }

            if (Attempted)
            {
                Error = "the Steam client library did not load earlier in this run";
                return false;
            }

            Attempted = true;

            if (!HostSteamInstall.TryLocate(out string Dir, out Error))
                return false;

            // The client reads the app id from the environment while its own startup code runs.
            Environment.SetEnvironmentVariable("SteamAppId", AppId.ToString());
            Environment.SetEnvironmentVariable("SteamGameId", AppId.ToString());

            try
            {
                foreach (string Support in HostSteamInstall.SupportLibraries)
                {
                    string Path = System.IO.Path.Combine(Dir, Support);
                    if (File.Exists(Path))
                        NativeLibrary.Load(Path);
                }

                string ClientPath = System.IO.Path.Combine(Dir, HostSteamInstall.ClientLibrary);
                IntPtr Client = NativeLibrary.Load(ClientPath);

                CreateInterfaceFn = (delegate* unmanaged<byte*, int*, IntPtr>)NativeLibrary.GetExport(Client, "CreateInterface");
                BGetCallbackFn = (delegate* unmanaged<int, void*, int*, byte>)NativeLibrary.GetExport(Client, "Steam_BGetCallback");
                FreeLastCallbackFn = (delegate* unmanaged<int, byte>)NativeLibrary.GetExport(Client, "Steam_FreeLastCallback");
                GetApiCallResultFn = (delegate* unmanaged<int, ulong, void*, int, int, byte*, byte>)NativeLibrary.GetExport(Client, "Steam_GetAPICallResult");

                NativeLibrary.TryGetExport(Client, "Steam_NotifyMissingInterface", out IntPtr Notify);
                NotifyMissingInterfaceFn = (delegate* unmanaged<int, byte*, void>)Notify;

                Directory = Dir;
            }
            catch (Exception Ex)
            {
                Error = Ex.Message;
                return false;
            }

            if (!TryProbe(out ulong SteamId, out uint RunningAppId, out Error))
                return false;

            AccountSteamId = SteamId;
            AccountAppId = RunningAppId;
            Ready = true;
            return true;
        }

        public static ulong AccountSteamId { get; private set; }

        public static uint AccountAppId { get; private set; }

        // A client that is installed but not signed in must read as unavailable.
        private static bool TryProbe(out ulong SteamId, out uint RunningAppId, out string Error)
        {
            SteamId = 0;
            RunningAppId = 0;
            Error = null;

            IntPtr Client = CreateInterface("SteamClient017");
            if (Client == IntPtr.Zero)
            {
                Error = "the Steam client library has no SteamClient017 interface";
                return false;
            }

            IntPtr* Vtable = *(IntPtr**)Client;
            int Pipe = ((delegate* unmanaged<IntPtr, int>)Vtable[0])(Client);
            if (Pipe == 0)
            {
                Error = "Steam is not running";
                return false;
            }

            try
            {
                int User = ((delegate* unmanaged<IntPtr, int, int>)Vtable[2])(Client, Pipe);
                if (User == 0)
                {
                    Error = "no Steam user is signed in";
                    return false;
                }

                IntPtr SteamUser;
                fixed (byte* Version = Ascii("SteamUser023"))
                    SteamUser = ((delegate* unmanaged<IntPtr, int, int, byte*, IntPtr>)Vtable[5])(Client, User, Pipe, Version);

                if (SteamUser != IntPtr.Zero)
                {
                    // CSteamID has a constructor, so MSVC returns it through a hidden pointer while
                    // System V, which classifies by size alone, hands it back in RAX.
                    if (GeneralHelper.IsWindows)
                    {
                        ulong Value = 0;
                        ((delegate* unmanaged<IntPtr, ulong*, ulong*>)(*(IntPtr**)SteamUser)[2])(SteamUser, &Value);
                        SteamId = Value;
                    }
                    else
                    {
                        SteamId = ((delegate* unmanaged<IntPtr, ulong>)(*(IntPtr**)SteamUser)[2])(SteamUser);
                    }
                }

                IntPtr Utils;
                fixed (byte* Version = Ascii("SteamUtils010"))
                    Utils = ((delegate* unmanaged<IntPtr, int, byte*, IntPtr>)Vtable[9])(Client, Pipe, Version);

                if (Utils != IntPtr.Zero)
                    RunningAppId = ((delegate* unmanaged<IntPtr, uint>)(*(IntPtr**)Utils)[9])(Utils);

                ((delegate* unmanaged<IntPtr, int, int, void>)Vtable[4])(Client, Pipe, User);
            }
            finally
            {
                ((delegate* unmanaged<IntPtr, int, byte>)Vtable[1])(Client, Pipe);
            }

            if (SteamId == 0)
            {
                Error = "the Steam client reported no account";
                return false;
            }

            return true;
        }

        private static byte[] Ascii(string Value)
        {
            byte[] Bytes = new byte[Value.Length + 1];
            for (int i = 0; i < Value.Length; i++)
                Bytes[i] = (byte)Value[i];
            return Bytes;
        }

        public static IntPtr CreateInterface(string Version)
        {
            int ReturnCode = 0;
            fixed (byte* Name = Ascii(Version))
                return CreateInterfaceFn(Name, &ReturnCode);
        }

        public static IntPtr CreateInterface(byte* Version, int* ReturnCode) => CreateInterfaceFn(Version, ReturnCode);

        public static byte BGetCallback(int Pipe, void* Message, int* Call) => BGetCallbackFn(Pipe, Message, Call);

        public static byte FreeLastCallback(int Pipe) => FreeLastCallbackFn(Pipe);

        public static byte GetApiCallResult(int Pipe, ulong Call, void* Buffer, int BufferSize, int Expected, byte* Failed) =>
            GetApiCallResultFn(Pipe, Call, Buffer, BufferSize, Expected, Failed);

        public static void NotifyMissingInterface(int Pipe, byte* Version)
        {
            if (NotifyMissingInterfaceFn != null)
                NotifyMissingInterfaceFn(Pipe, Version);
        }
    }
}
