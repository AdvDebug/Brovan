using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation
{
    internal class Native
    {
        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_open(Arch arch, Mode mode, out IntPtr uc);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_close(IntPtr uc);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_map(IntPtr uc, ulong address, UIntPtr size, MemoryProtection Protection);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_map_ptr(IntPtr uc, ulong address, UIntPtr size, MemoryProtection Protection, IntPtr ptr);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_unmap(IntPtr uc, ulong address, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_protect(IntPtr uc, ulong address, ulong size, MemoryProtection Protection);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_write(IntPtr uc, ulong address, byte[] bytes, UIntPtr size);

        [DllImport("unicorn", EntryPoint = "uc_mem_write", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_write_ptr(IntPtr uc, ulong address, IntPtr bytes, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_read(IntPtr uc, ulong address, byte[] bytes, UIntPtr size);

        [DllImport("unicorn", EntryPoint = "uc_mem_read", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_read_ptr(IntPtr uc, ulong address, IntPtr bytes, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_read(IntPtr uc, ulong address, out ulong value, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_read(IntPtr uc, ulong address, out uint value, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_mem_read(IntPtr uc, ulong address, out ushort value, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_write(IntPtr uc, Registers Reg, ref ulong value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_write(IntPtr uc, Registers Reg, byte[] value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_read(IntPtr uc, Registers Reg, out ulong value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_write(IntPtr uc, Registers Reg, ref uint value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_read(IntPtr uc, Registers Reg, out uint value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_write(IntPtr uc, Registers Reg, ref byte value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_read(IntPtr uc, Registers Reg, out byte value);

        [StructLayout(LayoutKind.Sequential)]
        public struct uc_x86_mmr
        {
            public ushort selector;
            public ulong Base;
            public uint limit;
            public uint flags;
        }

        [DllImport("unicorn", EntryPoint = "uc_reg_write", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_write_mmr(IntPtr uc, Registers Reg, ref uc_x86_mmr value);

        [DllImport("unicorn", EntryPoint = "uc_reg_write", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_write_raw(IntPtr uc, int Reg, ref ulong value);

        [DllImport("unicorn", EntryPoint = "uc_reg_write", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_write_raw(IntPtr uc, int Reg, ref uint value);

        [DllImport("unicorn", EntryPoint = "uc_reg_write", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_write_raw(IntPtr uc, int Reg, ref byte value);

        [DllImport("unicorn", EntryPoint = "uc_reg_read", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_read_raw(IntPtr uc, int Reg, out ulong value);

        [DllImport("unicorn", EntryPoint = "uc_reg_read", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_read_raw(IntPtr uc, int Reg, out uint value);

        [DllImport("unicorn", EntryPoint = "uc_reg_read", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_reg_read_raw(IntPtr uc, int Reg, out byte value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe UCErrors uc_reg_read_batch(IntPtr uc, int* regs, void** vals, int count);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe UCErrors uc_reg_write_batch(IntPtr uc, int* regs, void** vals, int count);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_emu_start(IntPtr uc, ulong begin, ulong until, UIntPtr timeout, UIntPtr count);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_emu_stop(IntPtr uc);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_hook_add(IntPtr uc, out IntPtr hh, Hooks type, IntPtr callback, IntPtr user_data, ulong begin, ulong end);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_hook_add(IntPtr uc, out IntPtr hh, int type, IntPtr callback, IntPtr user_data, ulong begin, ulong end, INSTHooks InstructionHook);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_hook_del(IntPtr uc, IntPtr hook);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_context_save(IntPtr uc, out IntPtr context);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        public static extern UCErrors uc_context_restore(IntPtr uc, IntPtr context);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
        public static extern UCErrors uc_ctl0(IntPtr uc, int control);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
        public static extern UCErrors uc_ctl1(IntPtr uc, int control, int arg1);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
        public static extern UCErrors uc_ctl1_uint(IntPtr uc, int control, uint arg1);
    }

    internal static class NativeLibraryResolver
    {
        private static bool Registered;

        internal static void Register()
        {
            if (Registered)
                return;

            try { NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve); }
            catch (InvalidOperationException) { }
            try { NativeLibrary.SetDllImportResolver(typeof(Brovan.Core.Emulation.BinaryEmulator).Assembly, Resolve); }
            catch (InvalidOperationException) { }
            Registered = true;
        }

        private static IntPtr Resolve(string LibName, Assembly Asm, DllImportSearchPath? SearchPath)
        {
            if (string.Equals(LibName, "unicorn", StringComparison.OrdinalIgnoreCase))
            {
                if (GeneralHelper.IsWindows)
                    return NativeLibrary.Load("unicorn.dll", Asm, SearchPath);

                if (GeneralHelper.IsLinux)
                    return NativeLibrary.Load("libunicorn.so", Asm, SearchPath);

                throw new PlatformNotSupportedException("Brovan currently supports resolving unicorn for Windows and Linux only.");
            }

            if (string.Equals(LibName, "vulkan-1.dll", StringComparison.OrdinalIgnoreCase) && GeneralHelper.IsLinux)
            {
                if (NativeLibrary.TryLoad("libvulkan.so.1", out IntPtr handle))
                    return handle;
                if (NativeLibrary.TryLoad("libvulkan.so", out handle))
                    return handle;
            }

            if (string.Equals(LibName, "libX11-xcb.so.1", StringComparison.OrdinalIgnoreCase))
            {
                if (GeneralHelper.IsLinux)
                {
                    if (NativeLibrary.TryLoad("libX11-xcb.so.1", out IntPtr xcbHandle))
                        return xcbHandle;
                    if (NativeLibrary.TryLoad("libX11-xcb.so", out xcbHandle))
                        return xcbHandle;
                }
                return IntPtr.Zero;
            }

            return IntPtr.Zero;
        }
    }
}
