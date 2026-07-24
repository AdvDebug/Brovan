using System;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static unsafe class BrovVulkGenStruct
    {
        private const uint MaxElems = 1u << 20;
        private const long MaxBytes = 256L << 20;

        internal static int CheckedBytes(uint n, int elem)
        {
            if (elem <= 0)
                throw new InvalidOperationException("BrovVulk generic: non-positive element size.");
            if (n == 0)
                return 0;
            if (n > MaxElems)
                throw new InvalidOperationException($"BrovVulk generic: array count {n} exceeds cap.");
            long total = (long)n * elem;
            if (total > MaxBytes)
                throw new InvalidOperationException($"BrovVulk generic: allocation {total} bytes exceeds cap.");
            return (int)total;
        }

        private static void VerifyArrayLen(IntPtr dst, in BvkM d, uint n)
        {
            if (n != 0 && n != *(uint*)(dst + d.LenOffset))
                throw new InvalidOperationException("BrovVulk generic: array length mismatch.");
        }

        public static IntPtr Rebuild(int sid, GenReader r, GenState st)
        {
            IntPtr p = st.Alloc(BrovVulkStructMeta.Sizes[sid]);
            RebuildAt(sid, r, st, p);
            return p;
        }

        public static void RebuildAt(int sid, GenReader r, GenState st, IntPtr dst)
        {
            foreach (BvkM d in BrovVulkStructMeta.Members[sid])
            {
                IntPtr fp = dst + d.Offset;
                switch (d.Kind)
                {
                    case BvkMK.Scalar:
                        r.CopyInto(fp, (uint)d.Size);
                        break;
                    case BvkMK.Handle:
                        *(IntPtr*)fp = st.Lookup(r.ReadU32(), d.HandleType);
                        break;
                    case BvkMK.StructValue:
                        RebuildAt(d.Sub, r, st, fp);
                        break;
                    case BvkMK.StructPtr:
                        *(IntPtr*)fp = r.ReadU32() != 0 ? Rebuild(d.Sub, r, st) : IntPtr.Zero;
                        break;
                    case BvkMK.StructArray:
                    {
                        uint n = r.ReadU32();
                        VerifyArrayLen(dst, d, n);
                        if (n > 0)
                        {
                            int esz = BrovVulkStructMeta.Sizes[d.Sub];
                            int bytes = CheckedBytes(n, esz);
                            IntPtr arr = st.Alloc(bytes);
                            for (uint k = 0; k < n; k++)
                                RebuildAt(d.Sub, r, st, arr + (int)(k * (uint)esz));
                            *(IntPtr*)fp = arr;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.HandleArray:
                    {
                        uint n = r.ReadU32();
                        VerifyArrayLen(dst, d, n);
                        if (n > 0)
                        {
                            IntPtr arr = st.Alloc(CheckedBytes(n, 8));
                            for (uint k = 0; k < n; k++)
                                *(IntPtr*)(arr + (int)(k * 8)) = st.Lookup(r.ReadU32(), d.HandleType);
                            *(IntPtr*)fp = arr;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.ScalarArray:
                    {
                        uint n = r.ReadU32();
                        VerifyArrayLen(dst, d, n);
                        if (n > 0)
                        {
                            int bytes = CheckedBytes(n, d.Size);
                            IntPtr arr = st.Alloc(bytes);
                            r.CopyInto(arr, (uint)bytes);
                            *(IntPtr*)fp = arr;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.StringZ:
                    {
                        uint l = r.ReadU32();
                        if (l > 0)
                        {
                            IntPtr s = st.Alloc(CheckedBytes(l, 1) + 1);
                            r.CopyInto(s, l);
                            *(IntPtr*)fp = s;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.StringArray:
                    {
                        uint n = r.ReadU32();
                        VerifyArrayLen(dst, d, n);
                        if (n > 0)
                        {
                            IntPtr arr = st.Alloc(CheckedBytes(n, 8));
                            for (uint k = 0; k < n; k++)
                            {
                                uint l = r.ReadU32();
                                IntPtr s = st.Alloc(CheckedBytes(l, 1) + 1);
                                if (l > 0) r.CopyInto(s, l);
                                *(IntPtr*)(arr + (int)(k * 8)) = s;
                            }
                            *(IntPtr*)fp = arr;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.BlobPtr:
                    {
                        uint n = r.ReadU32();
                        ulong declared = d.Size == 8 ? *(ulong*)(dst + d.LenOffset) : *(uint*)(dst + d.LenOffset);
                        if (n != 0 && n != declared)
                            throw new InvalidOperationException("BrovVulk generic: blob length mismatch.");
                        if (n > 0)
                        {
                            IntPtr s = st.Alloc(CheckedBytes(n, 1));
                            r.CopyInto(s, n);
                            *(IntPtr*)fp = s;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.SelectArray:
                    {
                        uint dt = *(uint*)(dst + d.SelOffset);
                        if (dt < 32 && (d.SelMask & (1u << (int)dt)) != 0)
                        {
                            uint n = r.ReadU32();
                            if (n != *(uint*)(dst + d.LenOffset))
                                throw new InvalidOperationException("BrovVulk generic: descriptor array length mismatch.");
                            if (n > 0 && d.Sub >= 0)
                            {
                                int esz = BrovVulkStructMeta.Sizes[d.Sub];
                                IntPtr arr = st.Alloc(CheckedBytes(n, esz));
                                for (uint k = 0; k < n; k++)
                                    RebuildAt(d.Sub, r, st, arr + (int)(k * (uint)esz));
                                *(IntPtr*)fp = arr;
                            }
                            else if (n > 0)
                            {
                                IntPtr arr = st.Alloc(CheckedBytes(n, 8));
                                for (uint k = 0; k < n; k++)
                                    *(IntPtr*)(arr + (int)(k * 8)) = st.Lookup(r.ReadU32(), d.HandleType);
                                *(IntPtr*)fp = arr;
                            }
                            else *(IntPtr*)fp = IntPtr.Zero;
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.PNext:
                    {
                        uint has = r.ReadU32();
                        if (has != 0)
                        {
                            int psid = (int)r.ReadU32();
                            if (psid < 0 || psid >= BrovVulkStructMeta.PNext.Length || !BrovVulkStructMeta.PNext[psid])
                                throw new InvalidOperationException("BrovVulk generic: pNext sid not allowed.");
                            *(IntPtr*)fp = Rebuild(psid, r, st);
                        }
                        else *(IntPtr*)fp = IntPtr.Zero;
                        break;
                    }
                    case BvkMK.Ignore:
                        break;
                }
            }
        }

        public static void WritebackBody(int sid, GenBuf w, IntPtr src)
        {
            foreach (BvkM d in BrovVulkStructMeta.Members[sid])
            {
                switch (d.Kind)
                {
                    case BvkMK.Scalar:
                        w.WriteBytesFrom(src + d.Offset, (uint)d.Size);
                        break;
                    case BvkMK.StructValue:
                        WritebackBody(d.Sub, w, src + d.Offset);
                        break;
                }
            }
        }
    }
}
