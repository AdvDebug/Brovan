using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Brovan.Core.Emulation.OS.Windows;

namespace Brovan.Fuzz;

internal delegate void FuzzBody(ReadOnlySpan<byte> data);

internal static class Program
{
    private static FuzzBody Resolve(string target) => target switch
    {
        "struct" => StructTarget.Run,
        "spirv" => SpirvTarget.Run,
        "ioctl" => IoctlTarget.Run,
        _ => throw new ArgumentException($"unknown target '{target}' (struct | spirv | ioctl)")
    };

    private static void Prepare(string target)
    {
        if (target != "ioctl")
            return;

        IoctlTarget.Init();
        Console.Error.WriteLine(VulkanBootstrap.Available
            ? "[ioctl] host Vulkan device ready, handle ids 1 to 4 registered"
            : "[ioctl] no host Vulkan device, only the framing and the reader are reachable");
    }

    // Unlike Environment.Exit, this does not run managed shutdown.
    [DllImport("libc", EntryPoint = "_exit")]
    private static extern void HardExit(int code);

    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: Brovan.Fuzz <libfuzzer|run|seed|dict|replay|audit> ...");
            return 2;
        }

        // --target_arg carries exactly one argument, so the target is part of the command word.
        if (args[0].StartsWith("libfuzzer:", StringComparison.Ordinal))
        {
            string target = args[0]["libfuzzer:".Length..];
            FuzzBody body = Resolve(target);

            // Instrumented code writes to memory Fuzzer.Run maps, so Prepare waits for the first input.
            bool ready = false;
            SharpFuzz.Fuzzer.LibFuzzer.Run(d =>
            {
                if (!ready)
                {
                    Prepare(target);
                    ready = true;
                }
                body(d);
                MemoryGuard.Check();
            });

            // Run unmaps the shared memory that instrumented code traces through, so a managed
            // shutdown hook which reaches that code faults.
            HardExit(0);
            return 0;
        }

        switch (args[0])
        {
            case "run":
            {
                string target = args.Length > 1 ? args[1] : "struct";
                int seconds = args.Length > 2 ? int.Parse(args[2]) : 30;
                int seed = args.Length > 3 ? int.Parse(args[3]) : Environment.TickCount;
                return SelfDrive.Run(target, Resolve(target), Prepare, seconds, seed);
            }

            case "seed":
            {
                string target = args.Length > 1 ? args[1] : "struct";
                string dir = args.Length > 2 ? args[2] : $"corpus-{target}";
                int written = Corpus.Write(target, dir);
                Console.WriteLine($"wrote {written} seeds to {dir}");
                return 0;
            }

            case "dict":
            {
                string path = args.Length > 1 ? args[1] : "brovvulk.dict";
                File.WriteAllText(path, Grammar.Dictionary());
                Console.WriteLine($"wrote dictionary to {path}");
                return 0;
            }

            case "replay":
            {
                string target = args.Length > 1 ? args[1] : "struct";
                string path = args[2];
                Prepare(target);
                FuzzBody body = Resolve(target);

                // Unbuffered, so the name of the input that faults survives a native crash.
                string[] files = Directory.Exists(path)
                    ? Directory.GetFiles(path).Order().ToArray()
                    : new[] { path };

                using Stream err = Console.OpenStandardError();
                foreach (string f in files)
                {
                    byte[] data = File.ReadAllBytes(f);
                    err.Write(System.Text.Encoding.UTF8.GetBytes($"{f} ({data.Length} bytes)\n"));
                    err.Flush();
                    body(data);
                }
                Console.WriteLine($"{files.Length} input(s) returned without crashing");
                return 0;
            }

            case "audit":
                Audit.Report();
                return 0;

            default:
                Console.Error.WriteLine($"unknown command '{args[0]}'");
                return 2;
        }
    }
}

internal static class Corpus
{
    public static int Write(string target, string dir)
    {
        Directory.CreateDirectory(dir);
        int n = 0;

        void Emit(byte[] bytes)
        {
            string name = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()[..16];
            File.WriteAllBytes(Path.Combine(dir, name), bytes);
            n++;
        }

        switch (target)
        {
            case "struct":
                for (int sid = 0; sid < Grammar.StructCount; sid++)
                {
                    foreach ((uint len, int chain) in new[] { (0u, 0), (1u, 0), (1u, 1) })
                    {
                        byte[] payload;
                        try { payload = Grammar.Struct(sid, len, chain); }
                        catch { continue; }
                        byte[] input = new byte[2 + payload.Length];
                        input[0] = (byte)sid;
                        input[1] = (byte)(sid >> 8);
                        payload.CopyTo(input, 2);
                        Emit(input);
                    }
                }
                break;

            case "spirv":
                foreach (byte mode in new byte[] { 0x00, 0x1C, 0x01, 0x02, 0x03, 0x83 })
                    foreach (byte[] module in SpirvSeeds.All())
                    {
                        byte[] input = new byte[1 + module.Length];
                        input[0] = mode;
                        module.CopyTo(input, 1);
                        Emit(input);
                    }
                break;

            case "ioctl":
                // A command reads its dispatchable handle first, so seed one input per handle.
                foreach ((uint handle, uint standIns) in Shapes)
                    for (uint id = 0; id < (uint)Grammar.CommandCount; id++)
                        Emit(Frame(id, standIns, new WireWriter().U32(handle).U32(0).U32(0).Done()));

                Emit(Frame(0xFFFFFFFE, 0, new WireWriter().U32(2).U32(0).U32(3).U32(1).U32(3).Done()));
                break;

            default:
                throw new ArgumentException($"no corpus for target '{target}'");
        }

        return n;
    }

    private static readonly (uint Handle, uint StandIns)[] Shapes =
        { (1, 0), (2, 0), (3, 0), (3, 0xFFFFFFFF), (4, 0) };

    /// <summary>[knobs][standIns][id][payloadLen][payload]</summary>
    private static byte[] Frame(uint id, uint standIns, byte[] payload)
    {
        WireWriter w = new WireWriter();
        w.Raw(stackalloc byte[] { 0 });
        w.U32(standIns).U32(id).U32((uint)payload.Length).Raw(payload);
        return w.Done();
    }
}

internal static class SpirvSeeds
{
    private const uint Version10 = 0x10000;
    private const uint IdBound = 64;

    private static uint Head(uint len, int op) => (len << 16) | (uint)op;

    public static IEnumerable<byte[]> All()
    {
        yield return Words(Spirv.Magic, Version10, 0, IdBound, 0,
            Head(2, Spirv.OpCapability), Spirv.CapabilityShader,
            Head(2, Spirv.OpCapability), Spirv.CapabilityClipDistance,
            Head(4, Spirv.OpEntryPoint), Spirv.ModelVertex, 10, 0,
            Head(4, Spirv.OpDecorate), 40, Spirv.DecorationBuiltIn, Spirv.BuiltInClipDistance,
            Head(4, Spirv.OpDecorate), 41, Spirv.DecorationLocation, 7,
            Head(3, Spirv.OpTypeFloat), 50, 32,
            Head(4, Spirv.OpConstant), 50, 51, 4,
            Head(4, Spirv.OpTypeArray), 52, 50, 51,
            Head(4, Spirv.OpTypePointer), 53, Spirv.StorageOutput, 52,
            Head(4, Spirv.OpVariable), 53, 40, Spirv.StorageOutput,
            Head(5, Spirv.OpFunction), 50, 10, 0, 60);

        // Reaches SpirvClipDiscard's prologue scan.
        yield return Words(Spirv.Magic, Version10, 0, IdBound, 0,
            Head(4, Spirv.OpEntryPoint), Spirv.ModelFragment, 10, 0,
            Head(5, Spirv.OpFunction), 20, 10, 0, 21,
            Head(2, Spirv.OpLabel), 30,
            Head(4, Spirv.OpVariable), 53, 41, Spirv.StorageInput,
            Head(1, Spirv.OpReturn));

        // Reaches BuildType.
        yield return Words(Spirv.Magic, Version10, 0, IdBound, 0,
            Head(2, Spirv.OpCapability), Spirv.CapabilityShader,
            Head(4, Spirv.OpEntryPoint), Spirv.ModelVertex, 10, 0,
            Head(5, Spirv.OpMemberDecorate), 60, 0, Spirv.DecorationBuiltIn, Spirv.BuiltInPosition,
            Head(3, Spirv.OpTypeFloat), 50, 32,
            Head(4, Spirv.OpTypeVector), 61, 50, 4,
            Head(4, Spirv.OpTypeStruct), 60, 61, 61,
            Head(4, Spirv.OpTypePointer), 62, Spirv.StorageOutput, 60,
            Head(4, Spirv.OpVariable), 62, 40, Spirv.StorageOutput,
            Head(5, Spirv.OpFunction), 50, 10, 0, 60);

        // Header only.
        yield return Words(Spirv.Magic, Version10, 0, IdBound, 0);
    }

    private static byte[] Words(params uint[] w)
    {
        byte[] b = new byte[w.Length * 4];
        Buffer.BlockCopy(w, 0, b, 0, b.Length);
        return b;
    }
}

/// <summary>Mutational driver with no coverage feedback.</summary>
internal static class SelfDrive
{
    // Stands in for libFuzzer's -timeout, which run mode has no access to.
    private const int HangSeconds = 20;
    private const int Sigabrt = 6;

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int sig);

    private static long _execStart;
    private static int _inFlightLen;
    private static readonly byte[] InFlight = new byte[1 << 16];

    public static int Run(string target, FuzzBody body, Action<string> prepare, int seconds, int seed)
    {
        prepare(target);

        string dir = Path.Combine(Path.GetTempPath(), $"brovfuzz-{target}-{seed}");
        Corpus.Write(target, dir);
        List<byte[]> corpus = Directory.GetFiles(dir).Select(File.ReadAllBytes).ToList();
        if (corpus.Count == 0)
            corpus.Add(new byte[16]);

        Random rng = new(seed);
        DateTime deadline = DateTime.UtcNow.AddSeconds(seconds);
        long execs = 0;
        byte[] scratch = new byte[1 << 16];

        Console.WriteLine($"[{target}] seed={seed} corpus={corpus.Count} for {seconds}s");
        string hangPath = StartWatchdog(target);

        while (DateTime.UtcNow < deadline)
        {
            byte[] basis = corpus[rng.Next(corpus.Count)];
            int len = Math.Min(basis.Length, scratch.Length);
            basis.AsSpan(0, len).CopyTo(scratch);
            len = Mutate(scratch, len, rng);

            scratch.AsSpan(0, len).CopyTo(InFlight);
            Volatile.Write(ref _inFlightLen, len);
            Volatile.Write(ref _execStart, Environment.TickCount64);
            try
            {
                body(scratch.AsSpan(0, len));
            }
            catch (Exception e) when (StructTarget.Expected(e))
            {
            }
            catch (Exception e)
            {
                string crash = $"crash-{target}-{Convert.ToHexString(SHA256.HashData(scratch.AsSpan(0, len)))[..16]}";
                File.WriteAllBytes(crash, scratch.AsSpan(0, len).ToArray());
                Console.Error.WriteLine($"\n[{target}] UNEXPECTED {e.GetType().Name}: {e.Message}");
                Console.Error.WriteLine($"[{target}] input saved to {crash}");
                Console.Error.WriteLine(e.StackTrace);
                return 1;
            }

            Volatile.Write(ref _execStart, 0);
            MemoryGuard.Check();

            if (++execs % 200000 == 0)
                Console.WriteLine($"[{target}] {execs:N0} execs");
        }

        Console.WriteLine($"[{target}] done, {execs:N0} execs, no crash");
        File.Delete(hangPath);
        return 0;
    }

    // A loop with no safepoint stops the collector, so allocating on the fire path would block the
    // watchdog behind the loop it reports. Everything it needs is built up front.
    private static string StartWatchdog(string target)
    {
        string path = Path.GetFullPath($"hang-{target}-{Environment.ProcessId}.bin");
        FileStream file = new(path, FileMode.Create, FileAccess.Write, FileShare.Read, 1);
        Stream err = Console.OpenStandardError();
        byte[] notice = Encoding.UTF8.GetBytes(
            $"\n[{target}] HANG: one input ran for over {HangSeconds}s, saved to {path}\n");
        int self = Environment.ProcessId;
        kill(self, 0);

        Thread t = new(() =>
        {
            while (true)
            {
                Thread.Sleep(1000);
                long started = Volatile.Read(ref _execStart);
                if (started == 0 || Environment.TickCount64 - started < HangSeconds * 1000L)
                    continue;

                file.Write(InFlight, 0, Volatile.Read(ref _inFlightLen));
                file.Flush();
                err.Write(notice, 0, notice.Length);
                err.Flush();
                kill(self, Sigabrt);
            }
        })
        { IsBackground = true, Name = "watchdog" };
        t.Start();
        return path;
    }

    private static int Mutate(byte[] buf, int len, Random rng)
    {
        int rounds = 1 + rng.Next(6);
        for (int i = 0; i < rounds && len > 0; i++)
        {
            switch (rng.Next(6))
            {
                case 0: buf[rng.Next(len)] = (byte)rng.Next(256); break;
                case 1: buf[rng.Next(len)] ^= (byte)(1 << rng.Next(8)); break;
                case 2:
                {
                    // Counts and lengths are what the format gates on.
                    int at = rng.Next(Math.Max(1, len - 4));
                    uint v = rng.Next(5) switch
                    {
                        0 => 0u, 1 => 1u, 2 => 0xFFFFFFFFu, 3 => 1u << 20, _ => (uint)rng.Next()
                    };
                    if (at + 4 <= len) BitConverter.TryWriteBytes(buf.AsSpan(at, 4), v);
                    break;
                }
                case 3: if (len > 8) len -= rng.Next(1, Math.Min(8, len)); break;
                case 4:
                    if (len + 4 < buf.Length) { buf.AsSpan(len, 4).Clear(); len += 4; }
                    break;
                default:
                {
                    int a = rng.Next(len), b = rng.Next(len);
                    (buf[a], buf[b]) = (buf[b], buf[a]);
                    break;
                }
            }
        }
        return len;
    }
}

// libfuzzer-dotnet runs the target in a child of the driver, so -rss_limit_mb and -malloc_limit_mb
// watch the driver and never see this process.
internal static class MemoryGuard
{
    private const long LimitBytes = 1536L << 20;
    private const int Every = 4096;

    private static int _calls;

    public static void Check()
    {
        if ((++_calls & (Every - 1)) != 0)
            return;

        long resident = Environment.WorkingSet;
        if (resident <= LimitBytes)
            return;

        Console.Error.WriteLine(
            $"[fuzz] resident set {resident >> 20} MB is over the {LimitBytes >> 20} MB cap");
        Console.Error.Flush();
        Environment.FailFast("Brovan.Fuzz: harness memory growth");
    }
}

internal static class Audit
{
    public static void Report()
    {
        Console.WriteLine($"structs: {Grammar.StructCount}   commands: {Grammar.CommandCount}");
        Console.WriteLine();
        Console.WriteLine("Optional arrays - RebuildAt permits a non-zero count with a NULL pointer here.");
        Console.WriteLine("Any consumer that loops to the count without a null check crashes on these:");
        Console.WriteLine();

        int total = 0;
        for (int sid = 0; sid < Grammar.StructCount; sid++)
        {
            foreach (BvkM m in BrovVulkStructMeta.Members[sid])
            {
                bool isArray = m.Kind is BvkMK.StructArray or BvkMK.HandleArray or BvkMK.ScalarArray
                                      or BvkMK.StringArray or BvkMK.BlobPtr;
                if (isArray && m.Optional && m.LenOffset >= 0)
                {
                    Console.WriteLine($"  sid {sid,4}  offset {m.Offset,4}  {m.Kind,-12} count at +{m.LenOffset}");
                    total++;
                }
            }
        }

        Console.WriteLine();
        Console.WriteLine($"{total} optional array members across {Grammar.StructCount} structs.");
    }
}
