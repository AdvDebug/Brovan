using System.Text;
using System.Text.Json;
using Brovan.WinFacts.Readers;
using Brovan.WinFacts.Rules;
using Brovan.WinFacts.Sources;

namespace Brovan.WinFacts
{
    internal sealed class FactException : Exception
    {
        internal FactException(string Message) : base(Message)
        {
        }
    }

    // With Versions set, the run prints their facts and writes nothing unless Write is set.
    internal sealed record UpdateOptions(string Group, string Root, string Store, string Cache, string Report, HashSet<string> Versions, bool Write);

    // A network failure aborts before any write, so the output depends only on the binaries and the rules.
    internal static class Engine
    {
        private static readonly string ToolIdentity = typeof(Engine).Assembly.ManifestModule.ModuleVersionId.ToString("N");

        private sealed record CachedResult(string Tool, VersionResult Result);

        internal static int Update(UpdateOptions Options)
        {
            using HttpClient Client = new() { Timeout = TimeSpan.FromMinutes(2) };
            SymbolServer Server = new(Client, Options.Store);
            StringBuilder Report = new();
            foreach (FactGroup Group in FactGroup.All)
            {
                if (Options.Group != null && Group.Name != Options.Group)
                    continue;

                List<FileBuild> Builds = Winbindex.Read(Client, Group.KeyFile).Where(Build => Options.Versions?.Contains(Build.Version) != false).ToList();

                List<VersionResult> Results = new(Builds.Count);
                foreach (FileBuild Build in Builds)
                {
                    VersionResult Result = Extract(Group, Server, Build, Options.Cache);
                    Results.Add(Result);
                    Console.Error.WriteLine($"{Group.Name} {Build.Version}: {Result.Error ?? "ok"}");
                }

                Results = SettleDuplicates(Results);
                if (Options.Versions != null && !Options.Write)
                {
                    foreach (VersionResult Result in Results)
                        Console.WriteLine($"{Result.Version}: {Result.Error ?? Result.Facts}");

                    continue;
                }

                string Output = Path.Combine(Options.Root, Group.OutputPath);
                string Text = Group.Emit(Results);
                if (!File.Exists(Output) || File.ReadAllText(Output) != Text)
                    File.WriteAllText(Output, Text, new UTF8Encoding(false));

                AppendReport(Report, Group, Results);
            }

            if (Options.Report != null)
                File.WriteAllText(Options.Report, Report.ToString(), new UTF8Encoding(false));

            Console.Write(Report);
            return 0;
        }

        private static VersionResult Extract(FactGroup Group, SymbolServer Server, FileBuild Build, string Cache)
        {
            string CachePath = Cache == null ? null : Path.Combine(Cache, Group.Name, $"{Build.Version}-{Build.Timestamp:X8}{Build.VirtualSize:x}.json");
            if (CachePath != null && File.Exists(CachePath))
            {
                CachedResult Cached = JsonSerializer.Deserialize<CachedResult>(File.ReadAllText(CachePath));
                if (Cached.Tool == ToolIdentity)
                    return Cached.Result;
            }

            // A file the symbol server does not have yet can appear later, so that answer is never cached.
            VersionResult Result;
            bool Available = true;
            IByteSource Binary = Server.OpenBinary(Build);
            if (Binary == null)
            {
                Available = false;
                Result = new VersionResult(Build.Build, Build.Revision, null, "not on the symbol server");
            }
            else
            {
                // The binary's own version resource is the key Brovan reads, and it can differ from the index's.
                (ushort Build, ushort Revision) Version = (Build.Build, Build.Revision);
                try
                {
                    PeImage Image = PeImage.Open(Binary);
                    Version = Image.FileVersion() ?? throw new FactException("no version resource");
                    IByteSource Pdb = Image.PdbName == null ? null : Server.OpenPdb(Image.PdbName, Image.PdbGuid, Image.PdbAge);
                    if (Pdb == null)
                    {
                        Available = false;
                        throw new FactException("no public PDB");
                    }

                    PdbPublics Publics = PdbPublics.Open(Pdb, Image);
                    string Facts = Group.Extract(new VersionInputs(Version.Build, Version.Revision, Image, Publics));
                    Result = new VersionResult(Version.Build, Version.Revision, Facts, null);
                }
                catch (Exception Error) when (Error is FactException or InvalidDataException)
                {
                    Result = new VersionResult(Version.Build, Version.Revision, null, Error.Message);
                }
            }

            if (CachePath != null && Available)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(CachePath));
                File.WriteAllText(CachePath, JsonSerializer.Serialize(new CachedResult(ToolIdentity, Result)));
            }

            return Result;
        }

        // Two binaries that carry one version number must agree, or the version cannot pick a set.
        private static List<VersionResult> SettleDuplicates(List<VersionResult> Results)
        {
            List<VersionResult> Settled = new();
            foreach (IGrouping<string, VersionResult> Same in Results.GroupBy(Result => Result.Version))
            {
                List<VersionResult> Copies = Same.ToList();
                if (Copies.All(Copy => Copy.Facts == Copies[0].Facts && Copy.Error == Copies[0].Error))
                    Settled.Add(Copies[0]);
                else
                    Settled.Add(Copies[0] with { Facts = null, Error = $"{Copies.Count} binaries with this version disagree" });
            }

            return Settled;
        }

        private static void AppendReport(StringBuilder Report, FactGroup Group, List<VersionResult> Results)
        {
            List<VersionResult> Left = Results.Where(Result => Result.Error != null).ToList();
            int Sets = Results.Where(Result => Result.Error == null).Select(Result => Result.Facts).Distinct().Count();
            Report.Append($"### {Group.Name} ({Group.KeyFile})\n\n");
            Report.Append($"{Results.Count} versions, {Sets} table sets, {Left.Count} left out.\n");
            if (Left.Count != 0)
            {
                Report.Append('\n');
                foreach (VersionResult Result in Left)
                    Report.Append($"- {Result.Version}: {Result.Error}\n");
            }

            Report.Append('\n');
        }
    }
}
