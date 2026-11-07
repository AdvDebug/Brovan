using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class MmcssTask
    {
        public string Name;
        public int Category;
        public int BasePriority;
        public int BackgroundPriority;
    }

    internal sealed class MmcssTaskIndex
    {
        public uint Value;
        public MmcssTask Task;
        public int References;
    }

    // The state is per guest process, and the registry is read once, as mmcss reads it when it starts.
    internal sealed class Mmcss
    {
        internal const int TaskNameChars = 63;
        internal const int CategoryLow = 1;
        private const int CategoryMedium = 2;
        private const int CategoryHigh = 3;

        internal const byte ThreadClient = 0;
        internal const uint SetRelativePriority = 0;
        internal const uint QueryResponsiveness = 1;
        internal const uint OpenTaskIndex = 3;

        private const uint FileDeviceUnknown = 0x22;
        private const uint MethodNeither = 3;
        private const uint ControlBase = (FileDeviceUnknown << 16) | (0x800 << 2) | MethodNeither;
        private const uint FunctionMask = 0x7FF << 2;

        // The client and exact buffer sizes of each function, from CiApiTypeTable and CiApiBufferSizeTable.
        private static readonly byte[] FunctionClient = { 0, 0, 1, 0, 2, 2, 2, 2, 2 };
        private static readonly byte[] FunctionInput = { 4, 0, 4, 0, 0, 8, 0, 4, 0 };
        private static readonly byte[] FunctionOutput = { 0, 4, 0, 4, 4, 0, 0, 0, 4 };

        private const string ProfileKey = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile";
        private const string TasksKey = ProfileKey + "\\Tasks";
        private const uint NoReservation = 100;
        private const uint DefaultResponsiveness = 20;
        private const uint ResponsivenessStep = 10;
        private const uint MinPerProcessThreads = 8;
        private const uint MaxPerProcessThreads = 128;
        private const uint DefaultPerProcessThreads = 32;
        private const uint MinTotalThreads = 64;
        private const uint MaxTotalThreads = 0xFFFF;
        private const uint DefaultTotalThreads = 256;

        private const int PrioritiesPerCategory = 8;
        private const int HighBasePriority = 24;
        private const int HighPriorityFloor = 23;
        private const int HighPriorityCeiling = 26;
        private const int MediumPriorityFloor = 16;
        private const int MediumPriorityCeiling = 23;

        // What fits after the KEY_BASIC_INFORMATION and KEY_VALUE_PARTIAL_INFORMATION headers in mmcss's query buffers.
        private const int MaxListedNameChars = (0x98 - 16) / 2;
        private const int MaxValueBytes = 0x50 - 12;
        private const int MaxChoiceBytes = 0x40;

        private static readonly string[] Categories = { null, "Low", "Medium", "High" };
        private static readonly string[] TrueFalse = { "FALSE", "TRUE" };

        // The task values follow CiConfigTaskValues in mmcss.sys.
        private static readonly TaskValue[] TaskValues =
        {
            new TaskValue("Scheduling Category", Categories, 0, 0, CategoryLow),
            new TaskValue("Priority", null, 1, 8, 1),
            new TaskValue("Background Only", TrueFalse, 0, 0, 0),
            new TaskValue("Affinity", null, 0, uint.MaxValue, uint.MaxValue),
            new TaskValue("Clock Rate", null, 5000, 10000, 10000),
            new TaskValue("BackgroundPriority", null, 1, 8, 0),
            new TaskValue("Latency Sensitive", TrueFalse, 0, 0, 0),
            new TaskValue("Priority When Yielded", null, 1, 19, 16),
        };

        private const int CategoryValue = 0;
        private const int PriorityValue = 1;
        private const int BackgroundPriorityValue = 5;

        private readonly WinSysHelper Helper;
        private readonly Dictionary<string, MmcssTask> Tasks = new Dictionary<string, MmcssTask>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<uint, MmcssTaskIndex> Indexes = new Dictionary<uint, MmcssTaskIndex>();
        private bool Started;
        private int MaxThreads;
        private int ThreadCount;
        private uint NextIndex = 1;

        public Mmcss(WinSysHelper Helper)
        {
            this.Helper = Helper;
            Load();
        }

        // When mmcss does not start, \Device\MMCSS does not exist.
        public NTSTATUS DeviceStatus => Started ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_OBJECT_PATH_NOT_FOUND;

        public uint Responsiveness { get; private set; }

        // The system-wide limit counts the threads of this process only.
        public bool HasThreadRoom => ThreadCount < MaxThreads;

        public void AddThread()
        {
            ThreadCount++;
        }

        public void RemoveThread()
        {
            ThreadCount--;
        }

        public MmcssTask FindTask(string Name) => Tasks.TryGetValue(Name, out MmcssTask Task) ? Task : null;

        public bool TryFindIndex(uint Value, MmcssTask Task, out MmcssTaskIndex Index)
        {
            return Indexes.TryGetValue(Value, out Index) && Index.Task == Task;
        }

        public MmcssTaskIndex CreateIndex(MmcssTask Task)
        {
            while (NextIndex == 0 || Indexes.ContainsKey(NextIndex))
                NextIndex++;

            MmcssTaskIndex Index = new MmcssTaskIndex { Value = NextIndex++, Task = Task };
            Indexes.Add(Index.Value, Index);
            return Index;
        }

        public void Reference(MmcssTaskIndex Index)
        {
            Index.References++;
        }

        public void Release(MmcssTaskIndex Index)
        {
            if (--Index.References <= 0)
                Indexes.Remove(Index.Value);
        }

        internal static bool TryGetFunction(uint Code, in DeviceData Data, byte Client, out uint Function)
        {
            Function = (Code & FunctionMask) >> 2;
            return Function < FunctionClient.Length
                && (Code & ~FunctionMask) == ControlBase
                && FunctionClient[Function] == Client
                && Data.InputLength == FunctionInput[Function]
                && Data.OutputLength == FunctionOutput[Function];
        }

        // Relative is -2..2, and the rules follow CiThreadUpdatePriorities.
        internal static int ThreadPriority(MmcssTask Task, int Relative)
        {
            return Task.Category switch
            {
                CategoryHigh => Math.Clamp(Task.BasePriority + Relative, HighPriorityFloor, HighPriorityCeiling),
                CategoryMedium => Math.Clamp(Task.BasePriority + Relative, MediumPriorityFloor, MediumPriorityCeiling),
                _ => CategoryLow * PrioritiesPerCategory + (Task.BackgroundPriority != 0 ? Task.BackgroundPriority - 1 : Relative),
            };
        }

        // The checks and their order follow CiConfigInitialize in mmcss.sys.
        private void Load()
        {
            WinRegKey Profile = Helper.ResolveRegistryKey(ProfileKey);
            if (Profile == null)
                return;

            uint Configured = ReadConfig(Profile, "SystemResponsiveness", NoReservation);
            Responsiveness = Configured < ResponsivenessStep || Configured > NoReservation
                ? DefaultResponsiveness
                : Configured / ResponsivenessStep * ResponsivenessStep;
            if (Responsiveness == NoReservation)
                return;

            uint PerProcess = ReadConfig(Profile, "MaxThreadsPerProcess", DefaultPerProcessThreads);
            if (PerProcess < MinPerProcessThreads || PerProcess > MaxPerProcessThreads)
                PerProcess = DefaultPerProcessThreads;

            uint Total = ReadConfig(Profile, "MaxThreadsTotal", DefaultTotalThreads);
            if (Total < MinTotalThreads || Total > MaxTotalThreads)
                Total = DefaultTotalThreads;

            MaxThreads = (int)Math.Min(PerProcess, Total);

            if (!Helper.TryCollectRegistrySubKeyNames(Helper.ResolveRegistryKey(TasksKey), out List<string> Names))
                return;

            foreach (string Name in Names)
            {
                // NT fails the enumeration on a longer name, and mmcss does not start.
                if (Name.Length > MaxListedNameChars)
                    return;

                if (Name.Length <= TaskNameChars && TryReadTask(Name, out MmcssTask Task))
                    Tasks.TryAdd(Name, Task);
            }

            Started = true;
        }

        // The rules follow CiConfigReadDWORD in mmcss.sys.
        private uint ReadConfig(WinRegKey Key, string Name, uint Default)
        {
            if (!Helper.TryGetRegistryValue(Key, Name, out ValueNode Value) || Value.Type != WinSysHelper.RegDword
                || (Value.Data?.Length ?? 0) > sizeof(uint))
                return Default;

            Span<byte> Bytes = stackalloc byte[sizeof(uint)];
            Bytes.Clear();
            Value.Data?.CopyTo(Bytes);
            return BinaryPrimitives.ReadUInt32LittleEndian(Bytes);
        }

        // The task rules follow CiConfigQueryTaskFromRegistry and CiConfigTaskPolicy in mmcss.sys.
        private bool TryReadTask(string Name, out MmcssTask Task)
        {
            Task = null;
            WinRegKey Key = Helper.ResolveRegistryKey(TasksKey + "\\" + Name);
            if (Key == null)
                return false;

            Span<uint> Values = stackalloc uint[TaskValues.Length];
            for (int Index = 0; Index < TaskValues.Length; Index++)
            {
                if (!TryReadTaskValue(Key, TaskValues[Index], out Values[Index]))
                    return false;
            }

            int Category = (int)Values[CategoryValue];
            Task = new MmcssTask
            {
                Name = Name,
                Category = Category,
                BasePriority = Category == CategoryHigh ? HighBasePriority : Category * PrioritiesPerCategory + (int)Values[PriorityValue] - 1,
                BackgroundPriority = (int)Values[BackgroundPriorityValue],
            };
            return true;
        }

        // The rules follow CiConfigQueryValue, which does not check the registry type.
        private bool TryReadTaskValue(WinRegKey Key, in TaskValue Rule, out uint Result)
        {
            Result = Rule.Default;

            // NT reads a value larger than the query buffer as missing.
            if (!Helper.TryGetRegistryValue(Key, Rule.Name, out ValueNode Value) || (Value.Data?.Length ?? 0) > MaxValueBytes)
                return true;

            ReadOnlySpan<byte> Data = Value.Data;
            if (Rule.Choices == null)
            {
                if (Data.Length != sizeof(uint))
                    return false;

                Result = BinaryPrimitives.ReadUInt32LittleEndian(Data);
                return Result >= Rule.Low && Result <= Rule.High;
            }

            if (Data.Length >= MaxChoiceBytes)
                return false;

            string Text = Encoding.Unicode.GetString(Data.Slice(0, Data.Length & ~1));
            int End = Text.IndexOf('\0');
            if (End >= 0)
                Text = Text.Substring(0, End);

            for (int Index = 0; Index < Rule.Choices.Length; Index++)
            {
                if (Rule.Choices[Index] != null && string.Equals(Text, Rule.Choices[Index], StringComparison.OrdinalIgnoreCase))
                {
                    Result = (uint)Index;
                    return true;
                }
            }

            return false;
        }

        private readonly record struct TaskValue(string Name, string[] Choices, uint Low, uint High, uint Default);
    }
}
