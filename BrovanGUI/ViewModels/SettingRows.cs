using System.Globalization;
using BrovanGUI.Models;

namespace BrovanGUI.ViewModels
{
    public sealed class SettingsScope
    {
        private readonly Dictionary<string, string> Values;
        private readonly Func<string, string> Fallback;
        private readonly Action Changed;

        public SettingsScope(Dictionary<string, string> Values, Func<string, string> Fallback, Action Changed)
        {
            this.Values = Values;
            this.Fallback = Fallback;
            this.Changed = Changed;
        }

        public string? Get(string Key)
        {
            return Values.TryGetValue(Key, out string? Value) ? Value : null;
        }

        public string Effective(string Key)
        {
            return Get(Key) ?? Fallback(Key);
        }

        public void Set(string Key, string? Value)
        {
            if (Value == null)
                Values.Remove(Key);
            else
                Values[Key] = Value;

            Changed();
        }
    }

    public sealed class Choice
    {
        public Choice(string Value, string Label, bool IsEnabled = true)
        {
            this.Value = Value;
            this.Label = Label;
            this.IsEnabled = IsEnabled;
        }

        public string Value { get; }
        public string Label { get; }
        public bool IsEnabled { get; }
    }

    public abstract class SettingRow : ObservableObject
    {
        private bool Overridden;

        protected SettingRow(SettingEntry Entry, SettingsScope Scope)
        {
            this.Entry = Entry;
            this.Scope = Scope;
            Label = SettingLabels.Label(Entry.Key);
            Help = Entry.Help;
            ResetCommand = new RelayCommand(() =>
            {
                Scope.Set(Key, null);
                Refresh();
            });
        }

        public SettingEntry Entry { get; }
        protected SettingsScope Scope { get; }
        public string Key => Entry.Key;
        public string Label { get; }
        public string Help { get; protected set; }
        public RelayCommand ResetCommand { get; }
        protected bool Loading { get; private set; }

        public bool IsOverridden
        {
            get => Overridden;
            private set => Set(ref Overridden, value);
        }

        public void Refresh()
        {
            Loading = true;
            try
            {
                IsOverridden = Scope.Get(Key) != null;
                Load(Scope.Effective(Key));
            }
            finally
            {
                Loading = false;
            }
        }

        protected abstract void Load(string Text);

        protected void Store(string Text)
        {
            if (Loading)
                return;

            Scope.Set(Key, Text);
            IsOverridden = true;
        }

        public static SettingRow Create(SettingEntry Entry, SettingsScope Scope, bool HypervisorAvailable)
        {
            SettingRow Row = Entry.Type switch
            {
                "boolean" => new ToggleRow(Entry, Scope),
                "choice" => new ChoiceRow(Entry, Scope, HypervisorAvailable),
                "integer" or "real" => new NumberRow(Entry, Scope),
                "list" => new ListRow(Entry, Scope),
                _ => new TextRow(Entry, Scope),
            };

            Row.Refresh();
            return Row;
        }
    }

    public sealed class ToggleRow : SettingRow
    {
        private bool On;

        public ToggleRow(SettingEntry Entry, SettingsScope Scope) : base(Entry, Scope)
        {
        }

        public bool IsOn
        {
            get => On;
            set
            {
                if (Set(ref On, value))
                    Store(value ? "true" : "false");
            }
        }

        protected override void Load(string Text)
        {
            IsOn = Text.Trim().ToLowerInvariant() is "true" or "1" or "on" or "yes";
        }
    }

    public sealed class ChoiceRow : SettingRow
    {
        private Choice? Selected;

        public ChoiceRow(SettingEntry Entry, SettingsScope Scope, bool HypervisorAvailable) : base(Entry, Scope)
        {
            string[] Values = Entry.Values ?? Array.Empty<string>();
            Choice[] Items = new Choice[Values.Length];
            for (int i = 0; i < Items.Length; i++)
            {
                string Value = Values[i];
                bool Enabled = SettingLabels.ChoiceAvailable(Entry.Key, Value, HypervisorAvailable);
                string Label = SettingLabels.ChoiceLabel(Entry.Key, Value);
                Items[i] = new Choice(Value, Enabled ? Label : Label + " (unavailable)", Enabled);
            }

            Choices = Items;
        }

        public Choice[] Choices { get; }

        public Choice? SelectedChoice
        {
            get => Selected;
            set
            {
                if (Set(ref Selected, value) && value != null)
                    Store(value.Value);
            }
        }

        protected override void Load(string Text)
        {
            foreach (Choice Item in Choices)
            {
                if (string.Equals(Item.Value, Text.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    SelectedChoice = Item;
                    return;
                }
            }

            SelectedChoice = Choices.Length != 0 ? Choices[0] : null;
        }
    }

    public sealed class NumberRow : SettingRow
    {
        private decimal? Value;

        public NumberRow(SettingEntry Entry, SettingsScope Scope) : base(Entry, Scope)
        {
            IsInteger = Entry.Type == "integer";
            Minimum = (decimal)(Entry.Min ?? (IsInteger ? 0 : 0.0));
            Maximum = (decimal)(Entry.Max ?? 1000000000);
            Increment = IsInteger ? 1 : 0.05m;
            FormatString = IsInteger ? "0" : "0.##";
        }

        public bool IsInteger { get; }
        public decimal Minimum { get; }
        public decimal Maximum { get; }
        public decimal Increment { get; }
        public string FormatString { get; }

        public decimal? NumberValue
        {
            get => Value;
            set
            {
                if (Set(ref Value, value) && value.HasValue)
                    Store(value.Value.ToString(FormatString, CultureInfo.InvariantCulture));
            }
        }

        protected override void Load(string Text)
        {
            NumberValue = decimal.TryParse(Text, NumberStyles.Float, CultureInfo.InvariantCulture, out decimal Parsed) ? Parsed : 0;
        }
    }

    public sealed class TextRow : SettingRow
    {
        private string Text = string.Empty;

        public TextRow(SettingEntry Entry, SettingsScope Scope) : base(Entry, Scope)
        {
            IsPath = Entry.Key.EndsWith("dir", StringComparison.OrdinalIgnoreCase);
        }

        public bool IsPath { get; }

        public string TextValue
        {
            get => Text;
            set
            {
                if (Set(ref Text, value ?? string.Empty))
                    Store(Text);
            }
        }

        protected override void Load(string Value)
        {
            TextValue = Value;
        }
    }

    public sealed class ListRow : SettingRow
    {
        private string Text = string.Empty;

        public ListRow(SettingEntry Entry, SettingsScope Scope) : base(Entry, Scope)
        {
            Help = (Help.Length == 0 ? string.Empty : Help + " ") + "One per line.";
        }

        public string TextValue
        {
            get => Text;
            set
            {
                if (Set(ref Text, value ?? string.Empty))
                    Store(Text.Replace("\r\n", "\n"));
            }
        }

        protected override void Load(string Value)
        {
            TextValue = Value;
        }
    }

    public enum StatusKind
    {
        None,
        Good,
        Warn,
        Bad,
    }

    public sealed class CategoryViewModel
    {
        public CategoryViewModel(string Title, List<SettingRow> Rows)
        {
            this.Title = Title;
            this.Rows = Rows;
        }

        public string Title { get; }
        public List<SettingRow> Rows { get; }
    }

    // A key with no entry here still renders, from its own name.
    public static class SettingLabels
    {
        private static readonly string[] CategoryOrder = { "backend", "graphics", "platform", "network", "input", "diagnostics" };

        // Keys with no meaning for a user to change.
        private static readonly string[] Hidden = { "backend.quick" };

        public static string Label(string Key)
        {
            switch (Key)
            {
                case "backend.kind": return "Backend";
                case "backend.smp": return "Run threads in parallel";
                case "backend.cores": return "Cores";
                case "backend.hooks": return "Instrumentation hooks";
                case "jit.cache": return "Keep translated code between runs";
                case "jit.cache-dir": return "Code cache folder";
                case "jit.stats": return "Print code cache statistics";
                case "graphics.relax-vulkan": return "Relaxed Vulkan features";
                case "graphics.render-scale": return "Render scale";
                case "platform.low-memory": return "Low memory mode";
                case "net.mode": return "Network access";
                case "net.allow": return "Allowed addresses";
                case "log.silent": return "Show only the program's output";
            }

            int Dot = Key.LastIndexOf('.');
            string Tail = (Dot >= 0 ? Key.Substring(Dot + 1) : Key).Replace('-', ' ');
            return Tail.Length == 0 ? Key : char.ToUpperInvariant(Tail[0]) + Tail.Substring(1);
        }

        public static string ChoiceLabel(string Key, string Value)
        {
            switch (Key + "=" + Value)
            {
                case "backend.kind=unicorn": return "Unicorn (software)";
                case "backend.kind=whp": return "Windows Hypervisor";
                case "backend.kind=kvm": return "KVM hypervisor";
                case "net.mode=none": return "Blocked";
                case "net.mode=loopback": return "This computer only";
                case "net.mode=full": return "Full access";
            }

            return Value.Length == 0 ? Value : char.ToUpperInvariant(Value[0]) + Value.Substring(1);
        }

        public static bool ChoiceAvailable(string Key, string Value, bool HypervisorAvailable)
        {
            if (Key != "backend.kind")
                return true;

            return Value switch
            {
                "whp" => OperatingSystem.IsWindows() && HypervisorAvailable,
                "kvm" => OperatingSystem.IsLinux() && HypervisorAvailable,
                _ => true,
            };
        }

        public static string CategoryTitle(string Category)
        {
            return Category.ToLowerInvariant() switch
            {
                "backend" => "Emulation",
                "graphics" => "Graphics",
                "platform" => "Memory",
                "network" => "Network",
                "input" => "Input",
                "diagnostics" => "Diagnostics",
                _ => Category.Length == 0 ? "Other" : char.ToUpperInvariant(Category[0]) + Category.Substring(1),
            };
        }

        private static bool Names(List<string> Categories, string Category)
        {
            foreach (string Item in Categories)
            {
                if (string.Equals(Item, Category, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public static List<CategoryViewModel> BuildCategories(IReadOnlyList<SettingEntry> Schema, SettingsScope Scope, bool IncludeGlobal, bool HypervisorAvailable)
        {
            List<CategoryViewModel> Result = new List<CategoryViewModel>();
            List<string> Seen = new List<string>();

            foreach (string Category in CategoryOrder)
                Seen.Add(Category);

            foreach (SettingEntry Entry in Schema)
            {
                if (!Names(Seen, Entry.Category))
                    Seen.Add(Entry.Category);
            }

            foreach (string Category in Seen)
            {
                List<SettingRow> Rows = new List<SettingRow>();
                foreach (SettingEntry Entry in Schema)
                {
                    if (!string.Equals(Entry.Category, Category, StringComparison.OrdinalIgnoreCase)
                        || !Entry.AppliesToHost || Array.IndexOf(Hidden, Entry.Key) >= 0)
                        continue;

                    if (Entry.IsGlobal && !IncludeGlobal)
                        continue;

                    Rows.Add(SettingRow.Create(Entry, Scope, HypervisorAvailable));
                }

                if (Rows.Count != 0)
                    Result.Add(new CategoryViewModel(CategoryTitle(Category), Rows));
            }

            return Result;
        }
    }
}
