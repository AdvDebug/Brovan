using System.Runtime;
using System.Text;
using Avalonia.Threading;

namespace BrovanGUI.ViewModels
{
    public sealed class LineRing
    {
        private readonly string[] Buffer;
        private int Head;

        public LineRing(int Capacity)
        {
            Buffer = new string[Capacity];
        }

        public event Action? Changed;

        public int Count { get; private set; }
        public int LongestLine { get; private set; }

        // Grows as lines are dropped, so a selection stays valid across the drop.
        public long FirstLineNumber { get; private set; }

        public string this[int Index] => Buffer[(Head + Index) % Buffer.Length];

        public void Append(string Line)
        {
            if (Count == Buffer.Length)
            {
                Buffer[Head] = Line;
                Head = (Head + 1) % Buffer.Length;
                FirstLineNumber++;
            }
            else
            {
                Buffer[(Head + Count) % Buffer.Length] = Line;
                Count++;
            }

            if (Line.Length > LongestLine)
                LongestLine = Line.Length;
        }

        public void ReplaceLast(string Line)
        {
            if (Count == 0)
            {
                Append(Line);
                return;
            }

            Buffer[(Head + Count - 1) % Buffer.Length] = Line;
            if (Line.Length > LongestLine)
                LongestLine = Line.Length;
        }

        public void Clear()
        {
            Array.Clear(Buffer);
            FirstLineNumber += Count;
            Head = 0;
            Count = 0;
            LongestLine = 0;
        }

        public string Text(int From, int To)
        {
            StringBuilder Builder = new StringBuilder();
            for (int i = Math.Max(0, From); i <= To && i < Count; i++)
                Builder.Append(this[i]).Append(Environment.NewLine);

            return Builder.ToString();
        }

        public void RaiseChanged()
        {
            Changed?.Invoke();
        }
    }

    // Terminal rules: a newline ends a line, a carriage return starts the current line over.
    public sealed class OutputViewModel : ObservableObject
    {
        private const int Capacity = 5000;

        private readonly object Gate = new object();
        private readonly List<string> PendingLines = new List<string>();
        private readonly StringBuilder OpenLine = new StringBuilder();
        private bool OpenDirty;
        private bool CarriageReturn;
        private bool LastIsOpen;

        private readonly DispatcherTimer Timer;
        private readonly Action Persist;
        private bool TimerArmed;
        private string StatusValue = "Idle";
        private string InputValue = string.Empty;
        private bool Open;

        public OutputViewModel(bool Open, Action Persist)
        {
            this.Open = Open;
            this.Persist = Persist;
            Timer = new DispatcherTimer(TimeSpan.FromMilliseconds(50), DispatcherPriority.Background, Flush);
            ClearCommand = new RelayCommand(Clear);
            ToggleCommand = new RelayCommand(() => IsOpen = !IsOpen);
        }

        public event Action<string>? InputSubmitted;

        public LineRing Lines { get; } = new LineRing(Capacity);
        public RelayCommand ClearCommand { get; }
        public RelayCommand ToggleCommand { get; }

        public string Status
        {
            get => StatusValue;
            set => Set(ref StatusValue, value);
        }

        public string Input
        {
            get => InputValue;
            set => Set(ref InputValue, value ?? string.Empty);
        }

        public bool IsOpen
        {
            get => Open;
            set
            {
                if (Set(ref Open, value))
                    Persist();
            }
        }

        public void Write(string Text)
        {
            lock (Gate)
            {
                foreach (char Character in Text)
                {
                    if (Character == '\n')
                    {
                        PendingLines.Add(OpenLine.ToString());
                        OpenLine.Clear();
                        OpenDirty = true;
                        CarriageReturn = false;
                        continue;
                    }

                    if (Character == '\r')
                    {
                        CarriageReturn = true;
                        continue;
                    }

                    if (CarriageReturn)
                    {
                        OpenLine.Clear();
                        CarriageReturn = false;
                    }

                    OpenLine.Append(Character);
                    OpenDirty = true;
                }

                if (PendingLines.Count > Capacity)
                    PendingLines.RemoveRange(0, PendingLines.Count - Capacity);

                if (!TimerArmed)
                {
                    TimerArmed = true;
                    Dispatcher.UIThread.Post(Timer.Start);
                }
            }
        }

        public void WriteLine(string Text)
        {
            Write(Text + "\n");
        }

        public void SubmitInput()
        {
            string Text = Input;
            Input = string.Empty;
            InputSubmitted?.Invoke(Text);
        }

        public void Clear()
        {
            lock (Gate)
            {
                PendingLines.Clear();
                OpenLine.Clear();
                OpenDirty = false;
                CarriageReturn = false;
            }

            LastIsOpen = false;
            Lines.Clear();
            Lines.RaiseChanged();
            ReleaseMemory();
        }

        public static void ReleaseMemory()
        {
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
        }

        private void Flush(object? Sender, EventArgs Event)
        {
            List<string>? Completed = null;
            string? Partial;

            lock (Gate)
            {
                if (!OpenDirty)
                {
                    Timer.Stop();
                    TimerArmed = false;
                    return;
                }

                if (PendingLines.Count != 0)
                {
                    Completed = new List<string>(PendingLines);
                    PendingLines.Clear();
                }

                Partial = OpenLine.Length != 0 ? OpenLine.ToString() : null;
                OpenDirty = false;
            }

            int Index = 0;
            if (LastIsOpen)
            {
                if (Completed != null)
                {
                    Lines.ReplaceLast(Completed[0]);
                    Index = 1;
                    LastIsOpen = false;
                }
                else if (Partial != null)
                {
                    Lines.ReplaceLast(Partial);
                    Partial = null;
                }
            }

            if (Completed != null)
            {
                for (; Index < Completed.Count; Index++)
                    Lines.Append(Completed[Index]);
            }

            if (Partial != null)
            {
                Lines.Append(Partial);
                LastIsOpen = true;
            }

            Lines.RaiseChanged();
        }
    }
}
