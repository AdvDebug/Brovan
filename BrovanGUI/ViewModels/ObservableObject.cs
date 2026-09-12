using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace BrovanGUI.ViewModels
{
    public abstract class ObservableObject : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        protected bool Set<T>(ref T Field, T Value, [CallerMemberName] string? Name = null)
        {
            if (EqualityComparer<T>.Default.Equals(Field, Value))
                return false;

            Field = Value;
            Raise(Name);
            return true;
        }

        protected void Raise([CallerMemberName] string? Name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(Name));
        }
    }

    public sealed class RelayCommand : ICommand
    {
        private readonly Action Action;
        private readonly Func<bool>? Condition;

        public RelayCommand(Action Action, Func<bool>? Condition = null)
        {
            this.Action = Action;
            this.Condition = Condition;
        }

        public event EventHandler? CanExecuteChanged;

        public bool CanExecute(object? Parameter)
        {
            return Condition == null || Condition();
        }

        public void Execute(object? Parameter)
        {
            Action();
        }

        public void Refresh()
        {
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    // A failure goes to the error handler. An unobserved exception in a command would end the process.
    public sealed class AsyncCommand : ICommand
    {
        private readonly Func<Task> Action;
        private readonly Action<Exception> OnError;
        private readonly Func<bool>? Condition;
        private bool Running;

        public AsyncCommand(Func<Task> Action, Action<Exception> OnError, Func<bool>? Condition = null)
        {
            this.Action = Action;
            this.OnError = OnError;
            this.Condition = Condition;
        }

        public event EventHandler? CanExecuteChanged;

        public bool CanExecute(object? Parameter)
        {
            return !Running && (Condition == null || Condition());
        }

        public async void Execute(object? Parameter)
        {
            Running = true;
            Refresh();

            try
            {
                await Action();
            }
            catch (Exception Error)
            {
                OnError(Error);
            }
            finally
            {
                Running = false;
                Refresh();
            }
        }

        public void Refresh()
        {
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }
}
