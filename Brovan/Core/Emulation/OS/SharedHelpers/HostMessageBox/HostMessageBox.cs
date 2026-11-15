using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    public interface IHostMessageBox
    {
        // Blocks until the person answers. 0 when the host has nobody to ask.
        int Show(HostMessageBoxRequest Request);
    }

    public enum HostMessageBoxIcon
    {
        None,
        Error,
        Question,
        Warning,
        Information,
    }

    public readonly record struct HostMessageBoxButton(int Id, string Caption);

    public sealed class HostMessageBoxRequest
    {
        public string Caption { get; init; }
        public string Text { get; init; }

        // Only the bits the decoded form describes: the buttons, the icon, the default button and topmost.
        public uint Style { get; init; }
        public HostMessageBoxButton[] Buttons { get; init; }
        public int DefaultIndex { get; init; }

        // The answer to Esc and to the window's close button, 0 when the box ignores both.
        public int EscapeId { get; init; }
        public HostMessageBoxIcon Icon { get; init; }
    }

    public static class HostMessageBox
    {
        public const int IdOk = 1;
        public const int IdCancel = 2;
        public const int IdAbort = 3;
        public const int IdRetry = 4;
        public const int IdIgnore = 5;
        public const int IdYes = 6;
        public const int IdNo = 7;
        public const int IdTryAgain = 10;
        public const int IdContinue = 11;

        public const uint Ok = 0x0;
        public const uint OkCancel = 0x1;
        public const uint AbortRetryIgnore = 0x2;
        public const uint YesNoCancel = 0x3;
        public const uint YesNo = 0x4;
        public const uint RetryCancel = 0x5;
        public const uint CancelTryContinue = 0x6;
        public const uint IconError = 0x10;
        public const uint IconQuestion = 0x20;
        public const uint IconWarning = 0x30;
        public const uint IconInformation = 0x40;
        public const uint TopMost = 0x40000;

        private const uint TypeMask = 0xF;
        private const uint IconMask = 0xF0;
        private const uint DefaultMask = 0xF00;

        // user32's button strings, by control id 1 to 11.
        internal static readonly string[] ButtonCaptions =
        {
            "OK", "Cancel", "&Abort", "&Retry", "&Ignore", "&Yes", "&No", "Close", "Help", "&Try Again", "&Continue",
        };

        private static readonly int[][] TypeButtons =
        {
            new[] { IdOk },
            new[] { IdOk, IdCancel },
            new[] { IdAbort, IdRetry, IdIgnore },
            new[] { IdYes, IdNo, IdCancel },
            new[] { IdYes, IdNo },
            new[] { IdRetry, IdCancel },
            new[] { IdCancel, IdTryAgain, IdContinue },
        };

        private readonly record struct Question(HostMessageBoxRequest Request, TaskCompletionSource<int> Answer);

        private static readonly object QueueLock = new();
        private static BlockingCollection<Question> _queue;

        // One box at a time per process, on a thread of its own, so no guest thread waits on the host.
        public static Task<int> Ask(string Caption, string Text, uint Style)
        {
            HostMessageBoxRequest Request = Decode(Caption, Text, Style);
            TaskCompletionSource<int> Answer = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!EnsureWorker().TryAdd(new Question(Request, Answer)))
            {
                Utils.LogError($"[HostMessageBox] {MemoryBudget.HostMessageBoxes} questions already wait, so this one is not asked. {Request.Caption}: {Request.Text}");
                Answer.SetResult(0);
            }

            return Answer.Task;
        }

        private static BlockingCollection<Question> EnsureWorker()
        {
            lock (QueueLock)
            {
                if (_queue != null)
                    return _queue;

                _queue = new BlockingCollection<Question>(MemoryBudget.HostMessageBoxes);
                Thread Worker = new Thread(Serve)
                {
                    IsBackground = true,
                    Name = "BrovanHostMessageBox",
                };
                Worker.Start(_queue);
                return _queue;
            }
        }

        private static IHostMessageBox CreateHost()
        {
            if (Android.AndroidHost.IsActive)
                return new Android.AndroidMessageBox();

            return GeneralHelper.IsWindows ? new WindowsMessageBox() : new X11MessageBox();
        }

        private static void Serve(object Queue)
        {
            IHostMessageBox Host = CreateHost();
            foreach (Question Pending in ((BlockingCollection<Question>)Queue).GetConsumingEnumerable())
            {
                int Id = 0;
                try
                {
                    Id = Host.Show(Pending.Request);
                }
                catch (Exception Error)
                {
                    Utils.LogError($"[HostMessageBox] The host could not show the message: {Error.Message}");
                }

                if (Id == 0)
                    Utils.LogError($"[HostMessageBox] No one could be asked. {Pending.Request.Caption}: {Pending.Request.Text}");

                Pending.Answer.SetResult(Id);
            }
        }

        public static HostMessageBoxRequest Decode(string Caption, string Text, uint Style)
        {
            uint Type = Style & TypeMask;
            if (Type > CancelTryContinue)
                Type = Ok;

            int[] Ids = TypeButtons[Type];
            HostMessageBoxButton[] Buttons = new HostMessageBoxButton[Ids.Length];
            int EscapeId = Ids.Length == 1 ? IdOk : 0;
            for (int i = 0; i < Ids.Length; i++)
            {
                Buttons[i] = new HostMessageBoxButton(Ids[i], ButtonCaptions[Ids[i] - 1].Replace("&", string.Empty));
                if (Ids[i] == IdCancel)
                    EscapeId = IdCancel;
            }

            int DefaultIndex = (int)((Style & DefaultMask) >> 8);
            if (DefaultIndex >= Buttons.Length)
                DefaultIndex = 0;

            uint IconBits = Style & IconMask;
            HostMessageBoxIcon Icon = IconBits switch
            {
                IconError => HostMessageBoxIcon.Error,
                IconQuestion => HostMessageBoxIcon.Question,
                IconWarning => HostMessageBoxIcon.Warning,
                IconInformation => HostMessageBoxIcon.Information,
                _ => HostMessageBoxIcon.None,
            };

            return new HostMessageBoxRequest
            {
                Caption = Caption ?? string.Empty,
                Text = Text ?? string.Empty,
                Style = Type | (Icon == HostMessageBoxIcon.None ? 0 : IconBits) | ((uint)DefaultIndex << 8) | (Style & TopMost),
                Buttons = Buttons,
                DefaultIndex = DefaultIndex,
                EscapeId = EscapeId,
                Icon = Icon,
            };
        }
    }
}
