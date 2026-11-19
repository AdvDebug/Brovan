using System;

namespace Brovan.Core.Emulation
{
    internal class BackingBlock
    {
        public ulong Size;
        public int LivePages;
        public int AliasPages;
        public int Pins;
        public bool Held;
        public IDisposable Owner;

        public bool IsHeldOrPinned => Held || Pins > 0;

        public bool IsReferenced => LivePages > 0 || AliasPages > 0 || IsHeldOrPinned;

        public bool IsDiscardable => !HostDiscard.Disabled && AliasPages == 0 && !IsHeldOrPinned && Owner == null;
    }
}
