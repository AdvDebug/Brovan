using System;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Android
{
    internal sealed class AndroidMessageBox : IHostMessageBox
    {
        public int Show(HostMessageBoxRequest Request)
        {
            int[] Ids = new int[Request.Buttons.Length];
            string[] Captions = new string[Request.Buttons.Length];
            for (int i = 0; i < Ids.Length; i++)
            {
                Ids[i] = Request.Buttons[i].Id;
                Captions[i] = Request.Buttons[i].Caption;
            }

            return AndroidHost.ShowMessageBox(Request.Caption, Request.Text, string.Join('\n', Captions), Ids, Request.DefaultIndex, Request.EscapeId, (int)Request.Icon);
        }
    }
}
