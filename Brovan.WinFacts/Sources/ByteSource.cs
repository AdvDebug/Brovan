using System.Net;
using System.Net.Http.Headers;

namespace Brovan.WinFacts.Sources
{
    internal interface IByteSource
    {
        bool TryRead(long Offset, Span<byte> Destination);
    }

    internal sealed class LocalFile : IByteSource
    {
        private readonly byte[] Bytes;

        internal LocalFile(string Path)
        {
            Bytes = File.ReadAllBytes(Path);
        }

        public bool TryRead(long Offset, Span<byte> Destination)
        {
            if (Offset < 0 || Offset > Bytes.Length - Destination.Length)
                return false;

            Bytes.AsSpan((int)Offset, Destination.Length).CopyTo(Destination);
            return true;
        }
    }

    // Blocks are fetched once and kept, so only the parts a rule reads cross the network.
    internal sealed class RemoteFile : IByteSource
    {
        private const int BlockSize = 0x80000;
        private const int Attempts = 4;

        private readonly HttpClient Client;
        private readonly Uri Location;
        private readonly Dictionary<long, byte[]> Blocks = new();
        private readonly long Length;

        private RemoteFile(HttpClient Client, Uri Location, long Length)
        {
            this.Client = Client;
            this.Location = Location;
            this.Length = Length;
        }

        // Follows the redirect once and keeps the final address, so every range goes straight to the storage server.
        internal static RemoteFile Open(HttpClient Client, string Url) => WithRetries(() =>
        {
            using HttpRequestMessage Request = new(HttpMethod.Get, Url);
            Request.Headers.Range = new RangeHeaderValue(0, 0);
            using HttpResponseMessage Response = Client.Send(Request, HttpCompletionOption.ResponseHeadersRead);
            if (Response.StatusCode == HttpStatusCode.NotFound)
                return null;

            if (Response.StatusCode != HttpStatusCode.PartialContent || Response.Content.Headers.ContentRange?.Length is not long Total)
                throw new IOException($"{Url}: no range support ({(int)Response.StatusCode})");

            return new RemoteFile(Client, Response.RequestMessage.RequestUri, Total);
        });

        internal static bool TryDownload(HttpClient Client, string Url, string Destination) => WithRetries(() =>
        {
            using HttpRequestMessage Request = new(HttpMethod.Get, Url);
            using HttpResponseMessage Response = Client.Send(Request, HttpCompletionOption.ResponseHeadersRead);
            if (Response.StatusCode == HttpStatusCode.NotFound)
                return false;

            Response.EnsureSuccessStatusCode();
            string Partial = Destination + ".part";
            Directory.CreateDirectory(Path.GetDirectoryName(Destination));
            using (FileStream Output = File.Create(Partial))
                Response.Content.ReadAsStream().CopyTo(Output);

            File.Move(Partial, Destination, true);
            return true;
        });

        public bool TryRead(long Offset, Span<byte> Destination)
        {
            if (Offset < 0 || Offset > Length - Destination.Length)
                return false;

            while (!Destination.IsEmpty)
            {
                long Block = Offset / BlockSize;
                byte[] Data = GetBlock(Block);
                int Inside = (int)(Offset - Block * BlockSize);
                int Count = Math.Min(Destination.Length, Data.Length - Inside);
                Data.AsSpan(Inside, Count).CopyTo(Destination);
                Destination = Destination.Slice(Count);
                Offset += Count;
            }

            return true;
        }

        private byte[] GetBlock(long Block)
        {
            if (Blocks.TryGetValue(Block, out byte[] Data))
                return Data;

            long Start = Block * BlockSize;
            long End = Math.Min(Start + BlockSize, Length) - 1;
            Data = WithRetries(() =>
            {
                using HttpRequestMessage Request = new(HttpMethod.Get, Location);
                Request.Headers.Range = new RangeHeaderValue(Start, End);
                using HttpResponseMessage Response = Client.Send(Request);
                if (Response.StatusCode != HttpStatusCode.PartialContent)
                    throw new IOException($"{Location.Host}: range {Start}-{End} answered {(int)Response.StatusCode}");

                byte[] Received = Response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                if (Received.Length != End - Start + 1)
                    throw new IOException($"{Location.Host}: range {Start}-{End} returned {Received.Length} bytes");

                return Received;
            });

            Blocks[Block] = Data;
            return Data;
        }

        private static T WithRetries<T>(Func<T> Body)
        {
            for (int Attempt = 1; ; Attempt++)
            {
                try
                {
                    return Body();
                }
                catch (HttpRequestException) when (Attempt < Attempts)
                {
                    Thread.Sleep(1000 * Attempt);
                }
            }
        }
    }
}
