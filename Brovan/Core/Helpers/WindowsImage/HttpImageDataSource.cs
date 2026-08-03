using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal sealed class HttpImageDataSource : ImageDataSource
    {
        private const int BlockSize = 1 << 20;
        private const int CachedBlocks = 24;
        private const int ReadAheadBlocks = 4;
        private const int MaxAttempts = 5;

        public const string BrowserUserAgent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

        private readonly HttpClient Client;
        private readonly bool OwnsClient;
        private readonly BlockCache Cache = new BlockCache(BlockSize, CachedBlocks);
        private readonly long TotalLength;

        private Uri Address;

        public long TransferredBytes { get; private set; }

        public HttpImageDataSource(Uri Address, HttpClient? Client = null)
        {
            this.Address = Address;
            OwnsClient = Client == null;
            this.Client = Client ?? CreateClient();
            TotalLength = QueryLength();
        }

        public static HttpClient CreateClient()
        {
            HttpClientHandler Handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                AutomaticDecompression = DecompressionMethods.None,
            };

            HttpClient Created = new HttpClient(Handler);
            Created.Timeout = TimeSpan.FromMinutes(5);

            Created.DefaultRequestHeaders.UserAgent.ParseAdd(BrowserUserAgent);
            Created.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.9");
            Created.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            return Created;
        }

        public override long Length => TotalLength;

        private long QueryLength()
        {
            using HttpRequestMessage Request = new HttpRequestMessage(HttpMethod.Get, Address);
            Request.Headers.Range = new RangeHeaderValue(0, 0);

            using HttpResponseMessage Response = Client.Send(Request, HttpCompletionOption.ResponseHeadersRead);

            if (Response.StatusCode != HttpStatusCode.PartialContent)
                throw new NotSupportedException($"The server did not honour a range request for {Address} (status {(int)Response.StatusCode}). A local ISO path is required instead.");

            ContentRangeHeaderValue? Range = Response.Content.Headers.ContentRange;
            if (Range == null || !Range.HasLength || Range.Length is not long Total || Total <= 0)
                throw new NotSupportedException($"The server did not report a content length for {Address}. A local ISO path is required instead.");

            if (Response.RequestMessage?.RequestUri != null)
                Address = Response.RequestMessage.RequestUri;

            return Total;
        }

        public override int Read(long Offset, Span<byte> Buffer)
        {
            if (Offset >= TotalLength || Buffer.Length == 0)
                return 0;

            long Available = TotalLength - Offset;
            if (Buffer.Length > Available)
                Buffer = Buffer.Slice(0, (int)Available);

            long BlockNumber = Offset / BlockSize;
            int Inside = (int)(Offset - (BlockNumber * BlockSize));

            if (!Cache.TryGet(BlockNumber, out ReadOnlySpan<byte> Block))
            {
                Fetch(BlockNumber);

                if (!Cache.TryGet(BlockNumber, out Block))
                    return 0;
            }

            if (Inside >= Block.Length)
                return 0;

            int Count = Math.Min(Buffer.Length, Block.Length - Inside);
            Block.Slice(Inside, Count).CopyTo(Buffer);
            return Count;
        }

        private void Fetch(long FirstBlock)
        {
            long Start = FirstBlock * BlockSize;
            long Wanted = (long)ReadAheadBlocks * BlockSize;

            if (Start + Wanted > TotalLength)
                Wanted = TotalLength - Start;

            Exception? Failure = null;

            for (int Attempt = 0; Attempt < MaxAttempts; Attempt++)
            {
                try
                {
                    FetchOnce(FirstBlock, Start, Wanted);
                    return;
                }
                catch (Exception Error) when (Error is HttpRequestException || Error is IOException || Error is TaskCanceledException)
                {
                    Failure = Error;
                    Cache.Invalidate();
                    Thread.Sleep(250 * (1 << Attempt));
                }
            }

            throw new IOException($"Failed to read {Wanted} bytes at offset {Start} from {Address}.", Failure);
        }

        private void FetchOnce(long FirstBlock, long Start, long Wanted)
        {
            using HttpRequestMessage Request = new HttpRequestMessage(HttpMethod.Get, Address);
            Request.Headers.Range = new RangeHeaderValue(Start, Start + Wanted - 1);

            using HttpResponseMessage Response = Client.Send(Request, HttpCompletionOption.ResponseHeadersRead);

            if (Response.StatusCode != HttpStatusCode.PartialContent)
                throw new HttpRequestException($"Expected a partial content response, got {(int)Response.StatusCode}.");

            using Stream Content = Response.Content.ReadAsStream();

            long Remaining = Wanted;
            long BlockNumber = FirstBlock;

            while (Remaining > 0)
            {
                int Length = (int)Math.Min(BlockSize, Remaining);
                Span<byte> Target = Cache.Reserve(BlockNumber, Length);

                int Filled = 0;
                while (Filled < Length)
                {
                    int Count = Content.Read(Target.Slice(Filled));
                    if (Count <= 0)
                        throw new IOException($"The response body ended {Length - Filled} bytes early.");

                    Filled += Count;
                }

                TransferredBytes += Length;
                Remaining -= Length;
                BlockNumber++;
            }
        }

        public override void Dispose()
        {
            Cache.Dispose();

            if (OwnsClient)
                Client.Dispose();
        }
    }
}
