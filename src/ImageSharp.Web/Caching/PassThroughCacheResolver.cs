// Copyright (c) Six Labors.
// Licensed under the Apache License, Version 2.0.

using System.IO;
using System.Threading.Tasks;
using Microsoft.IO;
using SixLabors.ImageSharp.Web.Resolvers;

namespace SixLabors.ImageSharp.Web.Caching
{
    /// <summary>
    /// This resolver is designed to handle the serving of newly written images without the need
    /// to performa repeat read of the newly cached image.
    /// Due to the asynchronous locking within the middleware that detects duplicate requests
    /// this will run once per unique request.
    /// </summary>
    internal class PassThroughCacheResolver : IImageCacheResolver
    {
        private readonly ImageCacheMetadata metadata;
        private readonly Stream stream;
        private readonly RecyclableMemoryStreamManager manager;

        public PassThroughCacheResolver(ImageCacheMetadata metadata, Stream stream, RecyclableMemoryStreamManager manager)
        {
            this.metadata = metadata;
            this.stream = stream;
            this.manager = manager;
        }

        public Task<ImageCacheMetadata> GetMetaDataAsync() => Task.FromResult(this.metadata);

        public async Task<Stream> OpenReadAsync()
        {
            // Copy so that we can serve a unique stream for each identical response.
            this.stream.Position = 0;
            RecyclableMemoryStream outStream = new(this.manager);
            await this.stream.CopyToAsync(outStream);
            outStream.Position = 0;
            return outStream;
        }
    }
}
