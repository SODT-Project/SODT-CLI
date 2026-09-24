using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SODT_CLI
{
	internal static class Compression
	{
		public static async Task StartCompression(string filePath)
		{
			// Öffnen Sie die Eingabedatei zum Lesen
			using var inputStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
			// Öffnen Sie die Ausgabedatei zum Schreiben
			using var outputStream = new FileStream(filePath + ".sodtfzip", FileMode.Create, FileAccess.Write);
			// Komprimieren Sie den Eingabestrom in den Ausgabestrom
			await CompressStream(inputStream, outputStream);
		}

		public static async Task DecompressFile(string inputFile, string outputFile)
		{
			// Öffnen Sie die Eingabedatei zum Lesen
			using var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
			// Öffnen Sie die Ausgabedatei zum Schreiben
			using var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
			// Komprimieren Sie den Eingabestrom in den Ausgabestrom
			await DecompressStream(inputStream, outputStream);
		}

		private static async Task CompressStream(Stream inputStream, Stream outputStream)
		{
			// Wrap the output stream with GZipStream for compression
			using var gzipStream = new GZipStream(outputStream, CompressionLevel.Optimal, leaveOpen: true);
			// Copy data from the input stream to the GZipStream
			await inputStream.CopyToAsync(gzipStream);
			// Important: Don't close the outputStream if the leaveOpen parameter is true
		}

		private static async Task DecompressStream(Stream inputStream, Stream outputStream)
		{
			// Wrap the input stream with GZipStream for decompression
			using var gzipStream = new GZipStream(inputStream, CompressionMode.Decompress);
			// Copy data from the GZipStream to the output stream
			await gzipStream.CopyToAsync(outputStream);
		}
	}
}
