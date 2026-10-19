using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SODT_CLI
{
	internal static class SmartConsole
	{
		/// <summary>
		/// Queue that contains all write requests that are waiting to be executed
		/// </summary>
		private readonly static Queue<Task> writeRequests = new();

		/// <summary>
		/// Object that is used to lock the Console to prevent multiple threads from writing at the same time
		/// </summary>
		public static object LockObject { get; } = new();

		/// <summary>
		/// Adds a message to the writeRequests queue.
		/// </summary>
		/// <param name="text"></param>
		/// <param name="color"></param>
		private static void RequestWriteLine(string text, ConsoleColor color)
		{
			// Lock the console to prevent multiple threads from writing at the same time
			Task.Run(() =>
			{
				lock (LockObject)
				{
					Console.ForegroundColor = color;
					Console.WriteLine(text);
					Console.ResetColor();
				}
			});
		}

		/// <summary>
		/// Writes a message to the console with red text.
		/// </summary>
		/// <param name="text"></param>
		public static void WriteError(string text)
		{
			RequestWriteLine(text, ConsoleColor.Red);
		}
		/// <summary>
		/// Writes a message to the console with green text.
		/// </summary>
		/// <param name="text"></param>
		public static void WriteSuccess(string text)
		{
			RequestWriteLine(text, ConsoleColor.Green);
		}
		/// <summary>
		/// Writes a message to the console with white text.
		/// </summary>
		/// <param name="text"></param>
		public static void WriteInfo(string text)
		{
			RequestWriteLine(text, ConsoleColor.Gray);
		}
		/// <summary>
		/// Writes a message to the console with yellow text.
		/// </summary>
		/// <param name="text"></param>
		public static void WriteWarning(string text)
		{
			RequestWriteLine(text, ConsoleColor.Yellow);
		}

		public static void WriteLine()
		{
			WriteInfo("");
		}
		public static void WriteDebug(string text)
		{
			RequestWriteLine("DEBUG: " + text, ConsoleColor.Gray);
		}
	}
}
