namespace SODT_CLI
{
	internal static class SmartConsole
	{
		/// <summary>
		/// Object that is used to lock the Console to prevent multiple threads from writing at the same time
		/// </summary>
		public static object LockObject { get; } = new();
		public static bool ShowDebugOutput { get; set; } = false;
		private static bool yesNoQuestionActive = false;
		private static TaskCompletionSource<bool> yesNoTask = new();
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
		
		public static async Task<bool> AskYesNo(string question)
		{
			yesNoQuestionActive = true;
			WriteInfo(question + " (y/n): ");
			await yesNoTask.Task;
			return yesNoTask.Task.Result;
		}
		
		
		/// <summary>
		/// Reads a line from the console and splits it.
		/// File paths are kept together if they are in quotes.
		/// </summary>
		/// <param name="message"></param>
		/// <returns>Command like structure. [0] is the keyword, [1] is the first argument, [2] is the second argument, ...</returns>
		public static string[] GetInput(string message)
		{
			Console.Write(message);
			string input = Console.ReadLine() ?? "";
			
			// overwrite input if a yes/no question is active and return empty array to command handler to not execute any command so that the yes/no question can be answered
			if (yesNoQuestionActive) 
			{
				yesNoQuestionActive = false;
				while (input != "y" && input != "n")
				{
					WriteInfo("Please answer with 'y' or 'n': ");
					input = Console.ReadLine() ?? "";
				}
				yesNoTask.SetResult(input == "y");
				yesNoTask = new();
				return Array.Empty<string>();
			}

			//split input but keep file paths together
			List<string> parts = new();
			bool isPath = false;
			string current = "";
			foreach (char c in input)
			{
				if (c == ' ' && !isPath)
				{
					parts.Add(current);
					current = "";
				}
				else if (c == '"')
				{
					isPath = !isPath;
				}
				else
				{
					current += c;
				}
			}
			if (!string.IsNullOrEmpty(current))
				parts.Add(current);
			return parts.ToArray();
		}
		
		public static void WriteDebug(string text)
		{
			if (ShowDebugOutput)
				RequestWriteLine("DEBUG: " + text, ConsoleColor.Gray);

		}
	}
}
