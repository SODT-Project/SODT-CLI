namespace SODT_CLI
{
	/// <summary>
	/// Class that contains a collection of methods to interact with the console and the user.
	/// This class handles writing messages and reading user input while ensuring thread safety.
	/// </summary>
	internal static class SmartConsole
	{
		/// <summary>
		/// Object that is used to lock the Console to prevent multiple threads from writing at the same time
		/// </summary>
		public static object LockObject { get; } = new();
		/// <summary>
		/// Indicates whether debug output should be shown in the console. If set to true, debug messages will be displayed; otherwise, they will be suppressed.
		/// </summary>
		public static bool ShowDebugOutput { get; set; } = false;
		/// <summary>
		/// Indicates whether a yes/no question is currently active. This is used to manage user input for yes/no prompts.
		/// </summary>
		private static bool yesNoQuestionActive = false;
		/// <summary>
		/// TaskCompletionSource used to manage the result of a yes/no question.
		/// When a yes/no question is asked, this TaskCompletionSource will be completed with the user's response (true for yes, false for no).
		/// </summary>
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
		/// <param name="text">The text to write.</param>
		public static void WriteError(string text)
		{
			RequestWriteLine(text, ConsoleColor.Red);
		}
		/// <summary>
		/// Writes a message to the console with green text.
		/// </summary>
		/// <param name="text">The text to write.</param>
		public static void WriteSuccess(string text)
		{
			RequestWriteLine(text, ConsoleColor.Green);
		}
		/// <summary>
		/// Writes a message to the console with white text.
		/// </summary>
		/// <param name="text">The text to write.</param>
		public static void WriteInfo(string text)
		{
			RequestWriteLine(text, ConsoleColor.Gray);
		}
		/// <summary>
		/// Writes a message to the console with yellow text.
		/// </summary>
		/// <param name="text">The text to write.</param>
		public static void WriteWarning(string text)
		{
			RequestWriteLine(text, ConsoleColor.Yellow);
		}
		
		/// <summary>
		/// Writes a debug message to the console with gray text if ShowDebugOutput is true.
		/// </summary>
		/// <param name="text">The text to write.</param>
		public static void WriteDebug(string text)
		{
			if (ShowDebugOutput)
				RequestWriteLine("DEBUG: " + text, ConsoleColor.Gray);

		}
		
		/// <summary>
		/// Asks the user a yes/no question and returns true for yes and false for no.
		/// </summary>
		/// <param name="question">The question to ask.</param>
		/// <returns>A task that represents the asynchronous operation. The result of the task is true if the user answered yes, false otherwise.</returns>
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
	}
}
