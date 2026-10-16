using System.Text.Json.Serialization;
using System.IO;
using System;
using System.Runtime.InteropServices;
using System.Diagnostics.Metrics;
using System.Collections.ObjectModel;

namespace SODT_CLI
{
	internal class Program
	{
		static void Main(string[] args)
		{
			string publicServerKeyPath;
			if (args.Length > 0 && File.Exists(args[0].Replace("\"", "")))
				publicServerKeyPath = args[0].Replace("\"", "");
			else if (File.Exists("defaultServer.key"))
				publicServerKeyPath = "defaultServer.key";
			else
			{
				Console.WriteLine("No public key found. Please provide the path to the public key of the server as an argument.");
				Console.WriteLine("You can set the default public key afterwards with the 'set-default-key' command.");
				return;
			}
			SodtClient client = new SodtClient();
			CLI cli = new CLI(client);
			//main loop
			Console.WriteLine("SODTF-CLI initialized. Type 'help' for a list of commands.");
			Console.WriteLine();
			cli.Run();
		}


	}
	/// <summary>
	/// Class that contains a collection of methods to interact with the console and the user.
	/// </summary>
	internal class CLI
	{
		private readonly SodtClient client;
		private readonly Dictionary<string, ICommand> commands;
		private readonly Dictionary<string, string> aliases;
		public CLI(SodtClient client)
		{
			this.client = client;
			aliases = new()
			{
				{ "c", "connect-default" },
				{ "lc", "list-clients" },
				{ "dc", "disconnect" },
				{"q", "disconnect" },
				{"exit", "disconnect" },
				{ "ex", "exchange" },
				{ "s", "send" },
				{ "ls", "list-sends" },
				{ "lr", "list-receives" },
				{ "spw", "set-session-password" },
				{ "rstspw", "reset-session-password" },
				{ "?", "help" },
				{ "h", "help" }
			};
			commands = new()
			{
				{ "connect", new ConnectCommand() },
				{"connect-default", new DefaultConnectCommand() },
				{"set-default-server", new SetDefaultServerCommand() },
				{"set-default-key", new SetDefaultServerPublicKeyCommand() },
				{ "list-clients", new ListClientsCommand() },
				{ "disconnect", new DisconnectCommand() },
				{ "exchange", new ExchangeKeyCommand() },
				{ "set-session-password", new SetSessionPasswordCommand() },
				{ "reset-session-password", new ResetSessionPasswordCommand() },
				{ "send", new SendCommand() },
				{ "debug", new DebugCommand() },
				{ "list-sends", new ListSendsCommand() },
				{ "list-receives", new ListReceivesCommand() },
				{"clear", new ClearCommand() },
				{ "help", new HelpCommand() },
				{ "list-aliases", new ListAliasesCommand(aliases)}
			};

		}


		/// <summary>
		/// Reads a line from the console and splits it.
		/// File paths are kept together if they are in quotes.
		/// </summary>
		/// <param name="message"></param>
		/// <returns>Command like structure. [0] is the keyword, [1] is the first argument, [2] is the second argument, ...</returns>
		private static string[] GetInput(string message)
		{
			Console.Write(message);
			string input = Console.ReadLine() ?? "";

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
		/// <summary>
		/// Starts the CLI and listens for commands.
		/// </summary>
		public void Run()
		{
			//TODO: pre set the public key and the default server
			while (client != null)
			{
				//handle commands
				string[] keyword = GetInput("");
				if (keyword.Length == 0) continue;
				if (aliases.TryGetValue(keyword[0], out string? fullName))
				{
					keyword[0] = fullName;
				}
				if (commands.TryGetValue(keyword[0], out ICommand? command))
				{
					try
					{
						command.Execute(client, keyword[1..]);
					}
					catch (Exception e)
					{
						SmartConsole.WriteError(e.Message);
					}

					//after command 
					if (keyword[0] == "disconnect") return;
					continue;
				}
				SmartConsole.WriteInfo("Unknown command. Type 'help' for a list of commands.");
			}
		}
	}
}

