namespace SODT_CLI
{
	internal class Program
	{
		static void Main(string[] args)
		{
			SodtClient client = new();
			CLI cli = new(client);
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
				{ "send", new SendCommand() },
				{ "debug", new SetDebugOutputCommand() },
				{ "list-sends", new ListSendsCommand() },
				{ "list-receives", new ListReceivesCommand() },
				{"clear", new ClearCommand() },
				{ "list-aliases", new ListAliasesCommand(aliases)}
			};
			commands["help"] = new HelpCommand(commands); // help command needs to be added after all other commands are added to the dictionary so it can list them all

		}


		/// <summary>
		/// Starts the CLI and listens for commands.
		/// </summary>
		public void Run()
		{
			while (!client.Disconnected)
			{
				//handle commands
				string[] keyword = SmartConsole.GetInput("");
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

