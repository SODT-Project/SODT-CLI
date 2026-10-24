using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SODT_CLI
{
	/// <summary>
	/// Base interface for all commands.
	/// </summary>
	internal interface ICommand
	{
		/// <summary>
		/// Executes the command.
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args">Arguments needed for the command.</param>
		void Execute(SodtClient client, params string[] args);
		
		public string Description { get; }
	}
	/// <summary>
	/// Command to connect to a server.
	/// </summary>
	internal class ConnectCommand : ICommand
	{
		public virtual string Description => "Connects to a server. Usage: connect <host> <port>";
		
		/// <summary>
		/// Connects to a server.
		/// This command needs two arguments: <see cref="string"/> host , <see cref="int"/> port
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args"><see cref="string"/> host , <see cref="int"/> port</param>"/>
		public virtual void Execute(SodtClient client, params string[] args)
		{
			(string host, int port) = ValidateArgs(args);
			if (client.OwnId != 0)
			{
				SmartConsole.WriteInfo("Already connected!");
				return;
			}
			
			// check if public key is available
			if (!File.Exists("defaultServer.key"))
			{
				Console.WriteLine("No public key found. Please set a public key first.");
				Console.WriteLine("You can set the default public key with the 'set-default-key <path/to/public_key.pem>' command.");
				return;
			}

			var connectTask = client.Connect(host, port, File.ReadAllText("defaultServer.key"));
			for (int i = 0; i < 100; i++)
			{
				if (client.OwnId != 0)
				{
					SmartConsole.WriteSuccess($"Connected to server! Your Id: {client.OwnId}");
					return;
				}
				Thread.Sleep(20);
			}
			connectTask.Dispose();
			SmartConsole.WriteError("Connection failed!");
		}
		private (string host, int port) ValidateArgs(params string[] args)
		{
			if (args.Length != 2) throw new ArgumentException("Invalid number of arguments!");
			if (!int.TryParse(args[1], out int port)) throw new ArgumentException("Invalid port!");
			return (args[0], port);
		}
	}
	/// <summary>
	/// Command to connect to the default server, specified in a config file.
	/// </summary>
	internal class DefaultConnectCommand : ConnectCommand
	{
		public override string Description => "Connects to the default server. Usage: connect-default. The default server is specified in the defaultServer.txt file.";

		/// <summary>
		/// Connects to the default server.
		/// No arguments needed.
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args">No arguments needed.</param>
		public override void Execute(SodtClient client, params string[] args)
		{
			var server = File.ReadAllText("defaultServer.txt").Split(":");
			base.Execute(client, server[0], server[1]);
		}
	}
	/// <summary>
	/// Command to list all connected clients.
	/// </summary>
	internal class ListClientsCommand : ICommand
	{
		public string Description => "Lists all connected clients. Usage: list-clients.";

		/// <summary>
		/// Executes the list clients command.
		/// No arguments needed.
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args">No arguments needed.</param>
		public void Execute(SodtClient client, params string[] args)
		{
			//update
			var old = client.ConnectedClients.GetHashCode();
			client.RequestClientList().Wait();
			while (old == client.ConnectedClients.GetHashCode()) Thread.Sleep(20);  //wait for the client list to be updated

			//display the client list
			string clients = string.Join(", ", client.ConnectedClients.Where(id => id != 1));
			SmartConsole.WriteInfo($"Connected clients: {clients}");
		}
	}
	/// <summary>
	/// Command to disconnect from the server.
	/// </summary>
	internal class DisconnectCommand : ICommand
	{
		public string Description => "Disconnects from the server. Usage: disconnect.";

		/// <summary>
		/// Executes the disconnect command.
		/// No arguments needed.
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args">No arguments needed.</param>
		public void Execute(SodtClient client, params string[] args)
		{
			client.DisconnectFromServer().Wait();
		}
	}
	/// <summary>
	/// Command to exchange a aes session key with a specified client.
	/// </summary>
	internal class ExchangeKeyCommand : ICommand
	{
		public string Description => "Exchanges a session key with a client. Usage: exchange <targetId>";

		/// <summary>
		/// Executes the exchange key command.
		/// This command needs one argument: <see cref="byte"/> targetId to exchange the key with.
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args"><see cref="byte"/> targetId</param>"/>
		public void Execute(SodtClient client, params string[] args)
		{
			client.RequestKeyExchange(ValidateArgs(args)).Wait();
		}
		private byte ValidateArgs(params string[] args)
		{
			if (args.Length != 1) throw new ArgumentException("Invalid number of arguments!");
			if (!byte.TryParse(args[0], out byte id)) throw new ArgumentException("Invalid id!");
			return id;
		}
	}
	/// <summary>
	/// Command to set the session password, used for clients to authenticate themselves to other clients.
	/// </summary>
	internal class SetSessionPasswordCommand : ICommand
	{
		public string Description => "Sets the session password for client authentication. Usage: set-session-password <password>";

		public void Execute(SodtClient client, params string[] args)
		{
			client.SessionPassword = ValidateArgs(args);
		}
		private string ValidateArgs(params string[] args)
		{
			if (args.Length != 1) throw new ArgumentException("Invalid number of arguments!");
			return args[0];
		}
	}
	/// <summary>
	/// Command to reset the session password, used for clients to authenticate themselves to other clients.
	/// </summary>
	internal class ResetSessionPasswordCommand : ICommand
	{
		public string Description => "Resets the session password. Usage: reset-session-password";

		public void Execute(SodtClient client, params string[] args)
		{
			client.SessionPassword = null;
		}
	}
	/// <summary>
	/// Sends a file to a specified client.
	/// </summary>
	internal class SendCommand : ICommand
	{
		public string Description => "Sends a file to a client. Usage: send <targetId> <filePath>";

		/// <summary>
		/// Executes the send command.
		/// This command needs two arguments: <see cref="byte"/> targetId , <see cref="string"/> filePath
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args"><see cref="byte"/> tagetId , <see cref="string"/> filePath</param>
		public void Execute(SodtClient client, params string[] args)
		{
			(byte targetId, string filePath) = ValidateArgs(args);
			_ = ExecuteAsync(client, targetId, filePath).ContinueWith(
				task => SmartConsole.WriteError(task.Exception!.GetBaseException().Message),
				TaskContinuationOptions.OnlyOnFaulted);
		}

		private async Task ExecuteAsync(SodtClient client, byte targetId, string filePath)
		{
			//check if exchange key is needed
			if (!client.IsKeyExchanged(targetId))
			{
				SmartConsole.WriteInfo($"No session key found for {targetId}.");
				await client.RequestKeyExchange(targetId);
				SmartConsole.WriteInfo("Waiting for key exchange to complete...");
				while (!client.IsKeyExchanged(targetId))
					await Task.Delay(20);
			}
			//send the file
			bool accepted = await client.RequestFileTransfer(targetId, filePath);
			if (!accepted)
				SmartConsole.WriteError($"Transfer request failed. Client {targetId} rejected {Path.GetFileName(filePath)}");
		}
		private (byte, string) ValidateArgs(params string[] args)
		{
			if (args.Length != 2 && args.Length != 3) throw new ArgumentException("Invalid number of arguments!");
			if (!byte.TryParse(args[0], out byte id)) throw new ArgumentException("Invalid id!");
			string filePath = args[1].Trim();
			filePath = 
				(filePath.StartsWith('\"') || filePath.StartsWith('\''))
				&& (filePath.EndsWith('\"') || filePath.EndsWith('\''))
				? filePath[1..^1] : filePath;
			if (!File.Exists(filePath)) throw new ArgumentException("File not found!");

			return (id, filePath);
		}

	}
	/// <summary>
	/// Command to set the debug output.
	/// </summary>
	internal class SetDebugOutputCommand : ICommand
	{
		public string Description => "Set if debug output should be shown. Usage: debug <true/false>.";

		public void Execute(SodtClient client, params string[] args)
		{
			if (args.Length != 1) throw new ArgumentException("Invalid number of arguments!");
			if (!bool.TryParse(args[0], out bool show)) throw new ArgumentException("Invalid argument!");
			SmartConsole.ShowDebugOutput = show;
		}
	}
	/// <summary>
	/// Base class for commands that list the progress of file transfer tasks.
	/// </summary>
	internal abstract class ListCommand : ICommand
	{
		public abstract string Description { get; }
		
		protected const int progressBarLength = 30;
		/// <summary>
		/// Command to list the progress of file transfer tasks.
		/// No arguments needed.
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args">No arguments needed.</param>
		public void Execute(SodtClient client, params string[] args)
		{
			//init
			Console.WriteLine();
			Console.WriteLine("Press q to exit");
			CancellationTokenSource cts = new(); // token to cancel the progress display properly
			lock (SmartConsole.LockObject) // lock the console to prevent interference while showing the progress
			{
				//show the progress of the file transfers, as long as the user doesn't press q
				Task showTask = ShowProgress(client, cts.Token);

				//wait for q
				Console.CursorVisible = false;
				while (Console.ReadKey().Key != ConsoleKey.Q) Thread.Sleep(20);
				Console.CursorVisible = true;
				ResetConsole(2); // to remove the q from the console
				cts.Cancel(); //stop the progress display
				showTask.Wait(); //wait for the task to finish
			}
		}
		/// <summary>
		/// Launches an endless loop that shows the progress of the file transfer tasks.
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="token">Token to cancel the task.</param>
		/// <returns></returns>
		protected Task ShowProgress(SodtClient client, CancellationToken token)
		{
			return Task.Run(async () =>
			{
				//live update of progress
				while (!token.IsCancellationRequested)
				{
					//show the progress
					ResetConsole(ShowProgressContent(client));
					await Task.Delay(100);
				}
			}, token);
		}
		private void ResetConsole(int linesWritten)
		{
			//move the cursor to the top of the console
			while (linesWritten-- > 0)
			{
				Console.SetCursorPosition(0, Console.CursorTop);
				Console.Write(new string(' ', progressBarLength));
				Console.CursorTop--;
			}
			Console.SetCursorPosition(0, Console.CursorTop);
		}

		/// <summary>
		/// Displays the progress of receive file tasks in following format:
		/// <code>[##############......]  70%</code>
		/// Every # or . represents 5% of the progress.
		/// Its important to note that the progress bar must not shrink in size over time.
		/// This ensures that the overwrite of the progress bar works correctly.
		/// </summary>
		/// <param name="client"> Client on which the command is executed.</param>
		/// <returns>The amount of lines that were written to the console.</returns>
		protected abstract int ShowProgressContent(SodtClient client);
	}
	/// <summary>
	/// Command to list the progress of send file tasks.
	/// </summary>
	internal class ListSendsCommand : ListCommand
	{
		public override string Description => "Lists the progress of file sends. Usage: list-sends. Press q to exit.";

		protected override int ShowProgressContent(SodtClient client)
		{
			int linesWritten = 0;
			foreach (var progress in client.SendFileStreamProgress)
			{
				// The plain progress bar has a fixed length of 20 characters.
				// The progress value is divided by 5 to determine the number of '#' characters,
				// and the remaining progress is divided by 5 to determine the number of '.' characters.
				int progressValue = (int)Math.Round(progress.Value / 5.0) * 5; // round progress to the nearest multiple of 5
				string progressString = new string('#', progressValue / 5) + new string('.', (100 - progressValue) / 5);
				Console.WriteLine($"[{progressString}]  {progress.Value}%  ");
				linesWritten++;
			}
			return linesWritten;
		}
	}
	/// <summary>
	/// Command to list the progress of receive file tasks.
	/// </summary>
	internal class ListReceivesCommand : ListCommand
	{
		public override string Description => "Lists the progress of file receives. Usage: list-receives. Press q to exit.";

		protected override int ShowProgressContent(SodtClient client)
		{
			int linesWritten = 0;
			foreach (var progress in client.ReceivedFileStreamProgress)
			{
				// The plain progress bar has a fixed length of 20 characters.
				// The progress value is divided by 5 to determine the number of '#' characters,
				// and the remaining progress is divided by 5 to determine the number of '.' characters.
				int progressValue = (int)Math.Round(progress.Value / 5.0) * 5; // round progress to the nearest multiple of 5
				string progressString = new string('#', progressValue / 5) + new string('.', (100 - progressValue) / 5);
				Console.WriteLine($"[{progressString}]  {progress.Value}%  ");
				linesWritten++;
			}
			return linesWritten;
		}
	}
	/// <summary>
	/// Command to set the default server.
	/// </summary>
	internal class SetDefaultServerCommand : ICommand
	{
		public string Description => "Sets the default server. Usage: set-default-server <host> <port>";

		/// <summary>
		/// Executes the set default server command. Writes the server to the defaultServer.txt file.
		/// This command needs two arguments: <see cref="string"/> host , <see cref="int"/> port
		/// </summary>
		/// <param name="client"> Not used.</param>
		/// <param name="args">Default server with format: host:port or host port</param>
		public void Execute(SodtClient client, params string[] args)
		{
			File.WriteAllText("defaultServer.txt", ValidateArgs(args));
		}
		private string ValidateArgs(params string[] args)
		{
			return args.Length switch
			{
				1 => args[0],
				2 => args[0] + ":" + args[1],
				_ => throw new ArgumentException("Invalid number of arguments!"),
			};
		}
	}
	/// <summary>
	/// Command to set the default server public key.
	/// This command needs one argument: <see cref="string"/> path to the public key file.
	/// Path can be a file path or a URI. If the path is a URL, the public key will be downloaded from the URL and saved to the defaultServerPublic.key file.
	/// The public key must be in PEM format. The command will validate the public key before saving it.
	/// This command writes the public key to the defaultServerPublic.key file.
	/// </summary>
	internal class SetDefaultServerPublicKeyCommand : ICommand
	{
		public string Description => "Sets the default server public key. Usage: set-default-key <path/to/public_key.pem>. The public key must be in PEM format. Source can be a file path or a URL.";

		/// <summary>
		/// Executes the set default server public key command.
		/// </summary>
		/// <param name="client">Not used.</param>
		/// <param name="args">File path to the public key.</param>
		public void Execute(SodtClient client, params string[] args)
		{
			string content = ValidateArgs(args);
			File.WriteAllText("defaultServer.key", content);
		}
		/// <summary>
		/// Validates the arguments for the set default server public key command.
		/// </summary>
		/// <param name="args"></param>
		/// <returns>Returns the content of the public key file or the downloaded public key.</returns>
		/// <exception cref="ArgumentException"></exception>
		private string ValidateArgs(params string[] args)
		{
			if (args.Length != 1) throw new ArgumentException("Invalid number of arguments!");
			string keyPem;
			if (File.Exists(args[0])) 
				keyPem = File.ReadAllText(args[0]);
			else if (args[0].StartsWith("https://") || args[0].StartsWith("http://"))
			{
				keyPem = new HttpClient().GetStringAsync(args[0]).Result;
			}
			else
				throw new ArgumentException("Invalid path or URL!");
			try
			{
				ECDsa.Create().ImportFromPem(keyPem);
			}
			catch
			{
				throw new ArgumentException("Invalid public key!");
			}
			return keyPem;
		}
	}
	/// <summary>
	/// Command to clear the console.
	/// This command has no arguments.
	/// </summary>
	internal class ClearCommand : ICommand
	{
		public string Description => "Clears the console. Usage: clear";
		
		/// <summary>
		/// Executes the clear command.
		/// </summary>
		/// <param name="client">Not used.</param>
		/// <param name="args">No arguments needed.</param>
		public void Execute(SodtClient client, params string[] args)
		{
			Console.Clear();
		}
	}
	internal class ListAliasesCommand : ICommand
	{
		private readonly Dictionary<string, string> aliases;

		public string Description => "Lists all command aliases. Usage: list-aliases.";

		public ListAliasesCommand(Dictionary<string, string> aliases)
		{
			this.aliases = aliases;
		}
		public void Execute(SodtClient client, params string[] args)
		{
			foreach (var alias in aliases)
			{
				SmartConsole.WriteInfo($"{alias.Key} -> {alias.Value}");
			}
		}
	}
	/// <summary>
	/// Command to display the help message.
	/// </summary>
	internal class HelpCommand : ICommand
	{
		private readonly Dictionary<string, ICommand> commands;
		public HelpCommand(Dictionary<string, ICommand> commands)
		{
			this.commands = commands;
		}
		public string Description => "Displays this help message.";
		
		/// <summary>
		/// Executes the help command.
		/// </summary>
		/// <param name="client">Not used.</param>
		/// <param name="args">No arguments needed.</param>
		public void Execute(SodtClient client, params string[] args)
		{
			foreach((string command, ICommand value) in commands)
			{
				SmartConsole.WriteInfo($"{command}: \t{value.Description}");
			}
			SmartConsole.WriteInfo($"help: \t{Description}");
		}
	}
}