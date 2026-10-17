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
	}
	/// <summary>
	/// Command to connect to a server.
	/// </summary>
	internal class ConnectCommand : ICommand
	{
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
			client.Connect(host, port).Wait(); //not async to block the console
			while (client.OwnId == 0) Thread.Sleep(20);  //wait for the client to connect
			SmartConsole.WriteSuccess($"Connected to server! Your Id: {client.OwnId}");
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
		/// <summary>
		/// Executes the send command.
		/// This command needs two arguments: <see cref="byte"/> targetId , <see cref="string"/> filePath
		/// </summary>
		/// <param name="client">Client on which the command is executed.</param>
		/// <param name="args"><see cref="byte"/> tagetId , <see cref="string"/> filePath</param>
		public void Execute(SodtClient client, params string[] args)
		{
			(byte targetId, string filePath) = ValidateArgs(args);
			//check if exchange key is needed
			if (!client.IsKeyExchanged(targetId))
			{
				SmartConsole.WriteInfo($"No session key found for {targetId}.");
				new ExchangeKeyCommand().Execute(client, args[0]);
				while (!client.IsKeyExchanged(targetId)) Thread.Sleep(20); //wait for the key exchange to be completed
			}
			//send the file
			if (client.RequestFileTransfer(targetId, filePath).Result)
				SmartConsole.WriteInfo($"Transfer request successful. Client {targetId} accepted {Path.GetFileName(filePath)}");
			else
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
	/// Command to do fast debugging.
	/// </summary>
	internal class DebugCommand : ICommand
	{
		public void Execute(SodtClient client, params string[] args)
		{
			new DefaultConnectCommand().Execute(client, Array.Empty<string>());
			new ListClientsCommand().Execute(client, Array.Empty<string>());
			new ExchangeKeyCommand().Execute(client, [Convert.ToString(client.OwnId)]);
		}
	}
	/// <summary>
	/// Base class for commands that list the progress of file transfer tasks.
	/// </summary>
	internal abstract class ListCommand : ICommand
	{
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
	class ListSendsCommand : ListCommand
	{
		protected override int ShowProgressContent(SodtClient client)
		{
			int linesWritten = 0;
			foreach (var progress in client.SendFileStreamProgess)
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
	/// This command needs one argument: <see cref="string"/> filePath.
	/// This command writes the public key to the defaultServerPublic.key file.
	/// </summary>
	internal class SetDefaultServerPublicKeyCommand : ICommand
	{
		/// <summary>
		/// Executes the set default server public key command.
		/// </summary>
		/// <param name="client">Not used.</param>
		/// <param name="args">File path to the public key.</param>
		public void Execute(SodtClient client, params string[] args)
		{
			string content = File.ReadAllText(ValidateArgs(args));
			File.WriteAllText("defaultServer.key", content);
		}
		private string ValidateArgs(params string[] args)
		{
			if (args.Length != 1) throw new ArgumentException("Invalid number of arguments!");
			if (!File.Exists(args[0])) throw new ArgumentException("File not found!");
			try
			{
				RSA.Create().ImportFromPem(File.ReadAllText(args[0]));
			}
			catch
			{
				throw new ArgumentException("Invalid public key!");
			}
			return args[0];
		}
	}
	/// <summary>
	/// Command to clear the console.
	/// This command has no arguments.
	/// </summary>
	internal class ClearCommand : ICommand
	{
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
		/// <summary>
		/// Executes the help command.
		/// </summary>
		/// <param name="client">Not used.</param>
		/// <param name="args">No arguments needed.</param>
		public void Execute(SodtClient client, params string[] args)
		{
			Console.WriteLine("Commands (Client-Server):");
			Console.WriteLine("connect <host> <port> - Connect to a server.");
			Console.WriteLine("connect-default - Connect to the default server.");
			Console.WriteLine("list-clients - List all connected clients.");
			Console.WriteLine("disconnect - Disconnect from the server.");
			Console.WriteLine();
			Console.WriteLine("Commands (Client-Client):");
			Console.WriteLine("set-session-password <password> - Set the session password, used for clients to authenticate themselves to other clients.");
			Console.WriteLine("reset-session-password - Reset the session password.");
			Console.WriteLine("exchange <targetId> - Exchange a session key with a client.");
			Console.WriteLine("send <targetId> <filePath> - Send a file to a client.");
			Console.WriteLine();
			Console.WriteLine("Commands (Other):");
			Console.WriteLine("set-default-server <host> <port> - Set the default server.");
			Console.WriteLine("set-default-key <sourceFilePath> - Set the default server public key. File must be in PEM format.");
			Console.WriteLine("clear - Clear the console.");
			Console.WriteLine("help - Display this message.");
			Console.WriteLine("list-sends - List the progress of send file tasks.");
			Console.WriteLine("list-receives - List the progress of receive file tasks.");
			Console.WriteLine("list-aliases - List all command aliases.");
		}
	}
}