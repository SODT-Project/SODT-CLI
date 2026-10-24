using System.Reflection;
using SODT_CLI;

namespace SODT_CLI.Tests
{
	[CollectionDefinition("SodtClient integration", DisableParallelization = true)]
	public sealed class SodtClientCollection
	{
	}

	[Collection("SodtClient integration")]
	public sealed class SodtClientTests
	{
		private const string ServerIp = "127.0.0.1";
		private const int ServerPort = 45645;
		private const string ServerCertificatePath = "/home/ehrke/source/sodt-project/SODT-Server/SODT-Server/bin/Debug/net10.0/certs/public/ecdsa_cert.pem";
		private const int CommunicationTimeoutMilliseconds = 10000;

		[Fact]
        public async Task Connect_EstablishesServerSession()
		{
			SodtClient client = CreateClient();

			await client.Connect(ServerIp, ServerPort,await File.ReadAllTextAsync(ServerCertificatePath));
			await Task.Delay(1000); // wait for 1 second to let the server respond
			Assert.NotEqual((byte)0, client.OwnId);
			Assert.True(client.IsKeyExchanged(1));

			await client.DisconnectFromServer();
		}

		[Fact]
		public async Task RequestClientList_UpdatesConnectedClients()
		{
			SodtClient client = CreateClient();
			await client.Connect(ServerIp, ServerPort,await File.ReadAllTextAsync(ServerCertificatePath));
			await Task.Delay(1000); // wait for 1 second to let the server respond
			await client.RequestClientList();

			Assert.NotNull(client.ConnectedClients);
			await client.DisconnectFromServer();
		}

		[Fact]
        public async Task RequestKeyExchange_SendsRequestToServer()
		{
			SodtClient client = CreateClient();
			await client.Connect(ServerIp, ServerPort,await File.ReadAllTextAsync(ServerCertificatePath));

			await client.RequestKeyExchange(2);

			Assert.False(client.IsKeyExchanged(2));
			await client.DisconnectFromServer();
		}

		[Fact]
		public async Task RequestFileTransfer_WithMissingFile_ReturnsFalse()
		{
			SodtClient client = CreateClient();
			bool result = await client.RequestFileTransfer(2, Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".bin"));

			Assert.False(result);
		}

		[Fact]
        public async Task DisconnectFromServer_ClearsClientState()
		{
			SodtClient client = CreateClient();
			await client.Connect(ServerIp, ServerPort,await File.ReadAllTextAsync(ServerCertificatePath));

			await client.DisconnectFromServer();

			Assert.Equal((byte)0, client.OwnId);
			Assert.False(client.IsKeyExchanged(1));
			Assert.Empty(client.ConnectedClients);
		}

		[Fact]
		public async Task TwoClients_CanCompleteKeyExchange()
		{
			(SodtClient firstClient, SodtClient secondClient) = await ConnectTwoClients();
			try
			{
				await firstClient.RequestKeyExchange(secondClient.OwnId);
				await AnswerNextApprovalPrompt(true);

				await WaitUntilAsync(
					() => firstClient.IsKeyExchanged(secondClient.OwnId)
						&& secondClient.IsKeyExchanged(firstClient.OwnId));

				Assert.True(firstClient.IsKeyExchanged(secondClient.OwnId));
				Assert.True(secondClient.IsKeyExchanged(firstClient.OwnId));
			}
			finally
			{
				await firstClient.DisconnectFromServer();
				await secondClient.DisconnectFromServer();
			}
		}

		[Fact]
		public async Task TwoClients_CanTransferFileAfterKeyExchange()
		{
			(SodtClient sender, SodtClient receiver) = await ConnectTwoClients();
			string sourcePath = Path.Combine(Path.GetTempPath(), $"sodt-test-{Guid.NewGuid():N}.txt");
			string destinationPath = Path.Combine(
				Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
				"Downloads",
				Path.GetFileName(sourcePath));
			byte[] content = [1, 2, 3, 4, 5, 6, 7, 8];
			Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
			File.Delete(destinationPath);
			await File.WriteAllBytesAsync(sourcePath, content);

			try
			{
				await sender.RequestKeyExchange(receiver.OwnId);
				await AnswerNextApprovalPrompt(true);
				await WaitUntilAsync(() => sender.IsKeyExchanged(receiver.OwnId)
					&& receiver.IsKeyExchanged(sender.OwnId));
				Assert.True(await sender.RequestFileTransfer(receiver.OwnId, sourcePath));
				await AnswerNextApprovalPrompt(true);
				await WaitUntilAsync(() => File.Exists(destinationPath)
					&& !sender.SendFileStreamProgress.Any()
					&& !receiver.ReceivedFileStreamProgress.Any());

				Assert.Equal(content, await File.ReadAllBytesAsync(destinationPath));
			}
			finally
			{
				await sender.DisconnectFromServer();
				await receiver.DisconnectFromServer();
				File.Delete(sourcePath);
				File.Delete(destinationPath);
			}
		}

		private static async Task<(SodtClient First, SodtClient Second)> ConnectTwoClients()
		{
			SodtClient firstClient = CreateClient();
			await Task.Delay(10);
			SodtClient secondClient = CreateClient();
			await Task.WhenAll(
				firstClient.Connect(ServerIp, ServerPort, await File.ReadAllTextAsync(ServerCertificatePath)),
				secondClient.Connect(ServerIp, ServerPort, await File.ReadAllTextAsync(ServerCertificatePath)));
			await WaitUntilAsync(() => firstClient.OwnId != 0 && secondClient.OwnId != 0);
			await Task.Delay(1000);
			return (firstClient, secondClient);
		}

		private static async Task AnswerNextApprovalPrompt(bool answer)
		{
			Type consoleType = typeof(SodtClient).Assembly.GetType("SODT_CLI.SmartConsole")!;
			FieldInfo promptField = consoleType.GetField("yesNoTask", BindingFlags.Static | BindingFlags.NonPublic)!;
			FieldInfo activeField = consoleType.GetField("yesNoQuestionActive", BindingFlags.Static | BindingFlags.NonPublic)!;

			TaskCompletionSource<bool> currentPrompt = (TaskCompletionSource<bool>)promptField.GetValue(null)!;
			if (!(bool)activeField.GetValue(null)! && currentPrompt.Task.IsCompleted)
				promptField.SetValue(null, new TaskCompletionSource<bool>());

			for (int attempt = 0; attempt < CommunicationTimeoutMilliseconds / 10; attempt++)
			{
				TaskCompletionSource<bool> prompt = (TaskCompletionSource<bool>)promptField.GetValue(null)!;
				if ((bool)activeField.GetValue(null)! && !prompt.Task.IsCompleted)
				{
					prompt.SetResult(answer);
					activeField.SetValue(null, false);
					return;
				}
				await Task.Delay(10);
			}
			Assert.Fail("No approval prompt was raised before the timeout.");
		}

		private static async Task WaitUntilAsync(Func<bool> condition)
		{
			for (int attempt = 0; attempt < CommunicationTimeoutMilliseconds / 10; attempt++)
			{
				if (condition())
					return;
				await Task.Delay(10);
			}
			Assert.Fail("Condition was not met before the timeout.");
		}
		
		
		[Fact]
		public async Task FloodServerWithTooMuchClients()
		{
			// test if server can handle >max number of clients (253) without crashing or throwing exceptions
			var clientList = new List<SodtClient>();
			var connectTasks = new List<Task>();
			for (byte i = 2; i <= 254; i++)
			{
				clientList.Add(CreateClient());
				connectTasks.Add(clientList.Last().Connect(ServerIp, ServerPort, await File.ReadAllTextAsync(ServerCertificatePath)));
				await Task.Delay(75); // small delay to avoid overwhelming the server
			}
			await Task.WhenAll(connectTasks);
			await Task.Delay(1000); // wait for 1 second to let the server respond
			// all clients that could connect should have a non-zero OwnId, all other clients should have OwnId == 0 and Disconnected == true, at least 250 clients should have connected successfully
			foreach (var client in clientList)
			{
				if (client.OwnId == 0)
				{
					Assert.True(client.Disconnected);
				}
			}
			int successfulConnections = clientList.Count(client => client.OwnId != 0);
			Assert.True(successfulConnections >= 250, $"Expected at least 250 successful connections, but got {successfulConnections}.");

			// disconnect all clients
			var disconnectTasks = clientList.Select(client => client.DisconnectFromServer()).ToList();
			await Task.WhenAll(disconnectTasks);
		}

		private static SodtClient CreateClient()
		{
			return new SodtClient();
		}
	}
}
