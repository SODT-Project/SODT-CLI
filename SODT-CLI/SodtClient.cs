using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Net.Security;
using System.IO.Pipes;

namespace SODT_CLI
{
	internal class SodtClient
	{
		/// <summary>
		/// Size of the receive buffer. This is the default size of the buffer that is used to receive messages.
		/// </summary>
		private const int recieveBufferSize = 4096;
		/// <summary>
		/// Maximum size of the file buffer. This is the maximum size of file data that can be sent at once.
		/// </summary>
		//DO NOT TOUCH THIS VALUE UNLESS YOU KNOW WHAT YOU ARE DOING
		//the buffer size is 3003 because the json conversion messes with the encoded buffer size. It could be optimized by some bytes.
		//the current value was calculated by trial and error.
		private const int fileBufferSize = 3003;
		private const byte serverId = 1;
		private const string saveFilePath = "downloads/";
		public byte OwnId { get; private set; }
		private readonly TcpClient client = new();
		private readonly RSA serverPublicKey;
		private readonly ECDiffieHellman ecdhSessionKeyGenerator;
		/// <summary>
		/// Contains the session password hash for optional client to client authentication.
		/// </summary>
		private byte[]? privateSessionPasswordHash = null;
		/// <summary>
		/// Contains a double hashed version of the session password used to verify that all clients have the same password during the key exchange.
		/// </summary>
		private byte[]? publicSessionPasswordHash = null;
		/// <summary>
		/// Sets the session password for the client. This is used for optional client to client authentication.
		/// Set to <see langword="null"/> to disable the SessionPassword.
		/// </summary>
		public string? SessionPassword
		{
			set
			{
				if (value == null)
				{
					privateSessionPasswordHash = null;
					publicSessionPasswordHash = null;
				}
				else
				{
					privateSessionPasswordHash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
					publicSessionPasswordHash = SHA256.HashData(privateSessionPasswordHash);
				}
			}
		}
		/// <summary>
		/// Contains the connected clients. If a keyexchange has been done, the value is the aes key for the client othterwise null.
		/// </summary>
		private readonly Dictionary<byte, Aes?> sessionKeys = new();
		/// <summary>
		/// Contains all clients that are connected to the server.
		/// </summary>
		public byte[] ConnectedClients { get => sessionKeys.Keys.ToArray(); }
		/// <summary>
		/// Contains the file streams for the incoming file transfers.
		/// </summary>
		private readonly Dictionary<int, FileStream> incomingFileStreams = new();

		/// <summary>
		/// Contains the pending files that will be sent after the client has accepted the transfer.
		/// </summary>
		private readonly Dictionary<int, string> pendingFiles = new();

		/// <summary>
		/// Contains the bytes that have been received for each file transfer.
		/// The initial long value is the total file size. If it reaches 0 the file is complete 
		/// </summary>
		private readonly Dictionary<int, long> receivedFileProgress = new();

		/// <summary>
		/// Contains the remaining bytes that have to be sent for each file transfer.
		/// </summary>
		private readonly Dictionary<int, long> sendFileProgress = new();

		/// <summary>
		/// Contains the progress in percent of the file transfers that are being received.
		/// Key is the uuid of the transfer, value is the progress in percent.
		/// This is used externally to check if a file transfer is still in progress.
		/// This is a copy that is created on access to prevent external modification.
		/// </summary>
		public Dictionary<int, int> ReceivedFileStreamProgress
		{
			get
			{
				Dictionary<int, int> copy = new();
				foreach (var item in receivedFileProgress)
				{
					long toBeReceived = item.Value;
					long alreadyReceived = incomingFileStreams[item.Key].Length;
					long total = toBeReceived + alreadyReceived;
					int progress = (int)(100 - (toBeReceived * 100 / total));
					copy.Add(item.Key, progress);
				}
				return copy;
			}
		}
		/// <summary>
		/// Contains the progress in percent of the file transfers that are being sent.
		/// Key is the uuid of the transfer, value is the progress in percent.
		/// This is used externally to check if a file transfer is still in progress.
		/// This is a copy that is created on access to prevent external modification.
		/// </summary>
		public Dictionary<int, int> SendFileStreamProgess
		{
			get
			{
				Dictionary<int, int> copy = new();
				foreach (var item in sendFileProgress)
				{
					long toBeSent = item.Value;
					long total = new FileInfo(pendingFiles[item.Key]).Length;
					int progress = (int)(100 - (toBeSent * 100 / total));
					copy.Add(item.Key, progress);
				}
				return copy;
			}
		}
		/// <summary>
		/// Credeates a new SodtfClient instance with the public server key.
		/// </summary>
		/// <param name="publicServerKeyPath"> Path to the public server key file. The key must be in base64 format.</param>
		public SodtClient(string publicServerKeyPath)
		{
			//create client to client session key generator
			ecdhSessionKeyGenerator = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			//create server session key
			Aes serverSessionAes = Aes.Create();
			serverSessionAes.GenerateKey();
			serverSessionAes.GenerateIV();
			sessionKeys.Add(serverId, serverSessionAes);
			//load server public key
			serverPublicKey = RSA.Create();
			serverPublicKey.ImportFromPem(File.ReadAllText(publicServerKeyPath));
			//create save path dir
			Directory.CreateDirectory(saveFilePath);
		}

		/// <summary>
		/// Sends a message to the server or a client and encrypts it with the server public key or the client aes key.
		/// </summary>
		/// <param name="targetId">Destination id for this package. Set to 0 to adress the message to the server.</param>
		/// <param name="baseMessage">Message to be sent.</param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException"></exception>
		private async Task SendEncrypted(byte targetId, IBaseMessage baseMessage)
		{
			ReadOnlyMemory<byte> toSend;
			//if the message is a discovery request to the server encrypt with server public key
			if (targetId == serverId && baseMessage is Discovery discovery && discovery.Code == (int)PacketCode.Request)
				toSend = new([targetId, OwnId, .. discovery.ToEncryptedBytes(serverPublicKey)]);

			//else encrypt with client aes key
			else if (sessionKeys.TryGetValue(targetId, out Aes? aes) && aes != null)
				toSend = new([targetId, OwnId, .. aes.EncryptCfb(baseMessage.ToBytes(), aes.IV)]);
			else
			{
				//This case should never happen because the CLI always checks and requests, if neccessary, a key exchange before sending a message.
				SmartConsole.WriteError($"No key for target client {targetId} to encrypt with. How do you even get here?");
				throw new InvalidOperationException("No key for target client to encrypt with.");
			}


			await client.GetStream().WriteAsync(toSend);
		}

		/// <summary>
		/// Connect to the server and send a discovery message.
		/// Furthermore, start the receive loop.
		/// </summary>
		/// <param name="host"></param>
		/// <param name="port"></param>
		/// <returns></returns>
		public async Task Connect(string host, int port)
		{
			//connect to server
			await client.ConnectAsync(host, port);
			//start receive
			_ = Receive();
			//send discovery message
			//not null assertion is safe because the serverSessionAes is created in the constructor
			Discovery discovery = Discovery.CreateRequest(sessionKeys[serverId]!.Key, sessionKeys[serverId]!.IV, serverPublicKey);
			await SendEncrypted(serverId, discovery);

		}

		/// <summary>
		/// DisconnectFromServer from the server and send a disconnect message.
		/// This will also clear the own id, the connected clients, and dispose the server session aes as well as the client.
		/// </summary>
		/// <returns></returns>
		public async Task DisconnectFromServer()
		{
			try
			{
				await SendEncrypted(serverId, Disconnect.CreateRequest());
			}
			catch { }
			OwnId = 0;
			sessionKeys.Clear();
			client.Dispose();
			ecdhSessionKeyGenerator.Dispose();
		}

		/// <summary>
		/// Creates a new receive loop that listens for incoming messages asynchroniously.
		/// </summary>
		/// <returns></returns>
		/// <exception cref="NotImplementedException"></exception>
		private async Task Receive()
		{
			//init buffer and get stream
			byte[] buffer = new byte[recieveBufferSize];
			NetworkStream stream = client.GetStream();
			//receive loop
			while (client.Connected)
			{
				//wait for message
				while (client.Client.Available < recieveBufferSize)
				{
					await Task.Delay(10);
				}
				int bytesRead = await stream.ReadAsync(buffer);
				if (bytesRead == 0) break; // on disconnect

				//handle message
				switch (Decrypt(buffer))
				{
					case Discovery discovery:
						OwnId = discovery.Id == 0 ? throw new Exception() : discovery.Id;
						break;
					case ClientList clients:
						UpdateClientList(clients);
						break;
					case KeyExchange exchange:
						await HandleExchangeKey(exchange);
						break;
					case Transfer transfer:
						await HandleTransfer(transfer);
						break;
					case TransferData data:
						await ReceiveFile(data);
						break;
					default:
						SmartConsole.WriteError("Received Message contains one or more errors. Ignoring message.");
						break;
				}
			}
			SmartConsole.WriteError("Connection lost. The server could have been shut down.");
			throw new Exception("Connection lost.");
		}

		/// <summary>
		/// Decrypts a message with the aes key of the source client.
		/// </summary>
		/// <param name="buffer"> The buffer that contains the encrypted message.</param>
		/// <returns> The decrypted <see cref="IBaseMessage"/> message or <see langword="null"/> if the message type is unknown.</returns>
		/// <exception cref="InvalidOperationException"></exception>
		private IBaseMessage? Decrypt(byte[] buffer)
		{
			byte sourceId = buffer[1];
			Span<byte> decrypted;
			if (!sessionKeys.TryGetValue(sourceId, out Aes? aes) || aes == null)
			{
				SmartConsole.WriteWarning("An encrypted message was received from a client without a key. Ignoring message.");
				return null;
			}

			decrypted = aes.DecryptCfb(buffer[2..], aes.IV); //skip first two bytes because they contain target and source id

			//handle message
			ushort length = BitConverter.ToUInt16(decrypted[..2]); //first two bytes contain the length of the message
			Span<byte> content = decrypted[2..(length + 2)]; //get the content of the message
			return JsonSerializer.Deserialize<BaseMessage>(content).Type switch
			{
				"discovery" => JsonSerializer.Deserialize<Discovery>(content),
				"clients" => JsonSerializer.Deserialize<ClientList>(content),
				"exchange" => JsonSerializer.Deserialize<KeyExchange>(content),
				"transfer" => JsonSerializer.Deserialize<Transfer>(content),
				"file" => JsonSerializer.Deserialize<TransferData>(content),
				_ => null,
			};
		}

		/// <summary>
		/// Sends a request to exchange a key with the target client.
		/// </summary>
		/// <param name="targetId"></param>
		public async Task RequestExchangeKey(byte targetId)
		{
			SmartConsole.WriteInfo($"Requesting key exchange with {targetId}.");
			//send key exchange request
			KeyExchange exchange = KeyExchange.Create(PacketCode.Request, ecdhSessionKeyGenerator.ExportSubjectPublicKeyInfo(), publicSessionPasswordHash, OwnId, targetId);
			await SendEncrypted(serverId, exchange);
		}
		private async Task HandleExchangeKey(KeyExchange exchange)
		{
			//handle possible errors
			if (exchange.Key == null)
			{
				SmartConsole.WriteError($"Key exchange between {exchange.SourceId} and {exchange.TargetId} failed because the key is null.");
				await SendEncrypted(serverId, KeyExchange.Create(PacketCode.Denied, Array.Empty<byte>(), Array.Empty<byte>(), OwnId, exchange.SourceId));
				return;
			}
			// additionally check of same session password hashes
			if ((PacketCode)exchange.Code == PacketCode.Request || (PacketCode)exchange.Code == PacketCode.Ok)
			{
				if (!DoesSessionHashMatch(exchange))
				{
					await SendEncrypted(serverId, KeyExchange.Create(PacketCode.Denied, Array.Empty<byte>(), null, OwnId, exchange.SourceId));
					return;
				}
			}


			switch ((PacketCode)exchange.Code)
			{
				case PacketCode.Request: // PaketCode.Request is received when the target client requests a key exchange
					sessionKeys[exchange.SourceId] = GenerateSessionKey(exchange);
					SmartConsole.WriteInfo($"Client {exchange.SourceId} requested key exchange."); //TODO: Ask user for permission

					//send ok
					SmartConsole.WriteInfo($"Key exchange with {exchange.SourceId} accepted.");
					KeyExchange exchangeAccepted = KeyExchange.Create(PacketCode.Ok, ecdhSessionKeyGenerator.ExportSubjectPublicKeyInfo(), publicSessionPasswordHash, OwnId, exchange.SourceId);
					await SendEncrypted(serverId, exchangeAccepted);
					break;
				case PacketCode.Ok: // PaketCode.Ok is received when the target client accepts the key exchange
					sessionKeys[exchange.SourceId] = GenerateSessionKey(exchange);
					SmartConsole.WriteInfo($"Client {exchange.SourceId} accepted key exchange.");
					break;
				case PacketCode.Error:
				case PacketCode.Denied:
					if (sessionKeys.TryGetValue(exchange.SourceId, out Aes? value))
					{
						value?.Dispose();
						sessionKeys[exchange.SourceId] = null;
					}
					SmartConsole.WriteError($"Key exchange with client {exchange.SourceId} failed. ErrorCode: {exchange.Code}");
					break;
				default:
					SmartConsole.WriteError($"Key exchange code {exchange.Code} not implemented yet.");
					throw new NotImplementedException($"Key exchange code {exchange.Code} not implemented yet.");
			}
		}
		/// <summary>
		/// Generates an aes session key from the key exchange message with the other client. <br></br>
		/// Key generation uses ecdh and the session password hash if set.
		/// </summary>
		/// <param name="exchange"></param>
		/// <returns></returns>
		private Aes GenerateSessionKey(KeyExchange exchange)
		{
			//create shared secret
			var otherPublicKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			otherPublicKey.ImportSubjectPublicKeyInfo(exchange.Key, out _);
			//do not use sharedSecret directly as key. Use a key derivation function to derive a key from the shared secret.
			byte[] derivedKey = ecdhSessionKeyGenerator.DeriveKeyFromHash(otherPublicKey.PublicKey, HashAlgorithmName.SHA256);
			//create aes
			Aes aes = Aes.Create();
			if (privateSessionPasswordHash == null)
				aes.Key = derivedKey;
			else //if a session passwort is set for client authentication, use it as key
				using (HMACSHA256 hmac = new(privateSessionPasswordHash))
					aes.Key = hmac.ComputeHash(derivedKey);
			//generate IV by hashing the derived key again and using the first 16 bytes as IV
			aes.IV = SHA256.HashData(aes.Key)[..16];
			return aes;
		}
		/// <summary>
		/// Compares the session password hash of the client with own public session password hash.
		/// </summary>
		/// <param name="exchange"> The key exchange message that contains the session password hash of the other client.</param>
		/// <returns> <see langword="true"/> if the session password hash matches, otherwise <see langword="false"/>.</returns>
		private bool DoesSessionHashMatch(KeyExchange exchange)
		{
			//exaclty one of the session password hashs is null
			if ((exchange.SessionHash == null) ^ (publicSessionPasswordHash == null))
			{
				SmartConsole.WriteError("One client tries to authenticate with a session password, the other does not. Key exchange failed.");
				return false;
			}
			if (exchange.SessionHash != null && publicSessionPasswordHash != null && !exchange.SessionHash.SequenceEqual(publicSessionPasswordHash))
			{
				SmartConsole.WriteError($"Key exchange between {exchange.SourceId} and {exchange.TargetId} failed because the session password does not match.");
				return false;
			}
			return true;
		}
		public async Task<bool> RequestFileTransfer(byte targetId, string filePath, bool compress)
		{
			//check if filePath is valid
			if (!File.Exists(filePath))
				return false;
			if (Directory.Exists(filePath))
				return false;

			try
			{
				if (compress)
				{
					SmartConsole.WriteInfo($"Compressing file {Path.GetFileName(filePath)}.");
					await Compression.StartCompression(filePath);
					filePath += ".sodtfzip";
				}
				Transfer transfer = Transfer.CreateRequest(Path.GetFileName(filePath), new FileInfo(filePath).Length, OwnId, compress);
				pendingFiles.Add(transfer.Uuid, filePath);
				await SendEncrypted(targetId, transfer);
				return true;
			}
			catch
			{
				return false;
			}
		}
		private async Task HandleTransfer(Transfer transfer)
		{
			switch ((PacketCode)transfer.Code)
			{
				case PacketCode.Request:
					//prepare receiving file
					SmartConsole.WriteInfo($"Client {transfer.SourceId} requests to send file {transfer.FileName}.");
					incomingFileStreams.Add(transfer.Uuid, new FileStream(Path.Combine(saveFilePath,transfer.FileName), FileMode.Create, FileAccess.Write, FileShare.None));
					receivedFileProgress.Add(transfer.Uuid, transfer.FileSize); //TODO: implement permission check

					//send ok
					SmartConsole.WriteInfo($"File transfer with {transfer.SourceId} accepted.");
					Transfer transferAccepted = Transfer.CreateRespone(transfer, OwnId);
					await SendEncrypted(transfer.SourceId, transferAccepted);
					//special case: if the file is empty, no actual transferdata is send, therefore simulate receive manually:
					if (transfer.FileSize == 0)
					{
						await ReceiveFile(TransferData.CreateRequest(transfer.Uuid, Array.Empty<byte>(), 0));
					}

					break;
				case PacketCode.Ok:
					SmartConsole.WriteInfo($"Client {transfer.SourceId} accepted file transfer. Start sending file.");
					_ = SendFile(transfer.SourceId, transfer.Uuid); //fire and forget. SendFile will handle itself
					break;
				default:
					throw new NotImplementedException($"Transfer code {transfer.Code} not implemented yet.");
			}
		}

		private async Task SendFile(byte targetId, int tranferUuid)
		{
			string filePath = pendingFiles[tranferUuid];
			var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None);
			sendFileProgress.Add(tranferUuid, stream.Length);
			Memory<byte> buffer = new Memory<byte>(new byte[fileBufferSize]); //wrapping the buffer in a memory object for better performance
			int bytesRead;
			while (true)
			{
				long startPositionInFile = stream.Position;
				bytesRead = await stream.ReadAsync(buffer);
				if (bytesRead == 0) break;
				//buffer[..bytesRead] reduces the buffer to the actual data if the buffer is not full
				var req = TransferData.CreateRequest(tranferUuid, buffer[..bytesRead], startPositionInFile);
				await SendEncrypted(targetId, req);
				//update progress
				lock (sendFileProgress)
					sendFileProgress[tranferUuid] -= bytesRead;
			}
			SmartConsole.WriteSuccess($"File {Path.GetFileName(filePath)} sent to client {targetId}.");
			pendingFiles.Remove(tranferUuid);
			sendFileProgress.Remove(tranferUuid);
			stream.Close();
			if (Path.GetExtension(filePath) == ".sodtfzip")
			{
				File.Delete(filePath);
			}
		}

		/// <summary>
		/// Writes the received transfer data to the file. If the transfer is complete, the file stream is closed.
		/// </summary>
		/// <param name="transferData">The received transfer data to be written to the file.</param>
		/// <returns></returns>
		private async Task ReceiveFile(TransferData transferData)
		{
			//get file stream
			int uuid = transferData.Uuid;
			if (incomingFileStreams.TryGetValue(uuid, out FileStream? stream))
			{
				//write data to file
				stream.Position = transferData.Position;
				await stream.WriteAsync(transferData.Data);

				//update progress
				lock (receivedFileProgress)
					receivedFileProgress[uuid] -= transferData.Data.Length;

				//close file stream if transfer is complete
				if (receivedFileProgress[uuid] <= 0)
				{
					SmartConsole.WriteSuccess($"File {Path.GetFileName(stream.Name.Replace(".sodtfzip", ""))} received.");
					string filePath = stream.Name;
					Thread.Sleep(10);
					stream.Flush();
					stream.Close();
					incomingFileStreams.Remove(uuid);
					receivedFileProgress.Remove(uuid);
					if (Path.GetExtension(filePath) == ".sodtfzip")
					{
						await Compression.DecompressFile(filePath, filePath.Replace(".sodtfzip", ""));
						File.Delete(filePath);
					}
				}
			}
			else
			{
				SmartConsole.WriteWarning($"Received file data that was not requested. Ignoring Data. (Uuid: {transferData.Uuid}");
			}
		}
		/// <summary>
		/// Sends a request to the server to get a list of all connected clients.
		/// </summary>
		/// <returns></returns>
		public async Task RequestClientList()
		{
			await SendEncrypted(serverId, ClientList.CreateRequest());
		}

		/// <summary>
		/// Returns if a key exchange has been done with the client with the given id.
		/// </summary>
		/// <param name="id">The id of the client to check.</param>
		/// <returns>Returns <see langword="true"/> if a key exchange has been done with the client, otherwise <see langword="false"/>.</returns>
		public bool IsKeyExchanged(byte id)
		{
			return sessionKeys.TryGetValue(id, out Aes? aes) && aes != null;
		}

		/// <summary>
		/// Synchronizes the session keys with the provided list of active clients. 
		/// <br>- Removes clients not in the new list (except the server ID).</br>
		/// <br>- Adds new clients and updates existing ones.</br>
		/// </summary>
		/// <param name="clients">The updated list of active clients and a status code.</param>
		private void UpdateClientList(ClientList clients)
		{
			//if the client list is null or a check isalive request, ignore
			if (clients.Code != (int)PacketCode.Ok || clients.Clients == null)
				return;

			//for each oldClient client that is not in the new list, remove
			foreach (var oldClient in sessionKeys.Keys)
			{
				if (!clients.Clients.Contains(oldClient) && oldClient != serverId) //serverId is always connected
				{
					sessionKeys[oldClient]?.Dispose();
					_ = sessionKeys.Remove(oldClient);
				}
			}
			//for each new client that is not in the oldClient list, add
			//also for each new client that is in the oldClient list do nothing
			foreach (var newClient in clients.Clients)
			{
				if (newClient == serverId)
					continue; //serverId is always connected
				if (!sessionKeys.ContainsKey(newClient))
					sessionKeys.Add(newClient, null);
			}
		}
	}
}


