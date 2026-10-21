using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using SODT_Common;

namespace SODT_CLI
{
	internal class SodtClient
	{
		
		/// <summary>
		/// Maximum size of the file buffer. This is the maximum size of file data that can be sent at once.
		/// </summary>
		//DO NOT TOUCH THIS VALUE UNLESS YOU KNOW WHAT YOU ARE DOING
		//the buffer size is 3003 because the json conversion messes with the encoded buffer size. It could be optimized by some bytes.
		//the current value was calculated by trial and error.
		private const int FileBufferSize = 3003 - MessageHelper.NonceSize - MessageHelper.TagSize; // TODO improve
		private const byte ServerId = 1;
		private static readonly string SaveFilePath = Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
			"Downloads"); // Downloads is mostly the correct name. going with it for now
		public byte OwnId { get; private set; }
		private readonly TcpClient client = new();
		
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
		/// Contains the ids of all clients that are connected to the server.
		/// </summary>
		private readonly HashSet<byte> connectedClients = new();
		
		/// <summary>
		/// Contains the aes session keys for each client or the server. This is used to encrypt and decrypt messages for each connection individually.
		/// </summary>
		private readonly Dictionary<byte, AesGcm> aesSessionKeys = new();
		
		/// <summary>
		/// Contains the ecdh session key generators for each client or the server.
		/// This is used to generate the aes key for each connection individually.
		/// </summary>
		private readonly Dictionary<byte, ECDiffieHellman> ecdhSessionKeyGenerators = new();
		
		/// <summary>
		/// The certificate for this client to validate its authenticity during the session
		/// </summary>
		private readonly ECDsa ecdsaSessionCertificate = ECDsa.Create(ECCurve.NamedCurves.nistP256);

		/// <summary>
		/// The certificate of the server to validate its authenticity during the session
		/// </summary>
		private readonly ECDsa ecdsaServerCertificate;
		
		/// <summary>
		/// Contains all clients that are connected to the server.
		/// </summary>
		public byte[] ConnectedClients => connectedClients.ToArray();

		/// <summary>
		/// Contains the file streams for the incoming file transfers.
		/// </summary>
		private readonly Dictionary<int, FileStream> incomingFileStreams = new();

		private readonly Dictionary<int, byte[]> incomingFileStreamHashes = new();

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
		public Dictionary<int, int> SendFileStreamProgress
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

		public SodtClient(string ecdsaServerCertificatePath)
		{
            ecdsaServerCertificate = ECDsa.Create(ECCurve.NamedCurves.nistP256);
			ecdsaServerCertificate.ImportFromPem(File.ReadAllText(ecdsaServerCertificatePath));
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
			
			if (aesSessionKeys.TryGetValue(targetId, out AesGcm? aes))
			{
				byte[] finalMessage = new byte[MessageHelper.FullMessageSize];
				EncryptionHandler.EncryptAesGcm(aes, baseMessage, finalMessage);
				finalMessage[0] = targetId;
				finalMessage[1] = OwnId;
				toSend = finalMessage;
            }
            else
			{
				//This case should never happen because the CLI always checks and requests, if neccessary, a key exchange before sending a message.
				SmartConsole.WriteError($"No key for target client {targetId} to encrypt with. How do you even get here?");
				throw new InvalidOperationException("No key for target client to encrypt with.");
			}


			await client.GetStream().WriteAsync(toSend);
		}
		
		private async Task SendUnencrypted(byte targetId, IBaseMessage baseMessage)
		{
			// TODO make more elegant
			byte[] finalMessage = new byte[MessageHelper.FullMessageSize];
			finalMessage[0] = targetId;
			finalMessage[1] = OwnId;
			Array.Copy(baseMessage.ToBytes(), 0, finalMessage, MessageHelper.HeaderSizeWithoutContentLengthSize, MessageHelper.MessageWithContentSize);
			await client.GetStream().WriteAsync(finalMessage);
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
			_ = Receive(); // fire and forget. Receive will handle itself
			//send discovery key exchange
			ecdhSessionKeyGenerators.Add(ServerId, ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
			byte[] ecdhPublicKey = ecdhSessionKeyGenerators[ServerId].ExportSubjectPublicKeyInfo();
			Discovery discovery = Discovery.CreateRequest(ecdhPublicKey);
			await SendUnencrypted(ServerId, discovery);

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
				await SendEncrypted(ServerId, Disconnect.CreateRequest());
			}
			catch { }
			OwnId = 0;
			aesSessionKeys.Clear();
			ecdhSessionKeyGenerators.Clear();
			ecdsaSessionCertificate.Dispose();
			client.Dispose();
		}

		/// <summary>
		/// Creates a new receive loop that listens for incoming messages asynchroniously.
		/// </summary>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException"></exception>
		private async Task Receive()
		{
			//init buffer and get stream
			byte[] buffer = new byte[MessageHelper.FullMessageSize];
			NetworkStream stream = client.GetStream();
			
			// receive loop
			while (client.Connected)
			{
				//wait for message
				while (client.Client.Available < MessageHelper.FullMessageSize)
				{
					await Task.Delay(10);
				}
				int bytesRead = await stream.ReadAsync(buffer);
				if (bytesRead == 0) break; // on disconnect

				IBaseMessage? message = Decrypt(buffer);
				if (message is Discovery or PingPong or ClientList && buffer[1] != ServerId)
				{
					SmartConsole.WriteWarning($"Received message from client {buffer[1]} that should only be sent by the server. Ignoring message.");
					continue;
				}
				//handle message
				switch (Decrypt(buffer))
				{
					case Discovery discovery:
						await HandleDiscovery(discovery);
						break;
					case PingPong:
						await HandlePingPong();
						break;
					case ClientList clients:
						UpdateClientList(clients);
						break;
					case KeyExchange exchange:
						await HandleKeyExchange(exchange, buffer[1]);
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
			throw new InvalidOperationException("Connection lost.");
		}
		private async Task HandlePingPong()
		{
			SmartConsole.WriteDebug("Received ping from server. Sending pong.");
			await SendEncrypted(ServerId, PingPong.CreateResponse());
		}

		/// <summary>
		/// Decrypts a message with the aes key of the source client.
		/// </summary>
		/// <param name="buffer"> The buffer that contains the encrypted message.</param>
		/// <returns> The decrypted <see cref="IBaseMessage"/> message or <see langword="null"/> if the message type is unknown.</returns>
		/// <exception cref="InvalidOperationException"></exception>
		private IBaseMessage? Decrypt(Span<byte> buffer)
		{
			byte sourceId = buffer[1];
			
			// decrypt message
			Span<byte> decryptedMessage = new byte[MessageHelper.MessageWithContentSize];
            if (!aesSessionKeys.TryGetValue(sourceId, out AesGcm? aes))
			{
				SmartConsole.WriteWarning("An unencrypted message was received. Is this a key exchange?");
				decryptedMessage = buffer[MessageHelper.HeaderSizeWithoutContentLengthSize..];
			}
            else
            {
	            EncryptionHandler.DecryptAesGcm(aes, buffer, decryptedMessage);
            }
            // parse message
            return MessageHandler.ParseDecryptedMessage(decryptedMessage);
		}

		private async Task HandleDiscovery(Discovery discovery)
		{
			// basic checks if the discovery message is valid
			if (discovery.PublicKey == null || discovery.Signature == null || discovery.Id == 0)
			{
				SmartConsole.WriteError("Discovery message from server is invalid. Disconnecting.");
				await DisconnectFromServer();
				return;
			}
			
			// verify discovery message
			byte[] clientEcdhPublicKey = ecdhSessionKeyGenerators[ServerId].ExportSubjectPublicKeyInfo();
			byte[] serverEcdhPublicKey = discovery.PublicKey;
			byte[] toVerify = [..clientEcdhPublicKey, ..serverEcdhPublicKey, discovery.Id];
			if (!ecdsaServerCertificate.VerifyData(toVerify, discovery.Signature, HashAlgorithmName.SHA256))
			{
				SmartConsole.WriteError("Discovery message from server is signed with an invalid signature. Possible man-in-the-middle attack. Disconnecting.");
				await DisconnectFromServer();
				return;
			}
			// generate aes session key for server
			aesSessionKeys[ServerId] = EncryptionHandler.GenerateSessionKey(ecdhSessionKeyGenerators[ServerId], discovery.PublicKey);
			
			// Set own id.
			OwnId = discovery.Id;
			SmartConsole.WriteDebug($"Connected to server with id {OwnId}.");
		}
		
		/// <summary>
		/// Sends a request to exchange a key with the target client.
		/// </summary>
		/// <param name="targetId"></param>
		public async Task RequestKeyExchange(byte targetId)
		{
			SmartConsole.WriteInfo($"Requesting key exchange with {targetId}.");
			//send key exchange request
			ecdhSessionKeyGenerators[targetId] = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			KeyExchange exchange = KeyExchange.Create(PacketCode.Request, ecdhSessionKeyGenerators[targetId].ExportSubjectPublicKeyInfo(), ecdsaSessionCertificate.ExportSubjectPublicKeyInfo(), null);
			await SendUnencrypted(targetId, exchange);
		}
		private async Task HandleKeyExchange(KeyExchange exchange, byte remoteId)
		{
			//handle possible errors
			if (exchange.Key == null)
			{
				SmartConsole.WriteError($"Key exchange between {OwnId} and {remoteId} failed because the key is null.");
				return;
				// TODO write a response message to the other client?
			}
			// additionally check of same session password hashes
			if ((PacketCode)exchange.Code == PacketCode.Request || (PacketCode)exchange.Code == PacketCode.Ok)
			{
				if (!EncryptionHandler.DoesSessionHashMatch(publicSessionPasswordHash, exchange.SessionHash))
				{
					SmartConsole.WriteError("Key exchange failed because the session password hashes do not match.");
					return;
					// TODO send a response message to the other client?
				}
			}
			
			switch ((PacketCode)exchange.Code)
			{
				case PacketCode.Request: // PaketCode.Request is received when the target client requests a key exchange
					SmartConsole.WriteInfo($"Client {remoteId} requested key exchange."); //TODO: Ask user for permission
					ecdhSessionKeyGenerators.TryAdd(remoteId, ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)); // TryAdd is needed for special case where other client is yourself. In this case the key generator is already created and .TryAdd() prevents an overwrite.
					aesSessionKeys[remoteId] = EncryptionHandler.GenerateSessionKey(ecdhSessionKeyGenerators[remoteId], exchange.Key);
					//send ok
					SmartConsole.WriteInfo($"Key exchange with {remoteId} accepted.");
					KeyExchange exchangeAccepted = KeyExchange.Create(PacketCode.Ok, ecdhSessionKeyGenerators[remoteId].ExportSubjectPublicKeyInfo(), ecdsaSessionCertificate.ExportSubjectPublicKeyInfo(), publicSessionPasswordHash);
					await SendUnencrypted(remoteId, exchangeAccepted);
					break;
				case PacketCode.Ok: // PaketCode.Ok is received when the target client accepts the key exchange
					if (!ecdhSessionKeyGenerators.TryGetValue(remoteId, out ECDiffieHellman? ecdhGenerator))
					{
						SmartConsole.WriteError($"Key exchange with client {remoteId} failed the key exchange was never requested.");
						return;
					}
					aesSessionKeys[remoteId] = EncryptionHandler.GenerateSessionKey(ecdhGenerator, exchange.Key);
					SmartConsole.WriteInfo($"Client {remoteId} accepted key exchange.");
					break;
				case PacketCode.Error:
				case PacketCode.Denied:
					aesSessionKeys.Remove(remoteId);
					ecdhSessionKeyGenerators.Remove(remoteId);
					SmartConsole.WriteError($"Key exchange with client {remoteId} failed. ErrorCode: {exchange.Code}");
					break;
				default:
					SmartConsole.WriteError($"Key exchange code {exchange.Code} not implemented yet.");
					throw new NotImplementedException($"Key exchange code {exchange.Code} not implemented yet.");
			}
		}
		
		public async Task<bool> RequestFileTransfer(byte targetId, string filePath)
		{
			//check if filePath is valid
			if (!File.Exists(filePath))
				return false;
			if (Directory.Exists(filePath))
				return false; // TODO ask for recursive execution?
			if (Path.GetFileName(filePath).Length > 512) // File Name to Long
				return false;

			try
			{
				using FileStream fileStream = File.OpenRead(filePath); // used to compute hash
				Transfer transfer = Transfer.CreateRequest(Path.GetFileName(filePath), new FileInfo(filePath).Length, OwnId, SHA256.HashData(fileStream));
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
					incomingFileStreams.Add(transfer.Uuid, new FileStream(Path.Combine(SaveFilePath, transfer.FileName), FileMode.Create, FileAccess.ReadWrite, FileShare.None));
					incomingFileStreamHashes.Add(transfer.Uuid, transfer.FileHash);
					receivedFileProgress.Add(transfer.Uuid, transfer.FileSize); //TODO: implement permission check

					//send ok
					SmartConsole.WriteInfo($"File transfer with {transfer.SourceId} accepted.");
					Transfer transferAccepted = Transfer.CreateResponse(transfer, OwnId);
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

		private async Task SendFile(byte targetId, int transferUuid)
		{
			string filePath = pendingFiles[transferUuid];
			var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None);
			sendFileProgress.Add(transferUuid, stream.Length);
			Memory<byte> buffer = new Memory<byte>(new byte[FileBufferSize]); //wrapping the buffer in a memory object for better performance
			while (true)
			{
				long startPositionInFile = stream.Position;
				int bytesRead = await stream.ReadAsync(buffer);
				if (bytesRead == 0) break;
				//buffer[..bytesRead] reduces the buffer to the actual data if the buffer is not full
				var req = TransferData.CreateRequest(transferUuid, buffer[..bytesRead], startPositionInFile);
				await SendEncrypted(targetId, req);
				//update progress
				lock (sendFileProgress)
					sendFileProgress[transferUuid] -= bytesRead;
			}
			SmartConsole.WriteSuccess($"File {Path.GetFileName(filePath)} sent to client {targetId}.");
			pendingFiles.Remove(transferUuid);
			sendFileProgress.Remove(transferUuid);
			stream.Close();
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
					string fileName = Path.GetFileName(stream.Name);

                    SmartConsole.WriteSuccess($"File {fileName} received.");
					await stream.FlushAsync();
					if (!VerifyFileIntegretiy(stream, incomingFileStreamHashes[uuid]))
					{
						SmartConsole.WriteWarning($"The received File {fileName} does not match with the sent verification hash. The file's integretiy might be broken!");
					}
					stream.Close();
					incomingFileStreams.Remove(uuid);
					receivedFileProgress.Remove(uuid);
				}
			}
			else
			{
				SmartConsole.WriteWarning($"Received file data that was not requested. Ignoring Data. (Uuid: {transferData.Uuid}");
			}
		}

		private static bool VerifyFileIntegretiy(FileStream receivedFile, byte[] verifyHash)
		{
			byte[] hash = SHA256.HashData(receivedFile);
			return hash.SequenceEqual(verifyHash);
		}
		
		/// <summary>
		/// Sends a request to the server to get a list of all connected clients.
		/// </summary>
		/// <returns></returns>
		public async Task RequestClientList()
		{
			await SendEncrypted(ServerId, ClientList.CreateRequest());
		}

		/// <summary>
		/// Returns if a key exchange has been done with the client with the given id.
		/// </summary>
		/// <param name="id">The id of the client to check.</param>
		/// <returns>Returns <see langword="true"/> if a key exchange has been done with the client, otherwise <see langword="false"/>.</returns>
		public bool IsKeyExchanged(byte id)
		{
			return aesSessionKeys.TryGetValue(id, out _);
		}

		/// <summary>
		/// Updates the list of connected clients based on the received <see cref="ClientList"/> message. <br></br>
		/// Clients are updated in a 2-step process: <br></br>
		/// 1. Remove clients that are no longer in the new list. <br></br>
		/// 2. Add new clients that are not already in the old list. <br></br>
		/// This 2-step process ensures that the corresponding aes session keys are disposed of when a client is removed from the list.
		/// </summary>
		/// <param name="clients">The received client list message.</param>
		private void UpdateClientList(ClientList clients)
		{
			//ignore invalid list messages.
			if (clients.Code != (int)PacketCode.Ok || clients.Clients == null)
				return;

			//for each oldClient client that is not in the new list, remove
			foreach (byte oldClient in connectedClients)
			{
				if (clients.Clients.Contains(oldClient))
					continue;
				aesSessionKeys[oldClient].Dispose();
				_ = aesSessionKeys.Remove(oldClient);
			}
			
			// for each new client that is not in the oldClient list, add
			// also for each new client that is in the oldClient list do nothing
			foreach (byte newClient in clients.Clients)
			{
				connectedClients.Add(newClient); // only adds new client if not already in the list
			}
		}
	}
}

