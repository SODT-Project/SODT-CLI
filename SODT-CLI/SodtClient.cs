using System.Net.Sockets;
using System.Security.Cryptography;
using SODT_CLI.SODT_Common;

namespace SODT_CLI
{
	internal class SodtClient
	{
		/// <summary>
		/// The ID of the server that is used to identify the server in the network and to encrypt/decrypt messages with the server.
		/// </summary>
		private const byte ServerId = 1;
		
		/// <summary>
		/// The path where incoming files will be saved. This is set to the Downloads folder of the user profile.
		/// </summary>
		private static readonly string SaveFilePath = Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
			"Downloads"); // Downloads is mostly the correct name. going with it for now
		
		/// <summary>
		/// The ID of the client that is assigned by the server during the discovery process.
		/// This ID is used to identify the client in the network and to encrypt/decrypt messages with other clients or the server.
		/// If the client is not connected to the server, this ID is 0.
		/// </summary>
		public byte OwnId { get; private set; }
		
		/// <summary>
		/// The TcpClient that is used to connect to the server and send/receive messages.
		/// </summary>
		private readonly TcpClient client = new();
		
		/// <summary>
		/// Semaphore to ensure that only one message is sent at a time.
		/// This is necessary because the TcpClient is not thread-safe and sending multiple messages at the same time can cause data corruption.
		/// </summary>
		private readonly SemaphoreSlim sendSemaphore = new(1, 1);
		
		/// <summary>
		/// Lock object to ensure that cryptographic operations are thread-safe.
		/// This is necessary because the AesGcm and ECDiffieHellman classes are not thread-safe.
		/// </summary>
		private readonly Lock cryptoLock = new();

		public bool Disconnected { get; private set; } = false;
		
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
		/// The certificate of the server to validate its authenticity during the session.
		/// The is initialized in Connect() and used in HandleDiscovery() to verify the server's signature.
		/// </summary>
		// this cant be added in the constructor because the server certificate is not known at that point because the CLI needs SodtClient object beforehand
		private ECDsa? ecdsaServerCertificate; 
		
		/// <summary>
		/// Contains all clients that are connected to the server.
		/// </summary>
		public byte[] ConnectedClients => connectedClients.ToArray();

		/// <summary>
		/// Contains the file streams for the incoming file transfers.
		/// </summary>
		private readonly Dictionary<int, FileStream> incomingFileStreams = new();

		/// <summary>
		/// Contains the metadata for the incoming file transfers. Its main use is to store the file hash for verification after the transfer is complete.
		/// </summary>
		private readonly Dictionary<int, Transfer> incomingFileStreamMetaData = new();

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

		/// <summary>
		/// If set to true, the client will automatically accept key exchange requests from other clients without prompting the user.
		/// </summary>
		public bool AutoAcceptKeyExchanges { get; set; }

		/// <summary>
		/// If set to true, the client will automatically accept file transfer requests from other clients without prompting the user.
		/// </summary>
		public bool AutoAcceptFileTransfers { get; set; }

		/// <summary>
		/// Sends a message to the server or a client and encrypts it with the matching aes session key.
		/// </summary>
		/// <param name="targetId">Destination id for this package. Set to 1 to address the message to the server.</param>
		/// <param name="baseMessage">Message to be sent.</param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException">Thrown when no key is available for the target client.</exception>
		private async Task SendEncrypted(byte targetId, IBaseMessage baseMessage)
		{
			await sendSemaphore.WaitAsync();
			try
			{
				byte[] finalMessage = new byte[MessageHelper.FullMessageSize];
				lock (cryptoLock)
				{
					if (!aesSessionKeys.TryGetValue(targetId, out AesGcm? aes))
					{
						//This case should never happen because the CLI always checks and requests, if necessary, a key exchange before sending a message.
						SmartConsole.WriteError($"No key for target client {targetId} to encrypt with.");
						throw new InvalidOperationException("No key for target client to encrypt with.");
					}
					
					EncryptionHandler.EncryptAesGcm(aes, baseMessage, finalMessage);
				}
				
				finalMessage[0] = targetId;
				finalMessage[1] = OwnId;
				await client.GetStream().WriteAsync(finalMessage);
			}
			finally
			{
				sendSemaphore.Release();
			}
		}
		
		/// <summary>
		/// Sends a message to the server or a client without encryption. This is used for key exchanges and discovery messages.
		/// </summary>
		/// <param name="targetId"></param>
		/// <param name="baseMessage"></param>
		private async Task SendUnencrypted(byte targetId, IBaseMessage baseMessage)
		{
			await sendSemaphore.WaitAsync();
			try
			{
				byte[] finalMessage = [targetId, OwnId, .. new byte[MessageHelper.NonceSize + MessageHelper.TagSize], ..baseMessage.ToBytes()];
				await client.GetStream().WriteAsync(finalMessage);
			}
			finally
			{
				sendSemaphore.Release();
			}
		}

		/// <summary>
		/// Connects to the server via Discovery and starts the receive-loop and the ping-loop.
		/// This will also load the server certificate from the given PEM string.
		/// </summary>
		/// <param name="host">The host of the server.</param>
		/// <param name="port">The port of the server.</param>
		/// <param name="ecdsaServerCertificatePem">The ECDSA server certificate in PEM format.</param>
		public async Task Connect(string host, int port, string ecdsaServerCertificatePem)
		{

			ecdsaServerCertificate = ECDsa.Create(ECCurve.NamedCurves.nistP256);
			ecdsaServerCertificate.ImportFromPem(ecdsaServerCertificatePem);
			
			await client.ConnectAsync(host, port);
			_ = Receive(); // fire and forget. Receive will handle itself
			
			//send discovery key exchange
			ecdhSessionKeyGenerators.Add(ServerId, ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
			byte[] ecdhPublicKey = ecdhSessionKeyGenerators[ServerId].ExportSubjectPublicKeyInfo();
			Discovery discovery = Discovery.CreateRequest(ecdhPublicKey);
			await SendUnencrypted(ServerId, discovery);
			_ = SendPingPeriodically(); // fire and forget. SendPingPeriodically will handle itself
		}

		/// <summary>
		/// DisconnectFromServer from the server and send a disconnect message.
		/// This will also clear the own id, the connected clients, any other dictionary entries, and dispose the server session aes as well as the client.
		/// </summary>
		/// <returns></returns>
		public async Task DisconnectFromServer()
		{
			try
			{
				if (aesSessionKeys.TryGetValue(ServerId, out _))
					await SendEncrypted(ServerId, Disconnect.CreateRequest());
			}
			catch { /*Ignore. Announcing Disconnect is optional anyway.*/ }
			OwnId = 0;
			client.Close();
			aesSessionKeys.Clear();
			ecdhSessionKeyGenerators.Clear();
			incomingFileStreamMetaData.Clear();
			pendingFiles.Clear();
			incomingFileStreams.Clear();
			connectedClients.Clear();
			receivedFileProgress.Clear();
			sendFileProgress.Clear();
			Disconnected = true;
		}

		/// <summary>
		/// Creates a new receive-loop that listens for incoming messages asynchronously.
		/// </summary>
		private async Task Receive()
		{
			byte[] buffer = new byte[MessageHelper.FullMessageSize];
			NetworkStream stream = client.GetStream();
			try
			{
				while (client.Connected)
				{
					int bytesRead = 0;
					while (bytesRead < buffer.Length)
					{
						int read = await stream.ReadAsync(buffer.AsMemory(bytesRead));
						if (read == 0)
							return;
						bytesRead += read;
					}

					await HandleReceivedBuffer(buffer, buffer[1]);
				}
			}
			catch (IOException)
			{
				// The server has closed the connection. This is expected behavior when the server disconnects the client.
			}
			catch (Exception e)
			{
				SmartConsole.WriteError($"Receive loop failed with exception: {e}");
			}
			finally
			{
				SmartConsole.WriteInfo("Disconnected from server.");
				await DisconnectFromServer();
			}
		}
		
		/// <summary>
		/// Decrypts the received message from the server or a client.
		/// If the message is unencrypted, it will be parsed directly.
		/// If the message is encrypted, it will be decrypted with the aes session key for the source id.
		/// </summary>
		/// <param name="buffer">The buffer that contains the encrypted message.</param>
		/// <param name="sourceId">The id of the client that sent the message.</param>
		/// <returns> The decrypted <see cref="IBaseMessage"/> message or <see langword="null"/> if the message type is unknown.</returns>
		private IBaseMessage? Decrypt(Span<byte> buffer, byte sourceId)
		{
			Span<byte> decryptedMessage = new byte[MessageHelper.MessageWithContentSize];
			// get sum of all values in the tag and nonce to check if they are all zero. If they are all zero, the message is unencrypted.
			byte[] zeroCheck = new byte[MessageHelper.NonceSize + MessageHelper.TagSize];
			ReadOnlySpan<byte> tagAndNonce = buffer[MessageHelper.IdSize..MessageHelper.HeaderSizeWithoutContentLengthSize];
			
			lock (cryptoLock)
			{
	            if (!aesSessionKeys.TryGetValue(sourceId, out AesGcm? aes) || tagAndNonce.SequenceEqual(zeroCheck))
				{
					SmartConsole.WriteDebug("An unencrypted message was received. Is this a key exchange?");
					decryptedMessage = buffer[MessageHelper.HeaderSizeWithoutContentLengthSize..];
				}
	            else
	            {
			        EncryptionHandler.DecryptAesGcm(aes, buffer, decryptedMessage);
	            }
			}
            // parse message
            return MessageHandler.ParseDecryptedMessage(decryptedMessage);
		}
		
		/// <summary>
		/// Handles the received buffer from the server or a client.
		/// The buffer is decrypted and parsed into a message.
		/// The message is then handled based on its type by an appropriate handler method.
		/// </summary>
		/// <param name="buffer">The received buffer.</param>
		/// <param name="sourceId">The ID of the client that sent the buffer.</param>
		private async Task HandleReceivedBuffer(byte[] buffer, byte sourceId)
		{
			var message = Decrypt(buffer, sourceId);
			if (message is Discovery or PingPong or ClientList && sourceId != ServerId)
			{
				SmartConsole.WriteWarning($"Received message from client {sourceId} that should only be sent by the server. Ignoring message.");
				return;
			}
			//handle message
			switch (message)
			{
				case Discovery discovery:
					await HandleDiscovery(discovery);
					break;
				case PingPong:
					break; // PingPong is only used to check if the connection is still alive. No action needed.
				case ClientList clients:
					UpdateClientList(clients);
					break;
				case KeyExchange exchange:
					await HandleKeyExchange(exchange, sourceId);
					break;
				case Transfer transfer:
					await HandleTransfer(transfer, sourceId);
					break;
				case TransferData data:
					await ReceiveFile(data, sourceId);
					break;
				default:
					SmartConsole.WriteError("Received Message contains one or more errors. Ignoring message.");
					break;
			}
		}
		
		/// <summary>
		/// Sends a ping message to the server every 3 seconds to check if the connection is still alive.
		/// The Server will disconnect the client if it does not receive a ping message within x seconds.
		/// </summary>
		private async Task SendPingPeriodically()
		{
			while (client.Connected)
			{
				await Task.Delay(3000);
				if (!aesSessionKeys.TryGetValue(ServerId, out _))
					continue;
				await SendEncrypted(ServerId, PingPong.CreateRequest());
				SmartConsole.WriteDebug("Sent Ping to server.");
			}
		}

		/// <summary>
		/// Handles the received discovery message from the server.
		/// The signature of the discovery message is verified with the server certificate.
		/// If the signature is valid, the aes session key for the server is generated and the own id is set.
		/// </summary>
		/// <param name="discovery">The received discovery message.</param>
		private async Task HandleDiscovery(Discovery discovery)
		{
			// basic checks if the discovery message is valid
			if (discovery.PublicKey == null || discovery.Signature == null)
			{
				SmartConsole.WriteError("Discovery message from server is invalid. Disconnecting.");
				await DisconnectFromServer();
				return;
			}
			
			// verify discovery message
			byte[] clientEcdhPublicKey = ecdhSessionKeyGenerators[ServerId].ExportSubjectPublicKeyInfo();
			byte[] toVerify = [..clientEcdhPublicKey, ..discovery.PublicKey /*Server's ECDH public key*/, discovery.Id];
			if (!ecdsaServerCertificate!.VerifyData(toVerify, discovery.Signature, HashAlgorithmName.SHA256)) // serverCertificate is not null because it is set in Connect() before the discovery message is sent
			{
				SmartConsole.WriteError("Discovery message from server is signed with an invalid signature. Possible man-in-the-middle attack. Disconnecting.");
				await DisconnectFromServer();
				return;
			}
			switch ((PacketCode)discovery.Code)
			{
				case PacketCode.Ok:
					// generate aes session key for server
					aesSessionKeys[ServerId] = EncryptionHandler.GenerateSessionKey(ecdhSessionKeyGenerators[ServerId], discovery.PublicKey);
					// Set own id.
					if (discovery.Id == 0)
					{
						SmartConsole.WriteError("Discovery message from server is invalid. Server assigned id 0 to client. Disconnecting.");
						await DisconnectFromServer();
						return;
					}
					OwnId = discovery.Id;
					SmartConsole.WriteDebug($"Connected to server with id {OwnId}.");
					break;
				case PacketCode.Denied:
					SmartConsole.WriteError("Server denied the connection. The server might be full. Disconnecting.");
					await DisconnectFromServer();
					break;
				default:
					SmartConsole.WriteError("Discovery message from server has an unknown status code. Disconnecting.");
					await DisconnectFromServer();
					break;
			}
		}
		
		/// <summary>
		/// Sends a request to exchange a key with the target client.
		/// </summary>
		/// <param name="targetId">The id of the client to exchange a key with.</param>
		public async Task RequestKeyExchange(byte targetId)
		{
			if (targetId == OwnId)
			{
				SmartConsole.WriteError($"Cannot request key exchange with {targetId} because the target id is the same as the own id.");
				return;
			}
			if (!connectedClients.Contains(targetId))
			{
				SmartConsole.WriteError($"Cannot request key exchange with {targetId} because the client is not connected.");
				return;
			}
			SmartConsole.WriteInfo($"Requesting key exchange with {targetId}.");
			ecdhSessionKeyGenerators[targetId] = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			KeyExchange exchange = KeyExchange.CreateRequest(ecdhSessionKeyGenerators[targetId].ExportSubjectPublicKeyInfo());
			await SendUnencrypted(targetId, exchange);
		}
		
		/// <summary>
		/// Handles a key exchange message from the target client. This can be a request, an acceptance, a denial or an error of the key exchange.
		/// </summary>
		/// <param name="exchange">The key exchange message to handle.</param>
		/// <param name="remoteId">The id of the remote client.</param>
		/// <exception cref="NotImplementedException">Thrown when the key exchange status code is not implemented.</exception>
		private async Task HandleKeyExchange(KeyExchange exchange, byte remoteId)
		{
			//handle possible errors
			if (remoteId == OwnId)
			{
				SmartConsole.WriteError($"Key exchange between {OwnId} and {remoteId} failed because the remote id is the same as the own id.");
				return;
			}
			if (exchange.Key == null)
			{
				SmartConsole.WriteError($"Key exchange between {OwnId} and {remoteId} failed because the key is null.");
				await SendUnencrypted(remoteId, KeyExchange.CreateError(exchange));
				return;
			}
			
			switch ((PacketCode)exchange.Code)
			{
				case PacketCode.Request: // PaketCode.Request is received when the target client requests a key exchange
					bool permission = AutoAcceptKeyExchanges || await SmartConsole.AskYesNo($"Client {remoteId} requests a key exchange. Do you want to accept the key exchange?");
					if (!permission)
					{
						await SendUnencrypted(remoteId, KeyExchange.CreateDenied(exchange));
						return;
					}
					lock (cryptoLock)
					{
						ecdhSessionKeyGenerators[remoteId] = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
						aesSessionKeys[remoteId] = EncryptionHandler.GenerateSessionKey(ecdhSessionKeyGenerators[remoteId], exchange.Key);
						SmartConsole.WriteInfo($"Key exchange with {remoteId} accepted. Please check your shared phrase with the other client to verify the authenticity of the connection.");
						SmartConsole.WriteInfo($"Shared phrase with client {remoteId}: {EncryptionHandler.GetSharedPhrase(ecdhSessionKeyGenerators[remoteId], exchange.Key)}");
					}
					//send ok
					KeyExchange exchangeAccepted = KeyExchange.CreateResponse(ecdhSessionKeyGenerators[remoteId].ExportSubjectPublicKeyInfo());
					await SendUnencrypted(remoteId, exchangeAccepted);
					break;
				case PacketCode.Ok: // PaketCode.Ok is received when the target client accepts the key exchange
					lock (cryptoLock)
					{
						if (!ecdhSessionKeyGenerators.TryGetValue(remoteId, out ECDiffieHellman? ecdhGenerator))
						{
							SmartConsole.WriteError($"Key exchange with client {remoteId} failed the key exchange was never requested.");
							return;
						}
						aesSessionKeys[remoteId] = EncryptionHandler.GenerateSessionKey(ecdhGenerator, exchange.Key);
						SmartConsole.WriteInfo($"Client {remoteId} accepted key exchange. Please check your shared phrase with the other client to verify the authenticity of the connection.");
						SmartConsole.WriteInfo($"Shared phrase with client {remoteId}: {EncryptionHandler.GetSharedPhrase(ecdhGenerator, exchange.Key)}");
					}
					
					break;
				case PacketCode.Error:
				case PacketCode.Denied:
					aesSessionKeys.Remove(remoteId);
					ecdhSessionKeyGenerators.Remove(remoteId);
					SmartConsole.WriteError($"Key exchange with client {remoteId} failed. ErrorCode: {(PacketCode)exchange.Code}");
					break;
				default:
					SmartConsole.WriteError($"Key exchange code {exchange.Code} not implemented yet.");
					throw new NotImplementedException($"Key exchange code {exchange.Code} not implemented yet.");
			}
		}
		
		/// <summary>
		/// Sends a request to the target client to transfer a file. The file will be sent after the target client accepts the transfer.
		/// </summary>
		/// <param name="targetId"> The ID of the target client. </param>
		/// <param name="filePath"> The path to the file to be transferred. </param>
		/// <returns>True if the file transfer request is sent successfully, false otherwise.</returns>
		public async Task<bool> RequestFileTransfer(byte targetId, string filePath)
		{
			if (!File.Exists(filePath) || Directory.Exists(filePath)) // Check if filePath is a valid file and not a directory
				return false;
			if (Path.GetFileName(filePath).Length > 512) // File Name to Long
				return false;

			try
			{
				await using FileStream fileStream = File.OpenRead(filePath); // used to compute hash
				Transfer transfer = Transfer.CreateRequest(Path.GetFileName(filePath), new FileInfo(filePath).Length, await SHA256.HashDataAsync(fileStream));
				pendingFiles.Add(transfer.Uuid, filePath);
				await SendEncrypted(targetId, transfer);
				return true;
			}
			catch (Exception e)
			{
				SmartConsole.WriteError($"File transfer request failed. Error: {e}");
				return false;
			}
		}
		
		/// <summary>
		/// Handles a file transfer message from the target client. This can be a request, an acceptance,
		/// an acknowledgment, a denial, or an error of the file transfer.
		/// </summary>
		/// <param name="transfer">The received transfer message.</param>
		/// <param name="sourceId">The ID of the source client.</param>
		/// <exception cref="NotImplementedException">Thrown when a transfer code is not implemented yet.</exception>
		private async Task HandleTransfer(Transfer transfer, byte sourceId)
		{
			try{
				switch ((PacketCode)transfer.Code)
				{
					case PacketCode.Request:
						if (await PrepareReceiveFile(transfer, sourceId))
						{
							SmartConsole.WriteInfo($"File transfer request from client {sourceId} accepted. Sending acceptance.");
							await SendEncrypted(sourceId, Transfer.CreateResponse(transfer));
						}
						else
						{
							SmartConsole.WriteInfo($"File transfer request from client {sourceId} rejected. Sending denial.");
							await SendEncrypted(sourceId, Transfer.CreateDenied(transfer));
						}
						break;
					case PacketCode.Ok:
						SmartConsole.WriteInfo($"Client {sourceId} accepted file transfer. Start sending file.");
						_ = SendFile(sourceId, transfer.Uuid); //fire and forget. SendFile will handle itself
						break;
					case PacketCode.Ack:
						SmartConsole.WriteSuccess($"Client {sourceId} reported successful receipt of file {transfer.FileName}");
						break;
					case PacketCode.Denied:
						SmartConsole.WriteInfo($"Client {sourceId} denied the file transfer. File transfer aborted.");
						CleanIncomingFileTransfer(transfer.Uuid);
						break;
					case PacketCode.Error:
						SmartConsole.WriteError($"Client {sourceId} reported an error with the file transfer. File transfer aborted.");
						CleanIncomingFileTransfer(transfer.Uuid);
						break;
					default:
						throw new NotImplementedException($"Transfer code {transfer.Code} not implemented yet.");
				}
			}
			catch (Exception e)
			{
				SmartConsole.WriteError($"Transfer with client {sourceId} failed. Error: {e.Message}");
				// send error to other client
				Transfer transferError = Transfer.CreateError(transfer);
				await SendEncrypted(sourceId, transferError);
				// cleanup
				CleanIncomingFileTransfer(transfer.Uuid);
			}
		}
		
		/// <summary>
		/// Cleans up the incoming file transfer by closing the file stream and removing it from the incomingFileStreams dictionary. <br></br>
		/// </summary>
		/// <param name="transferUuid">The UUID of the transfer to clean up.</param>
		private void CleanIncomingFileTransfer(int transferUuid)
		{
			if (incomingFileStreams.TryGetValue(transferUuid, out FileStream? fileStream))
			{
				fileStream.Close();
				incomingFileStreams.Remove(transferUuid);
			}
			incomingFileStreamMetaData.Remove(transferUuid);
			receivedFileProgress.Remove(transferUuid);
		}
		
		/// <summary>
		/// Prepares the client to receive a file transfer by creating a file stream and adding it to the incomingFileStreams dictionary. <br></br>
		/// If the file transfer is accepted, the file stream will be used to write the incoming file data.
		/// </summary>
		/// <param name="transfer">The Transfer request.</param>
		/// <param name="sourceId">The ID of the source client.</param>
		/// <returns></returns>
		private async Task<bool> PrepareReceiveFile(Transfer transfer, byte sourceId)
		{
			//prepare receiving file
			bool permission = AutoAcceptFileTransfers || await SmartConsole.AskYesNo($"Client {sourceId} requests a file transfer. Do you want to accept the file {transfer.FileName} ({transfer.FileSize / 1000} KB)?");
			if (!permission) return false;
			
			incomingFileStreams.Add(transfer.Uuid, new FileStream(Path.Combine(SaveFilePath, transfer.FileName), FileMode.Create, FileAccess.ReadWrite, FileShare.None));
			incomingFileStreamMetaData.Add(transfer.Uuid, transfer);
			receivedFileProgress.Add(transfer.Uuid, transfer.FileSize);
			
			//special case: if the file is empty, no actual data is sent, therefore simulate receive manually:
			if (transfer.FileSize == 0)
			{
				await ReceiveFile(TransferData.CreateRequest(transfer.Uuid, Array.Empty<byte>(), 0), sourceId);
			}
			return true;
		}

		/// <summary>
		/// Sends the file to the target client in chunks of MessageHelper.FileBufferSize bytes. <br></br>
		/// If the transfer fails, an error message is sent to the target client and the transfer is aborted. <br></br>
		/// The file is read from the pendingFiles dictionary and the progress is updated in the sendFileProgress dictionary. <br></br>
		/// </summary>
		/// <param name="targetId"> The ID of the target client.</param>
		/// <param name="transferUuid">The UUID of the transfer. Used to identify the transfer in the pendingFiles and sendFileProgress dictionaries.</param>
		private async Task SendFile(byte targetId, int transferUuid)
		{
			FileStream? stream = null;
			try
			{
				string filePath = pendingFiles[transferUuid];
				stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None);
				sendFileProgress.Add(transferUuid, stream.Length);
				Memory<byte> buffer = new byte[MessageHelper.FileBufferSize]; //wrapping the buffer in a memory object for better performance
				while (true)
				{
					long startPositionInFile = stream.Position;
					int bytesRead = await stream.ReadAsync(buffer);
					if (bytesRead == 0) break;
					var req = TransferData.CreateRequest(transferUuid, buffer[..bytesRead], startPositionInFile);
					await SendEncrypted(targetId, req);
					//update progress
					lock (sendFileProgress)
						sendFileProgress[transferUuid] -= bytesRead;
				}
				SmartConsole.WriteSuccess($"File {Path.GetFileName(filePath)} sent to client {targetId}.");
				stream.Close();
			}
			catch (Exception e)
			{
				SmartConsole.WriteError($"File transfer to client {targetId} failed. Error: {e}");
				// send error to other client
				Transfer transferError = Transfer.CreateError(incomingFileStreamMetaData[transferUuid]);
				await SendEncrypted(targetId, transferError);

			}
			finally
			{
				// cleanup
				pendingFiles.Remove(transferUuid);
				sendFileProgress.Remove(transferUuid);
				stream?.Close();
			}
		}
		
		/// <summary>
		/// Receives a file transfer data message and writes the data to the corresponding file stream at the specified position. <br></br>
		/// If the transfer is complete, the file stream is closed and an acknowledgement is sent.
		/// If it receives data for a file transfer that was not requested, it will ignore the data and log a warning.
		/// </summary>
		/// <param name="transferData">Received file transfer data.</param>
		/// <param name="remoteId">The ID of the remote client.</param>
		private async Task ReceiveFile(TransferData transferData, byte remoteId)
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
					if (!VerifyFileIntegrity(stream, incomingFileStreamMetaData[uuid].FileHash))
					{
						SmartConsole.WriteWarning($"The received File {fileName} does not match with the sent verification hash. The file's integrity might be broken!");
					}
					stream.Close();
					await SendAcknowledgement(incomingFileStreamMetaData[uuid], remoteId);
					incomingFileStreams.Remove(uuid);
					receivedFileProgress.Remove(uuid);
                    incomingFileStreamMetaData.Remove(uuid);
				}
			}
			else
			{
				SmartConsole.WriteWarning($"Received file data that was not requested. Ignoring Data. (Uuid: {transferData.Uuid}");
			}
		}

		/// <summary>
		/// Verifies the integrity of the received file by comparing its hash with the provided verification hash.
		/// </summary>
		/// <param name="receivedFile">The received file to verify as a FileStream.</param>
		/// <param name="verifyHash">The hash to compare against.</param>
		/// <returns></returns>
		private static bool VerifyFileIntegrity(FileStream receivedFile, byte[] verifyHash)
		{
			receivedFile.Position = 0;
			byte[] hash = SHA256.HashData(receivedFile);
			return hash.SequenceEqual(verifyHash);
		}

		/// <summary>
		/// Sends an acknowledgement message to the target client for the received file transfer.
		/// </summary>
		/// <param name="originalRequest">The original file transfer request.</param>
		/// <param name="targetId">The ID of the target client.</param>
		private async Task SendAcknowledgement(Transfer originalRequest, byte targetId)
		{
			Transfer ack = Transfer.CreateAcknowledgement(originalRequest);
			await SendEncrypted(targetId, ack);
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
				
				if (aesSessionKeys.TryGetValue(oldClient, out AesGcm? aes))
				{
					aes.Dispose();
					aesSessionKeys.Remove(oldClient);
				}
				if (ecdhSessionKeyGenerators.TryGetValue(oldClient, out ECDiffieHellman? ecdh))
				{
					ecdh.Dispose();
					ecdhSessionKeyGenerators.Remove(oldClient);
				}
				connectedClients.Remove(oldClient);
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
