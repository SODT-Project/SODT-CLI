using System.Security.Cryptography;
using SODT_Common;

namespace SODT_CLI.Tests
{
	public class EncryptionTests
	{
		[Fact]
		public void EncryptAndDecryptAesGcm_RoundTripsMessage()
		{
			using AesGcm aes = new(RandomNumberGenerator.GetBytes(32), MessageHelper.TagSize);
			IBaseMessage message = PingPong.CreateRequest();
			byte[] encryptedMessage = new byte[MessageHelper.FullMessageSize];

			EncryptionHandler.EncryptAesGcm(aes, message, encryptedMessage);

			byte[] decryptedMessage = new byte[MessageHelper.MessageWithContentSize];
			EncryptionHandler.DecryptAesGcm(aes, encryptedMessage, decryptedMessage);

			Assert.Equal(message.ToBytes(), decryptedMessage);
		}

		[Fact]
		public void EncryptAesGcm_WithIncorrectMessageSize_Throws()
		{
			using AesGcm aes = new(RandomNumberGenerator.GetBytes(32), MessageHelper.TagSize);

			InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
				EncryptionHandler.EncryptAesGcm(
					aes,
					PingPong.CreateRequest(),
					new byte[MessageHelper.FullMessageSize - 1]));

			Assert.Equal(
				$"FinalMessage has wrong size. It should be {MessageHelper.FullMessageSize} bytes.",
				exception.Message);
		}

		[Fact]
		public void DecryptAesGcm_WithIncorrectMessageSize_Throws()
		{
			using AesGcm aes = new(RandomNumberGenerator.GetBytes(32), MessageHelper.TagSize);

			InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
				EncryptionHandler.DecryptAesGcm(
					aes,
					new byte[MessageHelper.FullMessageSize - 1],
					new byte[MessageHelper.MessageWithContentSize]));

			Assert.Equal(
				$"EncryptedMessage has wrong size. It should be {MessageHelper.FullMessageSize} bytes.",
				exception.Message);
		}

		[Fact]
		public void GenerateSessionKey_WithoutPassword_ProducesMatchingKeys()
		{
			using ECDiffieHellman ownKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using ECDiffieHellman remoteKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using AesGcm ownSessionKey = EncryptionHandler.GenerateSessionKey(
				ownKey,
				remoteKey.ExportSubjectPublicKeyInfo());
			using AesGcm remoteSessionKey = EncryptionHandler.GenerateSessionKey(
				remoteKey,
				ownKey.ExportSubjectPublicKeyInfo());

			AssertRoundTrip(ownSessionKey, remoteSessionKey);
		}

		[Fact]
		public void GenerateSessionKey_WithPassword_ProducesMatchingKeys()
		{
			byte[] passwordHash = RandomNumberGenerator.GetBytes(32);
			using ECDiffieHellman ownKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using ECDiffieHellman remoteKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using AesGcm ownSessionKey = EncryptionHandler.GenerateSessionKey(
				ownKey,
				remoteKey.ExportSubjectPublicKeyInfo(),
				passwordHash);
			using AesGcm remoteSessionKey = EncryptionHandler.GenerateSessionKey(
				remoteKey,
				ownKey.ExportSubjectPublicKeyInfo(),
				passwordHash);

			AssertRoundTrip(ownSessionKey, remoteSessionKey);
		}

		[Fact]
		public void GenerateSessionKey_WithDifferentPasswords_CannotDecrypt()
		{
			using ECDiffieHellman ownKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using ECDiffieHellman remoteKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using AesGcm ownSessionKey = EncryptionHandler.GenerateSessionKey(
				ownKey,
				remoteKey.ExportSubjectPublicKeyInfo(),
				new byte[32]);
			using AesGcm remoteSessionKey = EncryptionHandler.GenerateSessionKey(
				remoteKey,
				ownKey.ExportSubjectPublicKeyInfo(),
				[1, .. new byte[31]]);
			byte[] encryptedMessage = EncryptMessage(ownSessionKey);
			byte[] decryptedMessage = new byte[MessageHelper.MessageWithContentSize];

			Assert.ThrowsAny<CryptographicException>(() => EncryptionHandler.DecryptAesGcm(remoteSessionKey, encryptedMessage, decryptedMessage));
		}

		[Fact]
		public void GetSharedPhrase_WithMatchingKeyPairs_ReturnsSamePhrase()
		{
			using ECDiffieHellman ownKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using ECDiffieHellman remoteKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

			string ownPhrase = EncryptionHandler.GetSharedPhrase(
				ownKey,
				remoteKey.ExportSubjectPublicKeyInfo());
			string remotePhrase = EncryptionHandler.GetSharedPhrase(
				remoteKey,
				ownKey.ExportSubjectPublicKeyInfo());

			Assert.Equal(ownPhrase, remotePhrase);
			Assert.Matches("^(?:[0-9A-F]{2}-){4}[0-9A-F]{2}$", ownPhrase);
		}

		[Fact]
		public void GetSharedPhrase_ReturnsExpectedDerivedKeyBytes()
		{
			using ECDiffieHellman ownKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			using ECDiffieHellman remoteKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
			byte[] remotePublicKey = remoteKey.ExportSubjectPublicKeyInfo();
			byte[] derivedKey = ownKey.DeriveKeyFromHash(
				remoteKey.PublicKey,
				HashAlgorithmName.SHA256);
			string expectedPhrase =
				$"{derivedKey[0]:X2}-{derivedKey[4]:X2}-{derivedKey[8]:X2}-{derivedKey[16]:X2}-{derivedKey[31]:X2}";

			string actualPhrase = EncryptionHandler.GetSharedPhrase(ownKey, remotePublicKey);

			Assert.Equal(expectedPhrase, actualPhrase);
		}
		

		private static void AssertRoundTrip(AesGcm encryptingKey, AesGcm decryptingKey)
		{
			IBaseMessage message = PingPong.CreateRequest();
			byte[] encryptedMessage = new byte[MessageHelper.FullMessageSize];
			EncryptionHandler.EncryptAesGcm(encryptingKey, message, encryptedMessage);
			byte[] decryptedMessage = new byte[MessageHelper.MessageWithContentSize];

			EncryptionHandler.DecryptAesGcm(decryptingKey, encryptedMessage, decryptedMessage);

			Assert.Equal(message.ToBytes(), decryptedMessage);
		}

		private static byte[] EncryptMessage(AesGcm aes)
		{
			byte[] encryptedMessage = new byte[MessageHelper.FullMessageSize];
			EncryptionHandler.EncryptAesGcm(aes, PingPong.CreateRequest(), encryptedMessage);
			return encryptedMessage;
		}
	}
}