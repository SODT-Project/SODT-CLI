using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SODT_CLI
{
    internal static class EncryptionHandler
    {
        private const int AesGcmKeySize = 32;

        private const int AesTagSize = MessageHelper.TagSize;
        public static AesGcm GenerateNewAesGcm()
        {
            var key = RandomNumberGenerator.GetBytes(AesGcmKeySize);

            return new AesGcm(key, AesTagSize);
        }

        public static RSA ImportServerPublicKey(string rsaPublicKeyPath)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(rsaPublicKeyPath));
            return rsa;
        }

        public static void EncryptAesGcm(AesGcm aes, IBaseMessage baseMessage, Span<byte> finalMessage)
        {
            // slice the final message into its components
            // because of Span<byte> the slices are just references to the original array. This eliminates memory allocations and copying.
            Span<byte> nonce = finalMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize); // nonce starts after the id
            Span<byte> tag = finalMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize); // tag starts after the id and nonce
            Span<byte> ciphertext = finalMessage[MessageHelper.HeaderSizeWithoutContentLengthSize..]; // ciphertext starts after the header (id + nonce + tag) and goes to the end of the message

            // handle encryption
            RandomNumberGenerator.Fill(nonce);

            // encrypt the base message and write the ciphertext and tag inside the final message
            aes.Encrypt(nonce, baseMessage.ToBytes(), ciphertext, tag);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="encryptedMessage">Fully encrypted Message (4096 Bytes)</param>
        /// <param name="decryptedMessage"></param>
        public static void DecryptAesGcm(AesGcm aes, ReadOnlySpan<byte> encryptedMessage, Span<byte> decryptedMessage)
        {
            if (encryptedMessage.Length != MessageHelper.FullMessageSize) // TODO copy this into check into server
            {
                throw new InvalidOperationException("EncryptedMessage has wrong size");
            }
            aes.Decrypt(
                encryptedMessage.Slice(MessageHelper.IdSize, MessageHelper.NonceSize),
                encryptedMessage[MessageHelper.HeaderSizeWithoutContentLengthSize..],
                encryptedMessage.Slice(MessageHelper.IdSize + MessageHelper.NonceSize, MessageHelper.TagSize),
                decryptedMessage);
        }
    }
}
