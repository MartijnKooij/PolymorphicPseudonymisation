using System.Collections.Generic;
using Org.BouncyCastle.Utilities;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Crypto
{
    public static class Oaep
    {
        private static readonly byte[] Lhash = Sha384.EmptySha384;

        public static byte[] Decode(byte[] message, int pos, int length, int hashLength)
        {
            Guard.AssertNotNull(message, nameof(message));

            if (length > 48)
            {
                throw new CryptoException($"Length of message is too big ({length:D} > 48)");
            }

            if (hashLength > 48)
            {
                throw new CryptoException($"Hash length is too big ({hashLength:D} > 48)");
            }

            if (length <= 2 * hashLength)
            {
                throw new CryptoException($"Message is too short ({length:D} <= 2 * {hashLength:D})");
            }

            var seed = Mgf1(message, pos + hashLength, length - hashLength);
            Xor(message, pos, seed, hashLength);

            var db = Mgf1(seed, 0, hashLength);
            Xor(message, pos + hashLength, db, length - hashLength);

            Verify(db, hashLength);

            return Arrays.CopyOfRange(db, hashLength + 1, length - hashLength);
        }

        private static void Verify(IReadOnlyList<byte> db, int hashLength)
        {
            if (db[hashLength] != 1)
            {
                throw new CryptoException("OAEP decode error, db[hashLength] != 1");
            }

            for (var i = 0; i < hashLength; i++)
                if (Lhash[i] != db[i])
                {
                    throw new CryptoException("OAEP decode error, hash is not equal");
                }
        }

        /// <summary>
        ///     b = a XOR b
        /// </summary>
        private static void Xor(IReadOnlyList<byte> src, int srcPos, IList<byte> dest, int length)
        {
            for (var i = 0; i < length; i++) dest[i] ^= src[srcPos + i];
        }

        /// <summary>
        ///     Single block MGF1 with SHA-384 of input from pos to pos+length-1
        /// </summary>
        private static byte[] Mgf1(byte[] input, int offset, int count)
        {
            var md = Sha384.Instance;

            md.TransformBlock(input, offset, count, input, offset);
            md.TransformFinalBlock(new byte[] { 0, 0, 0, 0 }, 0, 4);

            return md.Hash;
        }
    }
}