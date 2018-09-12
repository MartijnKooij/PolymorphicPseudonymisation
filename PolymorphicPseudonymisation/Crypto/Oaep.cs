using System.Collections.Generic;
using Org.BouncyCastle.Utilities;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Crypto
{
    public static class Oaep
    {
        private static readonly sbyte[] Lhash = Sha384.EmptySha384Signed;

        public static sbyte[] Decode(sbyte[] message, int pos, int length, int hashLength)
        {
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

            return Arrays.CopyOfRange(db.ToUnSigned(), hashLength + 1, length - hashLength).ToSigned();
        }

        private static void Verify(IReadOnlyList<sbyte> db, int hashLength)
        {
            if (db[hashLength] != 1)
            {
                throw new CryptoException("OAEP decode error, db[hashLength] != 1");
            }

            for (var i = 0; i < hashLength; i++)
            {
                if (Lhash[i] != db[i])
                {
                    throw new CryptoException("OAEP decode error, hash is not equal");
                }
            }
        }

        /// <summary>
        /// b = a XOR b
        /// </summary>
        private static void Xor(IReadOnlyList<sbyte> src, int srcPos, IList<sbyte> dest, int length)
        {
            for (var i = 0; i < length; i++)
            {
                dest[i] ^= src[srcPos + i];
            }
        }

        /// <summary>
        /// Single block MGF1 with SHA-384 of input from pos to pos+length-1
        /// </summary>
        private static sbyte[] Mgf1(sbyte[] input, int offset, int count)
        {
            var md = Sha384.Instance;

            var unsignedInput = input.ToUnSigned();
            md.TransformBlock(unsignedInput, offset, count, unsignedInput, offset);
            md.TransformFinalBlock(new byte[] { 0, 0, 0, 0 }, 0, 4);

            return md.Hash.ToSigned();
        }
    }
}