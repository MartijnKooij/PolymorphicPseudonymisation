using System.Collections.Generic;
using Org.BouncyCastle.Utilities;

namespace PolymorphicPseudonymisation.Crypto
{
    public static class Oaep
    {
        private static readonly byte[] Lhash = Sha384.Instance.Hash;

        public static byte[] Decode(byte[] message, int pos, int length, int hlen)
        {
            if (length > 48)
            {
                throw new CryptoException($"Length of message is too big ({length:D} > 48)");
            }
            if (hlen > 48)
            {
                throw new CryptoException($"Hash length is too big ({hlen:D} > 48)");
            }
            if (length <= 2 * hlen)
            {
                throw new CryptoException($"Message is too short ({length:D} <= 2 * {hlen:D})");
            }

            var seed = Mgf1(message, pos + hlen, length - hlen);
            Xor(message, pos, seed, hlen);

            var db = Mgf1(seed, 0, hlen);
            Xor(message, pos + hlen, db, length - hlen);

            Verify(db, hlen);

            return Arrays.CopyOfRange(db, hlen + 1, length - hlen);
        }

        private static void Verify(IReadOnlyList<byte> db, int hlen)
        {
            if (db[hlen] != 1)
            {
                throw new CryptoException("OAEP decode error, db[hlen] != 1");
            }
            for (var i = 0; i < hlen; i++)
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
        private static void Xor(IReadOnlyList<byte> src, int srcPos, IList<byte> dest, int length)
        {
            for (var i = 0; i < length; i++)
            {
                dest[i] ^= src[srcPos + i];
            }
        }

        /// <summary>
        /// Single block MGF1 with SHA-384 of input from pos to pos+length-1
        /// </summary>
        private static byte[] Mgf1(byte[] input, int offset, int count)
        {
            var md = Sha384.Instance;
            md.ComputeHash(input, offset, count);
            md.ComputeHash(new byte[] {0, 0, 0, 0});

            return md.Hash;
        }
    }
}