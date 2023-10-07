using System.Security.Cryptography;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Utilities;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace PolymorphicPseudonymisation.Crypto
{
    public abstract class Signature
    {
        protected Signature(BigInteger r, BigInteger s)
        {
            R = r;
            S = s;
        }

        protected BigInteger R { get; }
        protected BigInteger S { get; }

        public abstract void Verify(ECPoint publicKey, ECPoint g, byte[] message);

        public override string ToString()
        {
            return $"{R}, {S}";
        }

        protected void AssertInputRequirements()
        {
            if (R.BitCount > 320 || R.CompareTo(BigInteger.Zero) <= 0 || S.CompareTo(BrainpoolP320R1.Q) >= 0)
            {
                throw new CryptoException("Invalid signature");
            }
        }

        protected static BigInteger Get320MostSignificantBytes(SHA384 md)
        {
            Guard.AssertNotNull(md, nameof(md));

            var hash = Arrays.CopyOfRange(md.Hash, 0, 40);
            var v = new BigInteger(1, hash);

            return v;
        }

        protected void AssertsSignaturesAreEqual(BigInteger v)
        {
            if (!R.Equals(v))
            {
                throw new CryptoException("Invalid signature");
            }
        }
    }
}