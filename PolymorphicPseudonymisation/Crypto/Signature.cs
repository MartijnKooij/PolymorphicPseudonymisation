using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Crypto
{
    public abstract class Signature
    {
        protected BigInteger R { get; set; }
        protected BigInteger S { get; set; }

        protected Signature(BigInteger r, BigInteger s)
        {
            R = r;
            S = s;
        }

        public static Signature Create(string objectIdentifier, BigInteger r, BigInteger s)
        {
            return objectIdentifier switch
            {
                Constants.EcSchnorrSha384Oid => new EcSchnorrSignature(r, s),
                Constants.EcSdsaSha384Oid => new EcSdsaSignature(r, s),
                _ => throw new ParsingException("Invalid signature, signature algoritm not implemented"),
            };
        }

        public abstract void Verify(ECPoint publicKey, ECPoint g, byte[] message);

        public override string ToString()
        {
            return $"{R.ToString()}, {S.ToString()}";
        }

        protected void AssertInputRequirements()
        {
            if (R.BitCount > 320 || R.CompareTo(BigInteger.Zero) <= 0 || S.CompareTo(BrainpoolP320R1.Q) >= 0)
            {
                throw new CryptoException("Invalid signature");
            }
        }

        protected static BigInteger Get320MostSignificantBytes(System.Security.Cryptography.SHA384 md)
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