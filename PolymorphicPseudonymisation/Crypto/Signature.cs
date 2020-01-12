using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Crypto
{
    public class Signature
    {
        private readonly BigInteger r;
        private readonly BigInteger s;

        public Signature(BigInteger r, BigInteger s)
        {
            this.r = r;
            this.s = s;
        }

        public void Verify(ECPoint publicKey, ECPoint g, byte[] message)
        {
            Guard.AssertNotNull(publicKey, nameof(publicKey));
            Guard.AssertNotNull(g, nameof(g));
            Guard.AssertNotNull(message, nameof(message));

            if (r.BitCount > 320 || r.CompareTo(BigInteger.Zero) <= 0 || s.CompareTo(BrainpoolP320R1.Q) >= 0)
            {
                throw new CryptoException("Invalid signature");
            }

            var q = g.Multiply(s).Add(publicKey.Multiply(r)).Normalize();
            if (q.IsInfinity)
            {
                throw new CryptoException("Invalid signature");
            }

            var md = Sha384.Instance;
            var encodedXCoordinate = q.AffineXCoord.GetEncoded();
            md.TransformBlock(message, 0, message.Length, message, 0);
            md.TransformFinalBlock(encodedXCoordinate, 0, encodedXCoordinate.Length);

            // Use only 320 MSB
            var hash = Arrays.CopyOfRange(md.Hash, 0, 40);
            var v = new BigInteger(1, hash);
            if (!r.Equals(v))
            {
                throw new CryptoException("Invalid signature");
            }
        }

        public override string ToString()
        {
            return $"{r.ToString()}, {s.ToString()}";
        }
    }
}