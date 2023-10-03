using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Crypto
{
    public class ECSDSASignature : Signature
    {
        public ECSDSASignature(BigInteger r, BigInteger s) : base(r, s)
        {
        }

        public override void Verify(ECPoint publicKey, ECPoint g, byte[] message)
        {
            Guard.AssertNotNull(publicKey, nameof(publicKey));
            Guard.AssertNotNull(g, nameof(g));
            Guard.AssertNotNull(message, nameof(message));

            // Step 1: check if r and s meet input requirements
            AssertInputRequirements();

            // Step 2 en 3: calculate points on curve
            var q = g.Multiply(S).Subtract(publicKey.Multiply(R)).Normalize();
            if (q.IsInfinity)
            {
                throw new CryptoException("Invalid signature");
            }

            // Step 4: Generate message digest and and apply points on curve --- ECSDSA verification
            var md = Sha384.Instance;
            var encodedXCoordinate = q.AffineXCoord.GetEncoded();
            var encodedYCoordinate = q.AffineYCoord.GetEncoded();
            md.TransformBlock(encodedXCoordinate, 0, encodedXCoordinate.Length, encodedXCoordinate, 0);
            md.TransformBlock(encodedYCoordinate, 0, encodedYCoordinate.Length, encodedYCoordinate, 0);
            md.TransformFinalBlock(message, 0, message.Length);

            // Use only 320 MSB
            var v = Get320MostSignificantBytes(md);

            // Step 5 Check if the signatures match
            AssertsSignaturesAreEqual(v);
        }
    }
}