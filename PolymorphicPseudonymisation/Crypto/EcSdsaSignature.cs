using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace PolymorphicPseudonymisation.Crypto
{
    public class EcSdsaSignature : Signature
    {
        public EcSdsaSignature(BigInteger r, BigInteger s) : base(r, s)
        {
        }

        public override void Verify(ECPoint publicKey, ECPoint g, byte[] message)
        {
            throw new NotImplementedException();
        }
    }
}