using Org.BouncyCastle.Math;

namespace PolymorphicPseudonymisation.Crypto
{
    public class EcSdsaSignature : Signature
    {
        public EcSdsaSignature(BigInteger r, BigInteger s) : base(r, s)
        {
        }
    }
}