using Org.BouncyCastle.Math;

namespace PolymorphicPseudonymisation.Crypto
{
    public class EcSchnorrSignature : Signature
    {
        public EcSchnorrSignature(BigInteger r, BigInteger s) : base(r, s)
        {
        }
    }
}