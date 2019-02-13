using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;

namespace PolymorphicPseudonymisation.Key
{
    /// <summary>
    /// Verifier that can be used to check encrypted entities
    /// It uses the public key of the decrypt key and a verification point that is published.
    /// </summary>
    public class EncryptedVerifier
    {
        private readonly ECPoint publicKey;
        private readonly ECPoint verificationPoint;

        internal EncryptedVerifier(ECPoint publicKey, ECPoint verificationPoint)
        {
            this.publicKey = publicKey;
            this.verificationPoint = verificationPoint;
        }

        public void Verify(byte[] payload, Signature signature)
        {
            signature.Verify(publicKey, verificationPoint, payload);
        }
    }
}