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

        public override bool Equals(object obj)
        {
            if (obj == null)
            {
                return false;
            }

            if (this == obj)
            {
                return true;
            }
            if (!(obj is EncryptedVerifier))
            {
                return false;
            }

            var encryptedVerifier = (EncryptedVerifier)obj;

            return publicKey.Equals(encryptedVerifier.publicKey) &&
                   verificationPoint.Equals(encryptedVerifier.verificationPoint);
        }

        public override int GetHashCode()
        {
            return ComputeHashFrom(publicKey, verificationPoint);
        }

        private static int ComputeHashFrom(params object[] obj)
        {
            ulong res = 0;
            for (uint i = 0; i < obj.Length; i++)
            {
                var val = obj[i];
                res += val == null ? i : (ulong)val.GetHashCode() * (1 + 2 * i);
            }
            return (int)(uint)(res ^ (res >> 32));
        }
    }
}