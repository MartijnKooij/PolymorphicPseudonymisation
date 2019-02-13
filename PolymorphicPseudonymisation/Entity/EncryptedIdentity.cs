using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Entity
{
    public class EncryptedIdentity : EncryptedEntity
    {
        public Identity Decrypt(IdentityDecryptKey decryptKey)
        {
            Check(decryptKey, true);

            var point = Points[1].Subtract(Points[0].Multiply(decryptKey.PrivateKey)).Normalize();

            return new Identity(point);
        }
    }
}