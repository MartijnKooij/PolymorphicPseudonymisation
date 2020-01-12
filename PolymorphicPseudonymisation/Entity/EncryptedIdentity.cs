using PolymorphicPseudonymisation.Key;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Entity
{
    public class EncryptedIdentity : EncryptedEntity
    {
        public Identity Decrypt(DecryptKey decryptKey)
        {
            Guard.AssertNotNull(decryptKey, nameof(decryptKey));
            Check(decryptKey);

            var point = Points[1].Subtract(Points[0].Multiply(decryptKey.KeyPair.PrivateKey)).Normalize();

            return new Identity(point);
        }
    }
}