using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Entity
{
    public class EncryptedIdentity : EncryptedEntity
    {
        public Identity Decrypt(DecryptKey decryptKey)
        {
            Check(decryptKey);

            var point = Points[1].Subtract(Points[0].Multiply(decryptKey.PrivateKey)).Normalize();

            return new Identity(point);
        }
    }
}