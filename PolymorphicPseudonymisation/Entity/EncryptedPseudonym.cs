using PolymorphicPseudonymisation.Key;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Entity
{
    public class EncryptedPseudonym : EncryptedEntity
    {
        public Pseudonym Decrypt(DecryptKey decryptKey, DecryptKey closingKey)
        {
            Guard.AssertNotNull(decryptKey, nameof(decryptKey));
            Check(decryptKey);
            Guard.AssertNotNull(closingKey, nameof(closingKey));
            Check(closingKey);

            var point = Points[1].Subtract(
                            Points[0].Multiply(decryptKey.KeyPair.PrivateKey)
                        )
                        .Multiply(closingKey.KeyPair.PrivateKey)
                        .Normalize();

            return new Pseudonym(closingKey.RecipientKeySetVersion, point);
        }
    }
}