using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Entity
{
    public class EncryptedPseudonym : EncryptedEntity
    {
        public Pseudonym Decrypt(DecryptKey decryptKey, DecryptKey closingKey)
        {
            Check(decryptKey);
            Check(closingKey);

            var point = Points[1].Subtract(
                            Points[0].Multiply(decryptKey.PrivateKey)
                        )
                        .Multiply(closingKey.PrivateKey)
                        .Normalize();

            return new Pseudonym(closingKey.RecipientKeySetVersion, point);
        }
    }
}