using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Key;
using PolymorphicPseudonymisation.Parser;

namespace PolymorphicPseudonymisation.Entity
{
    public class EncryptedPseudonym : EncryptedEntity
    {
        private readonly ECPoint[] points;

        internal EncryptedPseudonym(EncryptedEntityParser parser) : base(parser)
        {
            points = parser.Points;
        }

        public Pseudonym Decrypt(PseudonymDecryptKey decryptKey, PseudonymClosingKey closingKey)
        {
            Check(decryptKey, true);
            Check(closingKey, false);

            var point = points[1].Subtract(points[0].Multiply(decryptKey.PrivateKey))
                .Multiply(closingKey.PrivateKey).Normalize();

            return new Pseudonym(closingKey.RecipientKeySetVersion, point);
        }
    }
}