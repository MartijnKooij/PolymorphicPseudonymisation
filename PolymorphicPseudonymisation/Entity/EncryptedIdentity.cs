using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Key;
using PolymorphicPseudonymisation.Parser;

namespace PolymorphicPseudonymisation.Entity
{
    public class EncryptedIdentity : EncryptedEntity
    {
        private readonly ECPoint[] points;

        internal EncryptedIdentity(EncryptedEntityParser parser) : base(parser)
        {
            points = parser.Points;
        }

        public Identity Decrypt(IdentityDecryptKey decryptKey)
        {
            Check(decryptKey, true);
            ECPoint point = points[1].Subtract(points[0].Multiply(decryptKey.PrivateKey)).Normalize();
            return new Identity(point);
        }
    }
}