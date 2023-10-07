using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Entity
{
    public class Pseudonym : BaseEntity
    {
        private readonly ECPoint point;
        private readonly int version;

        internal Pseudonym(int version, ECPoint point)
        {
            this.version = version;
            this.point = point;
        }

        protected override string Standard => $"{version:D8}{Base16Util.Encode(point.GetEncoded(false))}";
    }
}