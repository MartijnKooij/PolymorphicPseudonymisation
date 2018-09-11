using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;

namespace PolymorphicPseudonymisation.Entity
{
    public class Identity : Entity
    {
        private readonly char type;
        private readonly string identifier;

        internal Identity(ECPoint point)
        {
            var encoded = point.AffineXCoord.GetEncoded();
            var offset = GetZeroOffset(encoded);
            byte[] decoded = Oaep.Decode(encoded, offset, encoded.Length - offset, 10);

            Version = decoded[0];
            type = (char)decoded[1];
            if (decoded[2] > decoded.Length - 3)
            {
                throw new PolymorphicPseudonymisationException(
                    $"Incorrect decoded identifier, length ({decoded[2]:D}) > {decoded.Length - 3:D}");
            }

            identifier = Encoding.ASCII.GetString(decoded, 3, decoded[2]);
        }

        public override string Standard => type == 'B' ? identifier : type + identifier;

        public virtual int Version { get; }

        public virtual char Type => type;

        public virtual string Identifier => identifier;

        private static int GetZeroOffset(IReadOnlyList<byte> encoded)
        {
            for (var i = 0; i < encoded.Count; i++)
            {
                if (encoded[i] != 0)
                {
                    return i;
                }
            }

            throw new PolymorphicPseudonymisationException("Zero point");
        }
    }
}