using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Entity
{
    public class Identity : Entity
    {
        private readonly char type;
        private readonly string identifier;

        internal Identity(ECPoint point)
        {
            var encoded = point.AffineXCoord.GetEncoded().ToSigned();
            var offset = GetZeroOffset(encoded);
            sbyte[] decoded = Oaep.Decode(encoded, offset, encoded.Length - offset, 10);

            Version = decoded[0];
            type = (char)decoded[1];
            if (decoded[2] > decoded.Length - 3)
            {
                throw new PolymorphicPseudonymisationException(
                    $"Incorrect decoded identifier, length ({decoded[2]:D}) > {decoded.Length - 3:D}");
            }

            var unsignedDecoded = decoded.ToUnSigned();
            identifier = Encoding.ASCII.GetString(unsignedDecoded, 3, unsignedDecoded[2]);
        }

        public override string Standard => type == 'B' ? identifier : type + identifier;

        public virtual int Version { get; }

        public virtual char Type => type;

        public virtual string Identifier => identifier;

        private static int GetZeroOffset(IReadOnlyList<sbyte> encoded)
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