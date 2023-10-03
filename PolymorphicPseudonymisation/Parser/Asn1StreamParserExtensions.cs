using Org.BouncyCastle.Asn1;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Parser
{
    public static class Asn1StreamParserExtensions
    {
        public static T ReadObject<T>(this Asn1StreamParser parser) where T : IAsn1Convertible
        {
            Guard.AssertNotNull(parser, nameof(parser));

            var obj = parser.ReadObject();
            return CheckObject<T>(obj);
        }

        public static T CheckObject<T>(IAsn1Convertible convertibleObject) where T : IAsn1Convertible
        {
            if (convertibleObject == null)
            {
                throw new ParsingException($"ASN1 decode error, expected {typeof(T).Name}, got null");
            }

            if (typeof(T).Name != convertibleObject.GetType().Name)
            {
                throw new ParsingException(
                    $"ASN1 decode error, expected {typeof(T).Name}, got {convertibleObject.GetType().Name}");
            }

            return (T)convertibleObject;
        }
    }
}