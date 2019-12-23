using Org.BouncyCastle.Asn1;
using PolymorphicPseudonymisation.Exceptions;

namespace PolymorphicPseudonymisation.Parser
{
    public static class Asn1StreamParserExtensions
    {
        public static T ReadObject<T>(this Asn1StreamParser parser) where T : IAsn1Convertible
        {
            var obj = parser.ReadObject();
            return CheckObject<T>(obj);
        }

        public static T CheckObject<T>(IAsn1Convertible obj) where T : IAsn1Convertible
        {
            if (obj == null)
            {
                throw new ParsingException($"ASN1 decode error, expected {typeof(T).Name}, got null");
            }

            if (typeof(T).Name != obj.GetType().Name)
            {
                throw new ParsingException(
                    $"ASN1 decode error, expected {typeof(T).Name}, got {obj.GetType().Name}");
            }

            return (T)obj;
        }
    }
}