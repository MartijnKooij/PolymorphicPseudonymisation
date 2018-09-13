using Org.BouncyCastle.Asn1;

namespace PolymorphicPseudonymisation.Parser
{
    public class Asn1Parser
    {
        private readonly Asn1StreamParser parser;

        public Asn1Parser(byte[] encoded)
        {
            parser = new Asn1StreamParser(encoded);
        }

        public T ReadObject<T>() where T : IAsn1Convertible
        {
            var obj = ReadObject();
            return CheckObject<T>(obj);
        }

        public IAsn1Convertible ReadObject()
        {
            return parser.ReadObject();
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

            return (T) obj;
        }

        public BsnkType CheckHeader()
        {
            ReadObject<DerSequenceParser>();
            var oid = ReadObject<DerObjectIdentifier>().Id;
            try
            {
                return BsnkType.ToBsnk(oid);
            }
            catch (System.ArgumentException e)
            {
                throw new ParsingException("Unknown BsnkType", e);
            }
        }
    }
}