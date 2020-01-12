using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Entity;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;
using System;

namespace PolymorphicPseudonymisation.Parser
{
    public static class Asn1Parser
    {
        public static string GetBsnkType(byte[] encoded)
        {
            var parser = new Asn1StreamParser(encoded);

            parser.ReadObject<DerSequenceParser>();
            var oid = parser.ReadObject<DerObjectIdentifier>().Id;

            return oid;
        }

        public static byte[] GetSignedPayload(byte[] encoded)
        {
            var parser = new Asn1StreamParser(encoded);

            parser.ReadObject<DerSequenceParser>();
            parser.ReadObject<DerObjectIdentifier>();

            var payload = parser.ReadObject<DerSequenceParser>().ToAsn1Object().GetDerEncoded();

            return payload;
        }

        public static T GetEncryptedEntity<T>(byte[] encoded, bool isPseudonym) where T: EncryptedEntity, new()
        {
            var parser = new Asn1StreamParser(encoded);
            var entity = new T();

            parser.ReadObject<DerSequenceParser>();
            parser.ReadObject<DerSequenceParser>();
            var oid = parser.ReadObject<DerObjectIdentifier>().Id;
            AssertBsnkTypeIsCorrect(oid, isPseudonym);

            entity.SchemeVersion = parser.ReadObject<DerInteger>().Value.IntValue;
            entity.SchemeKeyVersion = parser.ReadObject<DerInteger>().Value.IntValue;
            parser.ReadObject<DerIA5String>(); //Creator, not used
            entity.Recipient = parser.ReadObject<DerIA5String>().GetString();
            entity.RecipientKeySetVersion = parser.ReadObject<DerInteger>().Value.IntValue;

            if (isPseudonym)
            {
                var obj = parser.ReadObject();
                if (obj is DerIA5String derIa5String)
                {
                    derIa5String.GetString();
                    parser.ReadObject<DerInteger>(); //Type, not used
                }
                else
                {
                    Asn1StreamParserExtensions.CheckObject<DerInteger>(obj); //Type, not used
                }
            }

            parser.ReadObject<DerSequenceParser>();

            for (var i = 0; i < entity.Points.Length; i++)
            {
                var octet =
                    (DerOctetString)parser.ReadObject<DerOctetStringParser>().ToAsn1Object();
                try
                {
                    entity.Points[i] = BrainpoolP320R1.Curve.DecodePoint(octet.GetOctets());
                }
                catch (ArgumentException e)
                {
                    throw new ParsingException("Could not decode point on curve", e);
                }
            }

            return entity;
        }

        private static void AssertBsnkTypeIsCorrect(string bsnkType, bool expectPseudonym)
        {
            switch (bsnkType)
            {
                case Constants.EncryptedIdentityName:
                    if (expectPseudonym)
                    {
                        throw new ParsingException("Encrypted identity inside signed encrypted pseudonym");
                    }
                    break;
                case Constants.EncryptedPseudonymName:
                    if (!expectPseudonym)
                    {
                        throw new ParsingException("Encrypted pseudonym inside signed encrypted identity");
                    }
                    break;
                default:
                    throw new ParsingException($"Cannot handle type {bsnkType}");
            }
        }

        public static Signature GetSignature(byte[] encoded)
        {
            var parser = new Asn1StreamParser(encoded);

            //BSNk type
            parser.ReadObject<DerSequenceParser>();
            var _ = parser.ReadObject<DerObjectIdentifier>().Id;
            //Payload
            parser.ReadObject<DerSequenceParser>().ToAsn1Object().GetDerEncoded();

            parser.ReadObject<DerSequenceParser>();

            var objectIdentifier = parser.ReadObject<DerObjectIdentifier>().Id;
            if (objectIdentifier != Constants.EcSchnorrSha384Oid)
            {
                throw new ParsingException($"Expected EC Schnorr SHA-384 signature, got {objectIdentifier}");
            }

            parser.ReadObject<DerSequenceParser>();

            return new Signature(
                parser.ReadObject<DerInteger>().PositiveValue,
                parser.ReadObject<DerInteger>().PositiveValue
            );
        }

        internal static KeyPair GetKeyPair(byte[] encoded)
        {
            var parser = new Asn1StreamParser(encoded);
            var keyPair = new KeyPair();

            parser.ReadObject<DerSequenceParser>();
            var version = parser.ReadObject<DerInteger>().Value.IntValue;
            if (1 != version)
            {
                throw new ParsingException($"Expected version 1, got {version}");
            }

            var octetString = (DerOctetString)parser.ReadObject<DerOctetStringParser>().ToAsn1Object();
            keyPair.PrivateKey = new BigInteger(1, octetString.GetOctets());

            parser.ReadObject<BerTaggedObjectParser>();
            var oid = parser.ReadObject<DerObjectIdentifier>();
            if (!BrainpoolP320R1.ObjectIdentifier.Equals(oid))
            {
                throw new ParsingException($"Expected BrainpoolP320r1 ({BrainpoolP320R1.ObjectIdentifier}), got {oid}");
            }

            var obj = parser.ReadObject();
            if (obj == null)
            {
                return keyPair;
            }

            Asn1StreamParserExtensions.CheckObject<BerTaggedObjectParser>(obj);
            try
            {
                keyPair.PublicKey = BrainpoolP320R1.Curve.DecodePoint(parser.ReadObject<DerBitString>().GetBytes()).Normalize();
            }
            catch (ArgumentException e)
            {
                throw new ParsingException("Could not decode point on curve", e);
            }

            BrainpoolP320R1.G.Multiply(keyPair.PrivateKey).Normalize();
            if (!BrainpoolP320R1.G.Multiply(keyPair.PrivateKey).Equals(keyPair.PublicKey))
            {
                throw new ParsingException("Public key does not belong to private key");
            }

            return keyPair;
        }
    }
}