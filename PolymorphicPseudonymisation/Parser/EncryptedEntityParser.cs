using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Entity;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Parser
{
    public class EncryptedEntityParser
    {
        private const string EcSchnorrSha384Oid = "0.4.0.127.0.7.1.1.4.3.3";

        private const string EncryptedIdentityName = "2.16.528.1.1003.10.1.2.1";
        private const string EncryptedPseudonymName = "2.16.528.1.1003.10.1.2.2";
        private const string SignedEncryptedIdentityName = "2.16.528.1.1003.10.1.2.3";
        private const string SignedEncryptedPseudonymName = "2.16.528.1.1003.10.1.2.4";

        private readonly Dictionary<string, Func<EncryptedEntity>> validBsnkTypes;
        private readonly Asn1Parser parser;

        private string bsnkType;
        private int schemeVersion;
        private int schemeKeyVersion;
        private string recipient;
        private int recipientKeySetVersion;
        private ECPoint[] points;

        public EncryptedEntityParser(byte[] encoded)
        {
            parser = new Asn1Parser(encoded);

            validBsnkTypes = new Dictionary<string, Func<EncryptedEntity>>
            {
                {EncryptedIdentityName, Create<EncryptedIdentity>},
                {SignedEncryptedIdentityName, Create<EncryptedIdentity>},
                {EncryptedPseudonymName, Create<EncryptedPseudonym>},
                {SignedEncryptedPseudonymName, Create<EncryptedPseudonym>}
            };
        }

        public void Decode(EncryptedVerifier verifier)
        {
            try
            {
                bsnkType = parser.GetBsnkType();
                switch (bsnkType)
                {
                    case EncryptedIdentityName:
                        DecodePayload(parser, false);
                        return;
                    case EncryptedPseudonymName:
                        DecodePayload(parser, true);
                        return;
                    case SignedEncryptedIdentityName:
                        if (verifier == null)
                        {
                            throw new ParsingException("No verifier for identity found");
                        }

                        DecodeSigned(false, verifier);
                        return;
                    case SignedEncryptedPseudonymName:
                        if (verifier == null)
                        {
                            throw new ParsingException("No verifier for pseudonym found");
                        }

                        DecodeSigned(true, verifier);
                        return;
                    default:
                        throw new ParsingException($"Cannot handle type {bsnkType}");
                }
            }
            catch (IOException e)
            {
                throw new ParsingException("Could not read ASN1", e);
            }
        }

        public EncryptedEntity GetContent()
        {
            if (validBsnkTypes.ContainsKey(bsnkType))
            {
                return validBsnkTypes[bsnkType].Invoke();
            }

            throw new PolymorphicPseudonymisationException($"Unexpected type {bsnkType}");
        }


        private void DecodeSigned(bool isPseudonym, EncryptedVerifier verifier)
        {
            try
            {
                var payload = parser.ReadObject<DerSequenceParser>().ToAsn1Object().GetDerEncoded();
                var payloadParser = new Asn1Parser(payload);
                payloadParser.ReadObject<DerSequenceParser>();

                bsnkType = payloadParser.GetBsnkType();
                switch (bsnkType)
                {
                    case EncryptedIdentityName:
                        if (isPseudonym)
                        {
                            throw new ParsingException("Encrypted identity inside signed encrypted pseudonym");
                        }

                        DecodePayload(payloadParser, false);
                        break;
                    case EncryptedPseudonymName:
                        if (!isPseudonym)
                        {
                            throw new ParsingException("Encrypted pseudonym inside signed encrypted identity");
                        }

                        DecodePayload(payloadParser, true);
                        break;
                    default:
                        throw new ParsingException($"Cannot handle type {bsnkType}");
                }

                var signature = DecodeSignature();
                verifier.Verify(payload, signature);

            }
            catch (IOException e)
            {
                throw new ParsingException("ASN1 decode error", e);
            }
        }

        private void DecodePayload(Asn1Parser payloadParser, bool isPseudonym)
        {
            schemeVersion = payloadParser.ReadObject<DerInteger>().Value.IntValue;
            schemeKeyVersion = payloadParser.ReadObject<DerInteger>().Value.IntValue;
            payloadParser.ReadObject<DerIA5String>(); //Creator, not used
            recipient = payloadParser.ReadObject<DerIA5String>().GetString();
            recipientKeySetVersion = payloadParser.ReadObject<DerInteger>().Value.IntValue;

            if (isPseudonym)
            {
                var obj = payloadParser.ReadObject();
                if (obj is DerIA5String derIa5String)
                {
                    derIa5String.GetString();
                    payloadParser.ReadObject<DerInteger>(); //Type, not used
                }
                else
                {
                    Asn1Parser.CheckObject<DerInteger>(obj); //Type, not used
                }
            }

            payloadParser.ReadObject<DerSequenceParser>();

            points = new ECPoint[3];
            for (var i = 0; i < points.Length; i++)
            {
                var octet =
                    (DerOctetString) payloadParser.ReadObject<DerOctetStringParser>().ToAsn1Object();
                try
                {
                    points[i] = BrainpoolP320R1.Curve.DecodePoint(octet.GetOctets());
                }
                catch (ArgumentException e)
                {
                    throw new ParsingException("Could not decode point on curve", e);
                }
            }
        }

        private Signature DecodeSignature()
        {
            parser.ReadObject<DerSequenceParser>();
            var objectIdentifier = parser.ReadObject<DerObjectIdentifier>().Id;
            if (!EcSchnorrSha384Oid.Equals(objectIdentifier))
            {
                throw new ParsingException($"Expected EC Schnorr SHA-384 signature, got {objectIdentifier}");
            }

            parser.ReadObject<DerSequenceParser>();
            return new Signature(
                parser.ReadObject<DerInteger>().PositiveValue,
                parser.ReadObject<DerInteger>().PositiveValue
            );
        }

        private T Create<T>() where T : EncryptedEntity, new()
        {
            return new T
            {
                SchemeVersion = schemeVersion,
                SchemeKeyVersion = schemeKeyVersion,
                Recipient = recipient,
                RecipientKeySetVersion = recipientKeySetVersion,
                Points = points
            };
        }

    }
}
