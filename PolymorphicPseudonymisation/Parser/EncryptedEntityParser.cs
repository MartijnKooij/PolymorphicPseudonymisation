using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Parser
{
    public class EncryptedEntityParser
    {
        private const string EcSchnorrSha384Oid = "0.4.0.127.0.7.1.1.4.3.3";
        private readonly Asn1Parser parser;

        public BsnkType BsnkType { get; private set; }
        public int SchemeVersion { get; private set; }
        public int SchemeKeyVersion { get; private set; }
        public string Creator { get; private set; }
        public string Recipient { get; private set; }
        public int RecipientKeySetVersion { get; private set; }
        public string Diversifier { get; set; }
        public char Type { get; set; }
        public ECPoint[] Points { get; set; }

        public EncryptedEntityParser(byte[] encoded)
        {
            parser = new Asn1Parser(encoded);
        }

        public virtual void Decode(EncryptedVerifiers verifiers)
        {
            try
            {
                BsnkType = parser.CheckHeader();
                switch (BsnkType.ObjectIdentifier)
                {
                    case BsnkType.EncryptedIdentityName:
                        DecodePayload(parser, false);
                        return;
                    case BsnkType.EncryptedPseudonymName:
                        DecodePayload(parser, true);
                        return;
                    case BsnkType.SignedEncryptedIdentityName:
                        if (verifiers?.IdentityVerifier == null)
                        {
                            throw new ParsingException("No verifier for identity found");
                        }

                        DecodeSigned(false, verifiers.IdentityVerifier);
                        return;
                    case BsnkType.SignedEncryptedPseudonymName:
                        if (verifiers?.PseudonymVerifier == null)
                        {
                            throw new ParsingException("No verifier for pseudonym found");
                        }

                        DecodeSigned(true, verifiers.PseudonymVerifier);
                        return;
                    default:
                        throw new ParsingException($"Cannot handle type {BsnkType.ObjectIdentifier}");
                }
            }
            catch (IOException e)
            {
                throw new ParsingException("Could not read ASN1", e);
            }
        }

        private void DecodeSigned(bool isPseudonym, EncryptedVerifier verifier)
        {
            try
            {
                var payload = parser.ReadObject<DerSequenceParser>().ToAsn1Object().GetDerEncoded();
                var payloadParser = new Asn1Parser(payload);
                payloadParser.ReadObject<DerSequenceParser>();

                BsnkType = payloadParser.CheckHeader();
                switch (BsnkType.ObjectIdentifier)
                {
                    case BsnkType.EncryptedIdentityName:
                        if (isPseudonym)
                        {
                            throw new ParsingException("Encrypted identity inside signed encrypted pseudonym");
                        }

                        DecodePayload(payloadParser, false);
                        break;
                    case BsnkType.EncryptedPseudonymName:
                        if (!isPseudonym)
                        {
                            throw new ParsingException("Encrypted pseudonym inside signed encrypted identity");
                        }

                        DecodePayload(payloadParser, true);
                        break;
                    default:
                        throw new ParsingException($"Cannot handle type {BsnkType}");
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
            SchemeVersion = payloadParser.ReadObject<DerInteger>().Value.IntValue;
            SchemeKeyVersion = payloadParser.ReadObject<DerInteger>().Value.IntValue;
            Creator = payloadParser.ReadObject<DerIA5String>().GetString();
            Recipient = payloadParser.ReadObject<DerIA5String>().GetString();
            RecipientKeySetVersion = payloadParser.ReadObject<DerInteger>().Value.IntValue;

            if (isPseudonym)
            {
                var obj = payloadParser.ReadObject();
                if (obj is DerIA5String derIa5String)
                {
                    Diversifier = derIa5String.GetString();
                    //TODO: Is this the correct conversion from java?
                    //type = (char) payloadParser.readObject(ASN1Integer.class).getValue().byteValue();
                    Type = (char) payloadParser.ReadObject<DerInteger>().Value.SignValue;
                }
                else
                {
                    //TODO: Is this the correct conversion from java?
                    //type = (char) Asn1Parser.checkObject(obj, ASN1Integer.class).getValue().byteValue();
                    Type = (char) Asn1Parser.CheckObject<DerInteger>(obj).Value.SignValue;
                }
            }

            payloadParser.ReadObject<DerSequenceParser>();

            Points = new ECPoint[3];
            for (var i = 0; i < Points.Length; i++)
            {
                var octet =
                    (DerOctetString) payloadParser.ReadObject<DerOctetStringParser>().ToAsn1Object();
                try
                {
                    Points[i] = BrainpoolP320R1.Curve.DecodePoint(octet.GetOctets());
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
    }
}
