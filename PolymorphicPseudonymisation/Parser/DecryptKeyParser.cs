using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.IO.Pem;
using PolymorphicPseudonymisation.Crypto;

namespace PolymorphicPseudonymisation.Parser
{
    public class DecryptKeyParser
    {
        private readonly string contents;
        private int schemeVersion;
        private int schemeKeyVersion;
        private DecryptKeyType type;
        private string recipient;
        private int recipientKeySetVersion;
        private BigInteger privateKey;
        private ECPoint publicKey;

        public DecryptKeyParser(string contents)
        {
            this.contents = contents;
        }

        public void Decode()
        {
            try
            {
                var pemReader = new PemReader(new StringReader(contents));
                var pem = pemReader.ReadPemObject();
                if (!"EC PRIVATE KEY".Equals(pem.Type))
                {
                    throw new ParsingException($"Expected EC PRIVATE KEY, got {pem.Type}");
                }

                var headers = pem.Headers.OfType<PemHeader>().ToList();
                DecodeHeaders(headers);
                DecodeContent(pem.Content);
            }
            catch (IOException e)
            {
                throw new ParsingException("Could not read PEM", e);
            }
        }

        public void DecodeHeaders(List<PemHeader> headers)
        {
            var mandatory = new List<string>
            {
                "SchemeVersion",
                "SchemeKeyVersion",
                "Type",
                "Recipient",
                "RecipientKeySetVersion"
            };


            foreach (var header in headers)
            {
                var name = header.Name;
                var value = header.Value;

                mandatory.Remove(name);
                switch (name)
                {
                    case "SchemeVersion":
                        schemeVersion = ParseVersion(name, value);
                        break;
                    case "SchemeKeyVersion":
                        schemeKeyVersion = ParseVersion(name, value);
                        break;
                    case "Type":
                        type = ParseType(value);
                        break;
                    case "Recipient":
                        recipient = value;
                        break;
                    case "RecipientKeySetVersion":
                        recipientKeySetVersion = ParseVersion(name, value);
                        break;
                }
            }

            if (mandatory.Any())
            {
                throw new ParsingException($"Missing headers: {mandatory}");
            }
        }

        private void DecodeContent(byte[] encoded)
        {
            var parser = new Asn1Parser(encoded);

            parser.ReadObject<DerSequenceParser>();
            var version = parser.ReadObject<DerInteger>().Value.IntValue;
            if (1 != version)
            {
                throw new ParsingException($"Expected version 1, got {version}");
            }

            var octetString = (DerOctetString) parser.ReadObject<DerOctetStringParser>().ToAsn1Object();
            privateKey = new BigInteger(1, octetString.GetOctets());

            parser.ReadObject<BerTaggedObjectParser>();
            var oid = parser.ReadObject<DerObjectIdentifier>();
            if (!BrainpoolP320R1.ObjectIdentifier.Equals(oid))
            {
                throw new ParsingException($"Expected BrainpoolP320r1 ({BrainpoolP320R1.ObjectIdentifier}), got {oid}");
            }

            var obj = parser.ReadObject();
            if (obj == null)
            {
                return;
            }

            Asn1Parser.CheckObject<BerTaggedObjectParser>(obj);
            try
            {
                publicKey = BrainpoolP320R1.Curve.DecodePoint(parser.ReadObject<DerBitString>().GetBytes()).Normalize();
            }
            catch (ArgumentException e)
            {
                throw new ParsingException("Could not decode point on curve", e);
            }

            BrainpoolP320R1.G.Multiply(privateKey).Normalize();
            if (!BrainpoolP320R1.G.Multiply(privateKey).Equals(publicKey))
            {
                throw new ParsingException("Public key does not belong to private key");
            }
        }

        private static int ParseVersion(string name, string value)
        {
            int result;
            try
            {
                result = int.Parse(value);
            }
            catch (FormatException e)
            {
                throw new ParsingException($"Cannot parse {value} [{name}] as integer", e);
            }

            if (result <= 0)
            {
                throw new ParsingException($"Expect {result} [{name}] to be positive");
            }

            return result;
        }

        private static DecryptKeyType ParseType(string value)
        {
            try
            {
                return DecryptKeyType.ToType(value);
            }
            catch (ArgumentException e)
            {
                throw new ParsingException($"Unknown type {value}", e);
            }
        }

        public int GetSchemeVersion()
        {
            return schemeVersion;
        }

        public int GetSchemeKeyVersion()
        {
            return schemeKeyVersion;
        }

        public DecryptKeyType GetDecryptKeyType()
        {
            return type;
        }

        public string GetRecipient()
        {
            return recipient;
        }

        public int GetRecipientKeySetVersion()
        {
            return recipientKeySetVersion;
        }

        public BigInteger GetPrivateKey()
        {
            return privateKey;
        }

        public ECPoint GetPublicKey()
        {
            return publicKey;
        }
    }
}
