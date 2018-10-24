using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.IO.Pem;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Parser
{
    public class DecryptKeyParser
    {
        private readonly Dictionary<string, Func<DecryptKey>> validDecryptTypes;

        private readonly string pemContents;

        private int schemeVersion;
        private int schemeKeyVersion;
        private string decryptKeyType;
        private string recipient;
        private int recipientKeySetVersion;
        private BigInteger privateKey;
        private ECPoint publicKey;

        public DecryptKeyParser(string pemContents)
        {
            this.pemContents = pemContents;

            validDecryptTypes = new Dictionary<string, Func<DecryptKey>>
            {
                {"EI Decryption", Create<IdentityDecryptKey>},
                {"EP Decryption", Create<PseudonymDecryptKey>},
                {"EP Closing", Create<PseudonymClosingKey>}
            };
        }

        public void Decode()
        {
            try
            {
                var pemObject = ReadPemObject();

                DecodeHeaders(pemObject.Headers);
                DecodeContent(pemObject.Content);
            }
            catch (IOException e)
            {
                throw new ParsingException("Could not read PEM", e);
            }
        }

        public DecryptKey GetContent()
        {
            if (validDecryptTypes.ContainsKey(decryptKeyType))
            {
                return validDecryptTypes[decryptKeyType].Invoke();
            }

            throw new PolymorphicPseudonymisationException($"Unknown type {decryptKeyType}");
        }

        private PemObject ReadPemObject()
        {
            var pemReader = new PemReader(new StringReader(pemContents));
            var pem = pemReader.ReadPemObject();
            if (!"EC PRIVATE KEY".Equals(pem.Type))
            {
                throw new ParsingException($"Expected EC PRIVATE KEY, got {pem.Type}");
            }

            return pem;
        }

        private void DecodeHeaders(IEnumerable headers)
        {
            var pemHeaders = headers.OfType<PemHeader>().ToList();

            //All these headers are required, so they will throw if not found
            schemeVersion = TryParseVersion("SchemeVersion", pemHeaders.First(x => x.Name == "SchemeVersion").Value);
            schemeKeyVersion = TryParseVersion("SchemeKeyVersion", pemHeaders.First(x => x.Name == "SchemeKeyVersion").Value);
            decryptKeyType = pemHeaders.First(x => x.Name == "Type").Value;
            recipient = pemHeaders.First(x => x.Name == "Recipient").Value;
            recipientKeySetVersion = TryParseVersion("RecipientKeySetVersion", pemHeaders.First(x => x.Name == "RecipientKeySetVersion").Value);

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

        private static int TryParseVersion(string name, string value)
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

        private T Create<T>() where T : DecryptKey, new()
        {
            return new T
            {
                SchemeVersion = schemeVersion,
                SchemeKeyVersion = schemeKeyVersion,
                Recipient = recipient,
                RecipientKeySetVersion = recipientKeySetVersion,
                PrivateKey = privateKey,
                PublicKey = publicKey,
            };
        }
    }
}