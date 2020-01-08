using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Entity;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;
using System;
using System.Collections.Generic;
using System.IO;

namespace PolymorphicPseudonymisation.Parser
{
    public static class EncryptedEntityParser
    {

        public static EncryptedEntity Decode(byte[] encoded, EncryptedVerifier verifier)
        {
            try
            {
                var bsnkType = Asn1Parser.GetBsnkType(encoded);
                byte[] signedPayload;
                Signature signature;

                switch (bsnkType)
                {
                    case Constants.EncryptedIdentityName:
                        var encryptedIdentity = Asn1Parser.GetEncryptedEntity<EncryptedIdentity>(encoded, false);

                        return encryptedIdentity;
                    case Constants.EncryptedPseudonymName:
                        var encryptedPseudonym = Asn1Parser.GetEncryptedEntity<EncryptedPseudonym>(encoded, true);

                        return encryptedPseudonym;
                    case Constants.SignedEncryptedIdentityName:
                        if (verifier == null)
                        {
                            throw new ParsingException("No verifier for identity found");
                        }

                        signedPayload = Asn1Parser.GetSignedPayload(encoded);
                        var signedEncryptedIdentity = Asn1Parser.GetEncryptedEntity<EncryptedIdentity>(signedPayload, false);

                        signature = Asn1Parser.GetSignature(encoded);
                        verifier.Verify(signedPayload, signature);

                        return signedEncryptedIdentity;
                    case Constants.SignedEncryptedPseudonymName:
                        if (verifier == null)
                        {
                            throw new ParsingException("No verifier for pseudonym found");
                        }

                        signedPayload = Asn1Parser.GetSignedPayload(encoded);
                        var signedEncryptedPseudonym = Asn1Parser.GetEncryptedEntity<EncryptedPseudonym>(signedPayload, true);

                        signature = Asn1Parser.GetSignature(encoded);
                        verifier.Verify(signedPayload, signature);

                        return signedEncryptedPseudonym;
                    default:
                        throw new ParsingException($"Cannot handle type {bsnkType}");
                }
            }
            catch (IOException e)
            {
                throw new ParsingException("Could not read ASN1", e);
            }
        }
    }
}
