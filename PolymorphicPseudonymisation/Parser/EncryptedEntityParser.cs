using System.IO;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Entity;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Parser
{
    public static class EncryptedEntityParser
    {
        public static EncryptedEntity Decode(byte[] encoded, EncryptedVerifier verifier)
        {
            try
            {
                var bsnkType = Asn1Parser.GetBsnkType(encoded);

                // Unsigned entities don't require signature verification
                switch (bsnkType)
                {
                    case Constants.EncryptedIdentityName:
                        return Asn1Parser.GetEncryptedEntity<EncryptedIdentity>(encoded, false);
                    case Constants.EncryptedPseudonymName:
                        return Asn1Parser.GetEncryptedEntity<EncryptedPseudonym>(encoded, true);
                }

                if (verifier == null)
                {
                    throw new ParsingException($"No verifier for decoding entity with BSNk type [{bsnkType}] found");
                }

                byte[] signedPayload;
                Signature signature;

                switch (bsnkType)
                {
                    case Constants.SignedEncryptedIdentityName:
                        signedPayload = Asn1Parser.GetSignedPayload(encoded);
                        var signedEncryptedIdentity = Asn1Parser.GetEncryptedEntity<EncryptedIdentity>(signedPayload, false);

                        signature = Asn1Parser.GetSignature(encoded);
                        verifier.Verify(signedPayload, signature);

                        return signedEncryptedIdentity;
                    case Constants.SignedEncryptedIdentityNameV2:
                        signedPayload = Asn1Parser.GetSignedPayload(encoded);
                        var signedEncryptedIdentityV2 = Asn1Parser.GetEncryptedEntity<EncryptedIdentity>(signedPayload, false);

                        signature = Asn1Parser.GetSignatureV2(encoded);
                        verifier.Verify(signedPayload, signature);

                        return signedEncryptedIdentityV2;
                    case Constants.SignedEncryptedPseudonymName:
                        signedPayload = Asn1Parser.GetSignedPayload(encoded);
                        var signedEncryptedPseudonym = Asn1Parser.GetEncryptedEntity<EncryptedPseudonym>(signedPayload, true);

                        signature = Asn1Parser.GetSignature(encoded);
                        verifier.Verify(signedPayload, signature);

                        return signedEncryptedPseudonym;
                    case Constants.SignedEncryptedPseudonymNameV2:
                        signedPayload = Asn1Parser.GetSignedPayload(encoded);
                        var signedEncryptedPseudonymV2 = Asn1Parser.GetEncryptedEntity<EncryptedPseudonym>(signedPayload, true);

                        signature = Asn1Parser.GetSignatureV2(encoded);
                        verifier.Verify(signedPayload, signature);

                        return signedEncryptedPseudonymV2;
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