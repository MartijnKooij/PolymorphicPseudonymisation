using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Parser;

namespace PolymorphicPseudonymisation.Key
{
    public abstract class DecryptKey : Identifiable
    {
        private readonly ECPoint publicKey;

        public static DecryptKey FromPem(string pem)
        {
            var parser = new DecryptKeyParser(pem);
            parser.Decode();
            switch (parser.GetDecryptKeyType().Name)
            {
                case DecryptKeyType.IdentityDecryptionName:
                    return new IdentityDecryptKey(parser);
                case DecryptKeyType.PseudonymDecryptionName:
                    return new PseudonymDecryptKey(parser);
                case DecryptKeyType.PseudonymClosingName:
                    return new PseudonymClosingKey(parser);
                default:
                    throw new PolymorphicPseudonymisationException($"Unknown type {parser.GetDecryptKeyType().Name}");
            }
        }

        public static T FromPem<T>(string pem) where T : DecryptKey
        {
            var key = FromPem(pem);
            if (!(key is T))
            {
                throw new PolymorphicPseudonymisationException(
                    $"Expected instance of {typeof(T).Name}, got {key.GetType().Name}");
            }

            return (T) key;
        }

        protected DecryptKey(DecryptKeyParser parser)
        {
            SchemeVersion = parser.GetSchemeVersion();
            SchemeKeyVersion = parser.GetSchemeKeyVersion();
            Recipient = parser.GetRecipient();
            RecipientKeySetVersion = parser.GetRecipientKeySetVersion();
            PrivateKey = parser.GetPrivateKey();
            publicKey = parser.GetPublicKey();
        }

        public override int SchemeVersion { get; }

        public override int SchemeKeyVersion { get; }

        public override string Recipient { get; }

        public override int RecipientKeySetVersion { get; }

        public virtual BigInteger PrivateKey { get; }

        public virtual ECPoint PublicKey => publicKey;

        /// <summary>
        /// Convert decrypt key to encrypted verifier for this key
        /// </summary>
        public virtual EncryptedVerifier GetVerifier(string verificationPoint)
        {
            var point = BrainpoolP320R1.Curve.DecodePoint(Convert.FromBase64String(verificationPoint));
            return new EncryptedVerifier(publicKey, point);
        }
    }
}
