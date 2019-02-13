using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Parser;

namespace PolymorphicPseudonymisation.Key
{
    public abstract class DecryptKey : Identifiable
    {
        public BigInteger PrivateKey { get; set; }
        public ECPoint PublicKey { private get; set; }

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

        /// <summary>
        /// Convert decrypt key to encrypted verifier for this key
        /// </summary>
        protected EncryptedVerifier GetVerifier(string verificationPoint)
        {
            var point = BrainpoolP320R1.Curve.DecodePoint(Convert.FromBase64String(verificationPoint));
            return new EncryptedVerifier(PublicKey, point);
        }

        private static DecryptKey FromPem(string pem)
        {
            var parser = new DecryptKeyParser(pem);
            parser.Decode();

            return parser.GetContent();
        }
    }
}
