using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Parser;

namespace PolymorphicPseudonymisation.Key
{
    public class DecryptKey : Identifiable
    {
        public BigInteger PrivateKey { get; set; }
        public ECPoint PublicKey { private get; set; }

        public static DecryptKey FromPem(string pem)
        {
            var parser = new DecryptKeyParser(pem);
            parser.Decode();

            return parser.GetContent();
        }

        /// <summary>
        /// Convert decrypt key to encrypted verifier for this key
        /// </summary>
        public EncryptedVerifier ToVerifier(string verificationPoint)
        {
            var point = BrainpoolP320R1.Curve.DecodePoint(Convert.FromBase64String(verificationPoint));

            return new EncryptedVerifier(PublicKey, point);
        }
    }
}
