using System;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Parser;

namespace PolymorphicPseudonymisation.Key
{
    public class DecryptKey : Identifiable
    {
        public KeyPair KeyPair { get; set; }
        public string Type { get; set; }

        protected override bool ShouldCheckSetVersion => Type != "EP Closing";

        public static DecryptKey FromPem(string pem)
        {
            var parser = new DecryptKeyParser();

            return parser.Decode(pem);
        }

        /// <summary>
        ///     Convert decrypt key to encrypted verifier for this key
        /// </summary>
        public EncryptedVerifier ToVerifier(string verificationPoint)
        {
            var point = BrainpoolP320R1.Curve.DecodePoint(Convert.FromBase64String(verificationPoint));

            return new EncryptedVerifier(KeyPair.PublicKey, point);
        }
    }
}