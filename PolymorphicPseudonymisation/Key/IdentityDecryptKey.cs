﻿using PolymorphicPseudonymisation.Parser;

namespace PolymorphicPseudonymisation.Key
{
    public class IdentityDecryptKey : DecryptKey
    {

        protected internal IdentityDecryptKey(DecryptKeyParser parser) : base(parser)
        {
        }

        /// <summary>
        /// Convert decrypt key to encrypted verifiers for the identity only </summary>
        /// <param name="verificationPoint"> Base64 verification point for identity </param>
        public virtual EncryptedVerifiers ToVerifiers(string verificationPoint)
        {
            return new EncryptedVerifiers(GetVerifier(verificationPoint), null);
        }
    }
}