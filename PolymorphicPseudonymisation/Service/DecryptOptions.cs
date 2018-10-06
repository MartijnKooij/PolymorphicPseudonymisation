using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Service
{
    public class DecryptOptions
    {
        /// <summary>
        /// Identity verification point
        /// </summary>
        public string IdentityPoint { private get; set; }

        /// <summary>
        /// Pseudonym verification point
        /// </summary>
        public string PseudonymPoint { private get; set; }

        /// <summary>
        /// PEM EC PRIVATE KEY for the identity
        /// </summary>
        public string IdentityPem { private get; set; }

        /// <summary>
        /// PEM EC PRIVATE KEY for the pseudonym
        /// </summary>
        public string PseudoKeyPem { private get; set; }

        /// <summary>
        /// PEM EC PRIVATE KEY for the pseudonym's closing key
        /// </summary>
        public string PseudoClosingKeyPem { private get; set; }

        internal void Validate()
        {
            if (string.IsNullOrEmpty(IdentityPoint))
            {
                throw new DecryptOptionsException(nameof(IdentityPoint));
            }
            if (string.IsNullOrEmpty(PseudonymPoint))
            {
                throw new DecryptOptionsException(nameof(PseudonymPoint));
            }

            if (string.IsNullOrEmpty(IdentityPem))
            {
                throw new DecryptOptionsException(nameof(IdentityPem));
            }
            if (string.IsNullOrEmpty(PseudoKeyPem))
            {
                throw new DecryptOptionsException(nameof(PseudoKeyPem));
            }
            if (string.IsNullOrEmpty(PseudoClosingKeyPem))
            {
                throw new DecryptOptionsException(nameof(PseudoClosingKeyPem));
            }
        }

        internal EncryptedVerifiers GetIdentityVerifiers()
        {
            var identityDecryptKey = GetIdentityDecryptKey();

            return identityDecryptKey.ToVerifiers(IdentityPoint);
        }

        internal EncryptedVerifiers GetPseudonymVerifiers()
        {
            var pseudonymDecryptKey = GetPseudonymDecryptKey();

            return pseudonymDecryptKey.ToVerifiers(PseudonymPoint);
        }

        internal IdentityDecryptKey GetIdentityDecryptKey()
        {
            return DecryptKey.FromPem<IdentityDecryptKey>(IdentityPem);
        }

        internal PseudonymDecryptKey GetPseudonymDecryptKey()
        {
            return DecryptKey.FromPem<PseudonymDecryptKey>(PseudoKeyPem);
        }

        internal PseudonymClosingKey GetPseudonymClosingKey()
        {
            return DecryptKey.FromPem<PseudonymClosingKey>(PseudoClosingKeyPem);
        }
    }
}