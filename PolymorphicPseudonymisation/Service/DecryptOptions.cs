using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Service
{
    public class DecryptOptions
    {
        /// <summary>
        /// Identity verification point
        /// </summary>
        public string IdentityPoint { get; set; }

        /// <summary>
        /// Pseudonym verification point
        /// </summary>
        public string PseudonymPoint { get; set; }

        /// <summary>
        /// PEM EC PRIVATE KEY for the identity
        /// </summary>
        public string IdentityPem { get; set; }

        /// <summary>
        /// PEM EC PRIVATE KEY for the pseudonym
        /// </summary>
        public string PseudoKeyPem { get; set; }

        /// <summary>
        /// PEM EC PRIVATE KEY for the pseudonym's closing key
        /// </summary>
        public string PseudoClosingKeyPem { get; set; }

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

        internal EncryptedVerifier GetIdentityVerifiers()
        {
            var identityDecryptKey = GetIdentityDecryptKey();

            return identityDecryptKey.ToVerifier(IdentityPoint);
        }

        internal EncryptedVerifier GetPseudonymVerifiers()
        {
            var pseudonymDecryptKey = GetPseudonymDecryptKey();

            return pseudonymDecryptKey.ToVerifier(PseudonymPoint);
        }

        internal DecryptKey GetIdentityDecryptKey()
        {
            return DecryptKey.FromPem(IdentityPem);
        }

        internal DecryptKey GetPseudonymDecryptKey()
        {
            return DecryptKey.FromPem(PseudoKeyPem);
        }

        internal DecryptKey GetPseudonymClosingKey()
        {
            return DecryptKey.FromPem(PseudoClosingKeyPem);
        }
    }
}