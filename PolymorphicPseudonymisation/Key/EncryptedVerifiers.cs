namespace PolymorphicPseudonymisation.Key
{
    /// <summary>
    /// Class that holds both a verifier for the encrypted identity and pseudonym
    /// </summary>
    public class EncryptedVerifiers
    {
        public EncryptedVerifiers(EncryptedVerifier identityVerifier, EncryptedVerifier pseudonymVerifier)
        {
            IdentityVerifier = identityVerifier;
            PseudonymVerifier = pseudonymVerifier;
        }

        public virtual EncryptedVerifier IdentityVerifier { get; }

        public virtual EncryptedVerifier PseudonymVerifier { get; }
    }
}