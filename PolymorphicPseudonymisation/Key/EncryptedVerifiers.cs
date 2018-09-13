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

        public EncryptedVerifier IdentityVerifier { get; }

        public EncryptedVerifier PseudonymVerifier { get; }
    }
}