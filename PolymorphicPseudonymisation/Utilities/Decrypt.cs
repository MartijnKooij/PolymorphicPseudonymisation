using PolymorphicPseudonymisation.Entity;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Utilities
{
    public static class Decrypt
    {
        public static string GetIdentity(string ei, IdentityDecryptKey decryptKey, EncryptedVerifiers verifiers)
        {
            // Decrypt encrypted identity
            var encryptedIdentity = EncryptedEntity.FromBase64<EncryptedIdentity>(ei, verifiers);
            var identity = encryptedIdentity.Decrypt(decryptKey);

            return identity.ToString();
        }


        public static string GetPseudonym(string ep, PseudonymDecryptKey decryptKey, PseudonymClosingKey closingKey, EncryptedVerifiers verifiers)
        {
            // Decrypt encrypted pseudo
            var encryptedPseudo = EncryptedEntity.FromBase64<EncryptedPseudonym>(ep, verifiers);
            var pseudo = encryptedPseudo.Decrypt(decryptKey, closingKey);

            return pseudo.ToString();
        }
    }
}