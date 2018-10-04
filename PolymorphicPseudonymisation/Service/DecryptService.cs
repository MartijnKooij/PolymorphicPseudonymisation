using PolymorphicPseudonymisation.Entity;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Service
{
    public class DecryptService : IDecryptService
    {
        /// <inheritdoc />
        public string GetIdentity(string encryptedIdentity, IdentityDecryptKey decryptKey, EncryptedVerifiers verifiers)
        {
            var entity = EncryptedEntity.FromBase64<EncryptedIdentity>(encryptedIdentity, verifiers);
            var identity = entity.Decrypt(decryptKey);

            return identity.ToString();
        }

        /// <inheritdoc />
        public string GetPseudonym(string encryptedPseudonym, PseudonymDecryptKey decryptKey, PseudonymClosingKey closingKey,
            EncryptedVerifiers verifiers)
        {
            var entity = EncryptedEntity.FromBase64<EncryptedPseudonym>(encryptedPseudonym, verifiers);
            var pseudonym = entity.Decrypt(decryptKey, closingKey);

            return pseudonym.ToString();
        }
    }
}