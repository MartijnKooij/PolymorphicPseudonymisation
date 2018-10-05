using Microsoft.Extensions.Options;
using PolymorphicPseudonymisation.Entity;

namespace PolymorphicPseudonymisation.Service
{
    public class DecryptService : IDecryptService
    {
        private readonly DecryptOptions options;

        public DecryptService(IOptions<DecryptOptions> options)
        {
            this.options = options.Value;
        }

        /// <inheritdoc />
        public string GetIdentity(string encryptedIdentity)
        {
            var entity = EncryptedEntity.FromBase64<EncryptedIdentity>(encryptedIdentity, options.GetIdentityVerifiers());
            var identity = entity.Decrypt(options.GetIdentityDecryptKey());

            return identity.ToString();
        }

        /// <inheritdoc />
        public string GetPseudonym(string encryptedPseudonym)
        {
            var entity = EncryptedEntity.FromBase64<EncryptedPseudonym>(encryptedPseudonym, options.GetPseudonymVerifiers());
            var pseudonym = entity.Decrypt(options.GetPseudonymDecryptKey(), options.GetPseudonymClosingKey());

            return pseudonym.ToString();
        }
    }
}