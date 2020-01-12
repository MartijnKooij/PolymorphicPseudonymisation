using Microsoft.Extensions.Options;
using PolymorphicPseudonymisation.Entity;
using PolymorphicPseudonymisation.Utilities;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("PolymorphicPseudonymisation.Tests")]
namespace PolymorphicPseudonymisation.Service
{
    public class DecryptService : IDecryptService
    {
        private readonly DecryptOptions options;

        public DecryptService(IOptions<DecryptOptions> options)
        {
            Guard.AssertNotNull(options, nameof(options));

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