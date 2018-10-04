using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Service
{
    public interface IDecryptService
    {
        /// <summary>
        /// Decrypts the encrypted identity
        /// </summary>
        /// <param name="encryptedIdentity"></param>
        /// <param name="decryptKey"></param>
        /// <param name="verifiers"></param>
        /// <returns></returns>
        string GetIdentity(
            string encryptedIdentity, IdentityDecryptKey decryptKey, EncryptedVerifiers verifiers);

        /// <summary>
        /// Decrypts the encrypted pseudonym
        /// </summary>
        /// <param name="encryptedPseudonym"></param>
        /// <param name="decryptKey"></param>
        /// <param name="closingKey"></param>
        /// <param name="verifiers"></param>
        /// <returns></returns>
        string GetPseudonym(
            string encryptedPseudonym, PseudonymDecryptKey decryptKey, PseudonymClosingKey closingKey, EncryptedVerifiers verifiers);
    }
}
