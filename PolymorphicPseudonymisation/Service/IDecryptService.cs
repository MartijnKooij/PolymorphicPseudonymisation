namespace PolymorphicPseudonymisation.Service
{
    public interface IDecryptService
    {
        /// <summary>
        /// Decrypts the encrypted identity
        /// </summary>
        /// <param name="encryptedIdentity"></param>
        /// <returns></returns>
        string GetIdentity(string encryptedIdentity);

        /// <summary>
        /// Decrypts the encrypted pseudonym
        /// </summary>
        /// <param name="encryptedPseudonym"></param>
        /// <returns></returns>
        string GetPseudonym(string encryptedPseudonym);
    }
}
