using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Tests
{
    public static class KeyUtilities
    {
        private const string IdentityPoint = "AmUppru04ghsI/FvbvV59eoX3lCUWlMAZKu1pPdlvixch5avV+aFwQg=";
        private const string PseudonymPoint = "A9GtKDUn++nl2NWtN4F/2id1gmBhxn4I6Qr9BfeMN+fjNuXGvE79qHc=";

        public static IdentityDecryptKey GetIdentityDecryptKey(string identityKeyPem)
        {
            return DecryptKey.FromPem<IdentityDecryptKey>(identityKeyPem);
        }

        public static EncryptedVerifiers GetIdentityVerifiers(IdentityDecryptKey identityDecryptKey)
        {
            return identityDecryptKey.ToVerifiers(IdentityPoint);
        }

        public static PseudonymDecryptKey GetPseudonymDecryptKey(string pseudoKeyPem)
        {
            return DecryptKey.FromPem<PseudonymDecryptKey>(pseudoKeyPem);
        }

        public static PseudonymClosingKey GetPseudonymClosingKey(string pseudoClosingKeyPem)
        {
            return DecryptKey.FromPem<PseudonymClosingKey>(pseudoClosingKeyPem);
        }

        public static EncryptedVerifiers GetPseudonymVerifiers(PseudonymDecryptKey pseudonymDecryptKey)
        {
            return pseudonymDecryptKey.ToVerifiers(PseudonymPoint);
        }
    }
}