using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
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

        private static void GetIdentityKeys()
        {
            // Convert P7 key to PEM
            /*using (Stream file = new FileStream("resources\\" + "p7\\ID-4.p7", FileMode.Open, FileAccess.Read))
            {
                var identityKeyPem = Cms.Read(PrivateKey, file);
                // Convert PEM to IdentityDecryptKey
                decryptKey = Key.DecryptKey.FromPem<IdentityDecryptKey>(identityKeyPem);
                // Derive verifier (for signature verifying) from key
                verifiers = decryptKey.ToVerifiers(IdentityPoint);
            }*/

        }

        private static void GetPseudoKeys()
        {
            /*using (Stream file = new FileStream("resources\\" + "p7\\PD-4.p7", FileMode.Open, FileAccess.Read))
            {
                var pseudoKeyPem = Cms.Read(PrivateKey, file);
                // Convert PEM to IdentityDecryptKey
                pDecryptKey = Key.DecryptKey.FromPem<PseudonymDecryptKey>(pseudoKeyPem);
                // Derive verifier (for signature verifying) from key
                pVerifiers = pDecryptKey.ToVerifiers(PseudonymPoint);
            }*/

            /*using (Stream file = new FileStream("resources\\" + "p7\\PC-4.p7", FileMode.Open, FileAccess.Read))
            {
                var pseudoClosingKeyPem = Cms.Read(PrivateKey, file);
                // Convert PEM to IdentityDecryptKey
                pClosingKey = Key.DecryptKey.FromPem<PseudonymClosingKey>(pseudoClosingKeyPem);
            }*/
        }

        private static AsymmetricKeyParameter PrivateKey
        {
            get
            {
                //TODO: Is this the correct conversion from java?
                //return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytesArray));
                var keyBytes = File.ReadAllBytes("resources\\" + "private.p8");
                var privateKey = PrivateKeyFactory.CreateKey(keyBytes);

                return privateKey;
            }
        }
    }
}