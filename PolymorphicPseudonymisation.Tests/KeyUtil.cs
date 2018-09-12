using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using PolymorphicPseudonymisation.Key;

namespace PolymorphicPseudonymisation.Tests
{
    public class KeyUtil
    {
        private IdentityDecryptKey decryptKey;
        private EncryptedVerifiers verifiers;
        private EncryptedVerifiers pVerifiers;
        private PseudonymDecryptKey pDecryptKey;
        private PseudonymClosingKey pClosingKey;
        private const string IdentityPoint = "AmUppru04ghsI/FvbvV59eoX3lCUWlMAZKu1pPdlvixch5avV+aFwQg=";
        private const string PseudonymPoint = "A9GtKDUn++nl2NWtN4F/2id1gmBhxn4I6Qr9BfeMN+fjNuXGvE79qHc=";

        public KeyUtil()
        {
            GetIdentityKeys();
            GetPseudoKeys();
        }

        private void GetIdentityKeys()
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

            var identityKeyPem = File.ReadAllText("resources\\keys\\id-4.pem");
            // Convert PEM to IdentityDecryptKey
            decryptKey = Key.DecryptKey.FromPem<IdentityDecryptKey>(identityKeyPem);
            // Derive verifier (for signature verifying) from key
            verifiers = decryptKey.ToVerifiers(IdentityPoint);

        }

        private void GetPseudoKeys()
        {
            /*using (Stream file = new FileStream("resources\\" + "p7\\PD-4.p7", FileMode.Open, FileAccess.Read))
            {
                var pseudoKeyPem = Cms.Read(PrivateKey, file);
                // Convert PEM to IdentityDecryptKey
                pDecryptKey = Key.DecryptKey.FromPem<PseudonymDecryptKey>(pseudoKeyPem);
                // Derive verifier (for signature verifying) from key
                pVerifiers = pDecryptKey.ToVerifiers(PseudonymPoint);
            }*/

            var pseudoKeyPem = File.ReadAllText("resources\\keys\\pd-4.pem");
            // Convert PEM to IdentityDecryptKey
            pDecryptKey = Key.DecryptKey.FromPem<PseudonymDecryptKey>(pseudoKeyPem);
            // Derive verifier (for signature verifying) from key
            pVerifiers = pDecryptKey.ToVerifiers(PseudonymPoint);

            /*using (Stream file = new FileStream("resources\\" + "p7\\PC-4.p7", FileMode.Open, FileAccess.Read))
            {
                var pseudoClosingKeyPem = Cms.Read(PrivateKey, file);
                // Convert PEM to IdentityDecryptKey
                pClosingKey = Key.DecryptKey.FromPem<PseudonymClosingKey>(pseudoClosingKeyPem);
            }*/
            var pseudoClosingKeyPem = File.ReadAllText("resources\\keys\\pc-4.pem");

            // Convert PEM to IdentityDecryptKey
            pClosingKey = Key.DecryptKey.FromPem<PseudonymClosingKey>(pseudoClosingKeyPem);
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

        public virtual IdentityDecryptKey DecryptKey => decryptKey;

        public virtual EncryptedVerifiers Verifiers => verifiers;

        public virtual EncryptedVerifiers PVerifiers => pVerifiers;

        public virtual PseudonymDecryptKey PDecryptKey => pDecryptKey;

        public virtual PseudonymClosingKey PClosingKey => pClosingKey;
    }
}