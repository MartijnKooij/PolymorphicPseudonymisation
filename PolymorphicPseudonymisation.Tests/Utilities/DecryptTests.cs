using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Parser;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Tests.Utilities
{
    [TestClass]
    [DeploymentItem("resources", "resources")]
    public class DecryptTests
    {
        [TestMethod]
        public void GetIdentity_Succeeds()
        {
            var encryptedIdentity = File.ReadAllText("resources\\signed\\950053533-3-4-I.txt");

            var identityKeyPem = File.ReadAllText("resources\\keys\\id-4.pem");

            var identityDecryptKey = KeyUtilities.GetIdentityDecryptKey(identityKeyPem);
            var encryptedVerifiers = KeyUtilities.GetIdentityVerifiers(identityDecryptKey);

            var actualBsn = Decrypt.GetIdentity(encryptedIdentity, identityDecryptKey, encryptedVerifiers);

            Assert.AreEqual("950053533", actualBsn);
        }

        [TestMethod]
        public void GetIdentity_Fails_Pseudonym_In_Identity()
        {
            var encryptedIdentity = File.ReadAllText("resources\\signed\\pseudonym-inside-identity.txt");

            var identityKeyPem = File.ReadAllText("resources\\keys\\id-4.pem");

            var identityDecryptKey = KeyUtilities.GetIdentityDecryptKey(identityKeyPem);
            var encryptedVerifiers = KeyUtilities.GetIdentityVerifiers(identityDecryptKey);

            try
            {
                Decrypt.GetIdentity(encryptedIdentity, identityDecryptKey, encryptedVerifiers);
                Assert.Fail("Expected parsing exception.");
            }
            catch (ParsingException e)
            {
                Assert.AreEqual("Encrypted pseudonym inside signed encrypted identity", e.Message);
            }
        }

        [TestMethod]
        public void GetIdentity_Fails_Invalid_Signature()
        {
            var encryptedIdentity = File.ReadAllText("resources\\signed\\invalid-signature.txt");

            var identityKeyPem = File.ReadAllText("resources\\keys\\id-4.pem");

            var identityDecryptKey = KeyUtilities.GetIdentityDecryptKey(identityKeyPem);
            var encryptedVerifiers = KeyUtilities.GetIdentityVerifiers(identityDecryptKey);

            try
            {
                Decrypt.GetIdentity(encryptedIdentity, identityDecryptKey, encryptedVerifiers);
                Assert.Fail("Expected crypto exception.");
            }
            catch (CryptoException e)
            {
                Assert.AreEqual("Invalid signature", e.Message);
            }
        }

        [TestMethod]
        public void GetIdentity_Fails_Invalid_Signature_Type()
        {
            var encryptedIdentity = File.ReadAllText("resources\\signed\\invalid-signature-type.txt");

            var identityKeyPem = File.ReadAllText("resources\\keys\\id-4.pem");

            var identityDecryptKey = KeyUtilities.GetIdentityDecryptKey(identityKeyPem);
            var encryptedVerifiers = KeyUtilities.GetIdentityVerifiers(identityDecryptKey);

            try
            {
                Decrypt.GetIdentity(encryptedIdentity, identityDecryptKey, encryptedVerifiers);
                Assert.Fail("Expected parsing exception.");
            }
            catch (ParsingException e)
            {
                Assert.IsTrue(e.Message.StartsWith("Expected EC Schnorr SHA-384 signature"), "Expected the parsing error to start with [Expected EC Schnorr SHA-384 signature]");
            }
        }

        [TestMethod]
        public void GetIdentity_Fails_Signed_Inside_Signed()
        {
            var encryptedIdentity = File.ReadAllText("resources\\signed\\signed-inside-signed.txt");

            var identityKeyPem = File.ReadAllText("resources\\keys\\id-4.pem");

            var identityDecryptKey = KeyUtilities.GetIdentityDecryptKey(identityKeyPem);
            var encryptedVerifiers = KeyUtilities.GetIdentityVerifiers(identityDecryptKey);

            try
            {
                Decrypt.GetIdentity(encryptedIdentity, identityDecryptKey, encryptedVerifiers);
                Assert.Fail("Expected parsing exception.");
            }
            catch (ParsingException e)
            {
                Assert.AreEqual("Cannot handle type PolymorphicPseudonymisation.BsnkType", e.Message);
            }
        }

        [TestMethod]
        public void GetPseudonym_Succeeds()
        {
            var encryptedPseudonym = File.ReadAllText("resources\\signed\\950053533-3-4-P.txt");
            var pseudoKeyPem = File.ReadAllText("resources\\keys\\pd-4.pem");
            var pseudoClosingKeyPem = File.ReadAllText("resources\\keys\\pc-4.pem");

            var pseudonymClosingKey = KeyUtilities.GetPseudonymClosingKey(pseudoClosingKeyPem);
            var pseudonymDecryptKey = KeyUtilities.GetPseudonymDecryptKey(pseudoKeyPem);
            var pseudonymVerifiers = KeyUtilities.GetPseudonymVerifiers(pseudonymDecryptKey);

            var actualPseudonym = Decrypt.GetPseudonym(encryptedPseudonym, pseudonymDecryptKey, pseudonymClosingKey, pseudonymVerifiers);

            Assert.AreEqual("0000004404CAC3926533F301A13500D2379D383AD8717D1585F4174473AC0A715FE4786BC0A41B1D872BABBBB8C917945E5006FBDF61BFFAEC478979C72163FAF56A645496C3038C6A1F13E0B623384DD031B16F30", actualPseudonym);
        }

        [TestMethod]
        public void GetPseudonym_Fails_Identity_In_Pseudonym()
        {
            var encryptedPseudonym = File.ReadAllText("resources\\signed\\identity-inside-pseudonym.txt");
            var pseudoKeyPem = File.ReadAllText("resources\\keys\\pd-4.pem");
            var pseudoClosingKeyPem = File.ReadAllText("resources\\keys\\pc-4.pem");

            var pseudonymClosingKey = KeyUtilities.GetPseudonymClosingKey(pseudoClosingKeyPem);
            var pseudonymDecryptKey = KeyUtilities.GetPseudonymDecryptKey(pseudoKeyPem);
            var pseudonymVerifiers = KeyUtilities.GetPseudonymVerifiers(pseudonymDecryptKey);

            try
            {
                Decrypt.GetPseudonym(encryptedPseudonym, pseudonymDecryptKey, pseudonymClosingKey, pseudonymVerifiers);
                Assert.Fail("Expected parsing exception.");
            }
            catch (ParsingException e)
            {
                Assert.AreEqual("Encrypted identity inside signed encrypted pseudonym", e.Message);
            }
        }
    }
}
