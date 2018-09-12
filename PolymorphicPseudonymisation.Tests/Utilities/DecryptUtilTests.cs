using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolymorphicPseudonymisation.Utilities;

namespace PolymorphicPseudonymisation.Tests.Utilities
{
    [TestClass]
    [DeploymentItem("resources", "resources")]
    public class DecryptUtilTests
    {
        [TestMethod]
        public void GetIdentity()
        {
            var encryptedIdentity = File.ReadAllText("resources\\signed\\950053533-3-4-I.txt");

            var identityKeyPem = File.ReadAllText("resources\\keys\\id-4.pem");

            var identityDecryptKey = KeyUtilities.GetIdentityDecryptKey(identityKeyPem);
            var encryptedVerifiers = KeyUtilities.GetIdentityVerifiers(identityDecryptKey);

            var actualBsn = DecryptUtil.GetIdentity(encryptedIdentity, identityDecryptKey, encryptedVerifiers);

            Assert.AreEqual("950053533", actualBsn);
        }

        [TestMethod]
        public void GetPseudonym()
        {
            var encryptedPseudonym = File.ReadAllText("resources\\signed\\950053533-3-4-P.txt");
            var pseudoKeyPem = File.ReadAllText("resources\\keys\\pd-4.pem");
            var pseudoClosingKeyPem = File.ReadAllText("resources\\keys\\pc-4.pem");

            var pseudonymClosingKey = KeyUtilities.GetPseudonymClosingKey(pseudoClosingKeyPem);
            var pseudonymDecryptKey = KeyUtilities.GetPseudonymDecryptKey(pseudoKeyPem);
            var pseudonymVerifiers = KeyUtilities.GetPseudonymVerifiers(pseudonymDecryptKey);

            var actualPseudonym = DecryptUtil.GetPseudonym(encryptedPseudonym, pseudonymDecryptKey, pseudonymClosingKey, pseudonymVerifiers);

            Assert.AreEqual("0000004404CAC3926533F301A13500D2379D383AD8717D1585F4174473AC0A715FE4786BC0A41B1D872BABBBB8C917945E5006FBDF61BFFAEC478979C72163FAF56A645496C3038C6A1F13E0B623384DD031B16F30", actualPseudonym);
        }
    }
}
