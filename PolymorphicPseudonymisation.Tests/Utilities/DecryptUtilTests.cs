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
        public void Decrypt()
        {
            var keys = new KeyUtil();

            //simuleer een EncryptedID (ei) en EncryptedPseudonym (ep)
            var ei = File.ReadAllText("resources\\" + "signed\\900095222-2-4-I.txt");
            var ep = File.ReadAllText("resources\\" + "signed\\900095222-2-4-P.txt");

            //Pre-load complete, Decrypt de ei en ep
            var simBsn = DecryptUtil.GetIdentity(ei, keys.DecryptKey, keys.Verifiers);
            var simPseudo = DecryptUtil.GetPseudonym(ep, keys.PDecryptKey, keys.PClosingKey, keys.PVerifiers);

            Assert.AreEqual("", simBsn);
            Assert.AreEqual("", simPseudo);
        }
    }
}
