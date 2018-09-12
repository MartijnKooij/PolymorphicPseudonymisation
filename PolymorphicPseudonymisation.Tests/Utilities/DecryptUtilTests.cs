using System.IO;
using System.Text;
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

            var ei = File.ReadAllText("resources\\" + "signed\\950053533-3-4-I.txt", Encoding.UTF8);
            var ep = File.ReadAllText("resources\\" + "signed\\950053533-3-4-P.txt", Encoding.UTF8);

            var simBsn = DecryptUtil.GetIdentity(ei, keys.DecryptKey, keys.Verifiers);
            var simPseudo = DecryptUtil.GetPseudonym(ep, keys.PDecryptKey, keys.PClosingKey, keys.PVerifiers);

            Assert.AreEqual("", simBsn);
            Assert.AreEqual("", simPseudo);
        }
    }
}
