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

            var ei = File.ReadAllText("resources\\" + "signed\\950053533-3-4-I.txt");
            var ep = File.ReadAllText("resources\\" + "signed\\950053533-3-4-P.txt");

            var simBsn = DecryptUtil.GetIdentity(ei, keys.DecryptKey, keys.Verifiers);
            var simPseudo = DecryptUtil.GetPseudonym(ep, keys.PDecryptKey, keys.PClosingKey, keys.PVerifiers);

            Assert.AreEqual("950053533", simBsn);
            Assert.AreEqual("0000004404CAC3926533F301A13500D2379D383AD8717D1585F4174473AC0A715FE4786BC0A41B1D872BABBBB8C917945E5006FBDF61BFFAEC478979C72163FAF56A645496C3038C6A1F13E0B623384DD031B16F30", simPseudo);
        }
    }
}
