using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolymorphicPseudonymisation.Crypto;

namespace PolymorphicPseudonymisation.Tests.Crypto
{
    [TestClass]
    [DeploymentItem("resources", "resources")]
    public class CmsTests
    {
        [TestMethod]
        public void GetIdentity_Succeeds()
        {
            var expectedPem = File.ReadAllText("resources\\keys\\id-4.pem");

            var actualPem = Cms.ConvertToPem("resources\\p7\\ID-4.p7", "resources\\private.p8");

            Assert.AreEqual(expectedPem, actualPem);
        }
    }
}