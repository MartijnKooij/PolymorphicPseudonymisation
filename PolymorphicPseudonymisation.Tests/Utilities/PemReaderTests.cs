using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolymorphicPseudonymisation.Utilities;
using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace PolymorphicPseudonymisation.Tests.Utilities
{
    [TestClass]
    [DeploymentItem("resources", "resources")]
    public class PemReaderTests
    {
        [TestMethod]
        public void ShouldDecryptPems()
        {
            var p8Data = File.ReadAllBytes("resources/private.p8");
            var certData = File.ReadAllBytes("resources/cert.pem");

            var inputs = new[]
            {
                "resources/p7/ID-4.p7",
                "resources/p7/ID-5.p7",
                "resources/p7/PC-4.p7",
                "resources/p7/PC-5.p7",
                "resources/p7/PD-4.p7",
                "resources/p7/PD-5.p7"
            };
            var expectedOutputs = new[]
            {
                "resources/keys/id-4.pem",
                "resources/keys/id-5.pem",
                "resources/keys/pc-4.pem",
                "resources/keys/pc-5.pem",
                "resources/keys/pd-4.pem",
                "resources/keys/pd-5.pem"
            };

            for (var testCase = 0; testCase < inputs.Length; testCase+=1)
            {
                var p7Data = File.ReadAllBytes(inputs[testCase]);
                var expected = File.ReadAllText(expectedOutputs[testCase], Encoding.ASCII);

                var actual = PemReader.DecryptPem(p7Data, p8Data, certData);

                Assert.AreEqual(expected, actual, $"Test case {testCase} failed");

            }
        }
    }
}
