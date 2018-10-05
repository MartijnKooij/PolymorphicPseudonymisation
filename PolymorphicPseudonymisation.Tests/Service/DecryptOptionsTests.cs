using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Service;

namespace PolymorphicPseudonymisation.Tests.Service
{
    [TestClass]
    public class DecryptOptionsTests
    {
        private DecryptOptions options;

        [TestInitialize]
        public void Setup()
        {
            options = new DecryptOptions
            {
                IdentityPem = "IDENTITY KEY PEM DATA",
                IdentityPoint = "AmUppru04ghsI/FvbvV59eoX3lCUWlMAZKu1pPdlvixch5avV+aFwQg=",
                PseudoKeyPem = "PSEUDONYM KEY PEM DATA",
                PseudoClosingKeyPem = "PSEUDONYM CLOSING KEY PEM DATA",
                PseudonymPoint = "A9GtKDUn++nl2NWtN4F/2id1gmBhxn4I6Qr9BfeMN+fjNuXGvE79qHc="
            };
        }

        [TestMethod]
        public void Validate_OptionsAreValid()
        {
            try
            {
                options.Validate();
            }
            catch (DecryptOptionsException)
            {
                Assert.Fail("Test should have succeeded.");
            }
        }

        [TestMethod]
        public void Validate_OptionsIsMissingIdentityPem()
        {
            options.IdentityPem = "";
            try
            {
                options.Validate();
                Assert.Fail("Validate should have failed because of missing option");
            }
            catch (DecryptOptionsException e)
            {
                Assert.AreEqual("Invalid option provided for IdentityPem", e.Message);
            }
        }

        [TestMethod]
        public void Validate_OptionsIsMissingIdentityPoint()
        {
            options.IdentityPoint = "";
            try
            {
                options.Validate();
                Assert.Fail("Validate should have failed because of missing option");
            }
            catch (DecryptOptionsException e)
            {
                Assert.AreEqual("Invalid option provided for IdentityPoint", e.Message);
            }
        }

        [TestMethod]
        public void Validate_OptionsIsMissingPseudoKeyPem()
        {
            options.PseudoKeyPem = "";
            try
            {
                options.Validate();
                Assert.Fail("Validate should have failed because of missing option");
            }
            catch (DecryptOptionsException e)
            {
                Assert.AreEqual("Invalid option provided for PseudoKeyPem", e.Message);
            }
        }

        [TestMethod]
        public void Validate_OptionsIsMissingPseudoClosingKeyPem()
        {
            options.PseudoClosingKeyPem = "";
            try
            {
                options.Validate();
                Assert.Fail("Validate should have failed because of missing option");
            }
            catch (DecryptOptionsException e)
            {
                Assert.AreEqual("Invalid option provided for PseudoClosingKeyPem", e.Message);
            }
        }

        [TestMethod]
        public void Validate_OptionsIsMissingPseudonymPoint()
        {
            options.PseudonymPoint = "";
            try
            {
                options.Validate();
                Assert.Fail("Validate should have failed because of missing option");
            }
            catch (DecryptOptionsException e)
            {
                Assert.AreEqual("Invalid option provided for PseudonymPoint", e.Message);
            }
        }
    }
}