using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Math;
using PolymorphicPseudonymisation.Crypto;
using PolymorphicPseudonymisation.Entity;
using PolymorphicPseudonymisation.Parser;
using System;
using System.IO;

namespace PolymorphicPseudonymisation.Tests.Parser
{
	[TestClass]
	[DeploymentItem("resources", "resources")]
	public class Asn1ParserTests
	{
		[TestMethod]
		public void GetBsnkType_Succeeds()
		{
			var encryptedIdentity = File.ReadAllText("resources/signed/950053533-3-4-I.txt");
			var encodedData = Convert.FromBase64String(encryptedIdentity);

			var bsnkType = Asn1Parser.GetBsnkType(encodedData);

			Assert.AreEqual(Constants.SignedEncryptedIdentityName, bsnkType);
		}

		[TestMethod]
		public void GetEncryptedEntity_Identity_Succeeds()
		{
			var encryptedIdentity = File.ReadAllText("resources/signed/950053533-3-4-I.txt");
			var encodedData = Convert.FromBase64String(encryptedIdentity);

			var payload = Asn1Parser.GetSignedPayload(encodedData);

			var entity = Asn1Parser.GetEncryptedEntity<EncryptedIdentity>(payload, false);

			Assert.AreEqual(1, entity.SchemeVersion);
			Assert.AreEqual(11, entity.SchemeKeyVersion);
			Assert.AreEqual("00000000000000000004", entity.Recipient);
			Assert.AreEqual(44, entity.RecipientKeySetVersion);
		}

		[TestMethod]
		public void GetEncryptedEntity_Pseudonym_Succeeds()
		{
			var encryptedPseudonym = File.ReadAllText("resources/signed/900095222-2-4-P.txt");
			var encodedData = Convert.FromBase64String(encryptedPseudonym);

			var payload = Asn1Parser.GetSignedPayload(encodedData);

			var pseudonym = Asn1Parser.GetEncryptedEntity<EncryptedPseudonym>(payload, true);

			Assert.AreEqual(1, pseudonym.SchemeVersion);
			Assert.AreEqual(11, pseudonym.SchemeKeyVersion);
			Assert.AreEqual("00000000000000000004", pseudonym.Recipient);
			Assert.AreEqual(44, pseudonym.RecipientKeySetVersion);
		}

		[TestMethod]
		public void GetSignature_Succeeds()
		{
			var encryptedPseudonym = File.ReadAllText("resources/signed/900095222-2-4-P.txt");
			var encodedData = Convert.FromBase64String(encryptedPseudonym);

			var signature = Asn1Parser.GetSignature(encodedData);
			var expectedSignature = new EcSchnorrSignature(
				new BigInteger("107553452174033572320097286497696886003190384098237946520654141077292915400099016842332970896155"),
				new BigInteger("650320884538172458495892042411932561278118502434808303605427167594392943078504317702364621375984")
			);

			Assert.AreEqual(expectedSignature.ToString(), signature.ToString());
		}
	}
}
