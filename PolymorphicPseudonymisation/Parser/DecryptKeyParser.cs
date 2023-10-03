using Org.BouncyCastle.Utilities.IO.Pem;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace PolymorphicPseudonymisation.Parser
{
	public class DecryptKeyParser
	{
		private readonly List<string> validDecryptTypes = new List<string>
		{
			"EI Decryption",
			"EP Decryption",
			"EP Closing"
		};

		public DecryptKey Decode(string pemContents)
		{
			try
			{
				var pemObject = ReadPemObject(pemContents);

				var decryptKey = DecodeHeaders(pemObject.Headers);

				if (!validDecryptTypes.Contains(decryptKey.Type))
				{
					throw new PolymorphicPseudonymisationException($"Unknown type {decryptKey.Type}");
				}
				decryptKey.KeyPair = Asn1Parser.GetKeyPair(pemObject.Content);

				return decryptKey;

			}
			catch (IOException e)
			{
				throw new ParsingException("Could not read PEM", e);
			}
		}

		private static PemObject ReadPemObject(string pemContents)
		{
			var pemReader = new PemReader(new StringReader(pemContents));
			var pem = pemReader.ReadPemObject();
			if (!pem.Type.Equals("EC PRIVATE KEY", StringComparison.InvariantCultureIgnoreCase))
			{
				throw new ParsingException($"Expected EC PRIVATE KEY, got {pem.Type}");
			}

			return pem;
		}

		private static DecryptKey DecodeHeaders(IEnumerable headers)
		{
			var pemHeaders = headers.OfType<PemHeader>().ToList();

			//All these headers are required, so they will throw if not found
			return new DecryptKey
			{
				Type = pemHeaders.First(x => x.Name == "Type").Value,
				SchemeVersion = TryParseVersion("SchemeVersion", pemHeaders.First(x => x.Name == "SchemeVersion").Value),
				SchemeKeyVersion = TryParseVersion("SchemeKeyVersion", pemHeaders.First(x => x.Name == "SchemeKeyVersion").Value),
				Recipient = pemHeaders.First(x => x.Name == "Recipient").Value,
				RecipientKeySetVersion = TryParseVersion("RecipientKeySetVersion", pemHeaders.First(x => x.Name == "RecipientKeySetVersion").Value)
			};

		}

		private static int TryParseVersion(string name, string value)
		{
			int result;
			try
			{
				result = int.Parse(value, CultureInfo.InvariantCulture);
			}
			catch (FormatException e)
			{
				throw new ParsingException($"Cannot parse {value} [{name}] as integer", e);
			}

			if (result <= 0)
			{
				throw new ParsingException($"Expect {result} [{name}] to be positive");
			}

			return result;
		}
	}
}