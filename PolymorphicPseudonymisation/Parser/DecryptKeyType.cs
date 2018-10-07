using System.Collections.Generic;
using System.Linq;

namespace PolymorphicPseudonymisation.Parser
{
    public sealed class DecryptKeyType
    {
        public const string IdentityDecryptionName = "EI Decryption";
        public const string PseudonymDecryptionName = "EP Decryption";
        public const string PseudonymClosingName = "EP Closing";

        private static readonly DecryptKeyType IdentityDecryption = new DecryptKeyType(IdentityDecryptionName);
        private static readonly DecryptKeyType PseudonymDecryption = new DecryptKeyType(PseudonymDecryptionName);
        private static readonly DecryptKeyType PseudonymClosing = new DecryptKeyType(PseudonymClosingName);

        private static IEnumerable<DecryptKeyType> Values
        {
            get
            {
                yield return IdentityDecryption;
                yield return PseudonymDecryption;
                yield return PseudonymClosing;
            }
        }

        public readonly string Name;

        private DecryptKeyType(string name)
        {
            Name = name;
        }

        public static DecryptKeyType ToType(string name)
        {
            return Values.First(x => x.Name == name);
        }
    }
}