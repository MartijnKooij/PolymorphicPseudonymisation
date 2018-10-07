using System.Collections.Generic;
using System.Linq;

namespace PolymorphicPseudonymisation
{
    public class BsnkType
    {
        public const string EncryptedIdentityName = "2.16.528.1.1003.10.1.2.1";
        public const string EncryptedPseudonymName = "2.16.528.1.1003.10.1.2.2";
        public const string SignedEncryptedIdentityName = "2.16.528.1.1003.10.1.2.3";
        public const string SignedEncryptedPseudonymName = "2.16.528.1.1003.10.1.2.4";

        private static readonly BsnkType EncryptedIdentity = new BsnkType(EncryptedIdentityName);
        private static readonly BsnkType EncryptedPseudonym = new BsnkType(EncryptedPseudonymName);
        private static readonly BsnkType SignedEncryptedIdentity = new BsnkType(SignedEncryptedIdentityName);
        private static readonly BsnkType SignedEncryptedPseudonym = new BsnkType(SignedEncryptedPseudonymName);

        private static IEnumerable<BsnkType> Values
        {
            get
            {
                yield return EncryptedIdentity;
                yield return EncryptedPseudonym;
                yield return SignedEncryptedIdentity;
                yield return SignedEncryptedPseudonym;
            }

        }

        public readonly string ObjectIdentifier;

        private BsnkType(string objectIdentifier)
        {
            ObjectIdentifier = objectIdentifier;
        }

        public static BsnkType ToBsnk(string oid)
        {
            return Values.First(x => x.ObjectIdentifier == oid);
        }
    }
}