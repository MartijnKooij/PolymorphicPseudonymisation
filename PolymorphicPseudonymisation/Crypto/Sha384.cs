using System.Security.Cryptography;

namespace PolymorphicPseudonymisation.Crypto
{
    public static class Sha384
    {
        public static SHA384 Instance => SHA384.Create();
    }
}