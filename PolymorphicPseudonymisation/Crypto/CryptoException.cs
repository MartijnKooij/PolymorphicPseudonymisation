using System;

namespace PolymorphicPseudonymisation.Crypto
{
    public class CryptoException : PolymorphicPseudonymisationException
    {
        public CryptoException(string message) : base(message)
        {
        }

        public CryptoException(string message, Exception throwable) : base(message, throwable)
        {
        }
    }
}