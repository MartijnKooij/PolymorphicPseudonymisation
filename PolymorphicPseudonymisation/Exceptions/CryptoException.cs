using System;
using System.Runtime.Serialization;

namespace PolymorphicPseudonymisation.Exceptions
{
    [Serializable]
    public class CryptoException : PolymorphicPseudonymisationException
    {
        public CryptoException(string message) : base(message)
        {
        }

        public CryptoException()
        {
        }

        public CryptoException(string message, Exception innerException) : base(message, innerException)
        {
        }

        // Without this constructor, deserialization will fail
        protected CryptoException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}