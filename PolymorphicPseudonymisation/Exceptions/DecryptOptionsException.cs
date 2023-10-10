using System;
using System.Runtime.Serialization;

namespace PolymorphicPseudonymisation.Exceptions
{
    [Serializable]
    public class DecryptOptionsException : PolymorphicPseudonymisationException
    {
        public DecryptOptionsException(string option) : base($"Invalid option provided for {option}")
        {
        }

        public DecryptOptionsException()
        {
        }

        public DecryptOptionsException(string message, Exception innerException) : base(message, innerException)
        {
        }

        // Without this constructor, deserialization will fail
        protected DecryptOptionsException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}