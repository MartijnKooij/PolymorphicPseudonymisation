using System;
using System.Runtime.Serialization;

namespace PolymorphicPseudonymisation.Exceptions
{
    [Serializable]
    public class PolymorphicPseudonymisationException : Exception
    {
        public PolymorphicPseudonymisationException(string message) : base(message)
        {
        }

        protected PolymorphicPseudonymisationException(string message, Exception innerException) : base(message,
            innerException)
        {
        }

        // Without this constructor, deserialization will fail
        protected PolymorphicPseudonymisationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        public PolymorphicPseudonymisationException()
        {
        }
    }
}