using System;
using System.Runtime.Serialization;

namespace PolymorphicPseudonymisation.Exceptions
{
    [Serializable]
    public class ParsingException : PolymorphicPseudonymisationException
    {
        internal ParsingException(string message) : base(message)
        {
        }

        internal ParsingException(string message, Exception throwable) : base(message, throwable)
        {
        }

        public ParsingException()
        {
        }

        // Without this constructor, deserialization will fail
        protected ParsingException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}