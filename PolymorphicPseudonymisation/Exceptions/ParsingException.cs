using System;

namespace PolymorphicPseudonymisation.Exceptions
{
    public class ParsingException : PolymorphicPseudonymisationException
    {
        internal ParsingException(string message) : base(message)
        {
        }

        internal ParsingException(string message, Exception throwable) : base(message, throwable)
        {
        }
    }
}
