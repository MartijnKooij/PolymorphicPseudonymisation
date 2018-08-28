using System;

namespace PolymorphicPseudonymisation.Parser
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
