using System;

namespace PolymorphicPseudonymisation
{
    public class PolymorphicPseudonymisationException : Exception
    {
        public PolymorphicPseudonymisationException(string message) : base(message)
        {
        }

        public PolymorphicPseudonymisationException(string message, Exception innerException) : base(message,
            innerException)
        {
        }
    }
}