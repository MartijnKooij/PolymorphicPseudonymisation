using System;

namespace PolymorphicPseudonymisation.Utilities
{
    public static class Guard
    {
        public static void AssertNotNull(object argumentValue, string argumentName)
        {
            if (argumentValue == null)
            {
                throw new ArgumentNullException(argumentName);
            }
        }
    }
}
