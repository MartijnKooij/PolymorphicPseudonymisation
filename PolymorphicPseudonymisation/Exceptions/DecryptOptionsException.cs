namespace PolymorphicPseudonymisation.Exceptions
{
    public class DecryptOptionsException : PolymorphicPseudonymisationException
    {
        public DecryptOptionsException(string option) : base($"Invalid option provided for {option}")
        {
        }

    }
}