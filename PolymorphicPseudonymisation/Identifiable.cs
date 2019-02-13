using PolymorphicPseudonymisation.Exceptions;

namespace PolymorphicPseudonymisation
{
    public abstract class Identifiable
    {
        public int RecipientKeySetVersion { get; set; }
        public int SchemeVersion { private get; set; }
        public int SchemeKeyVersion { private get; set; }
        public string Recipient { private get; set; }
        protected virtual bool ShouldCheckSetVersion { get; } = false;

        protected void Check(Identifiable other)
        {
            if (SchemeVersion != other.SchemeVersion)
            {
                throw new PolymorphicPseudonymisationException($"Scheme version {SchemeVersion} is not equal to {other.SchemeVersion}");
            }

            if (SchemeKeyVersion != other.SchemeKeyVersion)
            {
                throw new PolymorphicPseudonymisationException(
                    $"Scheme key version {SchemeKeyVersion} is not equal to {other.SchemeKeyVersion}");
            }

            if (!Recipient.Equals(other.Recipient))
            {
                throw new PolymorphicPseudonymisationException($"Recipient '{Recipient}' is not equal to '{other.Recipient}'");
            }

            if ((ShouldCheckSetVersion || other.ShouldCheckSetVersion) && RecipientKeySetVersion != other.RecipientKeySetVersion)
            {
                throw new PolymorphicPseudonymisationException(
                    $"Recipient key set version {RecipientKeySetVersion} does not match key {other.RecipientKeySetVersion}");
            }
        }
    }
}