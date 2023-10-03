using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Utilities;
using System;

namespace PolymorphicPseudonymisation
{
    public abstract class Identifiable
    {
        public int RecipientKeySetVersion { get; set; }
        public int SchemeVersion { get; set; }
        public int SchemeKeyVersion { get; set; }
        public string Recipient { get; set; }
        protected virtual bool ShouldCheckSetVersion { get; } = false;

        protected void Check(Identifiable other)
        {
            Guard.AssertNotNull(other, nameof(other));

            if (SchemeVersion != other.SchemeVersion)
            {
                throw new PolymorphicPseudonymisationException($"Scheme version {SchemeVersion} is not equal to {other.SchemeVersion}");
            }

            if (SchemeKeyVersion != other.SchemeKeyVersion)
            {
                throw new PolymorphicPseudonymisationException(
                    $"Scheme key version {SchemeKeyVersion} is not equal to {other.SchemeKeyVersion}");
            }

            if (!Recipient.Equals(other.Recipient, StringComparison.InvariantCultureIgnoreCase))
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