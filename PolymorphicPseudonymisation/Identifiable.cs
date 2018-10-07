using PolymorphicPseudonymisation.Exceptions;

namespace PolymorphicPseudonymisation
{
    public abstract class Identifiable
    {
        public int RecipientKeySetVersion { get; protected set; }

        protected void Check(Identifiable other, bool includeKeySetVersion)
        {
            Check(this, other, includeKeySetVersion);
        }

        private static void Check(Identifiable a, Identifiable b, bool includeKeySetVersion)
        {
            if (a.SchemeVersion != b.SchemeVersion)
            {
                throw new PolymorphicPseudonymisationException($"Scheme version {a.SchemeVersion} is not equal to {b.SchemeVersion}");
            }

            if (a.SchemeKeyVersion != b.SchemeKeyVersion)
            {
                throw new PolymorphicPseudonymisationException(
                    $"Scheme key version {a.SchemeKeyVersion} is not equal to {a.SchemeKeyVersion}");
            }

            if (!a.Recipient.Equals(b.Recipient))
            {
                throw new PolymorphicPseudonymisationException($"Recipient '{a.Recipient}' is not equal to '{b.Recipient}'");
            }

            if (includeKeySetVersion && a.RecipientKeySetVersion != b.RecipientKeySetVersion)
            {
                throw new PolymorphicPseudonymisationException(
                    $"Recipient key set version {a.RecipientKeySetVersion} does not match key {b.RecipientKeySetVersion}");
            }
        }

        protected int SchemeVersion { private get; set; }
        protected int SchemeKeyVersion { private get; set; }
        protected string Recipient { private get; set; }
    }
}