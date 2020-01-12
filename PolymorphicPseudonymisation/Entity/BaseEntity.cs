namespace PolymorphicPseudonymisation.Entity
{
    public abstract class BaseEntity
    {
        protected abstract string Standard { get; }

        public override string ToString()
        {
            return Standard;
        }
    }
}
