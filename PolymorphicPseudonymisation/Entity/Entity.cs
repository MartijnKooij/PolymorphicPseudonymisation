namespace PolymorphicPseudonymisation.Entity
{
    public abstract class Entity
    {
        protected abstract string Standard { get; }

        public override string ToString()
        {
            return Standard;
        }
    }
}
