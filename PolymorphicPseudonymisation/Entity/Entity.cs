namespace PolymorphicPseudonymisation.Entity
{
    public abstract class Entity
    {
        public abstract string Standard { get; }

        public override string ToString()
        {
            return Standard;
        }
    }
}
