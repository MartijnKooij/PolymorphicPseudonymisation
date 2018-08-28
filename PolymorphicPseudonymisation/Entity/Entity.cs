namespace PolymorphicPseudonymisation.Entity
{
    public abstract class Entity
    {
        public abstract string Standard { get; }

        public virtual string Short => Standard;

        public override string ToString()
        {
            return Standard;
        }
    }
}
