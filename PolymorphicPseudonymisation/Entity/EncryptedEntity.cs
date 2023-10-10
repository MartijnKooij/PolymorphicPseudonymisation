using System;
using Org.BouncyCastle.Math.EC;
using PolymorphicPseudonymisation.Exceptions;
using PolymorphicPseudonymisation.Key;
using PolymorphicPseudonymisation.Parser;

namespace PolymorphicPseudonymisation.Entity
{
    public class EncryptedEntity : Identifiable
    {
        protected EncryptedEntity()
        {
            Points = new ECPoint[3];
        }

        public ECPoint[] Points { get; }

        public static T FromBase64<T>(string base64, EncryptedVerifier verifier) where T : EncryptedEntity
        {
            var key = FromBase64(base64, verifier);
            if (!(key is T entity))
            {
                throw new PolymorphicPseudonymisationException(
                    $"Expected instance of {typeof(T).Name}, got {key.GetType().Name}");
            }

            return entity;
        }

        private static EncryptedEntity FromBase64(string base64, EncryptedVerifier verifier)
        {
            var encoded = Convert.FromBase64String(base64);
            return EncryptedEntityParser.Decode(encoded, verifier);
        }
    }
}