using System;

namespace PolymorphicPseudonymisation.Utilities
{
    public static class ByteExtensions
    {
        public static sbyte[] ToSigned(this byte[] unsignedBytes)
        {
            return Array.ConvertAll(unsignedBytes, b => (sbyte)b);
        }

        public static byte[] ToUnSigned(this sbyte[] signedBytes)
        {
            return Array.ConvertAll(signedBytes, b => ((byte)b));
        }
    }
}