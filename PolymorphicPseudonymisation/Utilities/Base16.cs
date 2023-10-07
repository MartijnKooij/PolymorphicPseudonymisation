using System.Text;

namespace PolymorphicPseudonymisation.Utilities
{
    public static class Base16Util
    {
        private static readonly char[] HexCharacters =
            { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

        public static string Encode(byte[] byteArray)
        {
            Guard.AssertNotNull(byteArray, nameof(byteArray));

            var hexBuffer = new StringBuilder(byteArray.Length * 2);
            foreach (var byteValue in byteArray)
                for (var j = 1; j >= 0; j--)
                    hexBuffer.Append(HexCharacters[(byteValue >> (j * 4)) & 0xF]);

            return hexBuffer.ToString();
        }
    }
}