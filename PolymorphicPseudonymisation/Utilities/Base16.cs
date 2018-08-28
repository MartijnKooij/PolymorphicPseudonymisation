using System.Text;

namespace PolymorphicPseudonymisation.Utilities
{
    public static class Base16Util
    {
        private static readonly char[] HexCharacters =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

        public static string Encode(byte[] byteArray)
        {
            var hexBuffer = new StringBuilder(byteArray.Length * 2);
            foreach (var byteValue in byteArray)
            {
                for (var j = 1; j >= 0; j--)
                {
                    hexBuffer.Append(HexCharacters[(byteValue >> (j * 4)) & 0xF]);
                }
            }

            return hexBuffer.ToString();
        }

        public static sbyte[] Decode(string s)
        {
            var len = s.Length;
            var r = new sbyte[len / 2];
            for (var i = 0; i < r.Length; i++)
            {
                int digit1 = s[i * 2], digit2 = s[i * 2 + 1];
                if (digit1 >= '0' && digit1 <= '9')
                {
                    digit1 -= '0';
                }
                else if (digit1 >= 'A' && digit1 <= 'F')
                {
                    digit1 -= 'A' - 10;
                }

                if (digit2 >= '0' && digit2 <= '9')
                {
                    digit2 -= '0';
                }
                else if (digit2 >= 'A' && digit2 <= 'F')
                {
                    digit2 -= 'A' - 10;
                }

                r[i] = (sbyte) ((digit1 << 4) + digit2);
            }

            return r;
        }
    }
}
