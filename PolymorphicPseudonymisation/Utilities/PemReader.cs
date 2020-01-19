using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PolymorphicPseudonymisation.Utilities
{
    public static class PemReader
    {
        public static string DecryptPem(byte[] p7Data, byte[] p8Data, byte[] certData)
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(p8Data, out int _);
            using var cert = new X509Certificate2(certData);
            using var certWithKey = cert.CopyWithPrivateKey(rsa);

            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(p7Data);
            cms.Decrypt(new X509Certificate2Collection(certWithKey));

            var content = cms.ContentInfo.Content;
            var pemData = Encoding.UTF8.GetString(content);

            return pemData;
        }
    }
}
