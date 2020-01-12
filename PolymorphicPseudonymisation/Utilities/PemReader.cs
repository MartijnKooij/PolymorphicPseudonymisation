using System;
using System.Collections.Generic;
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
            using CngKey key = CngKey.Import(p8Data, CngKeyBlobFormat.Pkcs8PrivateBlob);

            // The export policy needs to be redefined because CopyWithPrivateKey
            // needs to export/re-import ephemeral keys
            key.SetProperty(
                new CngProperty(
                    "Export Policy",
                    BitConverter.GetBytes((int)CngExportPolicies.AllowPlaintextExport),
                    CngPropertyOptions.Persist));

            using RSA rsa = new RSACng(key);
            using X509Certificate2 cert = new X509Certificate2(certData);
            using X509Certificate2 certWithKey = cert.CopyWithPrivateKey(rsa);

            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(p7Data);
            cms.Decrypt(new X509Certificate2Collection(certWithKey));

            var content = cms.ContentInfo.Content;
            var pemData = Encoding.ASCII.GetString(content);

            return pemData;
        }
    }
}
