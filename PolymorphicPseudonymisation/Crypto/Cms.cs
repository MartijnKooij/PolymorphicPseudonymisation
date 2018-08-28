using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;

namespace PolymorphicPseudonymisation.Crypto
{
    public static class Cms
    {
        public static string Read(AsymmetricKeyParameter key, Stream inputStream)
        {
            try
            {
                var parser = new CmsEnvelopedDataParser(inputStream);
                var recipients = parser.GetRecipientInfos().GetRecipients().OfType<RecipientInformation>();
                var recipientInformation = recipients.First();

                var keyInfo = (KeyTransRecipientInformation)recipientInformation;

                //TODO: Not sure what this did in Java?
                //final byte[] message = keyInfo.getContent(new JceKeyTransEnvelopedRecipient(key).setProvider("BC"));
                var message = keyInfo.GetContent(key);

                return Encoding.ASCII.GetString(message);
            }
            catch (CmsException e)
            {
                throw new CryptoException("Could not read CMS", e);
            }
        }
    }
}
