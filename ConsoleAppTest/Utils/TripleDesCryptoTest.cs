using System.Text;
using ConsoleApp.Utils;

namespace ConsoleAppTest.Utils;

public class TripleDesCryptoTest
{
    [Fact]
    public void EncryptDecrypt()
    {
        var key = new byte[24];
        var iv = new byte[8];
        var plaintext = Encoding.UTF8.GetBytes("This is a secret message");
        var encrypted = TripleDesCrypto.Encrypt(key, iv, plaintext);
        var decrypted = TripleDesCrypto.Decrypt(key, iv, encrypted);
        Assert.Equal(plaintext, decrypted);
    }
}