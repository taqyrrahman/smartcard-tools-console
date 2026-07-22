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

    [Fact]
    public void TestEncryptCbcDecrypt()
    {
        // Test vector from Mustafa's comment on December 23, 2015:
        var key = Convert.FromHexString("22ED09F12803567A");
        var iv = Convert.FromHexString("0000000000000000");
        var plaintext = Convert.FromHexString("00000000000000000000000000000000008BE9EDB5000000");
        var expectedCiphertext = Convert.FromHexString("E2809112B45AEB54ADAE4103C7A453FD928C5CC831753CA0");

        var result = TripleDesCrypto.EncryptCbcDecrypt(key, iv, plaintext);
        Assert.Equal(expectedCiphertext, result);
    }
}