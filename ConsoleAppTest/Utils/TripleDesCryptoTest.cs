using System.Text;
using ConsoleApp.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

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

    [Fact]
    public void TestDecryptActualPayload()
    {
        var key = Convert.FromHexString("8362BF4E27DD17C88362BF4E27DD17C8");
        var iv = Convert.FromHexString("0000000000000000");
        var ciphertext = Convert.FromHexString("E53C294C12F05F33E9DBC268000FE4C67063D493B33677DD");

        var engine = new DesEdeEngine();
        engine.Init(true, new KeyParameter(Convert.FromHexString("8362BF4E27DD17C88362BF4E27DD17C88362BF4E27DD17C8"))); // true for encrypt

        var blockCount = ciphertext.Length / 8;
        var plaintext = new byte[ciphertext.Length];
        var previousBlock = new byte[8];
        Array.Copy(iv, previousBlock, 8);

        for (int i = 0; i < blockCount; i++)
        {
            var block = new byte[8];
            Array.Copy(ciphertext, i * 8, block, 0, 8);

            // Encrypt block
            var encryptedBlock = new byte[8];
            engine.ProcessBlock(block, 0, encryptedBlock, 0);

            // XOR with previous block
            for (int j = 0; j < 8; j++)
            {
                plaintext[i * 8 + j] = (byte)(encryptedBlock[j] ^ previousBlock[j]);
            }

            Array.Copy(block, previousBlock, 8);
        }

        var expectedPlaintext = Convert.FromHexString("00000000000000000000000000000000011DD9EAC2000000");
        Assert.Equal(expectedPlaintext, plaintext);
    }
}
