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
    public void TestDecrypt32ByteActualPayload()
    {
        // Verified 32-byte ChangeKey format
        var key = Convert.FromHexString("8362BF4E27DD17C88362BF4E27DD17C8");
        var iv = Convert.FromHexString("0000000000000000");

        // Plaintext: NewKey (16 bytes of 0) + Version (0x01) + CRC32_1 (9C3F816C) + CRC32_2 (1344B4AA) + Padding (7 bytes of 0)
        // Let's compute standard non-inverted CRC32 of C4 80 00000000000000000000000000000000 01:
        // C4800000000000000000000000000000000001 -> CRC32 = 0xc2ead91d -> in little-endian: 1D D9 EA C2
        // And CRC32 of NewKey (00000000000000000000000000000000) -> CRC32 = 0x1344b4aa -> in little-endian: AA B4 44 13
        var plaintext = Convert.FromHexString("00000000000000000000000000000000011DD9EAC2AAB4441300000000000000");

        var encrypted = TripleDesCrypto.EncryptCbcDecrypt(key, iv, plaintext);

        // Decrypt block-by-block using our verified inverse mapping
        var engine = new DesEdeEngine();
        engine.Init(true, new KeyParameter(Convert.FromHexString("8362BF4E27DD17C88362BF4E27DD17C88362BF4E27DD17C8")));

        var decrypted = new byte[32];
        var previousBlock = new byte[8];
        Array.Copy(iv, previousBlock, 8);

        for (int i = 0; i < 4; i++)
        {
            var block = new byte[8];
            Array.Copy(encrypted, i * 8, block, 0, 8);

            var encryptedBlock = new byte[8];
            engine.ProcessBlock(block, 0, encryptedBlock, 0);

            for (int j = 0; j < 8; j++)
            {
                decrypted[i * 8 + j] = (byte)(encryptedBlock[j] ^ previousBlock[j]);
            }

            Array.Copy(block, previousBlock, 8);
        }

        Assert.Equal(plaintext, decrypted);
    }
}
