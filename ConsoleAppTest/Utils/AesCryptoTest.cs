using System.Security.Cryptography;
using ConsoleApp.Utils;

namespace ConsoleAppTest.Utils;

public class AesCryptoTest
{
    private static byte[] AesDecrypt(byte[] key, byte[] iv, byte[] ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    private static byte[] AesEncrypt(byte[] key, byte[] iv, byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    [Fact]
    public void TestAesAuthVector()
    {
        // Test vector from Mustafa's comment on February 9, 2016
        var key = Convert.FromHexString("00000000000000000000000000000000");
        var encRndB = Convert.FromHexString("9C3FED4067DA26E3F9BC9CFA5D583810");
        var expectedRndB = Convert.FromHexString("306CB0EA51BAD113F6FDEB7C808AE3C8");

        // Decrypt RndB
        var rndB = AesDecrypt(key, new byte[16], encRndB);
        Assert.Equal(expectedRndB, rndB);

        // Shift RndB left
        var rndBShifted = ByteManipulation.RotateLeft(rndB);
        var expectedRndBShifted = Convert.FromHexString("6CB0EA51BAD113F6FDEB7C808AE3C830");
        Assert.Equal(expectedRndBShifted, rndBShifted);

        // Generate RndA (all 01s)
        var rndA = Convert.FromHexString("01010101010101010101010101010101");

        // Concatenate RndA and RndB'
        var plaintext = rndA.Concat(rndBShifted).ToArray();

        // Encrypt using encRndB as the starting IV
        var ciphertext = AesEncrypt(key, encRndB, plaintext);

        var expectedCiphertext = Convert.FromHexString("CB02BED478B258DD12E6422EA31AC5C2FD1E00FB64779EC89100B7CA1489610D");
        Assert.Equal(expectedCiphertext, ciphertext);
    }
}
