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

    [Fact]
    public void TestChangeKeyToAesEncryptionAndCrc()
    {
        // Verified ChangeKey to AES-128 example from hack.cert.pl:
        // * New Key:     00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80 (AES)
        // * Session Key: C2 A1 E4 7B 27 10 47 12 FE 6D 00 A7 11 77 A1 9B
        // * Key Version: 0x10
        // * Expected CRC Crypto:  0x6BE6C6D2 -> in little-endian: D2 C6 E6 6B
        // * Expected Plaintext:   00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80 10 D2 C6 E6 6B 00 00 00 00 00 00 00 00 00 00 00
        // * Expected Ciphertext:  E9 F8 5E 21 94 96 C2 B5 8C 10 90 DC 39 35 FA E9 E8 40 CF 61 B3 83 D9 53 19 46 25 6B 1F 11 0C 10

        var newAesKey = Convert.FromHexString("00102030405060708090A0B0B0A09080");
        byte newKeyVersion = 0x10;
        byte keyNoWithType = 0x00; // Application Master Key No 0 (no type flag for application keys)

        // Compute CRC32
        var crcData = new byte[2 + newAesKey.Length + 1];
        crcData[0] = 0xC4; // ChangeKey command
        crcData[1] = keyNoWithType;
        Array.Copy(newAesKey, 0, crcData, 2, newAesKey.Length);
        crcData[2 + newAesKey.Length] = newKeyVersion;

        var crc32 = DesfireCrc.CalculateCrc32(crcData);
        var expectedCrc32 = Convert.FromHexString("D2C6E66B");
        Assert.Equal(expectedCrc32, crc32);

        // Plaintext payload (32 bytes)
        var plaintext = new byte[32];
        Array.Copy(newAesKey, 0, plaintext, 0, newAesKey.Length);
        plaintext[16] = newKeyVersion;
        Array.Copy(crc32, 0, plaintext, 17, 4);

        var expectedPlaintext = Convert.FromHexString("00102030405060708090A0B0B0A0908010D2C6E66B0000000000000000000000");
        Assert.Equal(expectedPlaintext, plaintext);

        // Encrypt with Session Key and Zero IV
        var aesSessionKey = Convert.FromHexString("F44B26F5C05DDD7110772281C4D066E8");
        var zeroIv = new byte[16];
        var ciphertext = AesEncrypt(aesSessionKey, zeroIv, plaintext);

        var expectedCiphertext = Convert.FromHexString("E9F85E219496C2B58C1090DC3935FAE9E840CF61B383D9531946256B1F110C10");
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    [Fact]
    public void TestChangeKeyTo3DesPlaintextAndCrc()
    {
        // Test for ChangeKey back to 16-byte 3DES (2-key 3DES) under active AES-128 session:
        // * Target Key:  00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 (2K3DES)
        // * KeyNo:       0x00
        // * Expected CRC Crypto: 0x5001FFC5 (little-endian: C5 FF 01 50)
        // * Expected Plaintext: 00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 C5 FF 01 50 00 00 00 00 00 00 00 00 00 00 00 00

        var target3DesKey = Convert.FromHexString("00102031405060708090A0B0B0A09080");
        byte keyNoWithType = 0x00; // PICC Master Key No 0 | 2K3DES flag 0x00 = 0x00

        // Compute CRC32
        var crcData = new byte[2 + target3DesKey.Length];
        crcData[0] = 0xC4; // ChangeKey command
        crcData[1] = keyNoWithType;
        Array.Copy(target3DesKey, 0, crcData, 2, target3DesKey.Length);

        var crc32 = DesfireCrc.CalculateCrc32(crcData);
        var expectedCrc32 = Convert.FromHexString("C5FF0150");
        Assert.Equal(expectedCrc32, crc32);

        // Plaintext payload (32 bytes)
        var plaintext = new byte[32];
        Array.Copy(target3DesKey, 0, plaintext, 0, target3DesKey.Length);
        Array.Copy(crc32, 0, plaintext, target3DesKey.Length, 4);

        var expectedPlaintext = Convert.FromHexString("00102031405060708090A0B0B0A09080C5FF0150000000000000000000000000");
        Assert.Equal(expectedPlaintext, plaintext);
    }
}
