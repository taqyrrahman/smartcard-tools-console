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
    public void TestChangeKeyToAesCrc32PlaintextConstruction()
    {
        var newAesKey = new byte[16];
        byte newKeyVersion = 0x01;

        // CRC32_1 of: cmd (0xC4) + KeyNo (0x80) + newAesKey (16 bytes) + newKeyVersion (1 byte)
        var crcData1 = new byte[19];
        crcData1[0] = 0xC4; // ChangeKey command
        crcData1[1] = 0x80; // PICC Master Key No with AES type flag
        Array.Copy(newAesKey, 0, crcData1, 2, 16);
        crcData1[18] = newKeyVersion;

        var crc32_1 = DesfireCrc.CalculateCrc32(crcData1);

        // CRC32_2 of: newAesKey (16 bytes)
        var crc32_2 = DesfireCrc.CalculateCrc32(newAesKey);

        // Construct 32-byte plaintext block to be encrypted:
        // [newAesKey (16 bytes)] + [newKeyVersion (1 byte)] + [CRC32_1 (4 bytes)] + [CRC32_2 (4 bytes)] + [Padding (7 bytes of 0x00)]
        var plaintext = new byte[32];
        Array.Copy(newAesKey, 0, plaintext, 0, 16);
        plaintext[16] = newKeyVersion;
        Array.Copy(crc32_1, 0, plaintext, 17, 4);
        Array.Copy(crc32_2, 0, plaintext, 21, 4);

        var expectedPlaintext = Convert.FromHexString("00000000000000000000000000000000011DD9EAC2AAB4441300000000000000");
        Assert.Equal(expectedPlaintext, plaintext);
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

    [Fact]
    public void Test3K3DesSessionKeyDerivation()
    {
        // Verified 3-key 3DES session key derivation example from hack.cert.pl:
        // * RndB:      31 6E 6D 76 A4 49 F9 25 BA 30 4F B2 65 36 56 A2
        // * RndA:      36 C5 F8 BF 4A 09 AC 23 9E 8D A0 C7 32 51 D4 AB
        // * Expected SessKey:   36 C4 F8 BE 30 6E 6C 76 AC 22 9E 8C F8 24 BA 30 32 50 D4 AA 64 36 56 A2
        var rndB = Convert.FromHexString("316E6D76A449F925BA304FB2653656A2");
        var rndA = Convert.FromHexString("36C5F8BF4A09AC239E8DA0C73251D4AB");
        var masterKey = new byte[24]; // 3-key 3DES

        // Invoke private static GenerateSessionKey via Reflection
        var method = typeof(ConsoleApp.DesfireTools.DesfireAuth).GetMethod("GenerateSessionKey",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);

        var result = (byte[])method.Invoke(null, [rndA, rndB, masterKey])!;
        var expectedSessKey = Convert.FromHexString("36C4F8BE306E6C76AC229E8CF824BA303250D4AA643656A2");

        Assert.Equal(expectedSessKey, result);
    }

    [Fact]
    public void Test24ByteNativeAndIsoSessionKeyDerivations()
    {
        var masterKey = new byte[24]; // 24-byte key
        var method = typeof(ConsoleApp.DesfireTools.DesfireAuth).GetMethod("GenerateSessionKey",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);

        // 1. Test 24-byte key under Native (0x0A) authentication (8-byte challenges)
        // Since masterKey is all zeroes, it is treated as single DES, so session key is derived as:
        // RndA[0..3] + RndB[0..3] + RndA[0..3] + RndB[0..3] with cleared parity bits.
        var rndANative = Convert.FromHexString("0102030405060708");
        var rndBNative = Convert.FromHexString("1112131415161718");
        var resultNative = (byte[])method.Invoke(null, [rndANative, rndBNative, masterKey])!;

        var expectedSessKeyNative = Convert.FromHexString("00020204101212140002020410121214");
        Assert.Equal(expectedSessKeyNative, resultNative);

        // 2. Test 24-byte key under ISO (0x1A) authentication (16-byte challenges)
        var rndAIso = Convert.FromHexString("36C5F8BF4A09AC239E8DA0C73251D4AB");
        var rndBIso = Convert.FromHexString("316E6D76A449F925BA304FB2653656A2");
        var resultIso = (byte[])method.Invoke(null, [rndAIso, rndBIso, masterKey])!;

        var expectedSessKeyIso = Convert.FromHexString("36C4F8BE306E6C76AC229E8CF824BA303250D4AA643656A2");
        Assert.Equal(expectedSessKeyIso, resultIso);
    }
}
