using System.Security.Cryptography;
using ConsoleApp.Extensions;
using ConsoleApp.Utils;
using PCSC.Iso7816;

namespace ConsoleApp.DesfireTools;

public static class DesfireAuth
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

    /// <summary>
    /// Performs 3-pass mutual AES-128 authentication (0xAA).
    /// </summary>
    public static byte[] AuthenticateAes(IsoReader isoReader, byte keyNo, byte[] key)
    {
        var zeroIv = new byte[16];

        // Phase 1 — card sends encrypted RndB (16 bytes)
        var phase1 = isoReader.DfTransmit(DfConstants.Cmd.Auth.Aes, [keyNo]);
        var encRndB = phase1.GetData() ?? [];
        if (encRndB.Length != 16)
            throw new Exception($"Expected 16-byte encrypted RndB, got {encRndB.Length} bytes.");

        // Decrypt RndB using key and zero IV
        var rndB = AesDecrypt(key, zeroIv, encRndB);

        // Rotate RndB left by 1 byte to get RndB'
        var rndBShifted = ByteManipulation.RotateLeft(rndB);

        // Phase 2 — PCD generates random 16-byte RndA
        var rndA = RandomNumberGenerator.GetBytes(16);

        // Concatenate RndA and RndB' (32 bytes total)
        var plaintext = rndA.Concat(rndBShifted).ToArray();

        // Encrypt RndA + RndB' using key and encRndB as IV (as specified by NXP: the cipher text of the first block of the preceding exchange)
        var phase2Payload = AesEncrypt(key, encRndB, plaintext);

        // Phase 3 — card sends encrypted RndA' (rotated RndA), we verify it
        var phase3 = isoReader.DfTransmit(DfConstants.Cmd.AdditionalFrame, phase2Payload);
        var encRndARotated = phase3.GetData() ?? [];
        if (encRndARotated.Length != 16)
            throw new Exception($"Expected 16-byte encrypted RndA', got {encRndARotated.Length} bytes.");

        // Decrypt RndA' using key and the last 16 bytes of the phase 2 payload as the IV (from standard CBC mode)
        var phase2LastBlock = phase2Payload.AsSpan(16, 16).ToArray();
        var rndAPrime = AesDecrypt(key, phase2LastBlock, encRndARotated);

        // Verify rotated RndA
        var expectedRndAPrime = ByteManipulation.RotateLeft(rndA);
        if (!rndAPrime.SequenceEqual(expectedRndAPrime))
            throw new Exception("Authentication failed: card cryptogram invalid.");

        // Generate AES-128 session key
        // Session Key = RndA[0..3] + RndB[0..3] + RndA[12..15] + RndB[12..15]
        var sessionKey = new byte[16];
        Array.Copy(rndA, 0, sessionKey, 0, 4);
        Array.Copy(rndB, 0, sessionKey, 4, 4);
        Array.Copy(rndA, 12, sessionKey, 8, 4);
        Array.Copy(rndB, 12, sessionKey, 12, 4);

        return sessionKey;
    }

    /// <summary>
    /// Changes the PICC master key to AES and sets the key version.
    /// Since the current authenticated key is 0x00 (or we are changing key 0x00),
    /// we use the SAME-KEY ChangeKey scheme.
    /// Under native/legacy authentication (0x0A), we must use CRC16 of only [newAESKey + newKeyVersion].
    /// Aligned to the 8-byte block boundary of the active session, the plaintext block is exactly 24 bytes long.
    /// </summary>
    public static void ChangeKeyToAes(IsoReader isoReader, byte[] sessionKey, byte[] newAesKey, byte newKeyVersion, bool useCrc16 = true)
    {
        if (newAesKey.Length != 16)
            throw new ArgumentException("AES-128 key must be exactly 16 bytes.", nameof(newAesKey));

        byte[] plaintext;
        if (useCrc16)
        {
            // CRC16 of: newAesKey (16 bytes) + newKeyVersion (1 byte)
            var crcData = new byte[17];
            Array.Copy(newAesKey, 0, crcData, 0, 16);
            crcData[16] = newKeyVersion;

            var crc16 = DesfireCrc.CalculateCrc16(crcData);

            // Construct 24-byte plaintext block to be encrypted:
            // [newAesKey (16 bytes)] + [newKeyVersion (1 byte)] + [CRC16 (2 bytes)] + [Padding (5 bytes of 0x00)]
            plaintext = new byte[24];
            Array.Copy(newAesKey, 0, plaintext, 0, 16);
            plaintext[16] = newKeyVersion;
            Array.Copy(crc16, 0, plaintext, 17, 2);
        }
        else
        {
            // CRC32 of: cmd (0xC4) + KeyNo (0x80) + newAesKey (16 bytes) + newKeyVersion (1 byte)
            var crcData = new byte[19];
            crcData[0] = DfConstants.Cmd.ChangeKey;
            crcData[1] = 0x80; // PICC Master Key No with AES type flag (0x00 | 0x80 = 0x80)
            Array.Copy(newAesKey, 0, crcData, 2, 16);
            crcData[18] = newKeyVersion;

            var crc32 = DesfireCrc.CalculateCrc32(crcData);

            // Construct 24-byte plaintext block to be encrypted:
            // [newAesKey (16 bytes)] + [newKeyVersion (1 byte)] + [CRC32 (4 bytes)] + [Padding (3 bytes of 0x00)]
            plaintext = new byte[24];
            Array.Copy(newAesKey, 0, plaintext, 0, 16);
            plaintext[16] = newKeyVersion;
            Array.Copy(crc32, 0, plaintext, 17, 4);
        }

        // Encrypt the plaintext using the current DES/3DES session key in CBC send/decryption mode
        var zeroIv = new byte[8];
        var encryptedData = TripleDesCrypto.EncryptCbcDecrypt(sessionKey, zeroIv, plaintext);

        // Construct APDU payload: KeyNo (0x80) + encryptedData (24 bytes)
        var apduPayload = new byte[25];
        apduPayload[0] = 0x80;
        Array.Copy(encryptedData, 0, apduPayload, 1, 24);

        // Send ChangeKey APDU command to the card
        var response = isoReader.DfTransmit(DfConstants.Cmd.ChangeKey, apduPayload);
        if (response.SW2 != DfConstants.Sw.Sw2Ok)
            throw new Exception($"ChangeKey failed with SW: {BitConverter.ToString([response.SW1, response.SW2])}");
    }

    /// <summary>
    /// Performs 3-pass mutual DESFire authentication (Native 0x0A or ISO 0x1A).
    /// </summary>
    public static byte[] Authenticate(IsoReader isoReader, byte authType, byte keyNo, byte[] key)
    {
        var zeroIv = new byte[8];

        // Phase 1 — card sends encrypted RndB
        var phase1 = isoReader.DfTransmit(authType, [keyNo]);
        var encRndB = phase1.GetData() ?? [];
        var rndB = TripleDesCrypto.Decrypt(key, zeroIv, encRndB);
        var rndBShifted = ByteManipulation.RotateLeft(rndB);

        // Phase 2 — we send encrypted (RndA || RndB\')
        var rndA = RandomNumberGenerator.GetBytes(8);
        var plaintext = rndA.Concat(rndBShifted).ToArray();
        var phase2Iv = authType == DfConstants.Cmd.Auth.Iso ? encRndB : zeroIv;
        var phase2Payload = TripleDesCrypto.Encrypt(key, phase2Iv, plaintext);

        // IV rolls forward: for ISO auth it is the last 8 bytes of what we just sent
        var rollingIv = authType == DfConstants.Cmd.Auth.Iso
            ? phase2Payload.AsSpan(8, 8).ToArray()
            : zeroIv;

        // Phase 3 — card sends encrypted RndA' (rotated RndA), we verify it
        var phase3 = isoReader.DfTransmit(DfConstants.Cmd.AdditionalFrame, phase2Payload);
        var encRndARotated = phase3.GetData() ?? [];
        var rndAPrime = TripleDesCrypto.Decrypt(key, rollingIv, encRndARotated);

        if (!rndAPrime.SequenceEqual(ByteManipulation.RotateLeft(rndA)))
            throw new Exception("Authentication failed: card cryptogram invalid.");

        // var sessionIv = encRndARotated.AsSpan(encRndARotated.Length - 8, 8).ToArray();
        var sessionKey = GenerateSessionKey(rndA, rndB, key);
        return sessionKey;
    }

    private static byte[] GenerateSessionKey(byte[] rndA, byte[] rndB, byte[] masterKey)
    {
        bool isSingleDes = masterKey.Length == 8 ||
                           (masterKey.Length >= 16 && masterKey.Take(8).SequenceEqual(masterKey.Skip(8).Take(8)));

        var key = new byte[16];
        if (isSingleDes)
        {
            Array.Copy(rndA, 0, key, 0, 4);
            Array.Copy(rndB, 0, key, 4, 4);
            Array.Copy(rndA, 0, key, 8, 4);
            Array.Copy(rndB, 0, key, 12, 4);
        }
        else
        {
            Array.Copy(rndA, 0, key, 0, 4);
            Array.Copy(rndB, 0, key, 4, 4);
            Array.Copy(rndA, 4, key, 8, 4);
            Array.Copy(rndB, 4, key, 12, 4);
        }
        return key;
    }
}