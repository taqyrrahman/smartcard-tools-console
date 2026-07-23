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
            // For the SAME-KEY ChangeKey scheme (changing key 0 while authenticated with key 0),
            // a 24-byte plaintext payload containing a single CRC32 is required.
            // CRC32 of: cmd (0xC4) + KeyNoWithType (0x80) + newAesKey (16 bytes) + newKeyVersion (1 byte)
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
        // After any successful authentication (Native or ISO), the communication IV is always reset to all zeroes.
        var zeroIv = new byte[8];
        var encryptedData = TripleDesCrypto.EncryptCbcDecrypt(sessionKey, zeroIv, plaintext);

        // Construct APDU payload: KeyNo (0x80) + encryptedData
        var apduPayload = new byte[1 + encryptedData.Length];
        apduPayload[0] = 0x80;
        Array.Copy(encryptedData, 0, apduPayload, 1, encryptedData.Length);

        // Send ChangeKey APDU command to the card
        var response = isoReader.DfTransmit(DfConstants.Cmd.ChangeKey, apduPayload);
        if (response.SW2 != DfConstants.Sw.Sw2Ok)
            throw new Exception($"ChangeKey failed with SW: {BitConverter.ToString([response.SW1, response.SW2])}");
    }

    /// <summary>
    /// Changes the PICC master key from AES back to 3DES (2-key 3DES or 3-key 3DES) under an active AES-128 session.
    /// Since the current authenticated key is 0x00, we use the SAME-KEY ChangeKey scheme.
    /// </summary>
    public static void ChangeKeyTo3Des(IsoReader isoReader, byte[] aesSessionKey, byte[] new3DesKey)
    {
        if (new3DesKey.Length != 16 && new3DesKey.Length != 24)
            throw new ArgumentException("3DES key must be 16 or 24 bytes.", nameof(new3DesKey));

        // Determine target key type flag:
        // PICC Master Key No is 0.
        // For 16-byte 3DES (2-key 3DES), the flag is 0x00.
        // For 24-byte 3DES (3-key 3DES), the flag is 0x40.
        byte keyTypeFlag = new3DesKey.Length == 24 ? (byte)0x40 : (byte)0x00;
        byte keyNoWithType = (byte)(0x00 | keyTypeFlag);

        // CRC32 of: cmd (0xC4) + KeyNoWithType (0x00 or 0x40) + new3DesKey (16 or 24 bytes)
        var crcData = new byte[2 + new3DesKey.Length];
        crcData[0] = DfConstants.Cmd.ChangeKey;
        crcData[1] = keyNoWithType;
        Array.Copy(new3DesKey, 0, crcData, 2, new3DesKey.Length);

        var crc32 = DesfireCrc.CalculateCrc32(crcData);

        // Construct plaintext block: [new3DesKey] + [CRC32] + [Padding to 16-byte boundary]
        int unpaddedLength = new3DesKey.Length + 4;
        int paddedLength = ((unpaddedLength + 15) / 16) * 16; // Align to 16 bytes for AES block size
        var plaintext = new byte[paddedLength];
        Array.Copy(new3DesKey, 0, plaintext, 0, new3DesKey.Length);
        Array.Copy(crc32, 0, plaintext, new3DesKey.Length, 4);

        // Encrypt the plaintext using the active AES-128 session key in CBC mode with a zero IV
        var zeroIv = new byte[16];
        var encryptedData = AesEncrypt(aesSessionKey, zeroIv, plaintext);

        // Construct APDU payload: KeyNoWithType + encryptedData
        var apduPayload = new byte[1 + encryptedData.Length];
        apduPayload[0] = keyNoWithType;
        Array.Copy(encryptedData, 0, apduPayload, 1, encryptedData.Length);

        // Send ChangeKey APDU command to the card
        var response = isoReader.DfTransmit(DfConstants.Cmd.ChangeKey, apduPayload);
        if (response.SW2 != DfConstants.Sw.Sw2Ok)
            throw new Exception($"ChangeKey back to 3DES failed with SW: {BitConverter.ToString([response.SW1, response.SW2])}");
    }

    /// <summary>
    /// Performs 3-pass mutual DESFire authentication (Native 0x0A or ISO 0x1A).
    /// </summary>
    public static byte[] Authenticate(IsoReader isoReader, byte authType, byte keyNo, byte[] key)
    {
        var zeroIv = new byte[8];
        int rndSize = (authType == DfConstants.Cmd.Auth.Iso && key.Length == 24) ? 16 : 8;

        // Phase 1 — card sends encrypted RndB
        var phase1 = isoReader.DfTransmit(authType, [keyNo]);
        var encRndB = phase1.GetData() ?? [];
        if (encRndB.Length != rndSize)
            throw new Exception($"Expected {rndSize}-byte encrypted RndB, got {encRndB.Length} bytes.");

        var rndB = TripleDesCrypto.Decrypt(key, zeroIv, encRndB);
        var rndBShifted = ByteManipulation.RotateLeft(rndB);

        // Phase 2 — we send encrypted (RndA || RndB\')
        var rndA = RandomNumberGenerator.GetBytes(rndSize);
        var plaintext = rndA.Concat(rndBShifted).ToArray();
        var phase2Iv = authType == DfConstants.Cmd.Auth.Iso
            ? encRndB.AsSpan(encRndB.Length - 8, 8).ToArray()
            : zeroIv;
        var phase2Payload = TripleDesCrypto.Encrypt(key, phase2Iv, plaintext);

        // IV rolls forward: for ISO auth it is the last 8 bytes of what we just sent
        var rollingIv = authType == DfConstants.Cmd.Auth.Iso
            ? phase2Payload.AsSpan(phase2Payload.Length - 8, 8).ToArray()
            : zeroIv;

        // Phase 3 — card sends encrypted RndA' (rotated RndA), we verify it
        var phase3 = isoReader.DfTransmit(DfConstants.Cmd.AdditionalFrame, phase2Payload);
        var encRndARotated = phase3.GetData() ?? [];
        if (encRndARotated.Length != rndSize)
            throw new Exception($"Expected {rndSize}-byte encrypted RndA', got {encRndARotated.Length} bytes.");

        var rndAPrime = TripleDesCrypto.Decrypt(key, rollingIv, encRndARotated);

        if (!rndAPrime.SequenceEqual(ByteManipulation.RotateLeft(rndA)))
            throw new Exception("Authentication failed: card cryptogram invalid.");

        var sessionKey = GenerateSessionKey(rndA, rndB, key);
        return sessionKey;
    }

    private static byte[] GenerateSessionKey(byte[] rndA, byte[] rndB, byte[] masterKey)
    {
        if (masterKey.Length == 24 && rndA.Length == 16)
        {
            var key3k = new byte[24];
            // Session Key under 3K3DES:
            // RndA[0..3] + RndB[0..3] + RndA[6..9] + RndB[6..9] + RndA[12..15] + RndB[12..15]
            Array.Copy(rndA, 0, key3k, 0, 4);
            Array.Copy(rndB, 0, key3k, 4, 4);
            Array.Copy(rndA, 6, key3k, 8, 4);
            Array.Copy(rndB, 6, key3k, 12, 4);
            Array.Copy(rndA, 12, key3k, 16, 4);
            Array.Copy(rndB, 12, key3k, 20, 4);

            for (int i = 0; i < 24; i++)
            {
                key3k[i] &= 0xFE;
            }
            return key3k;
        }

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

        for (int i = 0; i < 16; i++)
        {
            key[i] &= 0xFE;
        }
        return key;
    }
}