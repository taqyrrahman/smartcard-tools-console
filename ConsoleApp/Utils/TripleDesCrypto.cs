using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace ConsoleApp.Utils;

public static class TripleDesCrypto
{
    public static byte[] Encrypt(byte[] key, byte[] iv, byte[] plaintext) => Transform(true, key, iv, plaintext);
    public static byte[] Decrypt(byte[] key, byte[] iv, byte[] ciphertext) => Transform(false, key, iv, ciphertext);

    /// <summary>
    /// Performs block-by-block DES/3DES CBC encryption, but using raw block decryption (deciphering).
    /// This is the "CBC send mode with decryption" required by legacy DES/3DES DESFire commands (e.g. ChangeKey).
    /// </summary>
    public static byte[] EncryptCbcDecrypt(byte[] key, byte[] iv, byte[] plaintext)
    {
        if (plaintext.Length % 8 != 0)
            throw new ArgumentException("Plaintext length must be a multiple of 8 for DES/3DES.", nameof(plaintext));

        var engine = new DesEdeEngine();
        engine.Init(false, new KeyParameter(NormalizeKey(key)));

        var blockCount = plaintext.Length / 8;
        var ciphertext = new byte[plaintext.Length];
        var previousBlock = new byte[8];
        Array.Copy(iv, previousBlock, 8);

        for (int i = 0; i < blockCount; i++)
        {
            var block = new byte[8];
            Array.Copy(plaintext, i * 8, block, 0, 8);

            // XOR with previous block (the ciphertext block of the previous iteration or IV)
            for (int j = 0; j < 8; j++)
            {
                block[j] ^= previousBlock[j];
            }

            // Decrypt block using the raw DES-EDE engine
            var decryptedBlock = new byte[8];
            engine.ProcessBlock(block, 0, decryptedBlock, 0);

            Array.Copy(decryptedBlock, 0, ciphertext, i * 8, 8);
            Array.Copy(decryptedBlock, previousBlock, 8);
        }

        return ciphertext;
    }

    private static byte[] Transform(bool encrypt, byte[] key, byte[] iv, byte[] input)
    {
        var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(NormalizeKey(key)), iv));

        var output = new byte[cipher.GetOutputSize(input.Length)];
        var offset = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        offset += cipher.DoFinal(output, offset);

        if (offset != output.Length)
            Array.Resize(ref output, offset);

        return output;
    }

    private static byte[] NormalizeKey(byte[] key)
    {
        if (key.Length == 24) return key;
        if (key.Length == 16)
        {
            var normalized = new byte[24];
            Buffer.BlockCopy(key, 0, normalized, 0, 16);
            Buffer.BlockCopy(key, 0, normalized, 16, 8);
            return normalized;
        }
        if (key.Length == 8)
        {
            var normalized = new byte[24];
            Buffer.BlockCopy(key, 0, normalized, 0, 8);
            Buffer.BlockCopy(key, 0, normalized, 8, 8);
            Buffer.BlockCopy(key, 0, normalized, 16, 8);
            return normalized;
        }

        throw new ArgumentException("3DES key must be 8, 16, or 24 bytes.", nameof(key));
    }
}