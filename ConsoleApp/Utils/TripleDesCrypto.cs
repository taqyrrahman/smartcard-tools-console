using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace ConsoleApp.Utils;

public static class TripleDesCrypto
{
    public static byte[] Encrypt(byte[] key, byte[] iv, byte[] plaintext) => Transform(true, key, iv, plaintext);
    public static byte[] Decrypt(byte[] key, byte[] iv, byte[] ciphertext) => Transform(false, key, iv, ciphertext);

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

        throw new ArgumentException("3DES key must be 16 or 24 bytes.", nameof(key));
    }
}