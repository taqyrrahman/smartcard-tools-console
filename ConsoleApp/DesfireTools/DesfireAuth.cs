using System.Security.Cryptography;
using ConsoleApp.Extensions;
using ConsoleApp.Utils;
using PCSC.Iso7816;

namespace ConsoleApp.DesfireTools;

public static class DesfireAuth
{
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
        var sessionKey = GenerateSessionKey(rndA, rndB);
        return sessionKey;
    }

    private static byte[] GenerateSessionKey(byte[] rndA, byte[] rndB)
    {
        var key = new byte[16];
        Array.Copy(rndA, 0, key, 0, 4);
        Array.Copy(rndB, 0, key, 4, 4);
        Array.Copy(rndA, 4, key, 8, 4);
        Array.Copy(rndB, 4, key, 12, 4);
        return key;
    }
}