using ConsoleApp.DesfireTools;
using ConsoleApp.Extensions;
using ConsoleApp.Utils;

namespace ConsoleApp;

internal static class Program
{
    private static void Main()
    {
        Logger.Info("Hello, World!");
        var reader = NfcReader.GetReader();

        var getVersionResponse = reader.DfTransmitChunks(DfConstants.Cmd.GetVersion, []);
        Logger.Info($"Get Version Response: {BitConverter.ToString(getVersionResponse)}");

        var getKeySettingsResponse = reader.DfTransmit(DfConstants.Cmd.GetKeySettings, []);
        Logger.Info($"Get Key Settings Response: {BitConverter.ToString(getKeySettingsResponse.GetData())}");

        var sessionKey = DesfireAuth.Authenticate(reader, DfConstants.Cmd.Auth.Native, 0, new byte[24]);
        Logger.Info($"Session key: {BitConverter.ToString(sessionKey)}");

        // 1. Change key to AES-128
        var newAesKey = new byte[16]; // All zeroes AES-128 master key
        byte newKeyVersion = 0x01;
        Logger.Info($"Changing master key to AES (Version: 0x{newKeyVersion:X2})...");
        // The master key is initially 3DES (24-byte, but since it is native/legacy auth (0x0A) using 24-bytes all-zeroes,
        // it acts as single-DES or 3DES key, which we normalize inside ChangeKeyToAes).
        DesfireAuth.ChangeKeyToAes(reader, sessionKey, newAesKey, newKeyVersion, new byte[24]);
        Logger.Info("Master key successfully changed to AES-128!");

        // 2. Re-authenticate using the new AES key via AES auth (0xAA)
        Logger.Info("Re-authenticating with the newly set AES-128 key...");
        var aesSessionKey = DesfireAuth.AuthenticateAes(reader, 0, newAesKey);
        Logger.Info($"AES Session key: {BitConverter.ToString(aesSessionKey)}");
        Logger.Info("AES-128 authentication successful!");
    }
}