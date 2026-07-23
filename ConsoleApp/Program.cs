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
        DesfireAuth.ChangeKeyToAes(reader, sessionKey, newAesKey, newKeyVersion, useCrc16: true);
        Logger.Info("Master key successfully changed to AES-128!");

        // 2. Re-authenticate using the new AES key via AES auth (0xAA)
        Logger.Info("Re-authenticating with the newly set AES-128 key...");
        var aesSessionKey = DesfireAuth.AuthenticateAes(reader, 0, newAesKey);
        Logger.Info($"AES Session key: {BitConverter.ToString(aesSessionKey)}");
        Logger.Info("AES-128 authentication successful!");

        // 3. Revert back to 3DES
        var reverted3DesKey = new byte[16]; // Standard all zeroes 3DES master key (same as original)
        Logger.Info("Changing master key back to 3DES...");
        DesfireAuth.ChangeKeyTo3Des(reader, aesSessionKey, reverted3DesKey);
        Logger.Info("Master key successfully reverted to 3DES!");

        // 4. Re-authenticate using the reverted 3DES key via Native auth (0x0A)
        Logger.Info("Re-authenticating with the reverted 3DES key...");
        var nativeSessionKey = DesfireAuth.Authenticate(reader, DfConstants.Cmd.Auth.Native, 0, reverted3DesKey);
        Logger.Info($"Native/3DES Session key: {BitConverter.ToString(nativeSessionKey)}");
        Logger.Info("Native/3DES authentication successful!");
    }
}