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

        // ── Step 1: Read key settings to detect the card's current master-key type ──────────────
        var getKeySettingsResponse = reader.DfTransmit(DfConstants.Cmd.GetKeySettings, []);
        var keySettingsData = getKeySettingsResponse.GetData() ?? [];
        Logger.Info($"Get Key Settings Response: {BitConverter.ToString(keySettingsData)}");

        var (keyType, keyCount) = DesfireAuth.ParseKeySettings(keySettingsData);
        Logger.Info($"Detected key type: {keyType}, key count: {keyCount}");

        // ── Step 2: Authenticate with the current master key ──────────────────────────────────
        // Auth command and key size depend on the key type stored on the card:
        //   DES / 2K3DES → Native (0x0A), 16-byte key, 8-byte challenges
        //   3K3DES        → ISO    (0x1A), 24-byte key, 16-byte challenges
        //   AES           → AES    (0xAA), 16-byte key, 16-byte challenges
        byte[] sessionKey;
        switch (keyType)
        {
            case DfKeyType.ThreeDes:
                Logger.Info("Authenticating with 3K3DES key via ISO auth (0x1A)...");
                var key3k = new byte[24]; // all-zeros 3K3DES master key
                sessionKey = DesfireAuth.Authenticate(reader, DfConstants.Cmd.Auth.Iso, 0, key3k);
                Logger.Info($"3K3DES session key: {BitConverter.ToString(sessionKey)}");
                break;

            case DfKeyType.Aes:
                Logger.Info("Authenticating with AES key via AES auth (0xAA)...");
                var keyAes = new byte[16]; // all-zeros AES-128 master key
                sessionKey = DesfireAuth.AuthenticateAes(reader, 0, keyAes);
                Logger.Info($"AES session key: {BitConverter.ToString(sessionKey)}");
                break;

            default: // DES / 2K3DES
                Logger.Info("Authenticating with 2K3DES key via Native auth (0x0A)...");
                var key2k = new byte[16]; // all-zeros 2K3DES master key
                sessionKey = DesfireAuth.Authenticate(reader, DfConstants.Cmd.Auth.Native, 0, key2k);
                Logger.Info($"2K3DES session key: {BitConverter.ToString(sessionKey)}");
                break;
        }
        Logger.Info("Initial authentication successful!");

        // ── Step 3: Change master key to AES-128 ──────────────────────────────────────────────
        var newAesKey = new byte[16]; // all-zeros AES-128 master key
        byte newKeyVersion = 0x01;
        Logger.Info($"Changing master key to AES-128 (Version: 0x{newKeyVersion:X2})...");

        if (keyType == DfKeyType.Aes)
        {
            // Already AES — skip the key change and go straight to AES re-auth
            Logger.Info("Card already uses AES. Skipping ChangeKey step.");
        }
        else
        {
            // ChangeKeyToAes auto-selects CRC/encryption mode from the session key length:
            //   16-byte session key (2K3DES/Native) → CRC16 + CBC-send mode
            //   24-byte session key (3K3DES/ISO)    → CRC32 + forward 3DES-CBC
            DesfireAuth.ChangeKeyToAes(reader, sessionKey, newAesKey, newKeyVersion);
            Logger.Info("Master key changed to AES-128.");
        }

        // ── Step 4: Re-authenticate with the new AES key ─────────────────────────────────────
        Logger.Info("Re-authenticating with the AES-128 key...");
        var aesSessionKey = DesfireAuth.AuthenticateAes(reader, 0, newAesKey);
        Logger.Info($"AES session key: {BitConverter.ToString(aesSessionKey)}");
        Logger.Info("AES authentication successful!");

        // ── Step 5: Revert master key back to 2K3DES (16-byte, all-zeros) ────────────────────
        var reverted2kDesKey = new byte[16]; // 16-byte 2K3DES all-zeros key
        Logger.Info("Changing master key back to 2K3DES (16-byte key)...");
        DesfireAuth.ChangeKeyTo3Des(reader, aesSessionKey, reverted2kDesKey);
        Logger.Info("Master key successfully reverted to 2K3DES!");

        // Verify what key type the card actually stored
        var postChangeKeySettings = reader.DfTransmit(DfConstants.Cmd.GetKeySettings, []);
        var postChangeData = postChangeKeySettings.GetData() ?? [];
        Logger.Info($"Post-ChangeKey GetKeySettings: {BitConverter.ToString(postChangeData)}");
        var (postKeyType, _) = DesfireAuth.ParseKeySettings(postChangeData);
        Logger.Info($"Card key type after ChangeKey: {postKeyType}");

        // ── Step 6: Re-authenticate with the reverted 2K3DES key (Native auth 0x0A) ────────────
        Logger.Info("Re-authenticating with the reverted 2K3DES key via Native auth (0x0A)...");
        var finalSessionKey = DesfireAuth.Authenticate(reader, DfConstants.Cmd.Auth.Native, 0, reverted2kDesKey);
        Logger.Info($"2K3DES session key: {BitConverter.ToString(finalSessionKey)}");
        Logger.Info("2K3DES authentication successful! Card is in a known 2K3DES state.");
    }
}