using ConsoleApp.DesfireTools;
using ConsoleApp.Extensions;
using ConsoleApp.Utils;

namespace ConsoleApp;

internal static class Program
{
    // ── Configuration ─────────────────────────────────────────────────────────────────────────
    // Set the target key type to revert to after the AES step.
    //   DfKeyType.TwoDes   → 2K3DES (16-byte key, Native auth 0x0A)
    //   DfKeyType.ThreeDes → 3K3DES (24-byte key, ISO auth 0x1A)
    private const DfKeyType TargetDesKeyType = DfKeyType.TwoDes;

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
                sessionKey = DesfireAuth.Authenticate(reader, DfConstants.Cmd.Auth.Iso, 0, new byte[24]);
                Logger.Info($"3K3DES session key: {BitConverter.ToString(sessionKey)}");
                break;

            case DfKeyType.Aes:
                Logger.Info("Authenticating with AES key via AES auth (0xAA)...");
                sessionKey = DesfireAuth.AuthenticateAes(reader, 0, new byte[16]);
                Logger.Info($"AES session key: {BitConverter.ToString(sessionKey)}");
                break;

            default: // DES / 2K3DES
                Logger.Info("Authenticating with 2K3DES key via Native auth (0x0A)...");
                sessionKey = DesfireAuth.Authenticate(reader, DfConstants.Cmd.Auth.Native, 0, new byte[16]);
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

        // ── Step 4: Re-authenticate with the AES key ─────────────────────────────────────────
        Logger.Info("Re-authenticating with the AES-128 key...");
        var aesSessionKey = DesfireAuth.AuthenticateAes(reader, 0, newAesKey);
        Logger.Info($"AES session key: {BitConverter.ToString(aesSessionKey)}");
        Logger.Info("AES authentication successful!");

        // ── Step 5: Revert master key to the target DES type (controlled by TargetDesKeyType) ──
        bool revertTo3k = TargetDesKeyType == DfKeyType.ThreeDes;
        var revertedKey = revertTo3k ? new byte[24] : new byte[16];
        Logger.Info($"Changing master key back to {(revertTo3k ? "3K3DES (24-byte)" : "2K3DES (16-byte)")}...");
        DesfireAuth.ChangeKeyTo3Des(reader, aesSessionKey, revertedKey);
        Logger.Info($"Master key successfully reverted to {(revertTo3k ? "3K3DES" : "2K3DES")}!");

        // ── Step 6: Re-authenticate with the reverted key ─────────────────────────────────────
        byte authCmd = revertTo3k ? DfConstants.Cmd.Auth.Iso : DfConstants.Cmd.Auth.Native;
        Logger.Info($"Re-authenticating via {(revertTo3k ? "ISO (0x1A)" : "Native (0x0A)")} auth...");
        var finalSessionKey = DesfireAuth.Authenticate(reader, authCmd, 0, revertedKey);
        Logger.Info($"{(revertTo3k ? "3K3DES" : "2K3DES")} session key: {BitConverter.ToString(finalSessionKey)}");
        Logger.Info($"{(revertTo3k ? "3K3DES" : "2K3DES")} authentication successful!");
    }
}