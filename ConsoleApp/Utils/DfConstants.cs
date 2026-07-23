namespace ConsoleApp.Utils;

/// <summary>
/// Key type as encoded in the upper nibble of byte 1 of the GetKeySettings response.
/// </summary>
public enum DfKeyType
{
    Des       = 0x00, // Single-DES (8-byte key)
    TwoDes    = 0x00, // 2-key 3DES (16-byte key) — same encoding as single-DES for the master key
    ThreeDes  = 0x40, // 3-key 3DES (24-byte key)
    Aes       = 0x80, // AES-128 (16-byte key)
}

public static class DfConstants
{
    public static class Cmd
    {
        public const byte AdditionalFrame = 0xAF;
        public const byte ChangeKey = 0xC4;
        public const byte FormatPicc = 0xFC;
        public const byte GetFileIds = 0x6A;
        public const byte GetKeySettings = 0x45;
        public const byte GetVersion = 0x60;
        public const byte SelectApplication = 0x5A;

        public static class Auth
        {
            public const byte Native = 0x0A;
            public const byte Iso = 0x1A;
            public const byte Aes = 0xAA;
        }
    }

    public static class Sw
    {
        public const byte Sw2Ok = 0x00;
        public const byte Sw2AdditionalFrame = 0xAF;
        public const byte Sw1Desfire = 0x91;
    }
}