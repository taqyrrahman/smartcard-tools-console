namespace ConsoleApp.Utils;

public static class DesfireCrc
{
    /// <summary>
    /// Computes the ISO 14443-A CRC-16 checksum.
    /// Initial value is 0x6363, polynomial is 0x8408.
    /// Returns 2 bytes in little-endian format.
    /// </summary>
    public static byte[] CalculateCrc16(byte[] data)
    {
        ushort crc = 0x6363;
        foreach (var b in data)
        {
            crc ^= b;
            for (var i = 0; i < 8; i++)
            {
                if ((crc & 1) != 0)
                {
                    crc = (ushort)((crc >> 1) ^ 0x8408);
                }
                else
                {
                    crc >>= 1;
                }
            }
        }

        return [ (byte)(crc & 0xFF), (byte)((crc >> 8) & 0xFF) ];
    }

    /// <summary>
    /// Computes the DESFire CRC-32 checksum.
    /// Uses standard polynomial 0xEDB88320, initial value 0xFFFFFFFF, but NO final inversion (~).
    /// Returns 4 bytes in little-endian format.
    /// </summary>
    public static byte[] CalculateCrc32(byte[] data)
    {
        uint crc = 0xFFFFFFFF;
        const uint poly = 0xEDB88320;

        foreach (var b in data)
        {
            crc ^= b;
            for (var i = 0; i < 8; i++)
            {
                if ((crc & 1) != 0)
                {
                    crc = (crc >> 1) ^ poly;
                }
                else
                {
                    crc >>= 1;
                }
            }
        }

        // Return little-endian format
        return
        [
            (byte)(crc & 0xFF),
            (byte)((crc >> 8) & 0xFF),
            (byte)((crc >> 16) & 0xFF),
            (byte)((crc >> 24) & 0xFF)
        ];
    }
}
