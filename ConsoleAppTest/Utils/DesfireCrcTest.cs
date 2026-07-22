using ConsoleApp.Utils;

namespace ConsoleAppTest.Utils;

public class DesfireCrcTest
{
    [Fact]
    public void TestCrc16()
    {
        var data1 = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        var crc16_1 = DesfireCrc.CalculateCrc16(data1);
        Assert.Equal(Convert.FromHexString("CC69"), crc16_1);

        var data2 = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        var crc16_2 = DesfireCrc.CalculateCrc16(data2);
        Assert.Equal(Convert.FromHexString("77F5"), crc16_2);
    }

    [Fact]
    public void TestCrc32()
    {
        var data1 = Convert.FromHexString("C4800000000000000000000000000000000000");
        var crc32_1 = DesfireCrc.CalculateCrc32(data1);
        Assert.Equal(Convert.FromHexString("8BE9EDB5"), crc32_1);
    }

    [Fact]
    public void TestCrc32_2()
    {
        var data2 = Convert.FromHexString("C4001111111111111111111111111111111100");
        var crc32_2 = DesfireCrc.CalculateCrc32(data2);
        Assert.Equal(Convert.FromHexString("CB01B365"), crc32_2);
    }
}
