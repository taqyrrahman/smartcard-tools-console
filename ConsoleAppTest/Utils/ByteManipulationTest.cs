using ConsoleApp.Utils;

namespace ConsoleAppTest.Utils;

public class ByteManipulationTest
{
    [Fact]
    public void RotateLeftTest()
    {
        var input = new byte[] { 1, 2, 3, 4, 5 };
        var expected = new byte[] { 2, 3, 4, 5, 1 };
        var result = ByteManipulation.RotateLeft(input);
        Assert.Equal(expected, result);
    }
}