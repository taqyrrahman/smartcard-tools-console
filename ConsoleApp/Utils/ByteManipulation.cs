namespace ConsoleApp.Utils;

public static class ByteManipulation
{
    public static byte[] RotateLeft(byte[] input)
    {
        var rotated = new byte[input.Length];
        Array.Copy(input, 1, rotated, 0, input.Length - 1);
        rotated[input.Length - 1] = input[0];
        return rotated;
    }
}