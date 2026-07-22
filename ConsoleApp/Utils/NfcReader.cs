using PCSC;
using PCSC.Iso7816;

namespace ConsoleApp.Utils;

public static class NfcReader
{
    public static IsoReader GetReader(int index = 0)
    {
        var contextFactory = ContextFactory.Instance;
        var context = contextFactory.Establish(SCardScope.System);

        var readers = context.GetReaders();
        if (readers is null || readers.Length == 0)
        {
            throw new Exception("No PC/SC reader found.");
        }

        Logger.Info("Available Readers:");
        for (var i = 0; i < readers.Length; i++)
        {
            var reader = readers[i];
            Logger.Info($"{i} - {reader}");
        }

        if (index < 0 || index >= readers.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "Invalid reader index.");
        }

        Logger.Info($"Chosen Reader: {index} - {readers[index]}");
        var isoReader = new IsoReader(context, readers[index], SCardShareMode.Shared, SCardProtocol.Any, false);
        return isoReader;
    }
}