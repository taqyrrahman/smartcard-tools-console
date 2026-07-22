using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;

namespace ConsoleApp.Utils;

public static class Logger
{
    public static void Info(
        string message,
        [CallerFilePath] string file = "")
        => Write(LogLevel.Information, message, file);

    public static void Debug(
        string message,
        [CallerFilePath] string file = "")
        => Write(LogLevel.Debug, message, file);

    public static void Warn(
        string message,
        [CallerFilePath] string file = "")
        => Write(LogLevel.Warning, message, file);

    public static void Error(
        string message,
        Exception? ex = null,
        [CallerFilePath] string file = "")
        => Write(LogLevel.Error, message, file, ex);

    private static void Write(LogLevel level, string message, string filePath, Exception? ex = null)
    {
        var category = Path.GetFileNameWithoutExtension(filePath);

        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var levelStr = level switch
        {
            LogLevel.Information => "INFO",
            LogLevel.Debug => "DEBUG",
            LogLevel.Warning => "WARN",
            LogLevel.Error => "ERROR",
            LogLevel.Trace => "TRACE",
            LogLevel.Critical => "CRITICAL",
            LogLevel.None => "NONE",
            _ => throw new ArgumentOutOfRangeException(nameof(level), level, null)
        };

        Console.WriteLine($"{timestamp} [{levelStr}] [{category}] {message}");
        if (ex != null) Console.WriteLine(ex);
    }
}