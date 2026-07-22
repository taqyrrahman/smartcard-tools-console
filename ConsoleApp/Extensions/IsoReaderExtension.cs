using ConsoleApp.Utils;
using PCSC.Iso7816;

namespace ConsoleApp.Extensions;

public static class IsoReaderExtension
{
    extension(IsoReader isoReader)
    {
        public Response DfTransmit(byte instruction, byte[]? data = null)
        {
            var hasData = data is { Length: > 0 };
            var apdu = new CommandApdu(hasData ? IsoCase.Case4Short : IsoCase.Case2Short, isoReader.ActiveProtocol)
                { CLA = 0x90, Instruction = (InstructionCode)instruction, Le = 0x00 };

            if (hasData)
            {
                apdu.Data = data;
            }

            var response = isoReader.Transmit(apdu);
            var sw = BitConverter.ToString([response.SW1, response.SW2]);
            var resData = BitConverter.ToString(response.GetData() ?? []);
            var ins = BitConverter.ToString([instruction]);
            var requestData = hasData ? BitConverter.ToString(data!) : string.Empty;
            Logger.Info(
                $"Req Instruction: {ins}, Req Data: {requestData}, SW: {sw}, Response: {(!string.IsNullOrEmpty(resData) ? resData : "<empty>")}");
            return response;
        }

        public byte[] DfTransmitChunks(byte instruction, byte[]? data = null)
        {
            var fullResponse = Array.Empty<byte>();
            var response = isoReader.DfTransmit(instruction, data);
            fullResponse = fullResponse.Concat(response.GetData() ?? []).ToArray();

            while (response.SW2 == DfConstants.Sw.Sw2AdditionalFrame)
            {
                response = isoReader.DfTransmit(DfConstants.Cmd.AdditionalFrame, []);
                fullResponse = fullResponse.Concat(response.GetData() ?? []).ToArray();
            }

            return fullResponse;
        }
    }
}