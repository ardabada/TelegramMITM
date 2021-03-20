using System.Threading;
using System.Threading.Tasks;
using Telegram.Core.Network;

namespace Telegram.Core.Auth
{
    public static class Authenticator
    {
        public static async Task<CompleteDHExchangeResponse> DoAuthentication(TcpTransport transport, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();

            var sender = new MtProtoPlainSender(transport);

            var step1 = new PQRequest();
            await sender.Send(step1.ToBytes(), token).ConfigureAwait(false);
            var step1Response = step1.FromBytes(await sender.Receive(token).ConfigureAwait(false));

            var step2 = new DHExchange();
            await sender.Send(step2.ToBytes(step1Response), token).ConfigureAwait(false);
            var step2Response = step2.FromBytes(await sender.Receive(token).ConfigureAwait(false));

            var step3 = new CompleteDHExchange();
            await sender.Send(step3.ToBytes(step2Response), token).ConfigureAwait(false);
            var step3Response = step3.FromBytes(await sender.Receive(token).ConfigureAwait(false));

            return step3Response;
        }
    }
}
