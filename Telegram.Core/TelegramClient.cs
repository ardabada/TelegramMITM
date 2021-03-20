using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Telegram.Core.Network;

namespace Telegram.Core
{
    public class TelegramClient : IDisposable
    {
        private MtProtoSender sender;
        private TcpTransport transport;

        public Session Session { get; private set; }

        public async Task ConnectAsync(bool reconnect = false, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();


        }



        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
