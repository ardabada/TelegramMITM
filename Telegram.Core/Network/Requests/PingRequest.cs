using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using TeleSharp.TL;

namespace Telegram.Core.Network.Requests
{
    public class PingRequest : TLMethod
    {
        public PingRequest()
        {
        }

        public override void SerializeBody(BinaryWriter writer)
        {
            writer.Write(Constructor);
            writer.Write(Utils.GenerateRandomLong());
        }

        public override void DeserializeBody(BinaryReader reader)
        {
            throw new NotImplementedException();
        }

        public override void DeserializeResponse(BinaryReader stream)
        {
            throw new NotImplementedException();
        }

        public override int Constructor
        {
            get
            {
                return 0x7abe77ec;
            }
        }
    }
}
