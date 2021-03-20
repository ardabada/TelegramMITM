using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Telegram.Core.MTProto;
using Telegram.Core.MTProto.Crypto;

namespace Telegram.Core.Auth
{
    public class CompleteDHExchangeResponse
    {
        public AuthKey AuthKey { get; set; }
        public int TimeOffset { get; set; }
    }

    public class CompleteDHExchange
    {
        private BigInteger _gab;
        private byte[] newNonce;
        private int timeOffset;

        public byte[] ToBytes(DHExchangeResponse dHExchangeResponse)
        {
            this.newNonce = dHExchangeResponse.NewNonce;
            AESKeyData key = AES.GenerateKeyDataFromNonces(dHExchangeResponse.ServerNonce, newNonce);
            byte[] plaintextAnswer = AES.DecryptAES(key, dHExchangeResponse.EncryptedAnswer);

            int g;
            BigInteger dhPrime;
            BigInteger ga;

            using (MemoryStream dhInnerData = new MemoryStream(plaintextAnswer))
            {
                using (BinaryReader dhInnerDataReader = new BinaryReader(dhInnerData))
                {
                    byte[] hashsum = dhInnerDataReader.ReadBytes(20);
                    uint code = dhInnerDataReader.ReadUInt32();
                    if (code != 0xb5890dba)
                    {
                        throw new InvalidOperationException($"Invalid dh_inner_data code: {code}");
                    }

                    byte[] nonceFromServer1 = dhInnerDataReader.ReadBytes(16);
                    if (!nonceFromServer1.SequenceEqual(dHExchangeResponse.Nonce))
                    {
                        throw new InvalidOperationException("Invalid nonce in encrypted answer");
                    }

                    byte[] serverNonceFromServer1 = dhInnerDataReader.ReadBytes(16);
                    if (!serverNonceFromServer1.SequenceEqual(dHExchangeResponse.ServerNonce))
                    {
                        throw new InvalidOperationException("invalid server nonce in encrypted answer");
                    }

                    g = dhInnerDataReader.ReadInt32();
                    dhPrime = new BigInteger(1, Serializers.Bytes.Read(dhInnerDataReader));
                    ga = new BigInteger(1, Serializers.Bytes.Read(dhInnerDataReader));

                    int serverTime = dhInnerDataReader.ReadInt32();
                    timeOffset = serverTime - (int)(Convert.ToInt64((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds) / 1000);
                }
            }

            BigInteger b = new BigInteger(2048, new Random());
            BigInteger gb = BigInteger.ValueOf(g).ModPow(b, dhPrime);
            _gab = ga.ModPow(b, dhPrime);

            byte[] clientDHInnerDataBytes;
            using (MemoryStream clientDhInnerData = new MemoryStream())
            {
                using (BinaryWriter clientDhInnerDataWriter = new BinaryWriter(clientDhInnerData))
                {
                    clientDhInnerDataWriter.Write(0x6643b654); // client_dh_inner_data
                    clientDhInnerDataWriter.Write(dHExchangeResponse.Nonce);
                    clientDhInnerDataWriter.Write(dHExchangeResponse.ServerNonce);
                    clientDhInnerDataWriter.Write((long)0); // TODO: retry_id
                    Serializers.Bytes.Write(clientDhInnerDataWriter, gb.ToByteArrayUnsigned());

                    using (MemoryStream clientDhInnerDataWithHash = new MemoryStream())
                    {
                        using (BinaryWriter clientDhInnerDataWithHashWriter = new BinaryWriter(clientDhInnerDataWithHash))
                        {
                            using (SHA1 sha1 = new SHA1Managed())
                            {
                                clientDhInnerDataWithHashWriter.Write(sha1.ComputeHash(clientDhInnerData.GetBuffer(), 0, (int)clientDhInnerData.Position));
                                clientDhInnerDataWithHashWriter.Write(clientDhInnerData.GetBuffer(), 0, (int)clientDhInnerData.Position);
                                clientDHInnerDataBytes = clientDhInnerDataWithHash.ToArray();
                            }
                        }
                    }
                }
            }

            // encryption
            byte[] clientDhInnerDataEncryptedBytes = AES.EncryptAES(key, clientDHInnerDataBytes);

            // prepare set_client_dh_params
            byte[] setclientDhParamsBytes;
            using (MemoryStream setClientDhParams = new MemoryStream())
            {
                using (BinaryWriter setClientDhParamsWriter = new BinaryWriter(setClientDhParams))
                {
                    setClientDhParamsWriter.Write(0xf5045f1f);
                    setClientDhParamsWriter.Write(dHExchangeResponse.Nonce);
                    setClientDhParamsWriter.Write(dHExchangeResponse.ServerNonce);
                    Serializers.Bytes.Write(setClientDhParamsWriter, clientDhInnerDataEncryptedBytes);

                    setclientDhParamsBytes = setClientDhParams.ToArray();
                }
            }

            return setclientDhParamsBytes;
        }

        public CompleteDHExchangeResponse FromBytes(byte[] response, byte[] step1_nonce = null, byte[] step2_serverNonce = null)
        {
            using (MemoryStream responseStream = new MemoryStream(response))
            {
                using (BinaryReader responseReader = new BinaryReader(responseStream))
                {
                    uint code = responseReader.ReadUInt32();
                    if (code == 0x3bcbf734)
                    { // dh_gen_ok

                        byte[] nonceFromServer = responseReader.ReadBytes(16);

                        if (step1_nonce != null && !nonceFromServer.SequenceEqual(step1_nonce))
                            throw new InvalidOperationException("Invalid nonce");

                        byte[] serverNonceFromServer = responseReader.ReadBytes(16);

                        if (step2_serverNonce != null && !serverNonceFromServer.SequenceEqual(step2_serverNonce))
                            throw new InvalidOperationException("Invalid server nonce");

                        byte[] newNonceHash1 = responseReader.ReadBytes(16);

                        AuthKey authKey = new AuthKey(_gab);

                        byte[] newNonceHashCalculated = authKey.CalcNewNonceHash(newNonce, 1);

                        if (!newNonceHash1.SequenceEqual(newNonceHashCalculated))
                            throw new InvalidOperationException("invalid new nonce hash");

                        //logger.info("generated new auth key: {0}", gab);
                        //logger.info("saving time offset: {0}", timeOffset);
                        //TelegramSession.Instance.TimeOffset = timeOffset;

                        return new CompleteDHExchangeResponse()
                        {
                            AuthKey = authKey,
                            TimeOffset = timeOffset
                        };
                    }
                    else if (code == 0x46dc1fb9)
                    { // dh_gen_retry
                        throw new NotImplementedException("dh_gen_retry");

                    }
                    else if (code == 0xa69dae02)
                    {
                        // dh_gen_fail
                        throw new NotImplementedException("dh_gen_fail");
                    }
                    else
                    {
                        throw new InvalidOperationException($"dh_gen unknown: {code}");
                    }
                }
            }
        }
    }
}
