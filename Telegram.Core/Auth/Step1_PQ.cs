using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Telegram.Core.MTProto;

namespace Telegram.Core.Auth
{
    public class PQRequest
    {
        private byte[] nonce;

        public PQRequest()
        {
            nonce = new byte[16];
        }

        public byte[] ToBytes()
        {
            Utils.Random.NextBytes(nonce);
            const int constructorNumber = 0x60469778;

            using (var memoryStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(memoryStream))
                {
                    binaryWriter.Write(constructorNumber);
                    binaryWriter.Write(nonce);

                    return memoryStream.ToArray();
                }
            }
        }

        public PQResponse FromBytes(byte[] bytes)
        {
            using (var ms = new MemoryStream(bytes, false))
            {
                using (var binaryReader = new BinaryReader(ms))
                {
                    const int responseConstructorNumber = 0x05162463;
                    var responseCode = binaryReader.ReadInt32();
                    if (responseCode != responseConstructorNumber)
                    {
                        throw new InvalidOperationException($"invalid response code: {responseCode}");
                    }

                    var nonceFromServer = binaryReader.ReadBytes(16);

                    if (!nonceFromServer.SequenceEqual(nonce))
                    {
                        throw new InvalidOperationException("invalid nonce from server");
                    }

                    var serverNonce = binaryReader.ReadBytes(16);

                    byte[] pqbytes = Serializers.Bytes.Read(binaryReader); //Single-byte prefix denoting length, an 8-byte string, and three bytes of padding
                    //pqbytes.length == 8
                    if (pqbytes.Length != 8)
                        throw new InvalidOperationException("invalid prefix or padding while evaluating pq value");

                    long pq = BitConverter.ToInt64(pqbytes.Reverse().ToArray(), 0);

                    var vectorId = binaryReader.ReadInt32();

                    const int vectorConstructorNumber = 0x1cb5c415;
                    if (vectorId != vectorConstructorNumber)
                    {
                        throw new InvalidOperationException($"Invalid vector constructor number {vectorId}");
                    }

                    var fingerprintCount = binaryReader.ReadInt32();
                    var fingerprints = new List<byte[]>();
                    for (var i = 0; i < fingerprintCount; i++)
                    {
                        byte[] fingerprint = binaryReader.ReadBytes(8);
                        fingerprints.Add(fingerprint);
                    }

                    return new PQResponse()
                    {
                        Nonce = nonce,
                        ServerNonce = serverNonce,
                        PQ = pq,
                        Fingerprints = fingerprints
                    };
                }
            }
        }
    }

    public class PQResponse
    {
        public byte[] Nonce { get; set; }
        public byte[] ServerNonce { get; set; }
        public long PQ { get; set; }
        public List<byte[]> Fingerprints { get; set; }
    }
}
