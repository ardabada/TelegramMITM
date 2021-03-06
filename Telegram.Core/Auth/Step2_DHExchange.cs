using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Telegram.Core.MTProto;
using Telegram.Core.MTProto.Crypto;

namespace Telegram.Core.Auth
{
	public class DHExchangeResponse
	{
		public byte[] Nonce { get; set; }
		public byte[] ServerNonce { get; set; }
		public byte[] NewNonce { get; set; }
		public byte[] EncryptedAnswer { get; set; }
	}

	public class DHExchange
	{
		private byte[] newNonce;

		public DHExchange()
		{
			newNonce = new byte[32];
		}

		public byte[] ToBytes(PQResponse pqResponse)
		{
			Utils.Random.NextBytes(newNonce);

			var pqPair = Factorizator.Factorize(pqResponse.PQ);

            byte[] reqDhParamsBytes;

            using (MemoryStream pqInnerData = new MemoryStream(255))
            {
                using (BinaryWriter pqInnerDataWriter = new BinaryWriter(pqInnerData))
                {
                    pqInnerDataWriter.Write(0x83c95aec); // pq_inner_data
                    Serializers.Bytes.Write(pqInnerDataWriter, pqResponse.PQ.ToByteArrayUnsigned());
                    Serializers.Bytes.Write(pqInnerDataWriter, pqPair.Min.ToByteArrayUnsigned());
                    Serializers.Bytes.Write(pqInnerDataWriter, pqPair.Max.ToByteArrayUnsigned());
                    pqInnerDataWriter.Write(pqResponse.Nonce);
                    pqInnerDataWriter.Write(pqResponse.ServerNonce);
                    pqInnerDataWriter.Write(newNonce);

                    byte[] ciphertext = null;
                    byte[] targetFingerprint = null;
                    foreach (byte[] fingerprint in pqResponse.Fingerprints)
                    {
                        ciphertext = RSA.Encrypt(BitConverter.ToString(fingerprint).Replace("-", string.Empty),
                                                 pqInnerData.GetBuffer(), 0, (int)pqInnerData.Position);
                        if (ciphertext != null)
                        {
                            targetFingerprint = fingerprint;
                            break;
                        }
                    }

                    if (ciphertext == null)
                    {
                        throw new InvalidOperationException(
                            String.Format("not found valid key for fingerprints: {0}", String.Join(", ", pqResponse.Fingerprints)));
                    }

                    using (MemoryStream reqDHParams = new MemoryStream(1024))
                    {
                        using (BinaryWriter reqDHParamsWriter = new BinaryWriter(reqDHParams))
                        {
                            reqDHParamsWriter.Write(0xd712e4be); // req_dh_params
                            reqDHParamsWriter.Write(pqResponse.Nonce);
                            reqDHParamsWriter.Write(pqResponse.ServerNonce);
                            Serializers.Bytes.Write(reqDHParamsWriter, pqPair.Min.ToByteArrayUnsigned());
                            Serializers.Bytes.Write(reqDHParamsWriter, pqPair.Max.ToByteArrayUnsigned());
                            reqDHParamsWriter.Write(targetFingerprint);
                            Serializers.Bytes.Write(reqDHParamsWriter, ciphertext);

                            reqDhParamsBytes = reqDHParams.ToArray();
                        }
                    }
                }
                return reqDhParamsBytes;
            }
        }

        public DHExchangeResponse FromBytes(byte[] response, byte[] step1_nonce = null, byte[] step2_serverNonce = null)
        {
            using (MemoryStream responseStream = new MemoryStream(response, false))
            {
                using (BinaryReader responseReader = new BinaryReader(responseStream))
                {
                    uint responseCode = responseReader.ReadUInt32();

                    if (responseCode == 0x79cb045d)
                    {
                        //TODO: server_DH_params_fail
                        //use new_nonce_hash
                        throw new InvalidOperationException("server_DH_params_fail");
                    }

                    if (responseCode != 0xd0e8075c)
                        throw new InvalidOperationException($"Invalid response code: {responseCode}");

                    byte[] nonce = responseReader.ReadBytes(16);

                    if (step1_nonce != null && !nonce.SequenceEqual(step1_nonce))
                        throw new InvalidOperationException("Invalid nonce");


                    byte[] serverNonce = responseReader.ReadBytes(16);
                    if (step2_serverNonce != null && !serverNonce.SequenceEqual(step2_serverNonce))
                        throw new InvalidOperationException("Invalid server nonce");

                    var encryptedAnswer = Serializers.Bytes.Read(responseReader);

                    return new DHExchangeResponse()
                    {
                        EncryptedAnswer = encryptedAnswer,
                        ServerNonce = serverNonce,
                        Nonce = nonce,
                        NewNonce = newNonce
                    };
                }
            }
        }
	}
}
