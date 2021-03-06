using System;
using System.Security.Cryptography;
using Telegram.Core.MTProto.Crypto;

namespace Telegram.Core
{
    internal static class Utils
    {
        public static readonly Random Random = new Random();

        public static long GenerateRandomLong()
        {
            long rand = (((long)Random.Next()) << 32) | ((long)Random.Next());
            return rand;
        }

        public static byte[] CalcMsgKey(byte[] data)
        {
            byte[] msgKey = new byte[16];
            Array.Copy(sha1(data), 4, msgKey, 0, 16);
            return msgKey;
        }

        public static AESKeyData CalcKey(byte[] sharedKey, byte[] msgKey, bool client)
        {
            int x = client ? 0 : 8;
            byte[] buffer = new byte[48];

            Array.Copy(msgKey, 0, buffer, 0, 16);            // buffer[0:16] = msgKey
            Array.Copy(sharedKey, x, buffer, 16, 32);     // buffer[16:48] = authKey[x:x+32]
            byte[] sha1a = sha1(buffer);                     // sha1a = sha1(buffer)

            Array.Copy(sharedKey, 32 + x, buffer, 0, 16);   // buffer[0:16] = authKey[x+32:x+48]
            Array.Copy(msgKey, 0, buffer, 16, 16);           // buffer[16:32] = msgKey
            Array.Copy(sharedKey, 48 + x, buffer, 32, 16);  // buffer[32:48] = authKey[x+48:x+64]
            byte[] sha1b = sha1(buffer);                     // sha1b = sha1(buffer)

            Array.Copy(sharedKey, 64 + x, buffer, 0, 32);   // buffer[0:32] = authKey[x+64:x+96]
            Array.Copy(msgKey, 0, buffer, 32, 16);           // buffer[32:48] = msgKey
            byte[] sha1c = sha1(buffer);                     // sha1c = sha1(buffer)

            Array.Copy(msgKey, 0, buffer, 0, 16);            // buffer[0:16] = msgKey
            Array.Copy(sharedKey, 96 + x, buffer, 16, 32);  // buffer[16:48] = authKey[x+96:x+128]
            byte[] sha1d = sha1(buffer);                     // sha1d = sha1(buffer)

            byte[] key = new byte[32];                       // key = sha1a[0:8] + sha1b[8:20] + sha1c[4:16]
            Array.Copy(sha1a, 0, key, 0, 8);
            Array.Copy(sha1b, 8, key, 8, 12);
            Array.Copy(sha1c, 4, key, 20, 12);

            byte[] iv = new byte[32];                        // iv = sha1a[8:20] + sha1b[0:8] + sha1c[16:20] + sha1d[0:8]
            Array.Copy(sha1a, 8, iv, 0, 12);
            Array.Copy(sha1b, 0, iv, 12, 8);
            Array.Copy(sha1c, 16, iv, 20, 4);
            Array.Copy(sha1d, 0, iv, 24, 8);

            return new AESKeyData(key, iv);
        }

        private static byte[] sha1(byte[] data)
        {
            using (SHA1 sha1 = new SHA1Managed())
            {
                return sha1.ComputeHash(data);
            }
        }
    }
}
