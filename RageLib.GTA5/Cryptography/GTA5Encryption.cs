/*
    Copyright(c) 2015 Neodymium

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
*/

using RageLib.Cryptography;
using RageLib.GTA5.Cryptography.Helpers;
using System;

namespace RageLib.GTA5.Cryptography
{


  


    /// <summary>
    /// Represents a GTA5 encryption algorithm.
    /// </summary>
    public class GTA5Crypto : IEncryptionAlgorithm
    {
        public byte[] Key { get; set; }

        ////////////////////////////////////////////////////////////////////////////
        // decryption
        ////////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// Decrypts data.
        /// </summary>
        public byte[] Decrypt(byte[] data)
        {
            return Decrypt(data, Key);
        }

        /// <summary>
        /// Decrypts data.
        /// </summary>
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            var decryptedData = new byte[data.Length];

            var keyuints = new uint[key.Length / 4];
            Buffer.BlockCopy(key, 0, keyuints, 0, key.Length);

            for (int blockIndex = 0; blockIndex < data.Length / 16; blockIndex++)
            {
                var encryptedBlock = new byte[16];
                Array.Copy(data, 16 * blockIndex, encryptedBlock, 0, 16);
                var decryptedBlock = DecryptBlock(encryptedBlock, keyuints);
                Array.Copy(decryptedBlock, 0, decryptedData, 16 * blockIndex, 16);
            }

            if (data.Length % 16 != 0)
            {
                var left = data.Length % 16;
                Buffer.BlockCopy(data, data.Length - left, decryptedData, data.Length - left, left);
            }

            return decryptedData;
        }

        public static byte[] DecryptBlock(byte[] data, uint[] key)
        {
            var buffer = data;

            // prepare key...
            var subKeys = new uint[17][];
            for (int i = 0; i < 17; i++)
            {
                subKeys[i] = new uint[4];
                subKeys[i][0] = key[4 * i + 0];
                subKeys[i][1] = key[4 * i + 1];
                subKeys[i][2] = key[4 * i + 2];
                subKeys[i][3] = key[4 * i + 3];
            }

            buffer = DecryptRoundA(buffer, subKeys[0], GTA5Constants.PC_NG_DECRYPT_TABLES[0]);
            buffer = DecryptRoundA(buffer, subKeys[1], GTA5Constants.PC_NG_DECRYPT_TABLES[1]);
            for (int k = 2; k <= 15; k++)
                buffer = DecryptRoundB(buffer, subKeys[k], GTA5Constants.PC_NG_DECRYPT_TABLES[k]);
            buffer = DecryptRoundA(buffer, subKeys[16], GTA5Constants.PC_NG_DECRYPT_TABLES[16]);

            return buffer;
        }

        // round 1,2,16
        public static byte[] DecryptRoundA(byte[] data, uint[] key, uint[][] table)
        {
            var x1 =
                table[0][data[0]] ^
                table[1][data[1]] ^
                table[2][data[2]] ^
                table[3][data[3]] ^
                key[0];
            var x2 =
                table[4][data[4]] ^
                table[5][data[5]] ^
                table[6][data[6]] ^
                table[7][data[7]] ^
                key[1];
            var x3 =
                table[8][data[8]] ^
                table[9][data[9]] ^
                table[10][data[10]] ^
                table[11][data[11]] ^
                key[2];
            var x4 =
                table[12][data[12]] ^
                table[13][data[13]] ^
                table[14][data[14]] ^
                table[15][data[15]] ^
                key[3];

            var result = new byte[16];
            Array.Copy(BitConverter.GetBytes(x1), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(x2), 0, result, 4, 4);
            Array.Copy(BitConverter.GetBytes(x3), 0, result, 8, 4);
            Array.Copy(BitConverter.GetBytes(x4), 0, result, 12, 4);
            return result;
        }

        // round 3-15
        public static byte[] DecryptRoundB(byte[] data, uint[] key, uint[][] table)
        {
            var x1 =
                table[0][data[0]] ^
                table[7][data[7]] ^
                table[10][data[10]] ^
                table[13][data[13]] ^
                key[0];
            var x2 =
                table[1][data[1]] ^
                table[4][data[4]] ^
                table[11][data[11]] ^
                table[14][data[14]] ^
                key[1];
            var x3 =
                table[2][data[2]] ^
                table[5][data[5]] ^
                table[8][data[8]] ^
                table[15][data[15]] ^
                key[2];
            var x4 =
                table[3][data[3]] ^
                table[6][data[6]] ^
                table[9][data[9]] ^
                table[12][data[12]] ^
                key[3];

            //var result = new byte[16];
            //Array.Copy(BitConverter.GetBytes(x1), 0, result, 0, 4);
            //Array.Copy(BitConverter.GetBytes(x2), 0, result, 4, 4);
            //Array.Copy(BitConverter.GetBytes(x3), 0, result, 8, 4);
            //Array.Copy(BitConverter.GetBytes(x4), 0, result, 12, 4);
            //return result;

            var result = new byte[16];
            result[0] = (byte)((x1 >> 0) & 0xFF);
            result[1] = (byte)((x1 >> 8) & 0xFF);
            result[2] = (byte)((x1 >> 16) & 0xFF);
            result[3] = (byte)((x1 >> 24) & 0xFF);
            result[4] = (byte)((x2 >> 0) & 0xFF);
            result[5] = (byte)((x2 >> 8) & 0xFF);
            result[6] = (byte)((x2 >> 16) & 0xFF);
            result[7] = (byte)((x2 >> 24) & 0xFF);
            result[8] = (byte)((x3 >> 0) & 0xFF);
            result[9] = (byte)((x3 >> 8) & 0xFF);
            result[10] = (byte)((x3 >> 16) & 0xFF);
            result[11] = (byte)((x3 >> 24) & 0xFF);
            result[12] = (byte)((x4 >> 0) & 0xFF);
            result[13] = (byte)((x4 >> 8) & 0xFF);
            result[14] = (byte)((x4 >> 16) & 0xFF);
            result[15] = (byte)((x4 >> 24) & 0xFF);
            return result;
        }

        public byte[] Encrypt(byte[] data)
        {
            return GTA5Crypto.Encrypt(data, this.Key);
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            byte[] array = new byte[data.Length];
            uint[] array2 = new uint[key.Length / 4];
            Buffer.BlockCopy(key, 0, array2, 0, key.Length);
            for (int i = 0; i < data.Length / 16; i++)
            {
                byte[] array3 = new byte[16];
                Array.Copy(data, 16 * i, array3, 0, 16);
                byte[] sourceArray = GTA5Crypto.EncryptBlock(array3, array2);
                Array.Copy(sourceArray, 0, array, 16 * i, 16);
            }
            if (data.Length % 16 != 0)
            {
                int num = data.Length % 16;
                Buffer.BlockCopy(data, data.Length - num, array, data.Length - num, num);
            }
            return array;
        }

        public static byte[] EncryptBlock(byte[] data, uint[] key)
        {
            uint[][] array = new uint[17][];
            for (int i = 0; i < 17; i++)
            {
                array[i] = new uint[4];
                array[i][0] = key[4 * i];
                array[i][1] = key[4 * i + 1];
                array[i][2] = key[4 * i + 2];
                array[i][3] = key[4 * i + 3];
            }
            byte[] array2 = GTA5Crypto.EncryptRoundA(data, array[16], GTA5Constants.PC_NG_ENCRYPT_TABLES[16]);
            for (int j = 15; j >= 2; j--)
            {
                array2 = GTA5Crypto.EncryptRoundB_LUT(array2, array[j], GTA5Constants.PC_NG_ENCRYPT_LUTs[j]);
            }
            array2 = GTA5Crypto.EncryptRoundA(array2, array[1], GTA5Constants.PC_NG_ENCRYPT_TABLES[1]);
            return GTA5Crypto.EncryptRoundA(array2, array[0], GTA5Constants.PC_NG_ENCRYPT_TABLES[0]);
        }

        public static byte[] EncryptRoundA(byte[] data, uint[] key, uint[][] table)
        {
            byte[] array = new byte[16];
            Buffer.BlockCopy(key, 0, array, 0, 16);
            uint value = table[0][(int)(data[0] ^ array[0])] ^ table[1][(int)(data[1] ^ array[1])] ^ table[2][(int)(data[2] ^ array[2])] ^ table[3][(int)(data[3] ^ array[3])];
            uint value2 = table[4][(int)(data[4] ^ array[4])] ^ table[5][(int)(data[5] ^ array[5])] ^ table[6][(int)(data[6] ^ array[6])] ^ table[7][(int)(data[7] ^ array[7])];
            uint value3 = table[8][(int)(data[8] ^ array[8])] ^ table[9][(int)(data[9] ^ array[9])] ^ table[10][(int)(data[10] ^ array[10])] ^ table[11][(int)(data[11] ^ array[11])];
            uint value4 = table[12][(int)(data[12] ^ array[12])] ^ table[13][(int)(data[13] ^ array[13])] ^ table[14][(int)(data[14] ^ array[14])] ^ table[15][(int)(data[15] ^ array[15])];
            byte[] array2 = new byte[16];
            Array.Copy(BitConverter.GetBytes(value), 0, array2, 0, 4);
            Array.Copy(BitConverter.GetBytes(value2), 0, array2, 4, 4);
            Array.Copy(BitConverter.GetBytes(value3), 0, array2, 8, 4);
            Array.Copy(BitConverter.GetBytes(value4), 0, array2, 12, 4);
            return array2;
        }

        public static byte[] EncryptRoundA_LUT(byte[] dataOld, uint[] key, GTA5NGLUT[] lut)
        {
            byte[] array = (byte[])dataOld.Clone();
            byte[] array2 = new byte[16];
            Buffer.BlockCopy(key, 0, array2, 0, 16);
            for (int i = 0; i < 16; i++)
            {
                byte[] array3 = array;
                int num = i;
                array3[num] ^= array2[i];
            }
            return new byte[]
            {
                lut[0].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[1].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[2].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[3].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[4].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[5].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[6].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[7].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[8].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[9].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[10].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[11].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[12].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[13].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[14].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[15].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0))
            };
        }

        public static byte[] EncryptRoundB_LUT(byte[] dataOld, uint[] key, GTA5NGLUT[] lut)
        {
            byte[] array = (byte[])dataOld.Clone();
            byte[] array2 = new byte[16];
            Buffer.BlockCopy(key, 0, array2, 0, 16);
            for (int i = 0; i < 16; i++)
            {
                byte[] array3 = array;
                int num = i;
                array3[num] ^= array2[i];
            }
            return new byte[]
            {
                lut[0].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[1].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[2].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[3].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[4].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[5].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[6].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[7].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[8].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[9].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[10].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[11].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[12].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[13].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[14].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[15].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0))
            };
        }
    }
}