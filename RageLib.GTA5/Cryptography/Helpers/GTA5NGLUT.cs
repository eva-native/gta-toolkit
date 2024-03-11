using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RageLib.GTA5.Cryptography.Helpers
{
    public class GTA5NGLUT
    {
        // Token: 0x060007A2 RID: 1954 RVA: 0x0002CA28 File Offset: 0x0002AC28
        public GTA5NGLUT()
        {
            this.LUT0 = new byte[256][];
            for (int i = 0; i < 256; i++)
            {
                this.LUT0[i] = new byte[256];
            }
            this.LUT1 = new byte[256][];
            for (int j = 0; j < 256; j++)
            {
                this.LUT1[j] = new byte[256];
            }
            this.Indices = new byte[65536];
        }

        // Token: 0x060007A3 RID: 1955 RVA: 0x0002CAB0 File Offset: 0x0002ACB0
        public byte LookUp(uint value)
        {
            uint num = (value & 4294901760U) >> 16;
            uint num2 = (value & 65280U) >> 8;
            uint num3 = value & 255U;
            return this.LUT0[(int)this.LUT1[(int)this.Indices[(int)num]][(int)num2]][(int)num3];
        }

        // Token: 0x04000E7A RID: 3706
        public byte[][] LUT0;

        // Token: 0x04000E7B RID: 3707
        public byte[][] LUT1;

        // Token: 0x04000E7C RID: 3708
        public byte[] Indices;
    }
}
