using System;
using System.Text;

namespace SecurityLibrary.MD5
{
    public class MD5
    {


        public string GetHash(string text)
        {
            byte[] m = Encoding.ASCII.GetBytes(text);
            uint[] tbl = new uint[64];
            for (int i = 0; i < 64; i++)
                tbl[i] = (uint)(long)((1L << 32) * Math.Abs(Math.Sin(i + 1)));

            int MLSByte, numblocks;
            byte[] padbytes;
            long mlen;
            messages(m, out MLSByte, out numblocks, out padbytes, out mlen);
            mlen = pad(padbytes, mlen);
            uint a = A;
            uint b = B;
            uint c = C;
            uint d = D;
            int[] buffer = new int[16];
            for (int i = 0; i < numblocks; i++)
            {
                int indx = i << 6;
                uint AA, BB, CC, DD;
                shifter(m, tbl, MLSByte, padbytes, ref a, ref b, ref c, ref d, buffer, ref indx, out AA, out BB, out CC, out DD);
                a += AA;
                b += BB;
                c += CC;
                d += DD;
            }
            byte[] md5 = new byte[16];
            int coun = 0;
            coun = revstring(a, b, c, d, md5, coun);

            return toString(md5);
        }


        public uint A = 0x67452301;
        public uint B = 0xEFCDAB89;
        public uint C = 0x98BADCFE;
        public uint D = 0x10325476;
        public int[] shift = new int[] { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };


        public static long Shift(long num, int l)
        {
            if (num < 0)
                return (num >> l) + (2 << ~l);
            return num >> l;
        }

        public uint rotate(uint x, int l)
        {
            return (x << l) | (x >> (32 - l));
        }


        private static int revstring(uint x, uint y, uint z, uint dw, byte[] text, int n)
        {
            for (int i = 0; i < 4; i++)
            {
                int number;
                switch (i)
                {
                    case 0:
                        number = (int)x;
                        break;
                    case 1:
                        number = (int)y;
                        break;
                    case 2:
                        number = (int)z;
                        break;
                    default:
                        number = (int)dw;
                        break;
                }
                for (int j = 0; j < 4; j++)
                {
                    text[n++] = (byte)number;
                    number = (int)Shift(number, 8);
                }
            }

            return n;
        }
        private void shifter(byte[] m, uint[] t, int len, byte[] pad, ref uint a, ref uint b, ref uint c, ref uint d, int[] buf,
            ref int indx, out uint AA, out uint BB, out uint CC, out uint DD)
        {
            for (int j = 0; j < 64; j++, indx++)
            {
                long shiftedJ = Shift(j, 2);
                int indexValue = (indx < len) ? m[indx] : pad[indx - len];
                int leftShiftedValue = indexValue << 24;
                long rightShiftedBufValue = Shift(buf[shiftedJ], 8);
                var result = leftShiftedValue | rightShiftedBufValue;
                buf[shiftedJ] = (int)result;
            }
            AA = a;
            BB = b;
            CC = c;
            DD = d;
            for (int j = 0; j < 64; j++)
            {
                int vid = (int)Shift(j, 4);
                int suf = 0;
                int bufind = j;
                if (vid == 0)
                {
                    suf = (int)((b & c) | (~b & d));
                }
                else if (vid == 1)
                {
                    suf = (int)((b & d) | (c & ~d));
                    bufind = (bufind * 5 + 1) & 0x0F;
                }
                else if (vid == 2)
                {
                    suf = (int)(b ^ c ^ d);
                    bufind = (bufind * 3 + 5) & 0x0F;
                }
                else if (vid == 3)
                {
                    suf = (int)(c ^ (b | ~d));
                    bufind = (bufind * 7) & 0x0F;
                }

                uint norm = b + rotate((uint)(a + suf + buf[bufind] + t[j]), shift[(vid << 2) | (j & 3)]);
                a = d;
                d = c;
                c = b;
                b = norm;
            }
        }
        private static long pad(byte[] pd, long mLb)
        {
            for (int i = 0; i < 8; i++)
            {
                pd[pd.Length - 8 + i] = (byte)mLb;
                mLb = Shift(mLb, 8);
            }

            return mLb;
        }
        private static void messages(byte[] message, out int mlb, out int nb, out byte[] pb, out long mlen)
        {
            mlb = message.Length;
            nb = ((int)Shift((mlb + 8), 6)) + 1;
            int len = nb << 6;

            pb = new byte[len - mlb];
            pb[0] = 0x80;

            mlen = (long)mlb << 3;
        }
        public string toString(byte[] text)
        {
            StringBuilder res = new StringBuilder();
            for (int i = 0; i < text.Length; i++)
            {
                res.Append(string.Format("{0:X2}", (text[i] & 0xFF)));
            }
            return res.ToString();
        }

    }
}