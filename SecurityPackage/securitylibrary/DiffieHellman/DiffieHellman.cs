using System.Collections.Generic;
using System;
using System.Numerics;
namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> key = new List<int>();
            //public= genrator ^private mod prime
            //q= prime
            //alpa< q
            //Ya=alpa ^xa mod q
            //Yb =alpa^xb mod q
            // k=Yb^xa mod q
            //k=Ya^xb mod q

            BigInteger bigA = new BigInteger(alpha);
            BigInteger bigXa = new BigInteger(xa);
            BigInteger bigq = new BigInteger(q);
            BigInteger result = BigInteger.ModPow(bigA, bigXa, bigq);
            int Ya = (int)(result % int.MaxValue);

            int Yb = 1;
            for (int i = 0; i < xb; i++)
            {
                Yb = (Yb * alpha) % q;
            }
            BigInteger bigYb = new BigInteger(Yb);
            BigInteger result1 = BigInteger.ModPow(bigYb, bigXa, bigq);
            int key1 = (int)(result1 % int.MaxValue);
            int key2 = 1;
            for (int i = 0; i < xb; i++)
            {
                key2 = (key2 * Ya) % q;
            }
            key.Add(key1);
            key.Add(key2);
            return key;
        }
    }
}
