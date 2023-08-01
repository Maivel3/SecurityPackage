using System.Collections.Generic;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> key = new List<long>();
            long k1 = 1;
            for (int i = 0; i < k; i++)
            {
                k1 = (k1 * alpha) % q;
            }
            long k2 = 1;
            for (int i = 0; i < k; i++)
            {
                k2 = (k2 * y) % q;
            }
            k2 = (k2 * m) % q;
            key.Add(k1);
            key.Add(k2);
            return key;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            AES.ExtendedEuclid extendedEuclid = new AES.ExtendedEuclid();

            long K = 1;
            long baseValue = c1 % q;
            while (x > 0)
            {
                if ((x & 1) == 1)
                {
                    K = (K * baseValue) % q;
                }

                x >>= 1;
                baseValue = (baseValue * baseValue) % q;
            }

            int d = extendedEuclid.GetMultiplicativeInverse((int)K, q);
            c2 %= q;
            int m = (c2 * d) % q;
            return m;
        }
    }
}
