using System;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {

            //key generation 
            int n = p * q;
            int Euler = (p - 1) * (q - 1);
            //Encription 
            double a = Math.Pow(M, e);
            
            long c = 1;
            long baseValue = M % n;

            while (e > 0)
            {
                if ((e & 1) == 1)
                {
                    c = (c * baseValue) % n;
                }

                e >>= 1;
                baseValue = (baseValue * baseValue) % n;
            }

            

            return (int)c;



        }

        public int Decrypt(int p, int q, int C, int e)
        {
            AES.ExtendedEuclid extendedEuclid = new AES.ExtendedEuclid();

            int n = p * q;
            int Euler = (p - 1) * (q - 1);
            int d = extendedEuclid.GetMultiplicativeInverse(e, Euler);
            int M = 1;
            for (int i = 0; i < d; i++)
            {
                M = (M * C) % n;
            }
            return M;

        }
    }
}
