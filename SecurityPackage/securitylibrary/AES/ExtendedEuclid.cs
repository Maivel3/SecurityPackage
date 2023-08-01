using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            double t1, t2, t3;
            double Q;
            int a1 = 1;
            int a2 = 0;
            int b1 = 0;
            int b2 = 1;
            int a3 = baseN;
            int b3 = number;
            
            for(int i=0; ; i++) {
               
                Q = a3 / b3;
                double l1 = Q * b1;
                double l2 = Q * b2;
                double l3 = Q * b3;
                t1 = a1 - l1;
                t2 = a2 - l2;
                t3 = a3 - l3;
                a1 = b1;
                a2 = b2;
                a3 = b3;
                b1 = (int)t1;
                b2 = (int)t2;
                b3 = (int)t3;
                if (b3 == 1 || b3 == 0)
                {
                    break;
                }
                
            }
            switch (b3)
            {
                case 0:
                    return -1;
                case 1:
                    if (b2 < -1)
                    {
                        return b2 + baseN;
                    }
                    else
                    {
                        return b2;
                    }
            }
            return -1;
        }
    }
}
