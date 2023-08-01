using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int limiter = plainText.Length;
            for (int i = 1; i < limiter; i++)
            {
                if (cipherText.Equals(Encrypt(plainText, i).ToUpper()) == true)
                {
                    return i;
                }
            }
            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            string DecryptText = null;
            if (cipherText == null)
                return null;
            int itr = 0;
            int NoOfColumns = (int)(Math.Ceiling(cipherText.Length / (double)key));
            char[,] DecryptionMatrix = new char[key, NoOfColumns];

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < NoOfColumns; j++)
                {
                    if (cipherText.Length <= itr)
                        continue;
                    else
                    {
                        DecryptionMatrix[i, j] = cipherText[itr];
                        itr++;
                    }
                }
            }

            for (int i = 0; i < NoOfColumns; i++)
            {
                for (int k = 0; k < key; k++)
                {
                    if (DecryptionMatrix[k, i] == '\0')
                        continue;
                    DecryptText += DecryptionMatrix[k, i];
                }
            }
            return DecryptText;
        }

        public string Encrypt(string plainText, int key)
        {
            string EncryptText = null;
            if (plainText == null)
                return null;
            int itr = 0;
            int NoOfColumns = (int)(Math.Ceiling(plainText.Length / (double)key));
            char[,] EncryptionMatrix = new char[key, NoOfColumns];

            for (int i = 0; i < NoOfColumns; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (plainText.Length <= itr)
                        continue;
                    else
                    {
                        EncryptionMatrix[j, i] = plainText[itr];
                        itr++;
                    }
                }
            }

            for (int i = 0; i < key; i++)
            {
                for (int k = 0; k < NoOfColumns; k++)
                {
                    if (EncryptionMatrix[i, k] == '\0')
                        continue;
                    EncryptText += EncryptionMatrix[i, k];
                }
            }
            return EncryptText;
        }
    }
}

