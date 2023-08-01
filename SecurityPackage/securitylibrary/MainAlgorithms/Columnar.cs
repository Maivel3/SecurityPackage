using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            string cipher = cipherText.ToLower();
            string clone = (string)cipher.Clone();
            double l = cipher.Length;
           
            SortedDictionary<int, int> table = new SortedDictionary<int, int>();
            Dictionary<int, int> dict = new Dictionary<int, int>();
            List<int> key = new List<int>();
            double y = 0.0;
            for (int len = 1; len < 10; len++)
            {
                int c = 0;
                y= Math.Ceiling((double)cipher.Length / len);
                string[,] sub = new string[(int)y, len];
                for (int i = 0; i < y; i++)
                {
                    for (int j = 0; j < len; j++)
                    {
                        if (c < l)
                        {
                            sub[i, j] = plainText[c].ToString();

                            c++;
                        }
                        else
                        {
                            sub[i, j] = "";
                        }
                    }
                }

                bool flag = true;
                table = new SortedDictionary<int, int>();
                for (int i = 0; i < len; i++)
                {
                    string word = "";
                    for (int j = 0; j < y; j++)
                    {
                        word += sub[j, i];
                    }
   
                    int a = clone.IndexOf(word);
                    switch (a)
                    {
                        case -1:
                            flag = false;
                            break;
                        default:
                            table.Add(a, i + 1);
                            clone.Replace(word, " ");
                            break;
                    }
                }
                if (flag)
                    break;

            }
            int counter = 0;
            foreach( var pair in table)
            {                 
                dict.Add(pair.Value, counter + 1);
                if (counter >= 1)
                {
                    key.Add(counter +1);
                }
                counter++;
              
            }
            key.Distinct();
            for(int i = 0; i < key.Count; i++)
            {
                Console.WriteLine(key[i]);
            }
            key = new List<int>();
           
            for (int k = 1; k < dict.Count + 1; k++)
            {
                
                key.Add(dict[k]);
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string DecryptText = null;
            if (cipherText == null)
                return null;

            int NoOfColumns = key.Count;
            int NoOfRows = (int)Math.Ceiling((double)cipherText.Length / NoOfColumns);
            int itr = 0, index = 1;
            char[,] DecryptionMatrix = new char[NoOfRows, NoOfColumns];
            while (NoOfColumns >= index)
            {
                for (int j = 0; j < NoOfRows; j++)
                {
                    if (cipherText.Length <= itr)
                        continue;
                    else
                    {
                        DecryptionMatrix[j, key.IndexOf(index)] = cipherText[itr];
                        itr++;
                    }
                }
                index++;
            }
            for (int j = 0; j < NoOfRows; j++)
            {
                for (int k = 0; k < NoOfColumns; k++)
                {
                    DecryptText += DecryptionMatrix[j, k];
                }
            }
            return DecryptText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string EncryptText = null;
            if (plainText == null)
                return null;

            int NoOfColumns = key.Count;
            int NoOfRows = (int)Math.Ceiling((double)plainText.Length / NoOfColumns);
            int itr = 0;
            char[,] EncryptionMatrix = new char[NoOfRows, NoOfColumns];
            for (int i = 0; i < NoOfRows; i++)
            {
                for (int j = 0; j < NoOfColumns; j++)
                {
                    if (plainText.Length <= itr)
                        continue;
                    else
                    {
                        EncryptionMatrix[i, j] = plainText[itr];
                        itr++;
                    }
                }
            }
            int index = 1;
            while (NoOfColumns >= index)
            {
                for (int k = 0; k < NoOfRows; k++)
                    EncryptText += EncryptionMatrix[k, key.IndexOf(index)];
                index++;
            }
            return EncryptText;
        }
    }
}