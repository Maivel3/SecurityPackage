using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            int[] arr = new int[26];
            IDictionary<char, int> table = new Dictionary<char, int>();
            int counte = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                table.Add(c, counte);
                counte++;
            }

            /* IDictionary<char,int> CipherTable = new Dictionary<char,int>();
             int count = 0;
             for (char c = 'A'; c <= 'Z'; c++)
             {
                 CipherTable.Add(c, (key + count) % 26);
                 count++;   
             }*/

            int a = plainText.Length;
            char[] chars = new char[a];
            int n = 0;
            foreach (char c in plainText)
            {
                int res, y = 0;
                if (table.TryGetValue(c, out res))
                {
                    y = (res + key) % 26;
                    var myKey = table.FirstOrDefault(x => x.Value == y).Key;
                    chars[n] = myKey;
                    n++;
                }
            }
            string s = new string(chars);
            return s;
        }

        public string Decrypt(string cipherText, int key)
        {
            IDictionary<char, int> table = new Dictionary<char, int>();
            int counte = 0;
            for (char c = 'A'; c <= 'Z'; c++)
            {
                table.Add(c, counte);
                counte++;
            }
            int a = cipherText.Length;
            char[] chars = new char[a];
            int n = 0;
            Console.WriteLine(cipherText);
            foreach (char c in cipherText)
            {
                int res, y = 0;
                if (table.TryGetValue(c, out res))
                {
                    if (res >= key)
                    {
                        y = (res - key);
                    }
                    else
                    {
                        y = res - key + 26;

                    }
                    var myKey = table.FirstOrDefault(x => x.Value == y).Key;
                    chars[n] = myKey;
                    n++;
                }
            }
            string s = new string(chars);
            Console.WriteLine(s);
            return s;
        }

        public int Analyse(string plainText, string cipherText)
        {
            IDictionary<char, int> table = new Dictionary<char, int>();
            int counte = 0;
            for (char c = 'A'; c <= 'Z'; c++)
            {
                table.Add(c, counte);
                counte++;
            }
            IDictionary<char, int> atable = new Dictionary<char, int>();
            int count = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                atable.Add(c, count);
                count++;
            }
            foreach (char c in cipherText)
            {
                int res, y = 0, result;
                if (table.TryGetValue(c, out res))
                {
                    foreach (char x in plainText)
                    {
                        if (atable.TryGetValue(x, out result))
                        {
                            if (res == result)
                            {
                                return 0;
                            }
                            y = res-result;

                            if (y > 0)
                            {
                                return y;
                            }
                            else
                            {
                                return y + 26;
                            }
                           
                        }
                    }

                 
                }
            }return 0;

        }
    }
}
