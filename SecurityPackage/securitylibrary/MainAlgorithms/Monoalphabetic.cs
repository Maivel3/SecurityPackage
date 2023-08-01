using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            List<char> plain = plainText.ToList<char>();
            List<char> cipher = cipherText.ToList<char>();
            Console.WriteLine(plainText);
            Console.WriteLine(cipherText);
            char[] str = plainText.ToLower().ToCharArray();
            int index = 0;

            for (int i = 0; i < str.Length; i++)
            {
                int j;
                for (j = 0; j < i; j++)
                {
                    if (str[i] == str[j])
                    {
                        break;
                    }
                }
                if (j == i)
                {
                    str[index++] = str[i];
                }
            }
            char[] ans = new char[index];
            Array.Copy(str, ans, index);
            string s = String.Join("", ans);
            Console.WriteLine(s);


            char[] ch = cipherText.ToLower().ToCharArray();
            int indx = 0;
            for (int i = 0; i < ch.Length; i++)
            {
                int j;
                for (j = 0; j < i; j++)
                {
                    if (ch[i] == ch[j])
                    {
                        break;
                    }
                }

                // If not present, then add it to
                // result.
                if (j == i)
                {
                    ch[indx++] = ch[i];
                }
            }
            char[] anser = new char[indx];
            Array.Copy(ch, anser, indx);
            string st = String.Join("", anser);
            Console.WriteLine(st);
            Dictionary<char, char> table = new Dictionary<char, char>();
            for (int i = 0; i < st.Length; i++)
            {
                table.Add(str[i], ch[i]);
            }
            
            List<char> chars = new List<char>();
            if (table.Count != 26)
            {
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (!table.ContainsKey(c))
                    {
                        for (char h = 'a'; h <= 'z'; h++)
                        {
                            if (!table.ContainsValue(h))
                            {
                                table.Add(c,h);
                                break;
                            }
                        }
                    }
                }
            }
            var items = from pair in table orderby pair.Key ascending select pair;
            foreach (KeyValuePair<char, char> pair in items)
            {
                Console.WriteLine("Key: {0}, Value: {1}", pair.Key, pair.Value);
                chars.Add(pair.Value);
            }
            string answer = new string(chars.ToArray());
            Console.WriteLine(answer);
            return answer;


        }

        public string Decrypt(string cipherText, string key)
        {
            IDictionary<char, char> table = new Dictionary<char, char>();
            int count = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                table.Add(key[count], c);
                count++;
            }
            int a = cipherText.Length;
            char[] chars = new char[a];
            int n = 0;
            foreach (char c in cipherText.ToLower())
            {
                char result;
                table.TryGetValue(c, out result);
                chars[n] = result;
                n++;

            }
            string s = new string(chars);
            Console.WriteLine(s);
            return s;

        }

        public string Encrypt(string plainText, string key)
        {
            IDictionary<char, char> table = new Dictionary<char, char>();
            int count = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                table.Add(c, key[count]);
                count++;
            }
            int a = plainText.Length;
            char[] chars = new char[a];
            int n = 0;
            foreach (char c in plainText)
            {
                char result;
                table.TryGetValue(c, out result);
                chars[n] = result;
                n++;

            }
            string s = new string(chars);
            return s;

        }

        /// <summary>
        /// Frequency Information: "ETAOINSRHLDCUMFPGWYBVKXJQZ"
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string chars = "";
            for(char c = 'A'; c <= 'Z'; c++)
            {
                chars += c;
            }
            string frequentChars = "ETAOINSRHLDCUMFPGWYBVKXJQZ";

            Dictionary<char, int> table = new Dictionary<char, int>();
            
            string ciphertxt = cipher;
            for (int i = 0; i < 26; i++)
            {
                char ch = chars[i];
               int counte = 0;
                for (int j = 0; j < ciphertxt.Length; j++)
                {
                    if (ch == ciphertxt[j])
                    {
                        counte++;
                    }
                }
                foreach (var c in ciphertxt)
                {
                    string s = ch.ToString();
                    ciphertxt = ciphertxt.Replace(s, string.Empty);
                }
                table.Add(ch, counte);
            }
            ciphertxt = cipher;
            


            char[] arr = new char[cipher.Length];
            for (int i = 0; i < cipher.Length; i++)
            {
                arr[i] = ciphertxt[i];

            }
            int counter = 0;

            foreach (var record in table.OrderByDescending(pair => pair.Value))
            {
                for (int i = 0; i < ciphertxt.Length; i++)
                {
                    if (ciphertxt[i] == record.Key)
                    {
                        arr[i] = frequentChars[counter];
                    }
                }
                counter++;
            }

            string plaintext =new string (arr);
           
            return plaintext.ToLower();
        }
    }
}

