using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[] chars = new char[26];
            int a = 0;
            string s = "";
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int size = cipherText.Length;
            for (char c = 'a'; c <= 'z'; c++)
            {
                chars[a] = c;
                a++;
            }

            for (int i = 0; i < size; i++)
            {
                s += chars[(cipherText[i] - plainText[i] + 26) % 26];
            }
            string key = "";
            int len = s.Length;
            for (int i = 1; i < len; i++)
            {
                if (!s.Substring(0, i).Contains(s.Substring(i, i)))
                {
                    continue;
                }
                key = s.Substring(0, i);
                break;
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string DecryptText = null;
            if (cipherText == null)
                return null;

            cipherText = cipherText.ToLower();
            string keyStream = null;
            int length = cipherText.Length;
            for (int i = 0; i < length; i++)
            {
                keyStream += key[i % key.Length];
                DecryptText += (char)(((int)cipherText[i] - 'a' - (int)(keyStream[i] - 'a') + 26) % 26 + 'a');
            }
            return DecryptText;
        }

        public string Encrypt(string plainText, string key)
        {
            string EncryptText = null;
            if (plainText == null)
                return null;

            string keyStream = null;
            int length = plainText.Length;
            for (int i = 0; i < length; i++)
            {
                keyStream += key[i % key.Length];
                EncryptText += (char)(((int)plainText[i] - 'a' + (int)(keyStream[i] - 'a')) % 26 + 'a');
            }
            return EncryptText;
        }
    }
}