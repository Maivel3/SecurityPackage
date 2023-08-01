namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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
            for (int i = 0; i <len ; i++)
            {
                int n = len - i;
                if (!s.Contains(plainText.Substring(0, n)))
                {
                    key += s[i];
                }
                else
                {
                    break;
                }
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
                if (i >= key.Length)
                    keyStream += DecryptText[i - key.Length];
                else
                    keyStream += key[i];
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
                if (i >= key.Length)
                    keyStream += plainText[i - key.Length];
                else
                    keyStream += key[i];
                EncryptText += (char)(((int)plainText[i] - 'a' + (int)(keyStream[i] - 'a')) % 26 + 'a');
            }
            return EncryptText;
        }
    }
}
