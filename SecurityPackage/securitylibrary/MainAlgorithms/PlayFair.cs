using System;
using System.Collections.Generic;
using System.Text;
namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {

            var uni = new HashSet<char>(key);
            List<char> ch = new List<char>();
            foreach (char c in uni)
            {
                ch.Add(c);

            }


            for (char c = 'a'; c <= 'z'; c++)
            {

                if (!ch.Contains(c))
                {

                    if (c != 'j')
                    {
                        ch.Add(c);
                    }

                }

            }
            char[,] chars = new char[5, 5];
            int n = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    chars[i, j] = ch[n];
                    n++;

                }

            }


            char[] arr = cipherText.ToLower().ToCharArray();


            List<char> cha = new List<char>();
            for (int k = 0; k < arr.Length; k += 2)
            {
                int a = 0, b = 0, y = 0, z = 0;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (arr[k] == chars[i, j])
                        {
                            a = i;
                            b = j;

                        }
                        if (arr[k + 1] == chars[i, j])
                        {
                            y = i;
                            z = j;
                        }


                    }
                }

                if (a == y)
                {
                    if (b > 0)
                    {
                        cha.Add(chars[a, b - 1]);
                    }
                    else
                    {
                        cha.Add(chars[a, 4]);
                    }
                    if (z > 0)
                    {
                        cha.Add(chars[y, z - 1]);
                    }
                    else
                    {
                        cha.Add(chars[y, 4]);
                    }
                }
                else if (b == z)
                {

                    if (a > 0)
                    {
                        cha.Add(chars[a - 1, b]);
                    }
                    else
                    {
                        cha.Add(chars[4, b]);

                    }
                    if (y > 0)
                    {
                        cha.Add(chars[y - 1, z]);
                    }
                    else
                    {
                        cha.Add(chars[4, z]);

                    }

                }


                else
                {
                    cha.Add(chars[a, z]);
                    cha.Add(chars[y, b]);

                }
            }


            string myString = new string(cha.ToArray());
            List<char> last = new List<char>();
            for (int i = 0; i < myString.Length; i++)
            {
                if (myString[i] != 'x')
                {
                    last.Add(myString[i]);
                }



            }
            string str = "";

            for (int i = 0; i < myString.Length - 2; i += 2)
            {
                str += myString[i];
                if (myString[i] == myString[i + 2] && myString[i + 1] == 'x')
                {
                    continue;
                }
                else
                {
                    str += myString[i + 1];

                }

            }
            str += myString[myString.Length - 2];
            if (myString[myString.Length - 1] != 'x')
            {
                str += myString[myString.Length - 1];
            }

            myString = str;
            return myString;
          
        }

        public string Encrypt(string plainText, string key)
        {

            char[] newplain = new char[plainText.Length];
            List<char> list = new List<char>();

            for (int i = 0; i < plainText.Length; i++)
            {
                newplain[i] = plainText[i];

                list.Add(newplain[i]);


            }

            StringBuilder str = new StringBuilder(plainText);

            for (int i = 0; i < str.Length; i += 2)
            {

                if (i == str.Length - 1 && str.Length % 2 == 1)
                {

                    str.Append("x");

                }

                else if (str[i] == str[i + 1])
                    str.Insert(i + 1, 'x');
            }
            plainText = str.ToString();
            Console.WriteLine(plainText);
            Console.WriteLine("######################");


            /*   List<char> newtext = new List<char>();


               string s = new string(newtext.ToArray());
               if (s.Length % 2 != 0)
               {
                   s += 'x';
               }

               Console.WriteLine(s);

                if (plainText.Length%2 != 0)
                {
                    plainText += 'x';
                }*/
            Console.WriteLine(key);
            Console.WriteLine(plainText);
            var uni = new HashSet<char>(key);
            List<char> ch = new List<char>();
            foreach (char c in uni)
            {
                ch.Add(c);

            }


            for (char c = 'a'; c <= 'z'; c++)
            {

                if (!ch.Contains(c))
                {

                    if (c != 'j')
                    {
                        ch.Add(c);
                    }

                }

            }
            char[,] chars = new char[5, 5];
            int n = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    chars[i, j] = ch[n];
                    n++;

                }

            }

            char[] arr = plainText.ToLower().ToCharArray();


            List<char> cha = new List<char>();
            for (int k = 0; k < arr.Length; k += 2)
            {
                int a = 0, b = 0, y = 0, z = 0;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (arr[k] == chars[i, j])
                        {
                            a = i;
                            b = j;

                        }
                        if (arr[k + 1] == chars[i, j])
                        {
                            y = i;
                            z = j;
                        }


                    }
                }

                if (a == y)
                {
                    if (b < 4)
                    {
                        cha.Add(chars[a, b + 1]);
                    }
                    else
                    {
                        cha.Add(chars[a, 0]);
                    }
                    if (z < 4)
                    {
                        cha.Add(chars[y, z + 1]);
                    }
                    else
                    {
                        cha.Add(chars[y, 0]);
                    }
                }
                else if (b == z)
                {

                    if (a < 4)
                    {
                        cha.Add(chars[a + 1, b]);
                    }
                    else
                    {
                        cha.Add(chars[0, b]);

                    }
                    if (y < 4)
                    {
                        cha.Add(chars[y + 1, z]);
                    }
                    else
                    {
                        cha.Add(chars[0, z]);

                    }

                }


                else
                {
                    cha.Add(chars[a, z]);
                    cha.Add(chars[y, b]);

                }
            }


            string myString = new string(cha.ToArray());
            Console.WriteLine(myString.ToUpper());
            return myString.ToUpper();


        }
    }
}
