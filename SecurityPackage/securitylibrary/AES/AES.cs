using System;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public string[,] Mat = { { "0e", "0b", "0d", "09" } ,
                             { "09", "0e", "0b", "0d" } ,
                             { "0d", "09", "0e", "0b" } ,
                             { "0b", "0d", "09", "0e" }};

        public string[,] Sbox = new string[16, 16] { { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                                                  { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                                                  { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                                                  { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                                                  { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                                                  { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                                                  { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                                                  { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                                                  { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                                                  { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                                                  { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                                                  { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                                                  { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
                                                  { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                                                  { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                                                  { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" } };
       public string[,] RC = new string[4, 10] { { "01" , "02" , "04" , "08", "10" , "20" , "40" , "80" , "1b" , "36" },
{ "00" , "00" , "00" ,"00" , "00" , "00" ,"00" ,"00", "00" ,"00" } ,
{ "00" , "00" , "00" ,"00" , "00" , "00" , "00" , "00" ,"00" ,"00" },
{ "00" , "00" , "00" , "00", "00" , "00" , "00" , "00" ,"00" ,"00" } };

        public override string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            int n = 4;
            int count = 2;
            string[,] mat = new string[n, n];
            string subs = "";
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    subs = key.Substring(count, 2);
                    count = count + 2;
                    mat[j, i] = subs;
                }
            }
            string[,] keymat = mat;
            count = 2;
            string[,] ciphermat = new string[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    subs = cipherText.Substring(count, 2);
                    count = count + 2;
                    ciphermat[j, i] = subs;
                }
            }
            for (int i = 0; i <= 9; i++)
            {
                keymat = AddRoundkey(keymat, i);
            }
            ciphermat = XORForMAt(ciphermat, keymat);
            for (int i = 9; i > 0; i--)
            {
                ciphermat = InvShiftRow(ciphermat, 4);
                ciphermat = InvSubByte(ciphermat, 4);
                count = 2;
                mat = new string[4, 4];
                string sl = "";
                for (int l = 0; l < 4; l++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        sl = key.Substring(count, 2);
                        mat[j, l] = sl;
                        count += 2;
                    }
                }
                keymat = mat;
                for (int j = 0; j < i; j++)
                {
                    keymat = AddRoundkey(keymat, j);
                }
                ciphermat = XORForMAt(keymat, ciphermat);
                ciphermat = InvMixCol(ciphermat);
            }
            ciphermat = InvShiftRow(ciphermat, 4);
            ciphermat = InvSubByte(ciphermat, 4);
            count = 2;
            mat = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    subs = key.Substring(count, 2);
                    mat[j, i] = subs;
                    count += 2;
                }
            }
            keymat = mat;

            ciphermat = XORForMAt(keymat, ciphermat);

            string result = "";
            int sizea = ciphermat.GetLength(0), sizeb = ciphermat.GetLength(1);
            for (int i = 0; i < sizeb; i++)
            {
                for (int j = 0; j < sizea; j++)
                {
                    result += ciphermat[j, i];
                }
            }
            string start = "0x";
            start += result.ToUpper();
            return start;
        }



        public override string Encrypt(string plainText, string key)
        {
            byte[,] inputMatrix = MatrixConstruction(plainText);
            byte[,] keyMatrix = MatrixConstruction(key);
            inputMatrix = AddRoundKey(inputMatrix, keyMatrix);
            byte[,] output = inputMatrix;
            byte[,] scheduler = keyMatrix;
            for (int i = 0; i < 10; i++)
            {
                output = SubstitutionBytes(output);
                output = ShiftRows(output);
                if (i != 9)
                    output = MixColumns(output);
                scheduler = KeyScheduler(scheduler, i);
                output = AddRoundKey(output, scheduler);
            }
            return MatrixDeConstruction(output);
        }
        public string[,] AddRoundkey(string[,] mat, int counter)
        {
            
            string[,] arr = new string[4, 1];
            string hex = "";
            int rcounter = 0;
            string indx = "";
            for (int i = 0; i < 3; i++)
            {
                arr[i, 0] = mat[i + 1, 3];
            }
            arr[3, 0] = mat[0, 3];
            indx = arr[0, 0];
            
            for (int i = 0; i < 4; i++)
            {
                
                if (i != 3)
                {
                    rcounter++;
                }
                int l = int.Parse(indx.Substring(0, 1), System.Globalization.NumberStyles.HexNumber);
                int m = int.Parse(indx.Substring(1, 1), System.Globalization.NumberStyles.HexNumber);
                arr[i, 0] = Sbox[l, m];
                indx = arr[rcounter, 0];
            }
           
            for (int i = 0; i < 4; i++)
            {
                string[] s1 = new string[3];
                s1[0] = Convert.ToString(Convert.ToInt32(mat[i, 0], 16), 2);
                s1[1] = Convert.ToString(Convert.ToInt32(arr[i, 0], 16), 2);

                s1[2] = Convert.ToString(Convert.ToInt32(RC[i, counter], 16), 2);
                string[] res = new string[3];
                for (int j = 0; j < 3; j++)
                {
                    int d = 8 - s1[j].Length;

                    for (int l = 0; l < d; l++)
                    {
                        res[j] += '0';
                    }
                    res[j] += s1[j];

                }



                hex = XOR(res[0], res[1]);
                int diff = 8 - hex.Length;
                string r = "";
                for (int l = 0; l < diff; l++)
                {
                    r += '0';
                }
                r += hex;

                hex = XOR(r, res[2]);
                string ss = Convert.ToString(Convert.ToInt32(hex, 2), 16);
                int len = 2 - ss.Length;
                string b = string.Empty;
                for (int l = 0; l < len; l++)
                {
                    b += '0';
                }
                b += ss;

                mat[i, 0] = b;
            }
 
            int count = 0;
         
            while (count < 3)
            {
                hex = "";
                for (int i = 0; i < 4; i++)
                {
                    string[] s1 = new string[2];
                    s1[0] = Convert.ToString(Convert.ToInt32(mat[i, count], 16), 2);
                    s1[1] = Convert.ToString(Convert.ToInt32(mat[i, count + 1], 16), 2);


                    string[] res = new string[2];
                    for (int j = 0; j < 2; j++)
                    {
                        int d = 8 - s1[j].Length;

                        for (int l = 0; l < d; l++)
                        {
                            res[j] += '0';
                        }
                        res[j] += s1[j];

                    }
                    hex = XOR(res[0], res[1]);
                    string ss = Convert.ToString(Convert.ToInt32(hex, 2), 16);
                    int len = 2 - ss.Length;
                    string b = "";
                    for (int l = 0; l < len; l++)
                    {
                        b += '0';
                    }
                    b += ss;


                    mat[i, count + 1] = b;

                }
                count++;
            }
            return mat;
        }

        public string[,] InvMixCol(string[,] input)
        {
            string[,] r = new string[4, 4];
           
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        string s1 = Convert.ToString(Convert.ToInt32(input[k, j], 16), 2);
                        int d = 8 - s1.Length;
                        string y = "";
                        for(int l = 0; l < d; l++)
                        {
                            y+='0';

                        }
                        y += s1;
                        Console.WriteLine("y = " + y);
                        string s = Mat[i, k];
                        if (r[i, j] == null)
                        {
                            r[i, j] = multiply(y, s);
                        }
                        else
                        {
                            r[i, j] = XOR(multiply(y, s), r[i, j]);
                        }
                    }
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string rr = Convert.ToString(Convert.ToInt32(r[i, j], 2), 16);
                    int d = 2 - rr.Length;
                    string rs = "";
                    for(int l = 0; l < d; l++)
                    {
                        rs += "0";

                    }
                    rs += rr;
                    Console.WriteLine("re =" + rs);
                    r[i, j] =rs;
                }
            }
            return r;

        }
        public string[,] InvSubByte(string[,] mat, int n = 4)
        {

            string[,] res = new string[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    mat[i, j] = mat[i, j].ToUpper();
                    for (int l = 0; l < n * n; l++)
                    {
                        for (int m = 0; m < n * n; m++)
                        {
                            if (mat[i, j] == Sbox[l, m])
                            {
                                res[i, j] = Convert.ToString(l, 16) + Convert.ToString(m, 16);
                            }
                        }
                    }
                }
            }
            mat = res;
            return mat;

        }
        public string[,] InvShiftRow(string[,] mat, int n = 4)
        {
            int count = 4;
            string[,] res = new string[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    if (j == 0)
                    {
                        res[i, j] = mat[i, j];
                    }
                    int y = (j + count) % 4;
                    res[i, j] = mat[i, y];
                }
                count--;
            }
            mat = res;
            return mat;
        }
        public string XOR(string s1, string s2)
        {
            string res = "";
            for (int i = 0; i < 8; i++)
            {
                if (s1[i] != s2[i])
                {
                    res += '1';
                }
                else
                {
                    res += '0';
                }
            }
            return res;
        }
       
        public string multiply(string s, string x)
        {
            string l = "";
            switch (x)
            {
                case "01":
                    l = s;
                    break;
                case "02":
                    if (s[0] == '0')
                    {
                        l = s.Substring(1, s.Length - 1) + "0";
                        
                    }
                    else
                    {
                        l = XOR(s.Substring(1, s.Length - 1) + "0", "00011011");
                        
                    }
                    break;

                case "03":
                    l = XOR(multiply(s, "02"), s);
                    break;
                case "09":
                    l = XOR(multiply(multiply(multiply(s, "02"), "02"), "02"), s);
                    break;
                case "0b":
                    l = XOR(multiply(XOR(multiply(multiply(s, "02"), "02"), s), "02"), s);
                    break;
                case "0d":
                    l = XOR(multiply(multiply(multiply(s, "03"), "02"), "02"), s);
                    break;
                case "0e":
                    l = multiply(XOR(multiply(multiply(s, "03"), "02"), s), "02");
                    break;
                default:
                    return l;
            }
            return l;
           
        }


        public string[,] XORForMAt(string[,] input1, string[,] input2, int n = 4)
        {
            string[,] res = new string[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    string str = Convert.ToString(Convert.ToInt32(input2[i, j], 16), 2);
                    string str1 = Convert.ToString(Convert.ToInt32(input1[i, j], 16), 2);
                    string r = string.Empty;
                    string rr = string.Empty;
                    int d = 8 - str.Length;

                    for (int l = 0; l < d; l++)
                    {
                        r += '0';
                    }
                    r += str;
                    d = 8 - str1.Length;
                    for (int l = 0; l < d; l++)
                    {
                        rr += '0';
                    }
                    rr += str1;
                    res[i, j] = XOR(rr, r);

                    string ss = Convert.ToString(Convert.ToInt32(res[i, j], 2), 16);
                    int len = 2 - ss.Length;
                    string b = "";
                    for (int l = 0; l < len; l++)
                    {
                        b += '0';
                    }
                    b += ss;
                    res[i, j] = b;
                }
            }
            return res;
        }
        byte[,] sBox ={
        // 0     1      2    3      4     5     6     7     8     9    10    11    12    13    14    15
        { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
        { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
        { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
        { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
        { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
        { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
        { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
        { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
        { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
        { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
        { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
        { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
        { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
        { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
        { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
        { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
        };

        public byte[,] MCMatrix =
        {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
        };
        public byte[,] RconMatrix =
        {
            {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
        };

        public byte[,] MatrixConstruction(string plain)
        {
            int index = 2;
            byte[,] SORMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    SORMatrix[j, i] = Convert.ToByte((plain[index].ToString() + plain[index + 1].ToString()), 16);

                    index += 2;
                }
            }
            return SORMatrix;
        }
        public string MatrixDeConstruction(byte[,] matrix)
        {
            string outer = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    outer += matrix[j, i].ToString("X2");
                }
            }
            return outer;
        }

        public byte[,] SubstitutionBytes(byte[,] StartOfRoundMatrix)
        {
            byte[,] ASB = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int row = StartOfRoundMatrix[i, j] >> 4;
                    int column = StartOfRoundMatrix[i, j] & 0x0f;
                    ASB[i, j] = sBox[row, column];
                }
            }
            return ASB;
        }

        public byte[,] ShiftRows(byte[,] AfterSubBytes)
        {
            byte[,] ASR = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ASR[i, j] = AfterSubBytes[i, (i + j) % 4];
                }
            }
            return ASR;
        }
        public byte HexMultiplication(byte one, byte two)
        {
            byte result = 0;
            byte checkMost;
            for (int i = 0; i < 8; i++)
            {
                if ((two & 1) != 0)
                    result ^= one;
                checkMost = Convert.ToByte((one & 0x80));
                one <<= 1;
                if (checkMost != 0)
                    one ^= 0x1b;
                two >>= 1;
            }
            return result;
        }
        public byte[,] MixColumns(byte[,] AfterShiftRows)
        {
            for (int i = 0; i < 4; i++)
            {
                byte r0 = AfterShiftRows[0, i];
                byte r1 = AfterShiftRows[1, i];
                byte r2 = AfterShiftRows[2, i];
                byte r3 = AfterShiftRows[3, i];

                AfterShiftRows[0, i] = Convert.ToByte(HexMultiplication(r0, MCMatrix[0, 0]) ^ HexMultiplication(r1, MCMatrix[0, 1]) ^ HexMultiplication(r2, MCMatrix[0, 2]) ^ HexMultiplication(r3, MCMatrix[0, 3]));
                AfterShiftRows[1, i] = Convert.ToByte(HexMultiplication(r0, MCMatrix[1, 0]) ^ HexMultiplication(r1, MCMatrix[1, 1]) ^ HexMultiplication(r2, MCMatrix[1, 2]) ^ HexMultiplication(r3, MCMatrix[1, 3]));
                AfterShiftRows[2, i] = Convert.ToByte(HexMultiplication(r0, MCMatrix[2, 0]) ^ HexMultiplication(r1, MCMatrix[2, 1]) ^ HexMultiplication(r2, MCMatrix[2, 2]) ^ HexMultiplication(r3, MCMatrix[2, 3]));
                AfterShiftRows[3, i] = Convert.ToByte(HexMultiplication(r0, MCMatrix[3, 0]) ^ HexMultiplication(r1, MCMatrix[3, 1]) ^ HexMultiplication(r2, MCMatrix[3, 2]) ^ HexMultiplication(r3, MCMatrix[3, 3]));
            }
            return AfterShiftRows;
        }
        public byte[,] AddRoundKey(byte[,] AfterMixColumns, byte[,] key)
        {
            for (int i = 0; i < 4; i++)
            {
                AfterMixColumns[0, i] ^= key[0, i];
                AfterMixColumns[1, i] ^= key[1, i];
                AfterMixColumns[2, i] ^= key[2, i];
                AfterMixColumns[3, i] ^= key[3, i];
            }
            return AfterMixColumns;
        }
        public byte[,] KeyScheduler(byte[,] key, int num)
        {
            byte[,] result = new byte[4, 4];
            byte[] vec = new byte[4];
            for (int k = 0; k < 4; k++)
            {
                vec[k] = key[(k + 1) % 4, key.GetLength(0) - 1];
                vec[k] = sBox[vec[k] >> 4, vec[k] & 0x0f];
                result[k, 0] = Convert.ToByte(key[k, 0] ^ vec[k] ^ RconMatrix[k, num]);
            }
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[j, i + 1] = Convert.ToByte(key[j, i + 1] ^ result[j, i]);
                }
            }
            return result;
        }
        


    }
}