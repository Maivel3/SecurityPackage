using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key;
            for(int i = 0; i < 26; i++)
            {
                for(int j = 0; j < 26; j++)
                {
                    for(int k = 0; k < 26; k++)
                    {
                        for(int l = 0; l < 26; l++)
                        {
                            key = new List<int>(new[] { i, j, k, l });
                            List<int> result = Encrypt(plainText, key);
                            if (result.SequenceEqual(cipherText))
                                return key;
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }
        

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> res = new List<int>();
            if (cipherText.Count == 0)
                return null;

            int row = (int)Math.Log((double)key.Count, 2);
            int[,] keyMat = MatrixConstruction(key, row, row, false);
            int colSize = (int)Math.Ceiling(cipherText.Count / (double)row);
            int[,] cipherMat = MatrixConstruction(cipherText, row, colSize, true);
            int det = Determinant(keyMat);
            det = Modulus(det, 26);
            int inver = modInverse(det, 26);
            if(inver == 0)
                throw new InvalidAnlysisException();
            int[,] adjKeyMat = Adjugate(keyMat, inver);
            int[,] inverseKeyMat = Transpose(adjKeyMat);
            res = MatrixMultiply(cipherMat, inverseKeyMat);
            return res;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> res = new List<int>();
            if (plainText.Count == 0)
                return null;

            int row = (int)Math.Log((double)key.Count, 2);
            int col = (int)Math.Ceiling(plainText.Count / (double)row);
            int[,] keyMatrix = MatrixConstruction(key, row, row, false);
            int[,] plainMatrix = MatrixConstruction(plainText, row, col, true);
            res = MatrixMultiply(plainMatrix, keyMatrix);
            return res;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {

            List<int> res = new List<int>();
            if (cipherText.Count == 0)
                return null;
            int[,] plain = MatrixConstruction(plainText, 3, 3, true);
            int[,] cipher = MatrixConstruction(cipherText, 3, 3, true);
            int[,] keyMat = matrixMultiplyArr(cipher,transpose(plain),3);
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    res.Add((keyMat[i, j]) % 26);
                }
            }
            return res;
        }

        public int[,] matrixMultiplyArr(int[,] matTxt, int[,] matrixKey, int s)
        {
            int col = matrixKey.Length / s;
            int[,] mat = new int[s, col];

            for (int i = 0; i < s; i++)
            {
                for (int j = 0; j < col; j++)
                {

                    for (int k = 0; k < s; k++)
                    {
                        int x = matrixKey[k, j] * matTxt[i, k];
                        mat[i, j] += x;
                    }
                }
            }
            return mat;
        }
        public int[,] transpose(int[,] mat)
        {
            int[,] res = new int[mat.GetLength(0), mat.GetLength(0)];
            int n = 26;
            int m = modInverse((Determinant(mat) % n + n) % n, n);
            int len = mat.GetLength(0);
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    int a = m * (int)Math.Pow(-1, i + j);
                    res[j, i] = a * Determinant(SubMatrix(mat, i, j));
                    res[j, i] = ((res[j, i] % n) + n) % n;
                }
            }
            return res;
        }
        public int Modulus(int a, int n)
        {
            int res = a % n;
            if (res < 0)
            {
                res += n;
            }
            return res;
        }

        public int[,] MatrixConstruction(List<int> text, int row, int col, bool isRow)
        {
            int[,] mat = new int[row, col];
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (isRow)
                        mat[i, j] = text[i + j * row];
                    else
                        mat[i, j] = text[i * col + j];
                }
            }
            return mat;
        }
        public int Determinant(int[,] mat)
        {
            int s = mat.GetLength(0);
            if (s == 0)
            {
                return mat[0, 0];
            }
            int det = 0;
            int sign = 1;
            if (s == 2)
            {
                det = mat[0, 0] * mat[1, 1] - mat[0, 1] * mat[1, 0];
            }
            else
            {
                for (int i = 0; i < s; i++)
                {
                    int[,] block = new int[2, 2];
                    for (int j = 1; j < s; j++)
                    {
                        for (int k = 0; k < s; k++)
                        {
                            if (k < i)
                                block[j - 1, k] = mat[j, k];
                            else if (k > i)
                                block[j - 1, k - 1] = mat[j, k];
                        }
                    }
                    det += sign * mat[0, i] * Determinant(block);
                    sign = -sign;
                }
            }
            return det;
        }
        public List<int> MatrixMultiply(int[,] matTxt, int[,] Keymat)
        {
            List<int> res = new List<int>();
            for (int i = 0; i < matTxt.GetLength(1); i++)
            {
                for (int j = 0; j < matTxt.GetLength(0); j++)
                {
                    int sum = 0;
                    for (int k = 0; k < Keymat.GetLength(1); k++)
                    {
                        sum += Keymat[j, k] * matTxt[k, i];
                    }
                    res.Add(sum % 26);
                }
            }
            return res;
        }

        static int modInverse(int A, int M)
        {
            for (int X = 1; X < M; X++)
                if (((A % M) * (X % M)) % M == 1)
                    return X;
            return 0;
        }

        public int[,] Adjugate(int[,] mat, int inv)
        {
            int n = mat.GetLength(0);
            int[,] adjugate = new int[n, n];

            if (n == 2)
            {
                adjugate[0, 0] = Modulus((inv * (mat[1, 1])), 26);
                adjugate[0, 1] = Modulus((inv * (-mat[1, 0])), 26);
                adjugate[1, 0] = Modulus((inv * (-mat[0, 1])), 26);
                adjugate[1, 1] = Modulus((inv * (mat[0, 0])), 26);
            }
            else
            {
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        int[,] subMatrix = SubMatrix(mat, i, j);
                        int subDet = Determinant(subMatrix);
                        int sign = ((i + j) % 2 == 0) ? 1 : -1;
                        int kij = Modulus((inv * sign * subDet), 26) % 26;
                        if (kij < 0)
                            kij += 26;

                        adjugate[i, j] = kij;
                    }
                }
            }
            return adjugate;
        }

        public int[,] SubMatrix(int[,] mat, int rowToDelete, int colToDelete)
        {
            int n = mat.GetLength(0);
            int[,] sub = new int[n - 1, n - 1];
            int row = 0;

            for (int i = 0; i < n; i++)
            {
                if (i != rowToDelete)
                {
                    int col = 0;

                    for (int j = 0; j < n; j++)
                    {
                        if (j != colToDelete)
                        {
                            sub[row, col] = mat[i, j];
                            col++;
                        }
                    }

                    row++;
                }
            }

            return sub;
        }

        public int[,] Transpose(int[,] mat)
        {
            int n = mat.GetLength(0);
            int[,] transposed = new int[n, n];

            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    transposed[i, j] = mat[j, i];
                }
            }

            return transposed;
        }
    }
}
