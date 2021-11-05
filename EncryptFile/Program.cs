using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// NOTE: this code is taken from this link directly so all credit given to that author.
// https://qawithexperts.com/article/c-sharp/encrypt-password-decrypt-it-c-console-application-example/169

namespace EncryptFile
{
    class Program
    {
        const int IDX_TYPE = 0;
        const int IDX_IN_FILE = 1;
        const int IDX_PASSWORD = 2;
        const int IDX_OUT_FILE = 3;


        static void Main(string[] args)
        {
            // Decide what we want to do based on first argument 
            if (args[IDX_TYPE] == "ENCRYPT")
            {
                // Read in the file we want to encrypt 
                string inContents = File.ReadAllText(args[IDX_IN_FILE]);

                // Encrypt the inContents 
                inContents = EncryptPlainTextToCipherText(inContents, args[IDX_PASSWORD]);

                // Now write back out to a file 
                File.WriteAllText(args[IDX_OUT_FILE], inContents);

                // Print the file out again after parsing just to make sure nothing got messed up 
                Console.WriteLine(DecryptCipherTextToPlainText(File.ReadAllText(args[IDX_OUT_FILE]), args[IDX_PASSWORD]));
            }
            else
            {
                // Read in the file we want to decrypt 
                string inContents = File.ReadAllText(args[IDX_IN_FILE]);

                // Decrypt the inContents 
                inContents = DecryptCipherTextToPlainText(inContents, args[IDX_PASSWORD]);

                // Now write back out to a file 
                File.WriteAllText(args[IDX_OUT_FILE], inContents);

                // Print the file out again after parsing just to make sure nothing got messed up 
                Console.WriteLine(inContents);
            }

            // Make the user hit a key
            Console.ReadKey();
        }

        //This method is used to convert the plain text to Encrypted/Un-Readable Text format.
        public static string EncryptPlainTextToCipherText(string PlainText, string SecurityKey)
        {
            // Getting the bytes of Input String.
            byte[] toEncryptedArray = UTF8Encoding.UTF8.GetBytes(PlainText);

            MD5CryptoServiceProvider objMD5CryptoService = new MD5CryptoServiceProvider();
            //Gettting the bytes from the Security Key and Passing it to compute the Corresponding Hash Value.
            byte[] securityKeyArray = objMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SecurityKey));
            //De-allocatinng the memory after doing the Job.
            objMD5CryptoService.Clear();

            var objTripleDESCryptoService = new TripleDESCryptoServiceProvider();
            //Assigning the Security key to the TripleDES Service Provider.
            objTripleDESCryptoService.Key = securityKeyArray;
            //Mode of the Crypto service is Electronic Code Book.
            objTripleDESCryptoService.Mode = CipherMode.ECB;
            //Padding Mode is PKCS7 if there is any extra byte is added.
            objTripleDESCryptoService.Padding = PaddingMode.PKCS7;


            var objCrytpoTransform = objTripleDESCryptoService.CreateEncryptor();
            //Transform the bytes array to resultArray
            byte[] resultArray = objCrytpoTransform.TransformFinalBlock(toEncryptedArray, 0, toEncryptedArray.Length);
            objTripleDESCryptoService.Clear();
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        //This method is used to convert the Encrypted/Un-Readable Text back to readable  format.
        public static string DecryptCipherTextToPlainText(string CipherText, string SecurityKey)
        {
            byte[] toEncryptArray = Convert.FromBase64String(CipherText);
            MD5CryptoServiceProvider objMD5CryptoService = new MD5CryptoServiceProvider();

            //Gettting the bytes from the Security Key and Passing it to compute the Corresponding Hash Value.
            byte[] securityKeyArray = objMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SecurityKey));
            objMD5CryptoService.Clear();

            var objTripleDESCryptoService = new TripleDESCryptoServiceProvider();
            //Assigning the Security key to the TripleDES Service Provider.
            objTripleDESCryptoService.Key = securityKeyArray;
            //Mode of the Crypto service is Electronic Code Book.
            objTripleDESCryptoService.Mode = CipherMode.ECB;
            //Padding Mode is PKCS7 if there is any extra byte is added.
            objTripleDESCryptoService.Padding = PaddingMode.PKCS7;

            var objCrytpoTransform = objTripleDESCryptoService.CreateDecryptor();
            //Transform the bytes array to resultArray
            byte[] resultArray = objCrytpoTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            objTripleDESCryptoService.Clear();

            //Convert and return the decrypted data/byte into string format.
            return UTF8Encoding.UTF8.GetString(resultArray);
        }
    }
}

