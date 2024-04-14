using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TrunkScannerSysKeyGen
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("TrunkScanner SysKey Generator\n");

            Console.Write("Enter SysId: ");
            string sysId = Console.ReadLine();

            Console.Write("Enter directory path to save the SysKey file (press Enter for current directory): ");
            string path = Console.ReadLine();
            string fullPath;

            if (string.IsNullOrWhiteSpace(path))
            {
                fullPath = Directory.GetCurrentDirectory();
            }
            else
            {
                try
                {
                    if (!Directory.Exists(path))
                    {
                        Console.WriteLine("Directory does not exist, using current directory instead.");
                        fullPath = Directory.GetCurrentDirectory();
                    }
                    else
                    {
                        fullPath = path;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error checking directory: {ex.Message}. Using current directory.");
                    fullPath = Directory.GetCurrentDirectory();
                }
            }

            string filename = $"SYS{sysId}.key";
            string filePath = Path.Combine(fullPath, filename);

            string encryptedKey = EncryptSysId(sysId, GenerateKeyFromSysId(sysId));
            File.WriteAllText(filePath, encryptedKey);
            Console.WriteLine($"SysKey saved to {filePath}");

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        private static string EncryptSysId(string sysId, string key)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(sysId);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(key, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                encryptor.Padding = PaddingMode.PKCS7;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        private static string GenerateKeyFromSysId(string sysId)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(sysId));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}