using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class Aes128Ejemplo{
    public static void Main(){
        // Clave de 128 bits (16 bytes) y Vector de Inicialización (IV) de 128 bits (16 bytes)
        byte[] key = Encoding.UTF8.GetBytes("1234567890123456"); // Debe tener exactamente 16 caracteres/bytes
        byte[] iv  = Encoding.UTF8.GetBytes("abcdefghijklmnop"); // Debe tener exactamente 16 caracteres/bytes

        string textoOriginal = "Mensaje secreto";

        string textoCifrado = Cifrar(textoOriginal, key, iv);
        Console.WriteLine($"Cifrado: {textoCifrado}");

        string textoDescifrado = Descifrar(textoCifrado, key, iv);
        Console.WriteLine($"Descifrado: {textoDescifrado}");
    }

    public static string Cifrar(string textoPlano, byte[] Key, byte[] IV){
        using (Aes aes = Aes.Create()){
            aes.KeySize = 128; // Forzar 128 bits
            aes.Key = Key;
            aes.IV = IV;

            using (MemoryStream ms = new MemoryStream()){
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write)){
                    using (StreamWriter sw = new StreamWriter(cs)){
                        sw.Write(textoPlano);
                    }
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }
}
