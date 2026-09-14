class RSAEncrypter(){
    public static void Main()
    {
        // Generate RSA keys
        using (var rsa = new RSACryptoServiceProvider(2048)){
            rsa.PersistKeyInCsp = false; // Do not store keys in the container

            // Export public and private keys
            string publicKey = rsa.ToXmlString(false); // Public key
            string privateKey = rsa.ToXmlString(true); // Private key

            Console.WriteLine("Public Key: \n" + publicKey);
            Console.WriteLine("Private Key: \n" + privateKey);

            // Data to encrypt
            string plainText = "Hello, RSA!";
            Console.WriteLine("\nOriginal Text: " + plainText);

            // Encrypt the data
            byte[] encryptedData = EncryptData(plainText, publicKey);
            Console.WriteLine("\nEncrypted Data (Base64): " + Convert.ToBase64String(encryptedData));

            // Decrypt the data
            string decryptedText = DecryptData(encryptedData, privateKey);
            Console.WriteLine("\nDecrypted Text: " + decryptedText);
        }
    }
     static byte[] EncryptData(string data, string publicKey){
        using (var rsa = new RSACryptoServiceProvider()){
            rsa.FromXmlString(publicKey);
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            return rsa.Encrypt(dataBytes, false); // Use PKCS#1 padding
        }
    }

    static string DecryptData(byte[] data, string privateKey){
        using (var rsa = new RSACryptoServiceProvider()){
            rsa.FromXmlString(privateKey);
            byte[] decryptedBytes = rsa.Decrypt(data, false); // Use PKCS#1 padding
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}