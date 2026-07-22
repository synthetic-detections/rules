// BENIGN — an ordinary crypto helper that uses AES-256-GCM and RSA plus generic
// GET/SEND HTTP verbs. It has no Graph calendar dead-drop and none of the implant's
// on-host config artifacts, so it must NOT match.
using System.Security.Cryptography;

class CryptoHelper
{
    byte[] Seal(byte[] plain, byte[] key)
    {
        using var aes = new AesGcm(key);   // AES-256-GCM
        var rsa = RSA.Create();
        return plain;
    }

    // A generic REST client with GET and SEND helpers.
    void Get(string url) { }
    void Send(string url, byte[] body) { }
}
