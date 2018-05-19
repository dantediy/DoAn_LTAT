using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace chat2
{
    class DH2
    {
        public byte[] bobPublicKey;

        public byte[] generatePublicKey()
        {
            using (ECDiffieHellmanCng bob = new ECDiffieHellmanCng())
            {
                bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                bob.HashAlgorithm = CngAlgorithm.Sha256;
                bobPublicKey = bob.PublicKey.ToByteArray();

                return bobPublicKey;
            }
        }
        public byte[] secretKey(byte[] alicePublicKey)
        {
            using (ECDiffieHellmanCng bob = new ECDiffieHellmanCng())
            {
                CngKey k = CngKey.Import(alicePublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] bobKey = bob.DeriveKeyMaterial(k);
                return bobKey;
            }
        }
    }
}
