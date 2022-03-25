#include <CkCrypt2.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
int Decrypt3DES() {
    char buffer[2048];
    std::string hKey;
    std::string hBlob;
    CkCrypt2 crypt;
    std::ifstream hFile("cryptoblob.tmp");
    std::getline(hFile, hKey);
    std::getline(hFile, hBlob);
    crypt.put_CryptAlgorithm("3des");
    crypt.put_CipherMode("cbc");
    crypt.put_EncodingMode("hex");
    crypt.SetEncodedKey(hKey.c_str(), "hex");
    std::string  decStr2 = crypt.decryptEncoded(hBlob.c_str());
    std::size_t len = decStr2.copy(buffer, 32, 148);
    buffer[len] = '\0';
    printf("        * NTLM : ");
    printf(buffer);
    hFile.close();
    return 0;
    
}