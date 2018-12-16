#ifndef BASE64_H
#define BASE64_H

#include <iostream>
#include <string>

using namespace std;

class base64
{
public:
    base64();
    int DecodeBase64(string, unsigned char* &);
};

#endif