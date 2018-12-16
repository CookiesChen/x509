#include "base64.h"

using namespace std;

static const unsigned char g_pMap[256] =
{
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
  52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
 255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
 255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
  49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
 255, 255, 255, 255
};

base64::base64(){
    
}

int base64::DecodeBase64(string s, unsigned char* &data){
    int len = s.size();
    int dataSize = len/4*3;
    if(s[len - 1] == '='){
        dataSize--;
    }
    if(s[len - 2] == '='){
        dataSize--;
    }
    data = new unsigned char[dataSize];
    for(int i = 0; i < dataSize; i++){
        data[i] = 0;
    }
    for(int i = 0; i < len/4 - 1; i++){
        data[i*3] = (g_pMap[s[i*4]] << 2) + (g_pMap[s[i*4 + 1]] >> 4);
        data[i*3 + 1] = ((g_pMap[s[i*4 + 1]] % 16) << 4) +  (g_pMap[s[i*4 + 2]] >> 2);
        data[i*3 + 2] = (g_pMap[s[i*4 + 2]] << 6) +  g_pMap[s[i*4 + 3]];
    }
    if(dataSize % 3 == 0){
        data[dataSize - 3] = (g_pMap[s[len - 4]] << 2) + (g_pMap[s[len - 3]] >> 4);
        data[dataSize - 2] = ((g_pMap[s[len - 3]] % 16) << 4) +  (g_pMap[s[len - 2]] >> 2);
        data[dataSize - 1] = (g_pMap[s[len - 2]] << 6) +  g_pMap[s[len - 1]];
    } else if(dataSize % 3 == 2){
        data[dataSize - 2] = (g_pMap[s[len - 4]] << 2) + (g_pMap[s[len - 3]] >> 4);
        data[dataSize - 1] = ((g_pMap[s[len - 3]] % 16) << 4) +  (g_pMap[s[len - 2]] >> 2);
    } else {
        data[dataSize - 1] = (g_pMap[s[len - 4]] << 2) + (g_pMap[s[len - 3]] >> 4);
    }
    return dataSize;
}