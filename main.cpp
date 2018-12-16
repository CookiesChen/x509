#include <iostream>
#include <string>
#include <fstream>
#include "base64.h"
#include <string.h>
#include <vector>
#include <map>

using namespace std;

int decodeANS(unsigned char* binaryData, int start, int end);
void printInfos(unsigned char* binaryData);

int main(){
    ifstream fin;
    fin.open("test.cer");
    string data;
    string s;
    while(getline(fin, s)){
        if (s.find("BEGIN CERTIFICATE") != -1) {
            /* 去除Begin */
        } else if (s.find("END CERTIFICATE") != -1) {
            /* 去除End */
        } else {
            data += s;
        }
    }
    base64 temp;
    unsigned char* binaryData;
    /* Base64转换 */
    int dataSize = temp.DecodeBase64(data, binaryData);
    for(int i = 0; i < dataSize; i++){
        cout << hex << int(binaryData[i]) << " ";
    }
    cout << dec;
    cout << endl;
    cout << "[证书长度] " << dataSize << endl;
    /* ANS.1解码 */
    decodeANS(binaryData, 0, dataSize - 1);
    /* 打印信息*/
    printInfos(binaryData);
    return 0;
}

struct Info{
    int type;   // 数据类型
    string tag; // 数据类型输出
    int length; // 数据长度
    int start;  // 数据开始位置
};

vector<Info> infos;

int decodeANS(unsigned char* binaryData, int start, int end){
    int start_index = start;
    int len = 0;
    int objHead;
    int objNext;
    string tag; // 输出信息标签
    while(start_index < end) {
        tag = "";
        len = 0;
        // 获取结构体类型
        int type = binaryData[start_index++];
        // 获取长度
        if(binaryData[start_index] >> 7){
            // 首位为1, 合并后面的字节数
            int byteNum = binaryData[start_index] & 0x7f;
            for(int i = 0; i < byteNum; i++){
                len = (len << 8) + int(binaryData[start_index + 1 + i]);
            }
            start_index += byteNum;
        } else {
            len = int(binaryData[start_index] & 0x7f);
        }
        switch(type){
            case 0x30: // 序列
            case 0x31:
                start_index += decodeANS(binaryData, start_index + 1, start_index + len);
                break;
            case 0xa0: // 版本号
                tag = "Version";
                infos.push_back({type, tag, 0, start_index});
                start_index += decodeANS(binaryData, start_index + 1, start_index + len);
                break;
            case 0x02: // 整数类型
            case 0x80:
                infos.push_back({type, tag, len, start_index + 1});
                start_index += len + 1;
                break;
            case 0x05:
                break;
            case 0x06:  // Object Identifier
                tag = "";
                objHead = int(binaryData[start_index + 1]) & 0x7f;
                objNext = min(objHead/40 , 2);
                tag.append(to_string(min(objHead/40, 2)));
                tag.append(".");
                tag.append(to_string(objHead - 40 * objNext));
                tag.append(".");
                objHead = 0;
                for(int i = 1; i < len; i++){
                    objHead <<= 7;
                    objHead += binaryData[start_index + i + 1] & 0x7f;
                    if (!(binaryData[start_index + i +1] & 0x80)) {
                        tag.append(to_string(objHead));
                        tag.append(".");
                        objHead = 0;
                    } 
                }
                infos.push_back({type, tag.substr(0, tag.length() - 1), 0, start_index + 1});
                start_index += len;
                break;
            case 0x13: // 字符串
                for (int i = 0; i < len; i++) {
                    tag += (char)binaryData[start_index + 1 + i];
                }
                infos.push_back({type, tag, 0, start_index + 1});
                break;
            default:
                start_index = end;
        }
    }
    return end - start + 2;
}

void printInfos(unsigned char* binaryData){
    std::map<string, string> titleToString = {
        {"1.3.6.1.5.5.7.3.1", "服务器身份验证(id_kp_serverAuth): True"},
        {"1.3.6.1.5.5.7.3.2", "客户端身份验证(id_kp_clientAuth): True"},
        {"2.5.29.37", "扩展密钥用法(Extended key usage):"},
        {"2.5.29.31", "CRL Distribution Points:"},
        {"1.2.840.10045.2.1", "EC Public Key:"},
        {"Extension", "扩展字段:"},
        {"2.23.140.1.2.2","组织验证(organization-validated):"},
        {"1.3.6.1.5.5.7.1.1", "AuthorityInfoAccess:"},
        {"2.5.29.19", "基本约束(Basic Constraints):"},
        {"1.3.6.1.5.5.7.3.2", "客户端身份验证(id_kp_clientAuth): True"}};
    std::map<string, string> titleToHex = {
        {"1.2.840.10045.3.1.7",
        "推荐椭圆曲线域(SEC 2 recommended elliptic curve domain): \n"},
        {"2.5.29.35", "授权密钥标识符(Authority Key Identifier): "},
        {"2.5.29.14", "主体密钥标识符(Subject Key Identifier): "}};
    std::map<string, string> titleToNext = {
        {"1.3.6.1.5.5.7.2.1", "OID for CPS qualifier: "},
        {"1.3.6.1.5.5.7.48.1", "OCSP: "},
        {"1.3.6.1.5.5.7.48.2", "id-ad-caIssuers: "},
        {"1.3.6.1.4.1.311.60.2.1.1", "所在地(Locality): "},
        {"1.3.6.1.4.1.311.60.2.1.3", "国家(Country): "},
        {"1.3.6.1.4.1.311.60.2.1.2", "州或省(State or province): "},
        {"2.5.4.3", "通用名称(id-at-commonName): "},
        {"2.5.4.5", "颁发者序列号(id-at-serialNumber): "},
        {"2.5.4.6", "颁发者国家名(id-at-countryName): "},
        {"2.5.4.7", "颁发者位置名(id-at-localityName): "},
        {"2.5.4.8", "颁发者州省名(id-at-stateOrProvinceName): "},
        {"2.5.4.9", "颁发者街区地址(id-at-streetAddress): "},
        {"2.5.4.10", "颁发者组织名(id-at-organizationName): "},
        {"2.5.4.11", "颁发者组织单位名(id-at-organizationalUnitName): "},
        {"2.5.4.12", "颁发者标题(id-at-title): "},
        {"2.5.4.13", "颁发者描述(id-at-description): "},
        {"2.5.4.15", "颁发者业务类别(id-at-businessCategory): "},
        {"2.5.29.32", "证书策略(Certificate Policies): "},
        {"2.5.29.15", "使用密钥(Key Usage): "}};

    std::map<string, string> algorithmObject = {
        {"1.2.840.10040.4.1", "DSA"},
        {"1.2.840.10040.4.3" , "sha1DSA"},
        {"1.2.840.113549.1.1.1" ,"RSA"},
        {"1.2.840.113549.1.1.2" , "md2RSA"},
        {"1.2.840.113549.1.1.3" , "md4RSA"},
        {"1.2.840.113549.1.1.4" , "md5RSA"},
        {"1.2.840.113549.1.1.5" , "sha1RSA"},
        {"1.3.14.3.2.29", "sha1RSA"},
        {"1.2.840.113549.1.1.13", "sha512RSA"},
        {"1.2.840.113549.1.1.11","sha256RSA"}};
      
    for (int i = 0; i < infos.size(); i++) {
        Info info = infos[i];
        if (!strcmp(info.tag.c_str(), "Version")) {
            info = infos[++i];
            if (info.type == 0x02) {
                cout << "证书版本: ";
                cout << "V" << int(binaryData[info.start]) + 1 << endl;
                info = infos[++i];
                cout << "序列号: ";
                cout << hex;
                for(int i = 0; i < info.length; i++){
                    cout << (int(binaryData[info.start + i])>>4) << (int(binaryData[info.start + i] & 0xf));
                }
                cout << dec << endl;
            }
        } else if (algorithmObject.find(info.tag) != algorithmObject.end()) {
            cout << "加密算法: " << algorithmObject[info.tag];

        }
    }
}