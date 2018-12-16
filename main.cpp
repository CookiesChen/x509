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
            /* ȥ��Begin */
        } else if (s.find("END CERTIFICATE") != -1) {
            /* ȥ��End */
        } else {
            data += s;
        }
    }
    base64 temp;
    unsigned char* binaryData;
    /* Base64ת�� */
    int dataSize = temp.DecodeBase64(data, binaryData);
    for(int i = 0; i < dataSize; i++){
        cout << hex << int(binaryData[i]) << " ";
    }
    cout << dec;
    cout << endl;
    cout << "[֤�鳤��] " << dataSize << endl;
    /* ANS.1���� */
    decodeANS(binaryData, 0, dataSize - 1);
    /* ��ӡ��Ϣ*/
    printInfos(binaryData);
    return 0;
}

struct Info{
    int type;   // ��������
    string tag; // �����������
    int length; // ���ݳ���
    int start;  // ���ݿ�ʼλ��
};

vector<Info> infos;

int decodeANS(unsigned char* binaryData, int start, int end){
    int start_index = start;
    int len = 0;
    int objHead;
    int objNext;
    string tag; // �����Ϣ��ǩ
    while(start_index < end) {
        tag = "";
        len = 0;
        // ��ȡ�ṹ������
        int type = binaryData[start_index++];
        // ��ȡ����
        if(binaryData[start_index] >> 7){
            // ��λΪ1, �ϲ�������ֽ���
            int byteNum = binaryData[start_index] & 0x7f;
            for(int i = 0; i < byteNum; i++){
                len = (len << 8) + int(binaryData[start_index + 1 + i]);
            }
            start_index += byteNum;
        } else {
            len = int(binaryData[start_index] & 0x7f);
        }
        switch(type){
            case 0x30: // ����
            case 0x31:
                start_index += decodeANS(binaryData, start_index + 1, start_index + len);
                break;
            case 0xa0: // �汾��
                tag = "Version";
                infos.push_back({type, tag, 0, start_index});
                start_index += decodeANS(binaryData, start_index + 1, start_index + len);
                break;
            case 0x02: // ��������
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
            case 0x13: // �ַ���
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
        {"1.3.6.1.5.5.7.3.1", "�����������֤(id_kp_serverAuth): True"},
        {"1.3.6.1.5.5.7.3.2", "�ͻ��������֤(id_kp_clientAuth): True"},
        {"2.5.29.37", "��չ��Կ�÷�(Extended key usage):"},
        {"2.5.29.31", "CRL Distribution Points:"},
        {"1.2.840.10045.2.1", "EC Public Key:"},
        {"Extension", "��չ�ֶ�:"},
        {"2.23.140.1.2.2","��֯��֤(organization-validated):"},
        {"1.3.6.1.5.5.7.1.1", "AuthorityInfoAccess:"},
        {"2.5.29.19", "����Լ��(Basic Constraints):"},
        {"1.3.6.1.5.5.7.3.2", "�ͻ��������֤(id_kp_clientAuth): True"}};
    std::map<string, string> titleToHex = {
        {"1.2.840.10045.3.1.7",
        "�Ƽ���Բ������(SEC 2 recommended elliptic curve domain): \n"},
        {"2.5.29.35", "��Ȩ��Կ��ʶ��(Authority Key Identifier): "},
        {"2.5.29.14", "������Կ��ʶ��(Subject Key Identifier): "}};
    std::map<string, string> titleToNext = {
        {"1.3.6.1.5.5.7.2.1", "OID for CPS qualifier: "},
        {"1.3.6.1.5.5.7.48.1", "OCSP: "},
        {"1.3.6.1.5.5.7.48.2", "id-ad-caIssuers: "},
        {"1.3.6.1.4.1.311.60.2.1.1", "���ڵ�(Locality): "},
        {"1.3.6.1.4.1.311.60.2.1.3", "����(Country): "},
        {"1.3.6.1.4.1.311.60.2.1.2", "�ݻ�ʡ(State or province): "},
        {"2.5.4.3", "ͨ������(id-at-commonName): "},
        {"2.5.4.5", "�䷢�����к�(id-at-serialNumber): "},
        {"2.5.4.6", "�䷢�߹�����(id-at-countryName): "},
        {"2.5.4.7", "�䷢��λ����(id-at-localityName): "},
        {"2.5.4.8", "�䷢����ʡ��(id-at-stateOrProvinceName): "},
        {"2.5.4.9", "�䷢�߽�����ַ(id-at-streetAddress): "},
        {"2.5.4.10", "�䷢����֯��(id-at-organizationName): "},
        {"2.5.4.11", "�䷢����֯��λ��(id-at-organizationalUnitName): "},
        {"2.5.4.12", "�䷢�߱���(id-at-title): "},
        {"2.5.4.13", "�䷢������(id-at-description): "},
        {"2.5.4.15", "�䷢��ҵ�����(id-at-businessCategory): "},
        {"2.5.29.32", "֤�����(Certificate Policies): "},
        {"2.5.29.15", "ʹ����Կ(Key Usage): "}};

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
                cout << "֤��汾: ";
                cout << "V" << int(binaryData[info.start]) + 1 << endl;
                info = infos[++i];
                cout << "���к�: ";
                cout << hex;
                for(int i = 0; i < info.length; i++){
                    cout << (int(binaryData[info.start + i])>>4) << (int(binaryData[info.start + i] & 0xf));
                }
                cout << dec << endl;
            }
        } else if (algorithmObject.find(info.tag) != algorithmObject.end()) {
            cout << "�����㷨: " << algorithmObject[info.tag];

        }
    }
}