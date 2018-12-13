#include <iostream>
#include <string>
#include <fstream>

using namespace std;

int main(){
    ifstream fin;
    string path = "test.cer";
    fin.open(path);
    string data;
    string s;
    while(getline(fin, s)){
        data += s;
    }
    cout << data << endl;
    return 0;
}