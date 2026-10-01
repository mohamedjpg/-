#include <fstream>
#include <string>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
using nlohmann::json;

std::string b64u(const unsigned char* d,size_t n){
    std::string s; s.resize(4((n+2)/3));
    int l=EVP_EncodeBlock((unsigned char)&s[0],d,n);
    s.resize(l);
    for(char& c:s){ if(c=='+')c='-'; else if(c=='/')c='_'; }
    while(!s.empty()&&s.back()=='=')s.pop_back();
    return s;
}

std::string hmac(const std::string& k,const std::string& m){
    unsigned char o[EVP_MAX_MD_SIZE]; unsigned int l=0;
    HMAC(EVP_sha256(),k.data(),k.size(),
         (unsigned char)m.data(),m.size(),o,&l);
    return b64u(o,l);
}

int main(){
    json h={{"alg","HS256"},{"typ","JWT"}};
    json p={{"id","free by zenithpulse"},{"exp","4071619885"},{"iat","1736064000"}}; // iat and expiry are strings, but it's fine, psm doesn't care
    std::string k="sorakasugano1337"; // change if you want
    std::string hb=b64u((unsigned char)h.dump().data(),h.dump().size());
    std::string pb=b64u((unsigned char*)p.dump().data(),p.dump().size());
    std::string m=hb+"."+pb;
    std::string sg=hmac(k,m);
    std::string t=m+"."+sg;
    json o={{"jwt",t},{"expiration","2099-01-09T05:31:25.0000000Z"}};
    std::ofstream("user.bin",std::ios::binary)<<o.dump(2);
}
