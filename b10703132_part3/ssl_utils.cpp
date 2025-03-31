#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <iostream>
#include <string>
#include <vector>
using namespace std;


// 檢查 OpenSSL 錯誤
void check_openssl_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        std::cerr << "OpenSSL Error: " << ERR_error_string(err, nullptr) << std::endl;
    }
}


SSL_CTX* init_client_ctx()
{
    SSL_CTX *ctx;
    SSL_library_init(); 
    OpenSSL_add_all_algorithms();  // 載入所有演算法
    SSL_load_error_strings();  // 載入所有錯誤訊息

    ctx = SSL_CTX_new(SSLv23_client_method());
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    SSL_CTX_set_verify(ctx, 
    SSL_VERIFY_PEER,  // 只要求 client 出示憑證
    [](int preverify_ok, X509_STORE_CTX* ctx) {
        // 始終返回成功，不論憑證是否通過標準驗證
        return 1;
    });

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();  // 終止程式
    }
    return ctx;  // 回傳初始化過的 SSL Content Text
}


// // 自定義回調函數
// int verify_callback(int preverify_ok, X509_STORE_CTX* x509_ctx) {
// // 如果 OpenSSL 預驗證失敗，你可以在這裡自定義邏輯
//     if (!preverify_ok) {
//         int err = X509_STORE_CTX_get_error(x509_ctx);
        
//         // 對於自簽憑證，通常會遇到 X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
//         // 你可以在這裡選擇接受自簽憑證
//         if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
//             return 1; // 返回 1 表示接受
//         }
//     }
//     return preverify_ok;
// }


SSL_CTX* init_server_ctx()
{
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_server_method());
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify(ctx, 
    SSL_VERIFY_PEER,  // 只要求 client 出示憑證
    [](int preverify_ok, X509_STORE_CTX* ctx) {
        // 始終返回成功，不論憑證是否通過標準驗證
        return 1;
    });


    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


// cmd to generate private key and certificate
// openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout a.key -out a.crt


// 生成自簽名憑證
// 呼叫前要先用 EVP_PKEY* pkey = EVP_RSA_gen(2048); 生成私鑰
X509* generate_certificate(EVP_PKEY* pkey) {
    X509* x509 = X509_new();
    if (!x509) {
        std::cerr << "Failed to create X509 structure" << std::endl;
        check_openssl_errors();
        abort();
    }

    X509_set_version(x509, 2); // X.509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); // 設置序列號

    // 設置有效期
    X509_gmtime_adj(X509_get_notBefore(x509), 0);          // 現在生效
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600); // 有效期 1 年

    // 設置主體名稱
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"TW", -1, -1, 0);  // 國家
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"NTU", -1, -1, 0); // 組織
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"Karen", -1, -1, 0); // 主機名
    X509_set_subject_name(x509, name);

    // 設置發行者名稱（自簽名）
    X509_set_issuer_name(x509, name);

    // 將公鑰添加到憑證
    X509_set_pubkey(x509, pkey);

    // 使用私鑰對憑證簽名
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        std::cerr << "Failed to sign certificate" << std::endl;
        check_openssl_errors();
        abort();
    }

    return x509;
}

// 將私鑰以及憑證讀進 ctx
void load_certificate(SSL_CTX* ctx, X509* cert, EVP_PKEY* pkey)
{
    // 載入使用者的憑證，憑證裡包含有公鑰
    if (SSL_CTX_use_certificate(ctx, cert) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // 載入使用者私鑰c
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // 檢查使用者私鑰是否正確
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void show_certificate(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("#### Digital certificate information ####\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Certificate: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        printf("-------------------------------------------\n");
        X509_free(cert);
    }
    else
        printf("No certificate information!\n");
}


EVP_PKEY* get_peer_public_key(SSL* ssl)
{
    // first get peer's certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert == NULL){
        fprintf(stderr, "Error getting peer's certificate\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    // then extract public key
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if(pkey == NULL){
        fprintf(stderr, "Error getting public key from certificate\n");
        ERR_print_errors_fp(stderr);
        abort();
    }

    return pkey;
}


string encrypt(string message, EVP_PKEY* public_key)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // Set padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // Determine the required buffer length for the encrypted message
    size_t encrypted_len = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &encrypted_len,
                         reinterpret_cast<const unsigned char*>(message.data()), message.size()) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // Allocate buffer for the encrypted message
    vector<unsigned char> encrypted_msg(encrypted_len);
    if (EVP_PKEY_encrypt(ctx, encrypted_msg.data(), &encrypted_len,
                         reinterpret_cast<const unsigned char*>(message.data()), message.size()) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // Resize the vector to the actual encrypted length
    encrypted_msg.resize(encrypted_len);

    // Free the EVP_PKEY context
    EVP_PKEY_CTX_free(ctx);

    // Convert encrypted message to a std::string and return
    return std::string(encrypted_msg.begin(), encrypted_msg.end());
}


string decrypt(string message, EVP_PKEY* private_key)
{

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (!ctx) {
        std::cerr << "Failed to create PKEY context" << std::endl;
        ERR_print_errors_fp(stderr);
        return "";
    }

    if(EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "Decrypt init failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // Set Padding
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Setting padding failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // Determine the required buffer length for the decrypted message
    size_t decrypted_len = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &decrypted_len,
                         reinterpret_cast<const unsigned char*>(message.data()), message.size()) <= 0) {
        std::cerr << "Decryption length determination failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // Allocate buffer for the decrypted message
    vector<unsigned char> decrypted_msg(decrypted_len);
    if (EVP_PKEY_decrypt(ctx, decrypted_msg.data(), &decrypted_len,
                         (unsigned char *)(message.data()), message.size()) <= 0) {
        std::cerr << "Decryption failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // Resize the vector to the actual decrypted length
    decrypted_msg.resize(decrypted_len);

    // Free the EVP_PKEY context
    EVP_PKEY_CTX_free(ctx);

    // Convert decrypted message to a std::string and return
    return std::string(decrypted_msg.begin(),decrypted_msg.end());
}
