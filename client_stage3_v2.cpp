#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string>
#include "ssl_utils.cpp"

#define BUFFER_SIZE 1024

// server's info
int server_socket_fd = 0;
SSL* ssl;
EVP_PKEY* server_public_key;

// my info
SSL_CTX* ctx;
EVP_PKEY* pkey;
X509* cert;

// Function to count the number of # in the user command
int count_hash(const char* str) {
    int count = 0;
    while (*str) {
        if (*str == '#') {
            count++;
        }
        str++;
    }
    return count;
}

// Function to extract port number from command
int extract_port(const char* command) {
    char user[BUFFER_SIZE];
    int port;
    if (sscanf(command, "%[^#]#%d", user, &port) == 2) {
        return port;
    }
    return -1; // Fail to extract port
}

// Function to send p2p message
void send_p2p_message(const char* target_ip, int target_port, const char* message) {

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("P2P socket creation failed");
        return;
    }

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(target_ip);
    target_addr.sin_port = htons(target_port);
    
    if (connect(socket_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) == -1) {
        perror("P2P connection failed");
        close(socket_fd);
        return;
    }

    // SSL connection
    SSL* p2p_ssl = SSL_new(ctx);  // 基於 ctx 產生一個新的 SSL
    SSL_set_fd(p2p_ssl, socket_fd);  // 將通道跟 socket fd 連結

    // 建立 SSL 連線
    if (SSL_connect(p2p_ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(p2p_ssl);
        return;
    }
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(p2p_ssl));
        show_certificate(p2p_ssl);
    }

    // encrypt data using receiver's public key
    EVP_PKEY* peer_pubilc_key = get_peer_public_key(p2p_ssl);
    string ciphertext = encrypt(message, peer_pubilc_key);

    SSL_write(p2p_ssl, ciphertext.c_str(), ciphertext.size());
    // printf("P2P message sent to %s:%d\n", target_ip, target_port);

    SSL_shutdown(p2p_ssl);
    SSL_free(p2p_ssl);
    close(socket_fd);
}

// Listener thread function
void* listener_thread(void* args) {
    int listen_port = *(int*)args;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("Listener socket creation failed");
        pthread_exit(NULL);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(listen_port);

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Listener socket bind failed");
        close(listen_fd);
        pthread_exit(NULL);
    }

    if (listen(listen_fd, 5) == -1) {
        perror("Listener socket listen failed");
        close(listen_fd);
        pthread_exit(NULL);
    }

    // printf("Listening on port %d for P2P communication...\n", listen_port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd == -1) {
            perror("Listener socket accept failed");
            continue;
        }
        
        SSL* p2p_ssl = SSL_new(ctx);  // 基於 ctx 產生一個新的 SSL
        SSL_set_fd(p2p_ssl, client_fd);  // 將通道跟 socket fd 連結

        // 接收 SSL 連線
        if (SSL_accept(p2p_ssl) == -1)
        {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            continue;
        }

        show_certificate(p2p_ssl);

        // 接收訊息
        char buffer[BUFFER_SIZE];
        int bytes_received = SSL_read(p2p_ssl, buffer, sizeof(buffer) - 1);

        if (bytes_received <= 0) {
                perror("Fail to receive response from peer");
                continue;
        }

        // decrypt data using my private key
        string message(buffer);
        string plaintext = decrypt(buffer, sizeof(buffer) - 1, pkey);

        // encrypt data using server's public key
        string ciphertext = encrypt(message, server_public_key);

        // 傳給 server
        SSL_write(ssl, ciphertext.c_str(), ciphertext.size());

        close(client_fd);
    }

    close(listen_fd);
    pthread_exit(NULL);
}



int main(int argc, char* argv[]) {

    // 先連上 server
    // 接收參數: server 的 IP 和 Port
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        return -1;
    }

    char* server_ip = argv[1];
    int server_port = atoi(argv[2]);

    // initialize SSL
    ctx = init_client_ctx();
    pkey = EVP_RSA_gen(4096);
    cert = generate_certificate(pkey);
    // save_pkey_and_certificate(key, cert, key_file, cert_file)
    load_certificate(ctx, cert, pkey);


    // socket 建立
    server_socket_fd = socket(AF_INET, SOCK_STREAM , 0);
    if (server_socket_fd == -1){
        perror("Fail to create a socket.\n");
        return -1;
    }

    // 設定 server 資訊
    struct sockaddr_in info;
    info.sin_family = AF_INET;
    info.sin_addr.s_addr = inet_addr(server_ip);
    info.sin_port = htons(server_port);

    // 連線到 server
    int err = connect(server_socket_fd, (struct sockaddr *)&info, sizeof(info));
    if(err == -1) {
        perror("Fail to connect to server");
        close(server_socket_fd);
        return -1;
    }
    else {
        ssl = SSL_new(ctx);  // 基於 ctx 產生一個新的 SSL
        SSL_set_fd(ssl, server_socket_fd);  // 將通道跟 socket fd 連結

        // 建立 SSL 連線
        if (SSL_connect(ssl) == -1)
        {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return -1;
        }
        else
        {
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            show_certificate(ssl);
            server_public_key = get_peer_public_key(ssl);
        }
    }

    // 處理使用者的不同輸入
    char command[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    while (1) {

        // 等待使用者輸入完整指令
        printf("Enter command: ");
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }

        // 移除換行符號
        size_t len = strlen(command);
        if (len > 0 && command[len - 1] == '\n') {
            command[len - 1] = '\0';
        }

        // 判斷指令
        // Case 1: Exit
        if (strcmp(command, "Exit") == 0) {

            // 告知 server
            string ciphertext = encrypt(string(command), server_public_key);
            int bytes_sent = SSL_write(ssl, ciphertext.c_str(), ciphertext.size());
            if (bytes_sent == -1) { 
                perror("Fail to send message to server");
                continue;
            }

            // 離開迴圈
            printf("Exiting...\n");
            break;
        }
        // Case 2: REGISTER#<UserAccountName> or List
        else if (strncmp(command, "REGISTER#", 9) == 0 || strcmp(command, "List") == 0) {

            // 直接傳給 server 並印出回應
            string ciphertext = encrypt(string(command), server_public_key);
            int bytes_sent = SSL_write(ssl, ciphertext.c_str(), ciphertext.size());
            if (bytes_sent == -1) { 
                perror("Fail to send message to server");
                continue;
            }

            
            int bytes_received = SSL_read(ssl, response, sizeof(response) - 1);
            if (bytes_received > 0) {
                response[bytes_received] = '\0';
                string plaintext = decrypt(response, sizeof(response) - 1, pkey);
                cout << plaintext << "-------------------------------" << endl;
            }
            else {
                perror("Failed to receive response from server");
                continue;
            }
        }
        // Case 3: <UserAccountName>#<portNum>
        else if (count_hash(command) == 1) {

            // 傳給 server
            string ciphertext = encrypt(string(command), server_public_key);
            int bytes_sent = SSL_write(ssl, ciphertext.c_str(), ciphertext.size());
            if (bytes_sent == -1) { 
                perror("Fail to send message to server"); 
                continue;
            }

            // 檢查是否登入成功（建立 portNum）
            int bytes_received = SSL_read(ssl, response, sizeof(response) - 1);
            if (bytes_received <= 0) {
                perror("Fail to receive response from server");
                continue;
            }
            else {
                response[bytes_received] = '\0';
                string plaintext = decrypt(response, sizeof(response) - 1, pkey);
                cout << plaintext << "-------------------------------" << endl;
            }

            if (strncmp(response, "220 AUTH_FAIL", 13) == 0) {
                continue;
            }

            // 登入成功，建立一個 listener thread，在 command 中的 portNum 上 listen
            int port_num = extract_port(command);
            if (port_num == -1) {
                perror("Invalid command format. Expected <UserAccountName>#<portNum>\n");
                continue;
            }

            pthread_t listener_tid; // Thread ID
            if (pthread_create(&listener_tid, NULL, listener_thread, &port_num) != 0) {
                perror("Fail to create listener thread");
                continue;
            }

            pthread_detach(listener_tid);
        }
        // Case 4: <MyUserAccountName>#<payAmount>#<PayeeUserAccountName>
        else {
            char list_response[20000] = {0};

            // 印出傳送前的 list
            printf("#### Current online list ####\n");

            string ciphertext = encrypt("List", server_public_key);
            int bytes_sent = SSL_write(ssl, ciphertext.c_str(), ciphertext.size());
            int bytes_received = SSL_read(ssl, list_response, sizeof(list_response));

            list_response[bytes_received] = '\0';
            string plaintext = decrypt(list_response, sizeof(list_response) - 1, pkey);
            
            cout << plaintext << "-------------------------------" << endl;

            // 找到傳送目標
            char target_ip[BUFFER_SIZE];
            int target_port;
            char* target_user = strrchr(command, '#') + 1;

            char* line = strtok(list_response, "\n");
            while (line) {
                if (strstr(line, target_user) != NULL) {
                    sscanf(line, "%*[^#]#%[^#]#%d", target_ip, &target_port);
                    break;
                }
                line = strtok(NULL, "\n");
            }
            
            // p2p transfer
            if (target_port) {
                send_p2p_message(target_ip, target_port, command);
            } 
            else {
                printf("User %s not found in online list.\n", target_user);
            }

            // 等待 server 回應
            bytes_received = SSL_read(ssl, response, sizeof(response) - 1);
            if (bytes_received > 0) {
                response[bytes_received] = '\0';
                string plaintext = decrypt(response, sizeof(response) - 1, pkey);
                cout << plaintext << "-------------------------------" << endl;
            }

            // 印出傳送後的 list
            printf("#### Current online list ####\n");

            ciphertext = encrypt("List", server_public_key);
            bytes_sent = SSL_write(ssl, ciphertext.c_str(), ciphertext.size());
            bytes_received = SSL_read(ssl, list_response, sizeof(list_response));

            list_response[bytes_received] = '\0';
            plaintext = decrypt(list_response, sizeof(list_response) - 1, pkey);
            cout << plaintext << "-------------------------------" << endl;
        }
    }

    close(server_socket_fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}



