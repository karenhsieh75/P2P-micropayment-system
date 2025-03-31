#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define BUFFER_SIZE 1024

int server_socket_fd = 0;

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

    send(socket_fd, message, strlen(message), 0);
    // printf("P2P message sent to %s:%d\n", target_ip, target_port);
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

        char buffer[BUFFER_SIZE];
        int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            // printf("Received P2P message: %s\n", buffer);

            // 傳給 server
            send(server_socket_fd, buffer, strlen(buffer), 0);

        }

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
    if(err == -1){
        perror("Fail to connect to server");
        close(server_socket_fd);
        return -1;
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
            int bytes_sent = send(server_socket_fd, command, strlen(command), 0);
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
            int bytes_sent = send(server_socket_fd, command, strlen(command), 0);
            if (bytes_sent == -1) { 
                perror("Fail to send message to server");
                continue;
            }

            int bytes_received = recv(server_socket_fd, response, sizeof(response) - 1, 0);
            if (bytes_received > 0) {
                response[bytes_received] = '\0';
                printf("%s-------------------------------\n", response);
            }
            else {
                perror("Failed to receive response from server");
                continue;
            }
        }
        // Case 3: <UserAccountName>#<portNum>
        else if (count_hash(command) == 1) {

            // 傳給 server
            int bytes_sent = send(server_socket_fd, command, strlen(command), 0);
            if (bytes_sent == -1) { 
                perror("Fail to send message to server"); 
                continue;
            }

            // 檢查是否登入成功（建立 portNum）
            int bytes_received = recv(server_socket_fd, response, sizeof(response) - 1, 0);
            if (bytes_received <= 0) {
                perror("Fail to receive response from server");
                continue;
            }
            else {
                response[bytes_received] = '\0';
                printf("%s-------------------------------\n", response);
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

            int bytes_sent = send(server_socket_fd, "List", 4, 0);
            int bytes_received = recv(server_socket_fd, list_response, sizeof(list_response), 0);

            list_response[bytes_received] = '\0';
            printf("%s-------------------------------\n", list_response);

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
            bytes_received = recv(server_socket_fd, response, sizeof(response) - 1, 0);
            if (bytes_received > 0) {
                response[bytes_received] = '\0';
                printf("%s-------------------------------\n", response);
            }

            // 印出傳送後的 list
            printf("#### Current online list ####\n");

            bytes_sent = send(server_socket_fd, "List", 4, 0);
            bytes_received = recv(server_socket_fd, list_response, sizeof(list_response), 0);

            list_response[bytes_received] = '\0';
            printf("%s-------------------------------\n", list_response);
        }
    }

    close(server_socket_fd);
    return 0;
}



