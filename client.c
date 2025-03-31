#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main(int argc , char *argv[])
{
    // 接收參數 IP 和 Port
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        return -1;
    }

    char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    // socket 建立
    int socket_fd = 0;
    socket_fd = socket(AF_INET , SOCK_STREAM , 0);

    if (socket_fd == -1){
        perror("Fail to create a socket.\n");
        return -1;
    }

    // 設定 server 資訊
    struct sockaddr_in info;
    // bzero(&info, sizeof(info));
    info.sin_family = PF_INET;
    info.sin_addr.s_addr = inet_addr(server_ip);
    info.sin_port = htons(server_port);

    // 連線到 server
    int err = connect(socket_fd, (struct sockaddr *)&info, sizeof(info));
    if(err == -1){
        perror("Connection error");
        close(socket_fd);
        return -1;
    }

    // 使用者輸入指令
    char command[1024];
    char response[1024];

    while (1) {
        // bzero(command, sizeof(command));
        // bzero(response, sizeof(response));

        // 等待使用者輸入完整指令
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }

        // 移除換行符號
        size_t len = strlen(command);
        if (len > 0 && command[len - 1] == '\n') {
            command[len - 1] = '\0';
        }

        // 傳送指令給 Server
        send(socket_fd, command, strlen(command), 0);

        // 接收 Server 回應
        int bytes_received = recv(socket_fd, response, sizeof(response) - 1, 0);
        if (bytes_received > 0) {
            response[bytes_received] = '\0';
            printf("%s\n", response);
        }

        // if (strcmp(response, "Bye\r\n") == 0) {
        //     printf("Exiting program...\n");
        //     break;
        // }
        
        if (strcmp(command, "Exit") == 0) {
            printf('Exiting...\n');
            break;
        }
    }

    // 關閉 socket
    close(socket_fd);
    return 0;
}
