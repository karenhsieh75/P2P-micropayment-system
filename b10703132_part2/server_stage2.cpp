#include <iostream>
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
#include <mutex>
#include <queue>
#include <vector>
#include <sstream>
using namespace std;

#define BUFFER_SIZE 1024
#define THREAD_POOL_SIZE 10


// 與連線相關的資訊存在 client
struct Client {
    int socket_fd;
    string ip;
    int port;
};

// 與帳戶相關的資訊存在 Account
class Account {
    public:
        string name;
        int balance = 0;
        Client client;

    Account(string name, int balance, Client client);
};

Account::Account(string name, int balance, Client client){
    this -> name = name;
    this -> balance = balance;
    this -> client = client;
}


// All account info
vector<Account> register_list;
vector<Account> online_list;

bool is_registered(string name) {

    for (int i = 0; i < register_list.size(); i++) {
        if (register_list[i].name == name){
            return true;
        }
    }
    return false;
}

// different functions to handle client's request
bool message_handler(Client client, string message);
void register_account(Client client, string name);
void login(Client client, string name, int port);
void list(int socket_fd);
void client_exit(int socket_fd);
void payment(int socket_fd, string sender, string receiver, int amount);


// process messages
bool message_handler(Client client, string message) {

    // 用 # 切割成 substring
    stringstream ss(message); // 將字串放入字串流
    string str;
    vector<string> tokens; // store substrings

    while (getline(ss, str, '#')) { // 使用 '#' 作為分隔符號
        tokens.push_back(str);
    }

    // 判斷字串
    if (message == "Exit") {
        client_exit(client.socket_fd);
        // 告訴 worker 關閉連線
        return true;
    }
    else if (message == "List") {
        list(client.socket_fd);
    }
    // register
    else if (tokens[0] == "REGISTER") {
        string name = tokens[1];
        register_account(client, name);
    }
    // login
    else if (tokens.size() == 2) {
        string name = tokens[0];
        int port = stoi(tokens[1]);
        login(client, name, port);
    }
    // payment
    else if (tokens.size() == 3) {
        string sender = tokens[0];
        string receiver = tokens[2];
        int amount = stoi(tokens[1]);
        payment(client.socket_fd, sender, receiver, amount);
    }
    // 格式不正確
    else {
        string errorMessage = "230 Input format error\n";
        send(client.socket_fd, errorMessage.c_str(), errorMessage.size(), 0);
    }

    // 如果訊息不是 Exit，繼續連線
    return false;
}


// register: REGISTER#<UserAccountName>
void register_account(Client client, string name) {

    if (is_registered(name)) {
        string failMessage = "210 FAIL\n";
        send(client.socket_fd, failMessage.c_str(), failMessage.size(), 0);
    } 
    else {
        // 如果尚未註冊，建立新的 Client 物件並新增至 register_list
        Account newAccount(name, 10000, client);
        register_list.push_back(newAccount);

        // 傳送成功訊息
        string successMessage = "100 OK\n";
        send(client.socket_fd, successMessage.c_str(), successMessage.size(), 0);
    }

}

// login: <UserAccountName>#<portNum>
void login(Client client, string name, int port) {

    // 尚未註冊
    if (!is_registered(name)) {
        string failMessage = "220 AUTH_FAIL\n";
        send(client.socket_fd, failMessage.c_str(), failMessage.size(), 0);
    }
    else {
        // 找到該 Account，將 client 資訊更新，並加入 online_list
        for (int i = 0; i < register_list.size(); i++) {
            if (register_list[i].name == name) {
                register_list[i].client = client;
                register_list[i].client.port = port; // 使用者指定 port
                online_list.push_back(register_list[i]);
            }
        }

        // 回傳上線清單
        list(client.socket_fd);
    }
}

// online list: List
void list(int socket_fd) {
    
    int balance = 0;
    string serverPublicKey = "public key";
    int online_num = online_list.size();

    // 找到該 Account 的 balance
    for (int i = 0; i < register_list.size(); i++) {
        if (register_list[i].client.socket_fd == socket_fd) {
            balance = register_list[i].balance;
        }
    }

    // generate list
    string list = "";
    list += to_string(balance) + "\n";
    list += serverPublicKey + "\n";
    list += "Online num: " + to_string(online_num) + "\n";

    for  (int i = 0; i < online_list.size(); i++) {
        list += online_list[i].name + "#";
        list += online_list[i].client.ip + "#";
        list += to_string(online_list[i].client.port) + "\n";
    }

    // send list
    int bytesSent = send(socket_fd, list.c_str(), list.size(), 0);
    if (bytesSent == -1) { 
        cerr << "Fail to send message to client." << endl;
    }

}

// end connection: Exit
void client_exit(int socket_fd) {

    string reply = "Bye\n";
    int bytesSent = send(socket_fd, reply.c_str(), reply.size(), 0);
    if (bytesSent == -1) { 
        cerr << "Fail to send message to client." << endl;
    }

    // 從 online_list 中移除
    for (int i = 0; i < online_list.size(); i++){
        if (online_list[i].client.socket_fd == socket_fd) {
            online_list.erase(online_list.begin() + i);
        }
    }

}

// payment: <MyUserAccountName>#<payAmount>#<PayeeUserAccountName>
void payment(int socket_fd, string sender, string receiver, int amount) {

    // 檢查發送者和接收者是否存在
    Account* sender_account = nullptr;
    Account* receiver_account = nullptr;

    // 此 message 是 receiver 發送的，但確認訊息要發送給 sender
    int sender_fd;

    // 在 register_list 中找到發送者和接收者帳戶
    for (int i = 0; i < register_list.size(); i++) {
        if (register_list[i].name == sender) {
            sender_account = &register_list[i];
            sender_fd = register_list[i].client.socket_fd;
        }
        if (register_list[i].name == receiver) {
            receiver_account = &register_list[i];
        }
    }

    // 檢查是否找到了發送者和接收者帳戶
    if (sender_account == nullptr || receiver_account == nullptr) {
        string failMessage = "Transfer Fail!\n";
        send(sender_fd, failMessage.c_str(), failMessage.size(), 0);
    }

    // 檢查發送者是否有足夠的餘額
    if (sender_account -> balance < amount) {
        string failMessage = "Transfer Fail!\n";
        send(sender_fd, failMessage.c_str(), failMessage.size(), 0);
    }

    // 執行交易：扣除發送者餘額，增加接收者餘額
    sender_account-> balance -= amount;
    receiver_account-> balance += amount;

    // 回傳成功訊息
    string successMessage = "Transfer OK!\n";
    send(sender_fd, successMessage.c_str(), successMessage.size(), 0);

}

// worker 處理 client
void handleClient(Client client) {
    char buffer[BUFFER_SIZE];

    while (true) {
        memset(buffer, 0, sizeof(buffer));

        int bytesReceived = recv(client.socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            cerr << "Client disconnected or error occurred." << endl;
            break;
        }

        // 解析收到的訊息
        string message(buffer);
        bool shouldClose = message_handler(client, message);

        // 如果訊息為 Exit，關閉連線
        if (shouldClose) {
            break;
        }
    }

    if (close(client.socket_fd) == -1) {
        cerr << "Fail to close the socket." << endl;
    }
}


// thread pool
queue<Client> clientQueue;
pthread_mutex_t queueMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t conditionVar = PTHREAD_COND_INITIALIZER;

// 分配工作給 worker
void* workerThread(void* arg) {
    while (true) {
        struct Client client;

        // 獲取工作
        pthread_mutex_lock(&queueMutex);

        while (clientQueue.empty()) {
            pthread_cond_wait(&conditionVar, &queueMutex);
        }

        client = clientQueue.front();
        clientQueue.pop();

        pthread_mutex_unlock(&queueMutex);

        // 處理工作
        handleClient(client);
    }
    return nullptr;
}


int main(int argc, char* argv[]) {

    // 接收參數: server 的 Port 和 Mode
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_port>\n", argv[0]);
        return -1;
    }

    int server_port = atoi(argv[1]);
    // char* mode = argv[2];
    
    // socket 建立
    int socket_fd = socket(AF_INET, SOCK_STREAM , 0);
    if (socket_fd == -1){
        perror("Fail to create a socket.\n");
        return -1;
    }

    // 設定 server 資訊
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_port);

    // 將建立的 socket 綁定到 server_addr 指定的 port
    if (bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Fail to bind.\n");
        close(socket_fd);
        return -1;
    }

    // 開始 listen
    if (listen(socket_fd, 5) == -1) {
        perror("Fail to listen.");
        close(socket_fd);
        return -1;
    }

    
    // create thread pool
    pthread_t threadPool[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; ++i) {
        pthread_create(&threadPool[i], nullptr, workerThread, nullptr);
    }

    while (true) {

        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        int client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd == -1) { 
            cout << "Fail to accept." << endl; 
        }

        char *client_ip = inet_ntoa(client_addr.sin_addr);
        int client_port = ntohs(client_addr.sin_port);
        cout << "Accept: " << endl;
        cout << "Client IP: " << client_ip << endl;
        cout << "Client Port: " << client_port << endl;

        // store client info
        struct Client client;
        client.socket_fd = client_fd;
        client.ip = client_ip;
        client.port = client_port;

        // insert client into queue
        pthread_mutex_lock(&queueMutex);
        clientQueue.push(client);
        pthread_cond_signal(&conditionVar);
        pthread_mutex_unlock(&queueMutex);
    }

    close(socket_fd);
    return 0;

}