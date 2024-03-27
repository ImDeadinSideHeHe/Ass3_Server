/* Start Header
*****************************************************************/
/*!
\file client.cpp (e.g. main.cpp)
\author Aloysius Liong, a.liong, 2201568
(e.g. William ZHENG, william.zheng, 60001906)
\par a.liong@digipen.edu (e.g. email: william.zheng\@digipen.edu)
5
\date Mar 2, 2024 (e.g. Jan 01, 2022)
\brief
Copyright (C) 20xx DigiPen Institute of Technology.
Reproduction or disclosure of this file or its contents without the
prior written consent of DigiPen Institute of Technology is prohibited.
*/
/* End Header
*******************************************************************/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Windows.h"		
#include "winsock2.h"	
#include "ws2tcpip.h"

#pragma comment(lib, "ws2_32.lib")

#include <iostream> 
#include <string> 
#include <sstream> 
#include <iomanip>
#include <vector>
#include <fstream>
#include <thread>
#include <regex>

enum CMDID {
    UNKNOWN = 0x0,          // Not used or unknown command
    REQ_QUIT = 0x1,         // Request to quit or disconnect
    REQ_DOWNLOAD = 0x2,     // Request to download a file
    RSP_DOWNLOAD = 0x3,     // Response to a download request
    REQ_LISTFILES = 0x4,    // Request to list available files
    RSP_LISTFILES = 0x5,    // Response with a list of files
    CMD_TEST = 0x20,        // Not used or for testing
    DOWNLOAD_ERROR = 0x30   // Indicates a download error
};

// Assume global configuration variables are defined as needed
std::string serverIP;
int serverTCPPort, serverUDPPort, clientUDPPort;
std::string downloadPath;

void receiveUDP() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in servaddr, cliaddr;

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(clientUDPPort);

    bind(sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr));

    char buffer[1024];
    std::ofstream outputFile;
    bool fileOpen = false;

    while (true) {
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd, (char*)buffer, 1024, MSG_WAITALL, (struct sockaddr*)&cliaddr, &len);
        buffer[n] = '\0';

        // Assuming the first packet contains the filename
        if (!fileOpen) {
            outputFile.open(downloadPath + std::string(buffer), std::ios::binary);
            fileOpen = true;
            continue; // Skip to the next iteration to start receiving file content
        }

        if (n <= 0) {
            break; // End of file or error
        }

        outputFile.write(buffer, n);

        // Here you'd also implement ACK sending based on your protocol
    }

    if (fileOpen) {
        outputFile.close();
    }

    closesocket(sockfd);
}

void listFiles(int tcpSocket) {
    char command = (char)CMDID::REQ_LISTFILES; // Assuming CMDID enum is defined elsewhere
    send(tcpSocket, &command, sizeof(command), 0);

    char buffer[1024];
    int n = recv(tcpSocket, buffer, 1024, 0);
    buffer[n] = '\0';

    std::cout << "Files available for download:\n" << buffer << std::endl;
}

void requestFileDownload(int tcpSocket, const std::string& filename) {
    char command = (char)CMDID::REQ_DOWNLOAD; // Assuming CMDID enum is defined elsewhere
    send(tcpSocket, &command, sizeof(command), 0);

    // Send filename length and filename
    uint32_t filenameLength = htonl(filename.size());
    send(tcpSocket, reinterpret_cast<const char*>(&filenameLength), sizeof(filenameLength), 0);
    send(tcpSocket, filename.c_str(), filename.size(), 0);

    // Wait for server's response
    char response;
    recv(tcpSocket, &response, sizeof(response), 0);
    if (response == (char)CMDID::RSP_DOWNLOAD) {
        std::cout << "Download initiated..." << std::endl;
    }
    else if (response == (char)CMDID::DOWNLOAD_ERROR) {
        std::cout << "Error: Download failed." << std::endl;
    }
}

int main() {
    // Initialize configuration
    std::cout << "Enter server IP address: ";
    std::cin >> serverIP;
    std::cout << "Enter server TCP port number: ";
    std::cin >> serverTCPPort;
    std::cout << "Enter server UDP port number: ";
    std::cin >> serverUDPPort;
    std::cout << "Enter client UDP port number: ";
    std::cin >> clientUDPPort;
    std::cout << "Enter path to store downloaded files: ";
    std::cin >> downloadPath;

    // Establish TCP connection to the server
    int tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(serverTCPPort);

    // Convert IPv4 or IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, serverIP.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cout << "\nInvalid address/ Address not supported \n";
        return -1;
    }

    if (connect(tcpSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cout << "\nConnection Failed \n";
        return -1;
    }

    // Start UDP receive thread
    std::thread udpThread(receiveUDP);

    // Main loop for user commands
    while (true) {
        std::string command;
        std::cout << "Enter command ('/l' to list, '/d filename' to download, '/q' to quit): ";
        std::cin >> command;

        if (command == "/q") break; // Exit loop
        else if (command == "/l") {
            listFiles(tcpSocket);
        }
        else if (command.find("/d") == 0) { // Check if command starts with /d
            std::string filename;
            std::cin >> filename; // Assume the filename follows the command directly
            requestFileDownload(tcpSocket, filename);
        }
    }

    // Clean up
    udpThread.join();
    closesocket(tcpSocket); // Close the TCP connection

    return 0;
}