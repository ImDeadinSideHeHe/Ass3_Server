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

#include <filesystem>

std::size_t limit = 805000000;
enum CMDID {
    UNKNOWN = (unsigned char)0x0,//not used
    REQ_QUIT = (unsigned char)0x1,
    REQ_DOWNLOAD = (unsigned char)0x2,
    RSP_DOWNLOAD = (unsigned char)0x3,
    REQ_LISTFILES = (unsigned char)0x4,
    RSP_LISTFILES = (unsigned char)0x5,
    CMD_TEST = (unsigned char)0x20,//not used
    DOWNLOAD_ERROR = (unsigned char)0x30
};

/*!***********************************************************************
\brief CustomEcho function takes a command string, extracts IP address,
       port number, and message from it, and assigns them to the
       corresponding variables.

\param command The input string containing the command in the format "/e IP:Port Message".
\param ip A reference to a string variable where the extracted IP address will be stored.
\param port A reference to a uint16_t variable where the extracted port number will be stored.
\param message A reference to a string variable where the extracted message will be stored.

\return Returns true if the command format is correct and the extraction was successful,
        false otherwise.
*************************************************************************/
bool CustomEcho(const std::string& command, std::string& ip, uint16_t& port, std::string& message) {
    std::regex pattern(R"(/e (\d+\.\d+\.\d+\.\d+):(\d+) (.+))");

    std::smatch match;
    if (std::regex_match(command, match, pattern)) {
        // Extract IP, port, and message from the matched groups
        ip = match[1];
        port = static_cast<uint16_t>(std::stoul(match[2]));
        message = match[3];
        return true;
    }
    else {
        return false; // Incorrect command format
    }
}

/*!***********************************************************************
\brief Appends binary data to a packet.

\param packet A reference to a vector of unsigned char where the data will be appended.
\param data A pointer to the data to be appended.
\param size The size of the data to be appended in bytes.
*************************************************************************/
void appendToPacket(std::vector<unsigned char>& packet, const void* data, size_t size) {
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(data);
    packet.insert(packet.end(), bytes, bytes + size);
}
void handleListFilesResponse(const char* buffer, int bytesReceived) {
    // Assuming the first 2 bytes after command ID indicate the number of files
    if (bytesReceived > 1) { // Check there's enough data for the number of files
        uint16_t numFiles;
        memcpy(&numFiles, buffer + 1, sizeof(numFiles));
        numFiles = ntohs(numFiles); // Convert from network byte order to host

        size_t index = 3; // Start index of file paths in the buffer
        for (int i = 0; i < numFiles; ++i) {
            // Assuming each file path is preceded by its length (2 bytes, network byte order)
            if (index + 2 > bytesReceived) break; // Sanity check

            uint16_t pathLength;
            memcpy(&pathLength, buffer + index, sizeof(pathLength));
            pathLength = ntohs(pathLength); // Convert from network byte order to host
            index += 2;

            if (index + pathLength > bytesReceived) break; // Sanity check

            std::string filePath(buffer + index, pathLength);
            std::cout << "File: " << filePath << std::endl;

            index += pathLength;
        }
    }
}
int main() {
    const uint16_t serverTCPPort = 9000;
    const uint16_t serverUDPPort = 9001;
    const uint16_t clientUDPPort = 9002;
    const std::string downloadPath = "C:\\Users\\chuak\\source\\repos\\Ass3_Server\\Ass3_Server\\";
    const int slidingWindowSize = 1;
    const double packetLossRate = 1.0; // 100% packet loss rate for demonstration
    const int ackTimer = 10; // Acknowledgement timer in milliseconds
    const std::string serverIP = "192.168.15.1";

    // Print server settings
    std::cout << "Server TCP Port Number: " << serverTCPPort << std::endl;
    std::cout << "Server UDP Port Number: " << serverUDPPort << std::endl;
    std::cout << "Download path: " << downloadPath << std::endl;
    std::cout << "Sliding window size [1,100]: " << slidingWindowSize << std::endl;
    std::cout << "Packet loss rate [0.0-1.0]: " << packetLossRate << std::endl;
    std::cout << "Ack timer [10ms-500ms]: " << ackTimer << " ms" << std::endl;
   /* std::string serverIP;
    int serverTCPPort, serverUDPPort, clientUDPPort, slidingWindow;
    float packetLoss;
    std::string downloadPath;

    std::cout << "Server IP Address: ";
    std::cin >> serverIP;
    std::cout << "\nServer TCP Port Number: ";
    std::cin >> serverTCPPort;
    std::cout << "\nServer UDP Port Number: ";
    std::cin >> serverUDPPort;
    std::cout << "\nClient UDP Port Number: ";
    std::cin >> clientUDPPort;
    std::cout << "\nPath to store files: ";
    std::cin >> downloadPath;
    std::cout << "\nSliding window size: ";
    std::cin >> slidingWindow;
    std::cout << "\nPacket loss rate: ";
    std::cin >> packetLoss;*/

    const std::string portString = std::to_string(serverTCPPort);
    const std::string UDPportString = std::to_string(clientUDPPort);

    WSADATA wsaData{};
    SecureZeroMemory(&wsaData, sizeof(wsaData));

    int errorCode = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (errorCode != NO_ERROR)
    {
        std::cerr << "WSAStartup() failed." << std::endl;
        return errorCode;
    }

    // Setup TCP connection
    addrinfo hints{};
    SecureZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* info = nullptr;
    errorCode = getaddrinfo(serverIP.c_str(), portString.c_str(), &hints, &info);
    if ((errorCode) || (info == nullptr)) {
        std::cerr << "getaddrinfo() failed." << std::endl;
        WSACleanup();
        return errorCode;
    }

    SOCKET clientSocket = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "socket() failed." << std::endl;
        freeaddrinfo(info);
        WSACleanup();
        return 2;
    }

    errorCode = connect(clientSocket, info->ai_addr, static_cast<int>(info->ai_addrlen));
    if (errorCode == SOCKET_ERROR) {
        std::cerr << "connect() failed." << std::endl;
        freeaddrinfo(info);
        closesocket(clientSocket);
        WSACleanup();
        return 3;
    }

    std::cout << "TCP connection established." << std::endl;
    freeaddrinfo(info); // No longer need the address information for TCP

    // Setup UDP socket for receiving file data
    SOCKET udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket == INVALID_SOCKET) {
        std::cerr << "UDP socket() failed." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 4;
    }

    sockaddr_in udpClientAddr;
    udpClientAddr.sin_family = AF_INET;
    udpClientAddr.sin_port = htons(static_cast<unsigned short>(clientUDPPort));
    udpClientAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on any IP the client machine has

    errorCode = bind(udpSocket, reinterpret_cast<sockaddr*>(&udpClientAddr), sizeof(udpClientAddr));
    if (errorCode == SOCKET_ERROR) {
        std::cerr << "UDP bind() failed." << std::endl;
        closesocket(udpSocket);
        closesocket(clientSocket);
        WSACleanup();
        return 5;
    }

    std::string text;
    std::cin.ignore(65535, '\n');
    std::cin >> std::ws;
    constexpr size_t BUFFER_SIZE = 1024;
    char buffer[BUFFER_SIZE];
    bool running = true;
    /*!***********************************************************************
    \brief This is a sending thread or loop responsible for getting user input
           and processing different commands.

    \param None.
    *************************************************************************/
    // Sending thread or loop
    std::thread send_thread([&]() {
        while (running) {
            // Get user input
            std::cout << "\nCommand Prompt > ";
            std::getline(std::cin, text);

            /*!***********************************************************************
            \brief Checks if the text input is a quit command ("/q"). If so, sends a quit command to the server,
                   closes the socket connection, and performs cleanup operations.

            \param text The input text to be checked for a quit command.
            *************************************************************************/
            if (text == "/q")
            {
                // Optionally send a quit command to the server
                unsigned char quitCommand = REQ_QUIT; // Make sure REQ_QUIT is defined correctly
                unsigned char buffer[sizeof(quitCommand)];
                std::memcpy(buffer, &quitCommand, sizeof(quitCommand));
                send(clientSocket, reinterpret_cast<const char*>(buffer), sizeof(buffer), 0);

                // Now close the socket and cleanup
                shutdown(clientSocket, SD_SEND); // Optional but gracefully shuts down sending
                closesocket(clientSocket);
                WSACleanup();
                std::cout << "disconnecting..." << std::endl;
                running = false;
                break;
            }
            /*!***********************************************************************
            \brief Checks if the text input is a list users command ("/l"). If so, constructs
                   and sends a list users command to the server.

            \param text The input text to be checked for a list users command.
            *************************************************************************/
            else if (text == "/l") {
                unsigned char listUsersCommand = CMDID::REQ_LISTFILES; // Assuming REQ_LISTUSERS is defined correctly
                unsigned char buffer[sizeof(listUsersCommand)];
                std::memcpy(buffer, &listUsersCommand, sizeof(listUsersCommand));

                int bytesSent = send(clientSocket, reinterpret_cast<const char*>(buffer), sizeof(buffer), 0);
                if (bytesSent == SOCKET_ERROR) {
                    std::cerr << "send() failed." << std::endl;
                    break;
                }
            }

            /*!***********************************************************************
            \brief Checks if the text input starts with "/e", indicating an echo command.
                   If so, extracts IP address, port, and message from the command and constructs
                   an echo packet to send to the server.

            \param text The input text to be checked for an echo command.
            *************************************************************************/
            if (text.size() > 3 && text.substr(0, 3) == "/d") {
                std::string ipAddress, portStr, fileName;
                std::istringstream iss(text.substr(3)); // Create a stream from the command without the "/d"
                // Parse the command format "/d <IP>:<Port> <FileName>"
                if (std::getline(iss, ipAddress, ':') && std::getline(iss, portStr, ' ') && std::getline(iss, fileName)) {
                    // Parse IP address and port number
                    in_addr ipAddr;
                    inet_pton(AF_INET, ipAddress.c_str(), &ipAddr); // Convert string IP to binary form
                    uint16_t port = static_cast<uint16_t>(std::stoi(portStr)); // Convert port string to int

                    // Create the REQ_DOWNLOAD message
                    unsigned char buffer[BUFFER_SIZE];
                    int messageLength = 0;
                    buffer[messageLength++] = static_cast<char>(CMDID::REQ_DOWNLOAD);

                    // Append the IP address to the message
                    std::memcpy(buffer + messageLength, &ipAddr, sizeof(ipAddr));
                    messageLength += sizeof(ipAddr);

                    // Append the port number to the message (in network byte order)
                    uint16_t portNetworkOrder = htons(port);
                    std::memcpy(buffer + messageLength, &portNetworkOrder, sizeof(portNetworkOrder));
                    messageLength += sizeof(portNetworkOrder);

                    // Append the length of the file name (in network byte order) to the message
                    uint32_t fileNameLengthNetworkOrder = htonl(static_cast<uint32_t>(fileName.size()));
                    std::memcpy(buffer + messageLength, &fileNameLengthNetworkOrder, sizeof(fileNameLengthNetworkOrder));
                    messageLength += sizeof(fileNameLengthNetworkOrder);

                    // Append the file name to the message
                    std::memcpy(buffer + messageLength, fileName.c_str(), fileName.size());
                    messageLength += fileName.size();

                    // Send the message to the server
                    if (send(clientSocket, reinterpret_cast<const char*>(buffer), messageLength, 0) == SOCKET_ERROR) {
                        std::cerr << "Failed to send download request. Error: " << WSAGetLastError() << std::endl;
                    }
                }
                else {
                    std::cerr << "Invalid download command format. Use: /d <IP>:<Port> <FileName>\n";
                }
            }



            std::cin.clear();
           //std::cin.ignore(std::numeric_limits<std::streamsize>::dmax(), '\n');
        }
        });

    /*!***********************************************************************
    \brief This is a receiving thread or loop responsible for receiving data from
           the server, processing it, and handling different command responses.

    \param None.
    *************************************************************************/
    // Receiving thread or loop
    std::thread receive_thread([&]() {
        while (running) {
            int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
            if (bytesReceived == SOCKET_ERROR)
            {
                std::cerr << "disconnecting...\n";
                running = false;
                break;
            }

            CMDID commandId = static_cast<CMDID>(buffer[0]);
            // Inside your receiving loop or thread:
            if (commandId == RSP_LISTFILES) {
                std::cout << "\n==========RECV START==========" << std::endl;

                // The first two bytes after command ID indicate the number of files
                if (bytesReceived > 3) { // Check there's enough data for the number of files
                    uint16_t numFiles;
                    memcpy(&numFiles, buffer + 1, sizeof(numFiles));
                    numFiles = ntohs(numFiles); // Convert from network byte order to host

                    std::cout << "# of Files: " << numFiles << std::endl;

                    size_t index = 3; // Start index of file paths in the buffer
                    for (int i = 0; i < numFiles; ++i) {
                        // Each file path is preceded by its length (2 bytes, network byte order)
                        if (index + 2 > bytesReceived) break; // Sanity check

                        uint16_t pathLength;
                        memcpy(&pathLength, buffer + index, sizeof(pathLength));
                        pathLength = ntohs(pathLength); // Convert from network byte order to host
                        index += 2;

                        if (index + pathLength > bytesReceived) break; // Sanity check
                        std::filesystem::path filePathObj(buffer + index, buffer + index + pathLength);
                        std::string fileName = filePathObj.filename().string();
                        std::cout << (i + 1) << "-th file: " << fileName << std::endl;

                        index += pathLength; // Move to the start of the next file entry
                    }
                }

                std::cout << "==========RECV END==========" << std::endl;
            }
            else if (commandId == RSP_DOWNLOAD) {
                // Assuming the UDP port is known and the UDP socket (udpSocket) is already set up and bound
                std::ofstream outputFile("received_file.dat", std::ios::binary);
                if (!outputFile.is_open()) {
                    std::cerr << "Failed to open file for writing.\n";
                    continue;
                }

                char udpBuffer[1024];
                sockaddr_in fromAddr;
                int fromAddrSize = sizeof(fromAddr);
                bool fileComplete = false;

                // Listen for UDP packets
                while (!fileComplete) {
                    int bytesReceivedUDP = recvfrom(udpSocket, udpBuffer, sizeof(udpBuffer), 0, (sockaddr*)&fromAddr, &fromAddrSize);
                    if (bytesReceivedUDP > 0) {
                        // Write received bytes into the file
                        outputFile.write(udpBuffer, bytesReceivedUDP);
                    }
                    else if (bytesReceivedUDP == 0) {
                        fileComplete = true; // Assuming end of file transmission is marked by a 0-byte packet
                    }
                    else {
                        std::cerr << "UDP recvfrom() failed or connection closed prematurely.\n";
                        break;
                    }
                }

                if (fileComplete) {
                    std::cout << "File download completed.\n";
                }

                outputFile.close();
            }


        }
        });
    // Wait for both threads to finish if they are used, otherwise, the loops will just run consecutively
    send_thread.join();
    receive_thread.join();
    closesocket(clientSocket);

    WSACleanup();
    return 0;
}