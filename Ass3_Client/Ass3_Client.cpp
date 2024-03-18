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


std::size_t limit = 805000000;
enum CMDID {
    UNKNOWN = (unsigned char)0x0,
    REQ_QUIT = (unsigned char)0x1,
    REQ_ECHO = (unsigned char)0x2,
    RSP_ECHO = (unsigned char)0x3,
    REQ_LISTUSERS = (unsigned char)0x4,
    RSP_LISTUSERS = (unsigned char)0x5,
    CMD_TEST = (unsigned char)0x20,
    ECHO_ERROR = (unsigned char)0x30
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

int main() {
    std::string serverIP;
    uint16_t port;

    std::cout << "Server IP Address: ";
    std::cin >> serverIP;

    std::cout << "\nServer Port Number: ";
    std::cin >> port;

    const std::string portString = std::to_string(port);

    WSADATA wsaData{};
    SecureZeroMemory(&wsaData, sizeof(wsaData));

    int errorCode = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (errorCode != NO_ERROR)
    {
        std::cerr << "WSAStartup() failed." << std::endl;
        return errorCode;
    }

    addrinfo hints{};
    SecureZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* info = nullptr;
    errorCode = getaddrinfo(serverIP.c_str(), portString.c_str(), &hints, &info);
    if ((errorCode) || (info == nullptr))
    {
        std::cerr << "getaddrinfo() failed." << std::endl;
        WSACleanup();
        return errorCode;
    }

    SOCKET clientSocket = socket(
        info->ai_family,
        info->ai_socktype,
        info->ai_protocol);
    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr << "socket() failed." << std::endl;
        freeaddrinfo(info);
        WSACleanup();
        return 2;
    }

    errorCode = connect(
        clientSocket,
        info->ai_addr,
        static_cast<int>(info->ai_addrlen));
    if (errorCode == SOCKET_ERROR)
    {
        std::cerr << "connect() failed." << std::endl;
        freeaddrinfo(info);
        closesocket(clientSocket);
        WSACleanup();
        return 3;
    }

    std::string text;
    constexpr size_t BUFFER_SIZE = 1000;
    char buffer[BUFFER_SIZE];

    /*!***********************************************************************
    \brief This is a sending thread or loop responsible for getting user input
           and processing different commands.

    \param None.
    *************************************************************************/
    // Sending thread or loop
    std::thread send_thread([&]() {
        while (true) {
            // Get user input
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
                break;
            }
            /*!***********************************************************************
            \brief Checks if the text input is a list users command ("/l"). If so, constructs
                   and sends a list users command to the server.

            \param text The input text to be checked for a list users command.
            *************************************************************************/
            else if (text == "/l") {
                unsigned char listUsersCommand = CMDID::REQ_LISTUSERS; // Assuming REQ_LISTUSERS is defined correctly
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
            else if (text.substr(0, 2) == "/e") {
                std::string ip;
                uint16_t port;
                std::string message;
                if (CustomEcho(text, ip, port, message)) {
                    // Construct the echo packet
                    std::vector<unsigned char> packet;
                    packet.push_back(REQ_ECHO); // Command ID

                    in_addr ip_addr;
                    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) {
                        std::cerr << "Invalid IP address format.\n";
                        return;
                    }
                    appendToPacket(packet, &ip_addr.s_addr, sizeof(ip_addr.s_addr));

                    uint16_t port_network = htons(port);
                    appendToPacket(packet, &port_network, sizeof(port_network));

                    uint32_t message_length = htonl(message.size());
                    appendToPacket(packet, &message_length, sizeof(message_length));

                    appendToPacket(packet, message.data(), message.size());

                    if (send(clientSocket, reinterpret_cast<const char*>(packet.data()), packet.size(), 0) == SOCKET_ERROR) {
                        std::cerr << "send() failed with error: " << WSAGetLastError() << std::endl;
                    }
                }
                else {
                    std::cerr << "Invalid echo command format." << std::endl;
                }
            }
            std::cin.clear();


        }
        });

    /*!***********************************************************************
    \brief This is a receiving thread or loop responsible for receiving data from
           the server, processing it, and handling different command responses.

    \param None.
    *************************************************************************/
    // Receiving thread or loop
    std::thread receive_thread([&]() {
        while (true) {
            int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
            if (bytesReceived == SOCKET_ERROR)
            {
                std::cerr << "disconnecting...\n";
                break;
            }

            CMDID commandId = static_cast<CMDID>(buffer[0]);

            /*!***********************************************************************
            \brief Processes the response for the list users command from the server.

            \param None.
            *************************************************************************/
            if (commandId == RSP_LISTUSERS)
            {
                // Extract the number of users
                uint16_t numUsers;
                std::copy(buffer + 1, buffer + 3, reinterpret_cast<unsigned char*>(&numUsers));
                numUsers = ntohs(numUsers); // Convert from network byte order to host byte order

                size_t offset = 3;
                std::cout << "==========RECV START==========\nUsers:" << std::endl;
                for (int i = 0; i < numUsers; ++i) {
                    // Extract IP address
                    uint32_t ipAddr;
                    std::copy(buffer + offset, buffer + offset + 4, reinterpret_cast<unsigned char*>(&ipAddr));
                    offset += 4;

                    // Extract port
                    uint16_t port;
                    std::copy(buffer + offset, buffer + offset + 2, reinterpret_cast<unsigned char*>(&port));
                    port = ntohs(port); // Convert port to host byte order
                    offset += 2;

                    // Convert IP address to string
                    struct in_addr ip_addr_struct;
                    ip_addr_struct.s_addr = ipAddr;
                    char str_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip_addr_struct, str_ip, INET_ADDRSTRLEN);

                    std::cout << str_ip << ":" << port << std::endl;
                }
                std::cout << "==========RECV END==========" << std::endl;
            }

            /*!***********************************************************************
            \brief Processes the response for the echo command from the server.

            \param None.
            *************************************************************************/
            else if (commandId == RSP_ECHO)
            {
                // Extract the source IP address
                uint32_t ipAddr;
                std::copy(buffer + 1, buffer + 5, reinterpret_cast<unsigned char*>(&ipAddr));

                // Convert IP address to string
                struct in_addr ip_addr_struct;
                ip_addr_struct.s_addr = ipAddr;
                char str_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip_addr_struct, str_ip, INET_ADDRSTRLEN);

                // Extract the source port
                uint16_t port;
                std::copy(buffer + 5, buffer + 7, reinterpret_cast<unsigned char*>(&port));
                port = ntohs(port); // Convert port to host byte order

                // Extract the message length
                uint32_t message_length;
                std::copy(buffer + 7, buffer + 11, reinterpret_cast<unsigned char*>(&message_length));
                message_length = ntohl(message_length); // Convert to host byte order

                // Extract the message
                std::string message(buffer + 11, buffer + 11 + message_length);

                std::cout << "==========RECV START==========" << std::endl;
                std::cout << str_ip << ":" << port << std::endl;
                std::cout << message << std::endl;
                std::cout << "==========RECV END==========" << std::endl;
            }

            /*!***********************************************************************
            \brief Processes the request echo command.

            \param None.
            *************************************************************************/
            else if (REQ_ECHO) {
                std::vector<unsigned char> packet;
                packet.push_back(RSP_ECHO);
                uint32_t ipAddr = *reinterpret_cast<uint32_t*>(buffer + 1);
                char str_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipAddr, str_ip, INET_ADDRSTRLEN);

                // IP Address in network byte order
                std::memcpy(&ipAddr, buffer + 1, sizeof(ipAddr));

                // Port in network byte order
                uint16_t port = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 5));

                // Message length and message
                uint32_t messageLength = ntohl(*reinterpret_cast<const uint32_t*>(buffer + 7));

                std::string message(reinterpret_cast<char*>(buffer + 11), messageLength);

                std::cout << "==========RECV START==========" << std::endl;
                std::cout << str_ip << ":" << port << std::endl;
                std::cout << message << std::endl;
                std::cout << "==========RECV END==========" << std::endl;

                appendToPacket(packet, &ipAddr, sizeof(ipAddr));
                uint16_t port_network = htons(port);
                appendToPacket(packet, &port_network, sizeof(port));
                uint32_t length = htonl(static_cast<uint32_t>(message.size()));
                appendToPacket(packet, &length, sizeof(length));
                packet.insert(packet.end(), message.begin(), message.end());

                // Send the packet
                if (send(clientSocket, reinterpret_cast<const char*>(packet.data()), packet.size(), 0) == SOCKET_ERROR) {
                    std::cerr << "send() failed with error: " << WSAGetLastError() << std::endl;
                }
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