/* Start Header
*****************************************************************/
/*!
\file server.cpp (e.g. main.cpp)
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
#include "ws2tcpip.h"

#include <iostream>			// cout, cerr
#include <string>			// string
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <optional>
#include <fstream>
#include <filesystem>
namespace fs = std::filesystem;
#pragma comment(lib, "ws2_32.lib")

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

static std::mutex _stdoutMutex;
std::vector<std::pair<SOCKET, std::pair<std::string, std::string>>> clientsVector;
std::string downloadPath;
template <typename TItem, typename TAction, typename TOnDisconnect>
class TaskQueue {
public:
    /*!***********************************************************************
    \brief Constructs a TaskQueue with the specified number of workers, slots, action, and onDisconnect callback.

    \param workerCount The number of worker threads.
    \param slotCount The number of available slots in the buffer.
    \param action The action to be performed by the workers.
    \param onDisconnect The callback function to be called on disconnection.
    *************************************************************************/
    TaskQueue(size_t workerCount, size_t slotCount, TAction& action, TOnDisconnect& onDisconnect) :
        _slotCount{ slotCount },
        _itemCount{ 0 },
        _onDisconnect{ onDisconnect },
        _stay{ true }
    {
        for (size_t i = 0; i < workerCount; ++i)
        {
            _workers.emplace_back([this, &action]() {
                this->work(*this, action);
                });
        }
    }

    /*!***********************************************************************
    \brief Destroys the TaskQueue instance, disconnects all workers, and joins them.

    \param None.
    *************************************************************************/
    ~TaskQueue()
    {
        disconnect();
        for (std::thread& worker : _workers)
        {
            worker.join();
        }
    }

    /*!***********************************************************************
    \brief Adds an item to the queue for consumption by the workers.

    \param item The item to be added to the queue.
    *************************************************************************/
    void produce(TItem item)
    {
        // Non-RAII unique_lock to be blocked by a producer who needs a slot.
        {
            // Wait for an available slot...
            std::unique_lock<std::mutex> slotCountLock{ _slotCountMutex };
            _producers.wait(slotCountLock, [&]() { return _slotCount > 0; });
            --_slotCount;
        }
        // RAII lock_guard locked for buffer.
        {
            // Lock the buffer.
            std::lock_guard<std::mutex> bufferLock{ _bufferMutex };
            _buffer.push(item);
        }
        // RAII lock_guard locked for itemCount.
        {
            // Announce available item.
            std::lock_guard<std::mutex> itemCountLock(_itemCountMutex);
            ++_itemCount;
            _consumers.notify_one();
        }
    }

    /*!***********************************************************************
    \brief Consumes an item from the queue.

    \return An optional containing the consumed item if available, otherwise nullopt.
    *************************************************************************/
    std::optional<TItem> consume()
    {
        std::optional<TItem> result = std::nullopt;
        // Non-RAII unique_lock to be blocked by a consumer who needs an item.
        {
            // Wait for an available item or termination...
            std::unique_lock<std::mutex> itemCountLock{ _itemCountMutex };
            _consumers.wait(itemCountLock, [&]() { return (_itemCount > 0) || (!_stay); });
            if (_itemCount == 0)
            {
                _consumers.notify_one();
                return result;
            }
            --_itemCount;
        }
        // RAII lock_guard locked for buffer.
        {
            // Lock the buffer.
            std::lock_guard<std::mutex> bufferLock{ _bufferMutex };
            result = _buffer.front();
            _buffer.pop();
        }
        // RAII lock_guard locked for slots.
        {
            // Announce available slot.
            std::lock_guard<std::mutex> slotCountLock{ _slotCountMutex };
            ++_slotCount;
            _producers.notify_one();
        }
        return result;
    }

    /*!***********************************************************************
    \brief Worker function that continuously waits for tasks from the task queue
           and executes them until termination.

    \param tq Reference to the TaskQueue instance.
    \param action Reference to the action function to be executed.
    *************************************************************************/
    void work(TaskQueue<TItem, TAction, TOnDisconnect>& tq, TAction& action)
    {
        while (true)
        {
            {
                std::lock_guard<std::mutex> usersLock{ _stdoutMutex };
                std::cout
                    << "Thread ["
                    << std::this_thread::get_id()
                    << "] is waiting for a task."
                    << std::endl;
            }
            std::optional<TItem> item = tq.consume();
            if (!item)
            {
                // Termination of idle threads.
                break;
            }

            {
                std::lock_guard<std::mutex> usersLock{ _stdoutMutex };
                std::cout
                    << "Thread ["
                    << std::this_thread::get_id()
                    << "] is executing a task."
                    << std::endl;
            }

            if (!action(*item))
            {
                // Decision to terminate workers.
                tq.disconnect();
            }
        }

        {
            std::lock_guard<std::mutex> usersLock{ _stdoutMutex };
            std::cout
                << "Thread ["
                << std::this_thread::get_id()
                << "] is exiting."
                << std::endl;
        }
    }

    /*!***********************************************************************
    \brief Initiates disconnection by setting the termination flag and invoking
           the onDisconnect callback.

    \param None.
    *************************************************************************/
    void disconnect()
    {
        _stay = false;
        _onDisconnect();
    }

private:
    // Pool of worker threads.
    std::vector<std::thread> _workers;

    // Buffer of slots for items.
    std::mutex _bufferMutex;
    std::queue<TItem> _buffer;

    // Count of available slots.
    std::mutex _slotCountMutex;
    size_t _slotCount;
    // Critical section condition for decreasing slots.
    std::condition_variable _producers;

    // Count of available items.
    std::mutex _itemCountMutex;
    size_t _itemCount;
    // Critical section condition for decreasing items.
    std::condition_variable _consumers;

    volatile bool _stay;

    TOnDisconnect& _onDisconnect;

};

bool execute(SOCKET clientSocket, SOCKET udpSocket);
void disconnect(SOCKET& listenerSocket);

/*!***********************************************************************
\brief Appends the binary representation of a value to the end of a vector.

\param vec Reference to the vector to which the value will be appended.
\param value The value to be appended to the vector.
*************************************************************************/
template <typename T>
void appendValueToVector(std::vector<unsigned char>& vec, T value) {
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&value);
    vec.insert(vec.end(), bytes, bytes + sizeof(T));
}

/*!***********************************************************************
\brief Appends the characters of a string to the end of a vector.

\param vec Reference to the vector to which the string will be appended.
\param str Reference to the string to be appended to the vector.
*************************************************************************/
void appendStringToVector(std::vector<unsigned char>& vec, const std::string& str) {
    vec.insert(vec.end(), str.begin(), str.end());
}

/*!***********************************************************************
\brief Converts an IPv4 address represented as a 32-bit integer to its
       string representation.

\param ipAddress The IPv4 address to be converted.
\return The string representation of the IPv4 address.
*************************************************************************/
std::string ipAddressToString(uint32_t ipAddress) {
    struct in_addr addr;
    addr.s_addr = ipAddress;
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
    return std::string(ipStr);
}

//*********************************************************************************//
int main() {
    const uint16_t serverTCPPortNumber = 9000;
    const uint16_t serverUDPPortNumber = 9001;
    const uint16_t clientUDPPort = 9002;
    const std::string downloadPath = "C:\\Users\\chuak\\source\\repos\\Ass3_Server\\Ass3_Server\\Test";
    const int slidingWindowSize = 1;
    const double packetLossRate = 1.0; // 100% packet loss rate for demonstration
    const int ackTimer = 10; // Acknowledgement timer in milliseconds
    const std::string serverIP = "192.168.15.1";

    // Print server settings
    std::cout << "Server TCP Port Number: " << serverTCPPortNumber << std::endl;
    std::cout << "Server UDP Port Number: " << serverUDPPortNumber << std::endl;
    std::cout << "Download path: " << downloadPath << std::endl;
    std::cout << "Sliding window size [1,100]: " << slidingWindowSize << std::endl;
    std::cout << "Packet loss rate [0.0-1.0]: " << packetLossRate << std::endl;
    std::cout << "Ack timer [10ms-500ms]: " << ackTimer << " ms" << std::endl;
    //uint16_t serverTCPPortNumber;
    //uint16_t serverUDPPortNumber;
    //int slidingWindowSize;
    //double packetLossRate;
    //int ackTimer; // Acknowledgement timer in milliseconds

    //std::cout << "Server TCP Port Number: ";
    //std::cin >> serverTCPPortNumber;

    //std::cout << "Server UDP Port Number: ";
    //std::cin >> serverUDPPortNumber;

    //std::cout << "Download path: ";
    //std::cin >> downloadPath;

    //std::cout << "Sliding window size [1,100]: ";
    //std::cin >> slidingWindowSize;

    //std::cout << "Packet loss rate [0.0-1.0]: ";
    //std::cin >> packetLossRate;

    //std::cout << "Ack timer [10ms-500ms]: ";
    //std::cin >> ackTimer;

    std::string portString = std::to_string(serverTCPPortNumber);
    std::string UDPportString = std::to_string(serverUDPPortNumber);

    WSADATA wsaData{};
    SecureZeroMemory(&wsaData, sizeof(wsaData));

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup() failed." << std::endl;
        return result;
    }

    addrinfo hints{};
    SecureZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4 addresses
    hints.ai_flags = AI_PASSIVE; // Use my IP
    char hostname[256];
    gethostname(hostname, 256);
    addrinfo* tcpInfo = nullptr, * udpInfo = nullptr;

    // Setup TCP socket
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_protocol = IPPROTO_TCP;
    result = getaddrinfo(hostname, portString.c_str(), &hints, &tcpInfo);
    if (result != 0 || tcpInfo == nullptr) {
        std::cerr << "getaddrinfo() failed for TCP with error: " << result << std::endl;
        WSACleanup();
        return result;
    }

    SOCKET tcpSocket = socket(tcpInfo->ai_family, tcpInfo->ai_socktype, tcpInfo->ai_protocol);
    if (tcpSocket == INVALID_SOCKET) {
        std::cerr << "TCP socket() failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(tcpInfo);
        WSACleanup();
        return 1;
    }

    result = bind(tcpSocket, tcpInfo->ai_addr, (int)tcpInfo->ai_addrlen);
    if (result == SOCKET_ERROR) {
        std::cerr << "TCP bind() failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(tcpInfo);
        closesocket(tcpSocket);
        WSACleanup();
        return 2;
    }

    // Setup UDP socket
    hints.ai_socktype = SOCK_DGRAM; // UDP
    hints.ai_protocol = IPPROTO_UDP;
    result = getaddrinfo(hostname, UDPportString.c_str(), &hints, &udpInfo);
    if (result != 0 || udpInfo == nullptr) {
        std::cerr << "getaddrinfo() failed for UDP with error: " << result << std::endl;
        closesocket(tcpSocket);
        WSACleanup();
        return result;
    }

    SOCKET udpSocket = socket(udpInfo->ai_family, udpInfo->ai_socktype, udpInfo->ai_protocol);
    if (udpSocket == INVALID_SOCKET) {
        std::cerr << "UDP socket() failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(udpInfo);
        closesocket(tcpSocket);
        WSACleanup();
        return 1;
    }

    result = bind(udpSocket, udpInfo->ai_addr, (int)udpInfo->ai_addrlen);
    if (result == SOCKET_ERROR) {
        std::cerr << "UDP bind() failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(udpInfo);
        closesocket(udpSocket);
        closesocket(tcpSocket);
        WSACleanup();
        return 2;
    }

    freeaddrinfo(tcpInfo);
    freeaddrinfo(udpInfo);

    // At this point, both TCP and UDP sockets are set up and bound to the same port.
    // You can now listen on the TCP socket and use the UDP socket for receiving datagrams.

    result = listen(tcpSocket, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        std::cerr << "listen() failed with error: " << WSAGetLastError() << std::endl;
        closesocket(tcpSocket);
        closesocket(udpSocket);
        WSACleanup();
        return 3;
    }

    sockaddr_in localAddress;
    int addressLength = sizeof(localAddress);
    getsockname(tcpSocket, (sockaddr*)&localAddress, &addressLength);
    char ipAddress[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &localAddress.sin_addr, ipAddress, INET_ADDRSTRLEN);
    std::cout << "\nServer IP Address: " << ipAddress
        << "\nServer TCP Port Number: " << ntohs(localAddress.sin_port) << std::endl;
    std::cout << "Server UDP Port Number: " << serverUDPPortNumber << std::endl;
    std::cout << "Download path: " << downloadPath << std::endl;
    std::cout << "Sliding window size [1,100]: " << slidingWindowSize << std::endl;
    std::cout << "Packet loss rate [0.0-1.0]: " << packetLossRate << std::endl;
    std::cout << "Ack timer [10ms-500ms]: " << ackTimer << " ms" << std::endl;
    std::cout << "Now sending message to port " << serverUDPPortNumber << "..." << std::endl;
    result = listen(tcpSocket, SOMAXCONN);
    if (result != NO_ERROR)
    {
        std::cerr << "listen() failed." << std::endl;
        closesocket(tcpSocket);
        WSACleanup();
        return 3;
    }

    const auto onDisconnect = [&]() { disconnect(tcpSocket); };
    auto executeAction = [udpSocket](SOCKET clientSocket) { return execute(clientSocket, udpSocket); };
    auto tq = TaskQueue<SOCKET, decltype(executeAction), decltype(onDisconnect)>{ 10, 15, executeAction, onDisconnect };
    while (tcpSocket != INVALID_SOCKET)
    {
        sockaddr clientAddress{};
        SecureZeroMemory(&clientAddress, sizeof(clientAddress));
        int clientAddressSize = sizeof(clientAddress);
        SOCKET clientSocket = accept(
            tcpSocket,
            &clientAddress,
            &clientAddressSize);
        if (clientSocket == INVALID_SOCKET)
        {
            std::cerr << "accept() failed." << std::endl;
            closesocket(tcpSocket);
            WSACleanup();
            return 4;
        }
        char clientIP[NI_MAXHOST];
        char clientPort[NI_MAXSERV];

        sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        getpeername(clientSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrLen);

        getnameinfo(
            reinterpret_cast<sockaddr*>(&clientAddr),
            clientAddrLen,
            clientIP,
            NI_MAXHOST,
            clientPort,
            NI_MAXSERV,
            NI_NUMERICHOST | NI_NUMERICSERV);

        clientsVector.emplace_back(clientSocket, std::make_pair(clientIP, clientPort));

        std::cout << "\nClient IP Address: " << clientIP << std::endl;
        std::cout << "Client Port Number: " << clientPort << std::endl;
        tq.produce(clientSocket);

    }
    WSACleanup();
}

/*!***********************************************************************
\brief Disconnects the specified socket.

\param listenerSocket Reference to the socket to be disconnected.
*************************************************************************/
void disconnect(SOCKET& listenerSocket)
{
    if (listenerSocket != INVALID_SOCKET)
    {
        shutdown(listenerSocket, SD_BOTH);
        closesocket(listenerSocket);
        listenerSocket = INVALID_SOCKET;
    }
}

/*!***********************************************************************
\brief Executes the command received from the client socket.

\param clientSocket The socket connected to the client.
\return Returns true if the execution is successful and the connection should stay open; otherwise, returns false.
*************************************************************************/
bool execute(SOCKET clientSocket, SOCKET udpSocket)
{

    // -------------------------------------------------------------------------
    // Receive some text and send it back.
    //
    // recv()
    // send()
    // -------------------------------------------------------------------------

    constexpr size_t BUFFER_SIZE = 1024;
    char buffer[BUFFER_SIZE];
    bool stay = true;
    char ipStr[INET_ADDRSTRLEN];
    while (true)
    {
        const int bytesReceived = recv(
            clientSocket,
            buffer,
            BUFFER_SIZE - 1,
            0);
        if (bytesReceived == SOCKET_ERROR)
        {
            for (auto it = clientsVector.begin(); it != clientsVector.end(); ++it) {
                if (it->first == clientSocket) {
                    clientsVector.erase(it);
                    break; // No need to continue iterating once found and erased
                }
            }
            break;
        }

        // Ensure network byte order is converted to host byte order
        // Determine the command ID
        CMDID commandId = static_cast<CMDID>(buffer[0]);

        // Handle REQ_LISTFILES command
        if (commandId == REQ_LISTFILES) {
            // Define the directory you want to list files from
            std::string directoryPath = downloadPath; // Update this with the actual path

            // Start building the response message
            std::vector<unsigned char> response;
            response.push_back(RSP_LISTFILES); // Command ID

            // Placeholder for files count, will be updated later
            size_t filesCountPosition = response.size();
            uint16_t numFiles = 0; // We will count the files and update this later
            response.resize(response.size() + sizeof(numFiles)); // Reserve space for the files count

            // List files
            for (const auto& entry : fs::directory_iterator(directoryPath)) {
                if (entry.is_regular_file()) {
                    std::string filePath = entry.path().string();
                    // Append file path length and file path to the response
                    uint16_t filePathLength = htons(static_cast<uint16_t>(filePath.size()));
                    response.insert(response.end(), reinterpret_cast<unsigned char*>(&filePathLength), reinterpret_cast<unsigned char*>(&filePathLength) + sizeof(filePathLength));
                    response.insert(response.end(), filePath.begin(), filePath.end());

                    ++numFiles; // Increment files count
                }
            }

            // Update files count in the response
            numFiles = htons(numFiles); // Convert files count to network byte order
            std::copy(reinterpret_cast<unsigned char*>(&numFiles), reinterpret_cast<unsigned char*>(&numFiles) + sizeof(numFiles), response.begin() + filesCountPosition);

            // Send response
            send(clientSocket, reinterpret_cast<char*>(response.data()), response.size(), 0);
        }
        else if (commandId == REQ_DOWNLOAD) {
            // Assuming buffer layout: [CMDID (1 byte)][IP Address (4 bytes)][Port (2 bytes)][File Name Length (4 bytes)][File Name (variable)]
            size_t offset = 1; // Starting after CMDID
            std::cout << "File sent: ";
            // Extract client IP address
            in_addr clientIP;
            std::memcpy(&clientIP, buffer + offset, sizeof(clientIP));
            offset += sizeof(clientIP);

            // Extract client port
            uint16_t clientPort;
            std::memcpy(&clientPort, buffer + offset, sizeof(clientPort));
            clientPort = ntohs(clientPort); // Convert from network byte order to host order
            offset += sizeof(clientPort);

            // Extract file name length
            uint32_t fileNameLength;
            std::memcpy(&fileNameLength, buffer + offset, sizeof(fileNameLength));
            fileNameLength = ntohl(fileNameLength); // Convert from network byte order to host order
            offset += sizeof(fileNameLength);

            // Extract file name
            std::string fileName(buffer + offset, fileNameLength);
            std::string fullPath = downloadPath + "/" + fileName; // Assuming downloadPath is your server's download directory

            // Open the file
            std::ifstream file(fullPath, std::ios::binary);
            if (!file.is_open()) {
                // Error opening file
                unsigned char errorResponse[] = { DOWNLOAD_ERROR };
                send(clientSocket, reinterpret_cast<char*>(errorResponse), sizeof(errorResponse), 0);
            }
            else {
                // Notify the client about the upcoming file transfer over UDP
                unsigned char response[] = { RSP_DOWNLOAD };
                send(clientSocket, reinterpret_cast<char*>(response), sizeof(response), 0);

                // Send file over UDP
                sockaddr_in clientAddr = {};
                clientAddr.sin_family = AF_INET;
                clientAddr.sin_port = htons(clientPort);
                clientAddr.sin_addr = clientIP;

                char fileBuffer[1024];
                while (file.read(fileBuffer, sizeof(fileBuffer)) || file.gcount() > 0) {
                    sendto(udpSocket, fileBuffer, file.gcount(), 0, reinterpret_cast<sockaddr*>(&clientAddr), sizeof(clientAddr));
                }
                std::cout << "File sent: " << fullPath << std::endl;
            }
        }

         else if (commandId == REQ_QUIT) {
            for (auto it = clientsVector.begin(); it != clientsVector.end(); ++it) {
                if (it->first == clientSocket) {
                    clientsVector.erase(it);
                    break; // No need to continue iterating once found and erased
                }
            }
        }
    }


    // -------------------------------------------------------------------------
    // Shut down and close sockets.
    //
    // shutdown()
    // closesocket()
    // -------------------------------------------------------------------------

    shutdown(clientSocket, SD_BOTH);
    closesocket(clientSocket);
    return stay;
}