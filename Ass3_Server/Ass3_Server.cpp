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

#pragma comment(lib, "ws2_32.lib")

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

static std::mutex _stdoutMutex;
std::vector<std::pair<SOCKET, std::pair<std::string, std::string>>> clientsVector;

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

bool execute(SOCKET clientSocket);
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
    uint16_t port;

    std::cout << "Server Port Number: ";
    std::cin >> port;

    std::string portString = std::to_string(port);

    WSADATA wsaData{};
    SecureZeroMemory(&wsaData, sizeof(wsaData));

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup() failed." << std::endl;
        return result;
    }

    addrinfo hints{};
    SecureZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    char hostname[256];
    gethostname(hostname, 256);

    addrinfo* info = nullptr;
    result = getaddrinfo(hostname, portString.c_str(), &hints, &info);
    if ((result) || (info == nullptr))
    {
        std::cerr << "getaddrinfo() failed." << std::endl;
        WSACleanup();
        return result;
    }

    SOCKET listenerSocket = socket(
        hints.ai_family,
        hints.ai_socktype,
        hints.ai_protocol);
    if (listenerSocket == INVALID_SOCKET)
    {
        std::cerr << "socket() failed." << std::endl;
        freeaddrinfo(info);
        WSACleanup();
        return 1;
    }

    result = bind(
        listenerSocket,
        info->ai_addr,
        static_cast<int>(info->ai_addrlen));
    if (result != NO_ERROR)
    {
        std::cerr << "bind() failed." << std::endl;
        closesocket(listenerSocket);
        listenerSocket = INVALID_SOCKET;
    }

    freeaddrinfo(info);

    if (listenerSocket == INVALID_SOCKET)
    {
        std::cerr << "bind() failed." << std::endl;
        WSACleanup();
        return 2;
    }

    result = listen(listenerSocket, SOMAXCONN);
    if (result != NO_ERROR)
    {
        std::cerr << "listen() failed." << std::endl;
        closesocket(listenerSocket);
        WSACleanup();
        return 3;
    }

    sockaddr_in localAddress;
    int addressLength = sizeof(localAddress);
    getsockname(listenerSocket, (sockaddr*)&localAddress, &addressLength);
    char ipAddress[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &localAddress.sin_addr, ipAddress, INET_ADDRSTRLEN);
    std::cout << "\nServer IP Address: " << ipAddress
        << "\nServer Port Number: " << ntohs(localAddress.sin_port) << std::endl;

    result = listen(listenerSocket, SOMAXCONN);
    if (result != NO_ERROR)
    {
        std::cerr << "listen() failed." << std::endl;
        closesocket(listenerSocket);
        WSACleanup();
        return 3;
    }

    const auto onDisconnect = [&]() { disconnect(listenerSocket); };
    auto tq = TaskQueue<SOCKET, decltype(execute), decltype(onDisconnect)>{ 10, 15, execute, onDisconnect };
    while (listenerSocket != INVALID_SOCKET)
    {
        sockaddr clientAddress{};
        SecureZeroMemory(&clientAddress, sizeof(clientAddress));
        int clientAddressSize = sizeof(clientAddress);
        SOCKET clientSocket = accept(
            listenerSocket,
            &clientAddress,
            &clientAddressSize);
        if (clientSocket == INVALID_SOCKET)
        {
            std::cerr << "accept() failed." << std::endl;
            closesocket(listenerSocket);
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
bool execute(SOCKET clientSocket)
{

    // -------------------------------------------------------------------------
    // Receive some text and send it back.
    //
    // recv()
    // send()
    // -------------------------------------------------------------------------

    constexpr size_t BUFFER_SIZE = 1000;
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

        // Handle REQ_LISTUSERS command
        if (commandId == REQ_LISTUSERS) {

            // Start building the response message
            std::vector<unsigned char> response;
            response.push_back(RSP_LISTUSERS); // Command ID

            // Number of users
            uint16_t numUsers = htons(static_cast<uint16_t>(clientsVector.size()));
            response.insert(response.end(), reinterpret_cast<unsigned char*>(&numUsers), reinterpret_cast<unsigned char*>(&numUsers) + sizeof(numUsers));

            // User data
            for (const auto& [clientSocket, clientInfo] : clientsVector) {
                // IP address
                in_addr ipAddr;
                inet_pton(AF_INET, clientInfo.first.c_str(), &ipAddr);
                uint32_t ipNetworkOrder = ipAddr.s_addr; // No need to use htonl here
                response.insert(response.end(), reinterpret_cast<unsigned char*>(&ipNetworkOrder), reinterpret_cast<unsigned char*>(&ipNetworkOrder) + sizeof(ipNetworkOrder));

                // Port number
                uint16_t portNumber = htons(static_cast<uint16_t>(std::stoi(clientInfo.second)));
                response.insert(response.end(), reinterpret_cast<unsigned char*>(&portNumber), reinterpret_cast<unsigned char*>(&portNumber) + sizeof(portNumber));
            }

            // Send response
            send(clientSocket, reinterpret_cast<char*>(response.data()), response.size(), 0);
        }

        else if (commandId == REQ_ECHO) {
            const int IP_OFFSET = 1;
            const int PORT_OFFSET = IP_OFFSET + sizeof(uint32_t);
            const int TEXT_LENGTH_OFFSET = PORT_OFFSET + sizeof(uint16_t);
            const int MESSAGE_TEXT_OFFSET = TEXT_LENGTH_OFFSET + sizeof(uint32_t);

            uint32_t destIP = *reinterpret_cast<const uint32_t*>(buffer + IP_OFFSET);
            uint16_t destPort = ntohs(*reinterpret_cast<const uint16_t*>(buffer + PORT_OFFSET));

            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &destIP, ipStr, INET_ADDRSTRLEN);

            // Extract the message text
            // Assuming buffer[7] to buffer[10] contain the text length
            uint32_t textLength = ntohl(*reinterpret_cast<const uint32_t*>(buffer + TEXT_LENGTH_OFFSET)); // Convert to host byte order
            std::string messageText(buffer + MESSAGE_TEXT_OFFSET, textLength); // Extract the text

            //std::cout << ipStr << ":" << destPort << std::endl;
            // Find the target client socket using the IP and port
            SOCKET targetClientSocket = INVALID_SOCKET;
            for (const auto& client : clientsVector) {
                const auto& clientInfo = client.second;
                if (clientInfo.first == ipStr && std::stoi(clientInfo.second) == destPort) {
                    targetClientSocket = client.first;
                    break;
                }
            }

            // If the target client is found, forward the message
            if (targetClientSocket != INVALID_SOCKET) {
                // Found the target client socket, now forward the message
                // Construct the message to send, beginning with the command ID for RSP_ECHO

                sockaddr_in sourceAddr;
                int addrLen = sizeof(sourceAddr);
                if (getpeername(clientSocket, (sockaddr*)&sourceAddr, &addrLen) == 0) {
                    std::vector<unsigned char> messageToSend;
                    std::vector<unsigned char> messageToBack;

                    uint32_t sourceIP = sourceAddr.sin_addr.s_addr;
                    uint16_t sourcePort = sourceAddr.sin_port;

                    // Construct the message
                    sourceIP = sourceAddr.sin_addr.s_addr;
                    sourcePort = sourceAddr.sin_port;

                    messageToSend.push_back(REQ_ECHO); // Command ID
                    appendValueToVector(messageToSend, sourceIP);
                    appendValueToVector(messageToSend, sourcePort);
                    appendValueToVector(messageToSend, htonl(textLength)); // Convert to network byte order
                    appendStringToVector(messageToSend, messageText);

                    // Construct message to back
                    messageToBack.push_back(REQ_ECHO); // Command ID
                    appendValueToVector(messageToBack, destIP);
                    appendValueToVector(messageToBack, htons(destPort)); // Convert to network byte order
                    appendValueToVector(messageToBack, htonl(textLength)); // Convert to network byte order
                    appendStringToVector(messageToBack, messageText);

                    // Printing the received message
                    std::cout << "==========RECV START==========" << std::endl;
                    std::cout << ipAddressToString(sourceIP) << ":" << htons(sourcePort) << std::endl;
                    std::cout << messageText << std::endl;
                    std::cout << "==========RECV END==========" << std::endl;

                    // Send the constructed message to the target client socket
                    const int bytesSent = send(targetClientSocket, reinterpret_cast<char*>(messageToSend.data()), messageToSend.size(), 0);
                    if (bytesSent == SOCKET_ERROR) {
                        std::cerr << "send() failed with error: " << WSAGetLastError() << std::endl;
                    }
                }
                else {
                    // Handle the error case where getsockname failed
                    std::cerr << "getpeername() failed with error: " << WSAGetLastError() << std::endl;
                }

            }
            else {
                // If the target client is not found, send an ECHO_ERROR response
                //std::cout << "IP and Port: " << destPort << std::endl;
                unsigned char errorResponse[] = { ECHO_ERROR };
                send(clientSocket, (char*)errorResponse, sizeof(errorResponse), 0);
            }
        }

        else if (RSP_ECHO) {
            const int IP_OFFSET = 1;
            const int PORT_OFFSET = IP_OFFSET + sizeof(uint32_t);
            const int TEXT_LENGTH_OFFSET = PORT_OFFSET + sizeof(uint16_t);
            const int MESSAGE_TEXT_OFFSET = TEXT_LENGTH_OFFSET + sizeof(uint32_t);

            uint32_t destIP = *reinterpret_cast<const uint32_t*>(buffer + IP_OFFSET);
            uint16_t destPort = ntohs(*reinterpret_cast<const uint16_t*>(buffer + PORT_OFFSET));

            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &destIP, ipStr, INET_ADDRSTRLEN);

            // Extract the message text
            // Assuming buffer[7] to buffer[10] contain the text length
            uint32_t textLength = ntohl(*reinterpret_cast<const uint32_t*>(buffer + TEXT_LENGTH_OFFSET)); // Convert to host byte order
            std::string messageText(buffer + MESSAGE_TEXT_OFFSET, textLength); // Extract the text

            //std::cout << ipStr << ":" << destPort << std::endl;
            // Find the target client socket using the IP and port
            SOCKET targetClientSocket = INVALID_SOCKET;
            for (const auto& client : clientsVector) {
                const auto& clientInfo = client.second;
                if (clientInfo.first == ipStr && std::stoi(clientInfo.second) == destPort) {
                    targetClientSocket = client.first;
                    break;
                }
            }

            // If the target client is found, forward the message
            if (targetClientSocket != INVALID_SOCKET) {
                sockaddr_in sourceAddr;
                int addrLen = sizeof(sourceAddr);
                std::vector<unsigned char> messageToSend;
                if (getpeername(clientSocket, (sockaddr*)&sourceAddr, &addrLen) == 0) {

                    uint32_t sourceIP = sourceAddr.sin_addr.s_addr;
                    uint16_t sourcePort = sourceAddr.sin_port;

                    // Construct the message
                    sourceIP = sourceAddr.sin_addr.s_addr;
                    sourcePort = sourceAddr.sin_port;

                    messageToSend.push_back(RSP_ECHO); // Command ID
                    appendValueToVector(messageToSend, sourceIP);
                    appendValueToVector(messageToSend, sourcePort);
                    appendValueToVector(messageToSend, htonl(textLength)); // Convert to network byte order
                    appendStringToVector(messageToSend, messageText);
                    // Send the constructed message to the target client socket
                    const int bytesSent = send(targetClientSocket, reinterpret_cast<char*>(messageToSend.data()), messageToSend.size(), 0);
                    if (bytesSent == SOCKET_ERROR) {
                        std::cerr << "send() failed with error: " << WSAGetLastError() << std::endl;
                    }
                }
                else {
                    // Handle the error case where getsockname failed
                    std::cerr << "getpeername() failed with error: " << WSAGetLastError() << std::endl;
                }

            }
            else {
                unsigned char errorResponse[] = { ECHO_ERROR };
                send(clientSocket, (char*)errorResponse, sizeof(errorResponse), 0);
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