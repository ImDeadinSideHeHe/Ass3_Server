/*******************************************************************************
 * A simple UDP/IP client application
 ******************************************************************************/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Windows.h"		// Entire Win32 API...
 // #include "winsock2.h"	// ...or Winsock alone
#include "ws2tcpip.h"		// getaddrinfo()

// Tell the Visual Studio linker to include the following library in linking.
// Alternatively, we could add this file to the linker command-line parameters,
// but including it in the source code simplifies the configuration.
#pragma comment(lib, "ws2_32.lib")

#include <iostream>			// cout, cerr
#include <string>			// string

int main(int argc, char** argv)
{
	constexpr uint16_t serverPort = 9048;
	constexpr uint16_t clientPort = 9049;

	if (argc != 2)
	{
		std::cerr << "Specify a server ip." << std::endl;
		return 1;
	}

	const std::string serverHost{argv[1]};
	const std::string serverPortString = std::to_string(serverPort);
	const std::string clientPortString = std::to_string(clientPort);


	// -------------------------------------------------------------------------
	// Start up Winsock, asking for version 2.2.
	//
	// WSAStartup()
	// -------------------------------------------------------------------------

	// This object holds the information about the version of Winsock that we
	// are using, which is not necessarily the version that we requested.
	WSADATA wsaData{};
	SecureZeroMemory(&wsaData, sizeof(wsaData));

	// Initialize Winsock. You must call WSACleanup when you are finished.
	// As this function uses a reference counter, for each call to WSAStartup,
	// you must call WSACleanup or suffer memory issues.
	int errorCode = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (errorCode != NO_ERROR)
	{
		std::cerr << "WSAStartup() failed." << std::endl;
		return errorCode;
	}

	std::cout
		<< "Winsock version: "
		<< static_cast<int>(LOBYTE(wsaData.wVersion))
		<< "."
		<< static_cast<int>(HIBYTE(wsaData.wVersion))
		<< "\n"
		<< std::endl;


	// -------------------------------------------------------------------------
	// Resolve own host name into IP addresses (in a singly-linked list).
	//
	// getaddrinfo()
	// -------------------------------------------------------------------------

	// Object hints indicates which protocols to use to fill in the info.
	addrinfo hints{};
	SecureZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;			// IPv4
	// For UDP use SOCK_DGRAM instead of SOCK_STREAM.
	hints.ai_socktype = SOCK_DGRAM;		// Best effort
	// Could be 0 for autodetect, but best effort over IPv4 is always UDP.
	hints.ai_protocol = IPPROTO_UDP;	// UDP

	addrinfo* info = nullptr;
	errorCode = getaddrinfo(nullptr, clientPortString.c_str(), &hints, &info);
	if ((errorCode) || (info == nullptr))
	{
		std::cerr << "getaddrinfo() failed." << std::endl;
		WSACleanup();
		return errorCode;
	}


	// -------------------------------------------------------------------------
	// Create a socket and bind it to own network interface controller.
	//
	// socket()
	// bind()
	// -------------------------------------------------------------------------

	SOCKET serverSocket = socket(
		hints.ai_family,
		hints.ai_socktype,
		hints.ai_protocol);
	if (serverSocket == INVALID_SOCKET)
	{
		std::cerr << "socket() failed." << std::endl;
		freeaddrinfo(info);
		WSACleanup();
		return 1;
	}

	struct sockaddr_in socketAddress;
	(void)memset(&socketAddress, 0, sizeof(socketAddress));
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_port = htons(clientPort);
	errorCode = bind(serverSocket, (struct sockaddr*) & socketAddress, sizeof(socketAddress));	

	if (errorCode != NO_ERROR)
	{
		std::cerr << "bind() failed." << std::endl;
		closesocket(serverSocket);
		freeaddrinfo(info);
		WSACleanup();
		return 2;
	}
	
	//connect to server (optional)
	struct sockaddr_in serverAddress;
	(void)memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	inet_pton(AF_INET, serverHost.c_str(), &(serverAddress.sin_addr));
	serverAddress.sin_port = htons(serverPort);
	if (connect(serverSocket, (struct sockaddr*) & serverAddress, sizeof(serverAddress)) < 0) {
		std::cerr << "connect() failed." << std::endl;
		closesocket(serverSocket);
		freeaddrinfo(info);
		WSACleanup();
		return false;
	}

	while (true)
	{
		std::string text;
		//std::cin >> text; 
		std::getline(std::cin, text);
		std::cout << "input text length = " << text.size() << std::endl;
		int serverAddressSize = sizeof(serverAddress);
		const int bytesSent = sendto(serverSocket, text.c_str(), static_cast<int>(text.size() + 1), 0, (sockaddr*)&serverAddress, serverAddressSize);
		if (bytesSent == SOCKET_ERROR)
		{
			std::cerr << "send() failed." << std::endl;
			break;
		}


		std::cout
			<< "Text sent:  " << text << "\n"
			<< "Bytes sent: " << bytesSent << "\n"
			<< std::endl;

		if (text == "quit")
		{
			std::cerr << "Graceful shutdown." << std::endl;
			break;
		}

		constexpr size_t BUFFER_SIZE = 1000;
		char buffer[BUFFER_SIZE]{0};
		const int bytesReceived = recvfrom(serverSocket,
			buffer,
			BUFFER_SIZE - 1,
			0,
			(sockaddr*)&serverAddress,
			&serverAddressSize);
		if (bytesReceived == SOCKET_ERROR)
		{
			std::cerr << "recvfrom() failed." << std::endl;
			break;
		}
		if (bytesReceived == 0)
		{
			std::cerr << "Graceful shutdown." << std::endl;
			break;
		}


		buffer[bytesReceived] = '\0';
		text = std::string(buffer, bytesReceived);
		std::cout
			<< "Text received:  " << text << "\n"
			<< "Bytes received: " << bytesReceived << "\n"
			<< std::endl;
	}


	// -------------------------------------------------------------------------
	// Close socket and clean-up after Winsock.
	//
	// WSACleanup()
	// -------------------------------------------------------------------------

	closesocket(serverSocket);
	WSACleanup();
}
