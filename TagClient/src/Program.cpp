#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <iostream>

void RemoteReverse(char* data, size_t length)
{
	DWORD bytesRead;

	CallNamedPipeA(
		"\\\\.\\pipe\\TagServicePipe",
		data,
		length,
		data,
		length,
		&bytesRead,
		50);
}

int main(int argc, char* argv[])
{
	std::cout << "Hello Tagged World!" << std::endl;

	char numbers[] = "1234567890";
	RemoteReverse(numbers, strlen(numbers));
	std::cout << "Received: " << numbers << std::endl;

	char phrase[] = "Hello World of Tags!";
	RemoteReverse(phrase, strlen(phrase));
	std::cout << "Received: " << phrase << std::endl;

	return EXIT_SUCCESS;
}
