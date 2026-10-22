/* Harmless Windows verification program. Never run samples on the host.
 * Creates a marker in the guest TEMP directory and queries a reserved .invalid
 * name to provide observable process, file and DNS activity.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>

int main(void) {
    char path[MAX_PATH];
    DWORD length = GetTempPathA(MAX_PATH, path);
    if (length && length + 28 < MAX_PATH) {
        strcat(path, "sentinelscan-smoke.txt");
        HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            const char message[] = "SentinelScan harmless sandbox verification\r\n";
            DWORD written;
            WriteFile(file, message, sizeof(message) - 1, &written, NULL);
            CloseHandle(file);
        }
    }
    WSADATA sockets;
    if (WSAStartup(MAKEWORD(2, 2), &sockets) == 0) {
        struct addrinfo *result = NULL;
        if (getaddrinfo("sentinelscan-smoke.invalid", NULL, NULL, &result) == 0) freeaddrinfo(result);
        WSACleanup();
    }
    Sleep(1000);
    return 0;
}
