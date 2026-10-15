/* Harmless Windows test executable. No network, filesystem or registry access. */
#include <windows.h>
int WINAPI WinMain(HINSTANCE a,HINSTANCE b,LPSTR c,int d) {
    MessageBoxA(NULL,"SentinelScan safe client demonstration sample.","SentinelScan demo",MB_OK);
    return 0;
}
