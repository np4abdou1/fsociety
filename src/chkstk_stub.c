// Stub for __chkstk_ms required by MinGW-compiled Zstandard library
// For x64, we can just alias it to the MSVC __chkstk

#ifdef _M_X64
// Tell linker to alias __chkstk_ms to __chkstk
#pragma comment(linker, "/alternatename:__chkstk_ms=__chkstk")
#else
// For x86, provide a simple implementation
extern void __cdecl __chkstk_ms(void);
void __cdecl __chkstk_ms(void) {
    // Stack probe - simplified version
}
#endif
