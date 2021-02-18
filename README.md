# DetectFrida
This project has 3 ways to detect frida hooking
  1. Detect through named pipes used by Frida
  2. Detect through frida specific named thread
  3. Compare text section in memory with text section in disk for both libc and native library

More details can be found in my blog -> [DetectFrida](https://darvincitech.wordpress.com/2019/12/23/detect-frida-for-android)

Also this project has 3 mechanisms to harden the native code
  1. Replace certain libc calls with syscalls
  2. Replace string,memory related operation with custom implementation
  3. Apply O-LLVM native obfuscation

More details can be found in my blog -> [Hardening Native Code](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code)

arm64, armv7a, x86_64 architectures are supported in this project. The hardened APK is provided for interested reverse engineers to analyze.

## Updates
- Re-aligned functions
- Fix scanning of executable sections only if it is readable to avoid crashes when app is targetting API 29
- Stripped comment section in native library to prevent APKId detecting O-LLVM obfuscator is used
- Updated Target API to 30
- Updated Obfuscator-LLVM to [OLLVM-TLL](https://github.com/yazhiwang/ollvm-tll)
- Fixed false positives found in Android 10 and Android 11. Now the memdisk compare checks the PLT and TEXT sections of libc and native library in a proper way
- Memdisk comparison approach is frida agnostic, hence [frida specific signature changes](https://github.com/feicong/strong-frida) does not bypass this detection mechanism.

## Note
Henceforth, Please don't raise issue asking for OLLVM binary for Windows.  PRs welcome. 
