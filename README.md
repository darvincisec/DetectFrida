# DetectFrida
This project has 3 ways to detect frida hooking
a. Detect through named pipes used by Frida
b. Detect through frida specific named thread
c. Compare text section in memory with text section in disk for both libc and native library

More details can be found in my blog -> [DetectFrida](https://darvincitech.wordpress.com/2019/12/23/detect-frida-for-android)

Also this project has 3 mechanisms to harden the native code
a. Replace certain libc calls with syscalls
b. Replace string,memory related operation with custom implementation
c. Apply O-LLVM native obfuscation

More details can be found in my blog -> [Hardening Native Code](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code)

arm64, armv7a, x86_64 architectures are supported in this project. The hardened APK is provided for interested reverse engineers to analyze.

## Updates
a. Re-aligned functions
b. Fix scanning of executable sections only if it is readable to avoid crashes when app is targetting API 29
c. Stripped comment section in native library to prevent APKId detecting O-LLVM obfuscator is used
d. Updated Target API to 30
e. Updated Obfuscator-LLVM to [OLLVM-TLL] (https://github.com/yazhiwang/ollvm-tll)
f. Fixed false positives found in Android 10 and Android 11. Now the memdisk compare checks the PLT and TEXT sections of libc and native library in a proper way
g. Memdisk comparison approach is frida agnostic, hence [frida specific signature changes] (https://github.com/feicong/strong-frida) does not bypass this detection mechanism.

## Note
Henceforth, pls dont raise issue asking for OLLVM binary for Windows.  PRs welcome. 
