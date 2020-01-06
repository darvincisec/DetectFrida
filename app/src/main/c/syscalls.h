#ifndef DETECTFRIDA_SYSCALLS_H
#define DETECTFRIDA_SYSCALLS_H
/*
 * System calls such as file operations, sleep are converted to syscalls to avoid easy bypass
 * through readymade scripts hooking onto libc calls.
 */
__attribute__((always_inline))
static inline int  my_openat(int __dir_fd, const void* __path, int __flags, int __mode ){
    return (int)__syscall4(__NR_openat, __dir_fd, (long)__path, __flags, __mode);
}

__attribute__((always_inline))
static inline ssize_t my_read(int __fd, void* __buf, size_t __count){
    return __syscall3(__NR_read, __fd, (long)__buf, (long)__count);
}

__attribute__((always_inline))
static inline off_t my_lseek(int __fd, off_t __offset, int __whence){
    return __syscall3(__NR_lseek, __fd, __offset, __whence);
}

__attribute__((always_inline))
static inline int my_close(int __fd){
    return (int)__syscall1(__NR_close, __fd);
}

__attribute__((always_inline))
static inline int my_nanosleep(const struct timespec* __request, struct timespec* __remainder){
    return (int)__syscall2(__NR_nanosleep, (long)__request, (long)__remainder);
}

__attribute__((always_inline))
static inline ssize_t my_readlinkat(int __dir_fd, const char* __path, char* __buf, size_t __buf_size){
    return __syscall4(__NR_readlinkat, __dir_fd, (long)__path, (long)__buf,(long)__buf_size);
}

//Not Used
__attribute__((always_inline))
static inline int my_tgkill(int __tgid, int __tid, int __signal){
    return (int)__syscall3(__NR_tgkill, __tgid, __tid, __signal);
}

//Not Used
__attribute__((always_inline))
static inline void my_exit(int __status){
    __syscall1(__NR_exit, __status);
}

#endif //DETECTFRIDA_SYSCALLS_H