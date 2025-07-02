/**
 * @file threading.c3
 * @brief Use a threading interface based on the current environment.
 *
 * @author Zack Puhl <github@xmit.xyz>
 * @date 2025-06-25
 * 
 * 
 * Copyright (c) 2025 Zack Puhl <github@xmit.xyz> - https://github.com/NotsoanoNimus/mftah.c3l
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
module mftah::threading;

// We expect that these functions will be defined either through a direct PTHREAD linkage,
//   or through some other implementation when MFTAH is called. This is probably not ideal.

alias PosixThreadFn = fn void* (void*);
typedef Pthread_t = void*;

extern fn CInt pthread_create(Pthread_t*, Pthread_attr_t*, PosixThreadFn, void*);
extern fn CInt pthread_join(Pthread_t, void** value_ptr);

extern fn CInt pthread_attr_destroy(Pthread_attr_t*);
extern fn CInt pthread_attr_init(Pthread_attr_t*);


module mftah::threading @if(env::POSIX && !env::LINUX);
typedef Pthread_attr_t = ulong[8];
typedef Pthread_cond_t = ulong[6];
typedef Pthread_condattr_t = ulong[8];
typedef Pthread_key_t = ulong;
typedef Pthread_mutex_t = ulong[8];
typedef Pthread_mutexattr_t = ulong[2];
typedef Pthread_once_t = ulong[2];
typedef Pthread_rwlock_t = ulong[25];
typedef Pthread_rwlockattr_t = ulong[3];
typedef Pthread_sched_param = ulong;

module mftah::threading @if(env::LINUX);
typedef Pthread_attr_t = ulong[7]; // 24 on 32bit
typedef Pthread_cond_t = ulong[6];
typedef Pthread_condattr_t = uint;
typedef Pthread_key_t = uint;
typedef Pthread_mutex_t = ulong[5]; // 24 on 32 bit
typedef Pthread_mutexattr_t = uint;
typedef Pthread_once_t = int;
typedef Pthread_rwlock_t = ulong[7]; // 32 on 3bit
typedef Pthread_rwlockattr_t = uint;
typedef Pthread_sched_param = uint;
