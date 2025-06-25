module prng_test;

import mftah::prng;
import std::io;


fn void main()
{
    Xoshiro256pp prng @noinit;
    prng.init();

    io::printf("Numbers of any size...\n");
    ulong[64] randoms;
    for (usz i = 0; i < 64; ++i) randoms[i] = prng.next();
    for (usz i = 0; i < 64; ++i) io::printf("%x,%c", randoms[i], (i+1) % 16 ? ' ' : '\n'); io::printn("\n");

    io::printf("Numbers between 100 (%x) and 1,000 (%x)...\n", 100, 1000);
    ulong[64] randoms_bounded;
    for (usz i = 0; i < 64; ++i) randoms_bounded[i] = prng.next_bounded(100, 1000);
    for (usz i = 0; i < 64; ++i) io::printf("%x,%c", randoms_bounded[i], (i+1) % 16 ? ' ' : '\n'); io::printn("\n");
}
