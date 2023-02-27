time openssl rand 1000000000 > /dev/shm/data.dump
real    0m7,108s
user    0m6,271s
sys     0m0,836s

time dd if=/dev/urandom of=/dev/shm/data-urandom.dump bs=1000000000 count=1
1+0 records in
1+0 records out
1000000000 bytes (1,0 GB, 954 MiB) copied, 6,62855 s, 151 MB/s
real    0m6,875s
user    0m0,000s
sys     0m6,873s
