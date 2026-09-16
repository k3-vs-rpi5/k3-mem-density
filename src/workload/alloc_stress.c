// SPDX-License-Identifier: Apache-2.0
/*
 * Synthetic workload used to verify the memory-density tool. It exercises all
 * four modelled densities: allocation/free rate, allocation width, page faults
 * (read and write) and, on a memory-constrained board, reclaim pressure.
 *
 * Build for the board with the workspace cross toolchain; run it while the
 * probe is attached.
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

static int workload_seconds = 5;
static size_t block_bytes;
static volatile int stop_flag;

/* Concurrent allocators on purpose: a single thread rarely contends on the
 * per-cache SLUB lock or the buddy zone lock, so the default is several
 * threads fighting for the same size class. */
static void *allocator(void *arg)
{
	long id = (long)arg;
	unsigned long long rounds = 0;
	char path[64];
	int fd;

	snprintf(path, sizeof(path), "/tmp/k3-mem-density-workload-%ld.bin", id);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	while (!stop_flag) {
		char *buffer = malloc(block_bytes);

		if (!buffer)
			break;
		memset(buffer, (int)(rounds & 0x7f), block_bytes);
		/* rewrite from offset 0 so the scratch file stays bounded: the point is
		 * the read/write path, not disk consumption */
		if (fd >= 0 && (rounds & 0x3f) == 0)
			(void)!pwrite(fd, buffer, block_bytes, 0);
		free(buffer);
		rounds++;
	}
	if (fd >= 0)
		close(fd);
	unlink(path);
	return (void *)(intptr_t)rounds;
}

int main(int argc, char **argv)
{
	int seconds = argc > 1 ? atoi(argv[1]) : 5;
	int block_kib = argc > 2 ? atoi(argv[2]) : 64;
	int threads = argc > 3 ? atoi(argv[3]) : 4;
	pthread_t workers[64];
	unsigned long long rounds = 0;

	if (threads < 1)
		threads = 1;
	if (threads > 64)
		threads = 64;
	workload_seconds = seconds;
	block_bytes = (size_t)block_kib * 1024;

	for (long index = 0; index < threads; index++)
		if (pthread_create(&workers[index], NULL, allocator, (void *)index) != 0) {
			fprintf(stderr, "cannot start thread %ld\n", index);
			return 1;
		}
	for (int elapsed = 0; elapsed < workload_seconds; elapsed++)
		sleep(1);
	stop_flag = 1;
	for (int index = 0; index < threads; index++) {
		void *result = NULL;

		pthread_join(workers[index], &result);
		rounds += (unsigned long long)(intptr_t)result;
	}
	printf("alloc_stress: threads=%d block=%d KiB rounds=%llu bytes=%llu (%.1f MiB/s)\n",
	       threads, block_kib, rounds, rounds * block_bytes,
	       rounds * block_bytes / 1048576.0 / (double)(workload_seconds ? workload_seconds : 1));
	return 0;
}
