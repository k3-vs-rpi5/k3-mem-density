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
#include <time.h>
#include <unistd.h>

static double now_seconds(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	int seconds = argc > 1 ? atoi(argv[1]) : 5;
	int block_kib = argc > 2 ? atoi(argv[2]) : 64;
	size_t block = (size_t)block_kib * 1024;
	double deadline = now_seconds() + seconds;
	unsigned long long rounds = 0, bytes = 0;
	int fd = open("/tmp/k3-mem-density-workload.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);

	while (now_seconds() < deadline) {
		char *buffer = malloc(block);

		if (!buffer) {
			fprintf(stderr, "allocation failed\n");
			return 1;
		}
		/* write every page: read-modify-write faults, then hand pages back */
		memset(buffer, (int)(rounds & 0x7f), block);
		if (fd >= 0)
			(void)!write(fd, buffer, block);
		free(buffer);
		rounds++;
		bytes += block;
	}
	if (fd >= 0)
		close(fd);
	printf("alloc_stress: rounds=%llu bytes=%llu (%.1f MiB/s)\n", rounds, bytes,
	       bytes / 1048576.0 / (double)seconds);
	return 0;
}
