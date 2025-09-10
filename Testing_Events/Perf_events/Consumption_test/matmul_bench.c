// matmul_bench.c

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cblas.h>

static double now_sec(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static void fill_mat(double *A, size_t N, unsigned int seed) {
    srand(seed);
    for (size_t i = 0; i < N * N; ++i) A[i] = (double)(rand() % 100) / 10.0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <N> <reps>\n", argv[0]);
        return 1;
    }
    int N = atoi(argv[1]);
    int reps = atoi(argv[2]);
    if (N <= 0 || reps <= 0) { fprintf(stderr, "Invalid args\n"); return 1; }

    size_t elems = (size_t)N * (size_t)N;
    double *A = aligned_alloc(64, elems * sizeof(double));
    double *B = aligned_alloc(64, elems * sizeof(double));
    double *C = aligned_alloc(64, elems * sizeof(double));
    if (!A || !B || !C) {
        fprintf(stderr, "Allocation failed\n");
        return 1;
    }

    fill_mat(A, N, 123);
    fill_mat(B, N, 456);
    for (size_t i=0;i<elems;i++) C[i] = 0.0;

    // Warm-up
    cblas_dgemm(CblasRowMajor, CblasNoTrans, CblasNoTrans,
                N, N, N, 1.0, A, N, B, N, 0.0, C, N);

    double t0 = now_sec();
    for (int r = 0; r < reps; ++r) {
        // C = A * B
        cblas_dgemm(CblasRowMajor, CblasNoTrans, CblasNoTrans,
                    N, N, N, 1.0, A, N, B, N, 0.0, C, N);
    }
    double t1 = now_sec();
    double elapsed = t1 - t0;

    // GFLOPS: 2 * N^3 operations per multiplication
    double flops = 2.0 * (double)N * (double)N * (double)N * (double)reps;
    double gflops = flops / (elapsed * 1e9);

    printf("%d x %d matrix multiply, reps=%d\n", N, N, reps);
    printf("Elapsed wall time: %.6f s\n", elapsed);
    printf("GFLOPS: %.3f\n", gflops);

    free(A); free(B); free(C);
    return 0;
}

