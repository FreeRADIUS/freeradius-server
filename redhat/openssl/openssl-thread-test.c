/* Test program to verify that RSA signing is thread-safe in OpenSSL. */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

/* Just assume we want to do engine stuff if we're using 0.9.6b or
 * higher. This assumption is only valid for versions bundled with RHL. */
#if OPENSSL_VERSION_NUMBER  >= 0x0090602fL
#include <openssl/engine.h>
#define USE_ENGINE
#endif

#define MAX_THREAD_COUNT	10000
#define ITERATION_COUNT		10
#define MAIN_COUNT		100

/* OpenSSL requires us to provide thread ID and locking primitives. */
pthread_mutex_t *mutex_locks = NULL;
static unsigned long
thread_id_cb(void)
{
	return (unsigned long) pthread_self();
}
static void
lock_cb(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&mutex_locks[n]);
	} else {
		pthread_mutex_unlock(&mutex_locks[n]);
	}
}

struct thread_args {
	RSA *rsa;
	int digest_type;
	unsigned char *digest;
	unsigned int digest_len;
	unsigned char *signature;
	unsigned int signature_len;
	pthread_t main_thread;
};

static int print = 0;

pthread_mutex_t sign_lock = PTHREAD_MUTEX_INITIALIZER;
static int locked_sign = 0;
static void SIGN_LOCK() {if (locked_sign) pthread_mutex_lock(&sign_lock);}
static void SIGN_UNLOCK() {if (locked_sign) pthread_mutex_unlock(&sign_lock);}

pthread_mutex_t verify_lock = PTHREAD_MUTEX_INITIALIZER;
static int locked_verify = 0;
static void VERIFY_LOCK() {if (locked_verify) pthread_mutex_lock(&verify_lock);}
static void VERIFY_UNLOCK() {if (locked_verify) pthread_mutex_unlock(&verify_lock);}

pthread_mutex_t failure_count_lock = PTHREAD_MUTEX_INITIALIZER;
long failure_count = 0;
static void
failure()
{
	pthread_mutex_lock(&failure_count_lock);
	failure_count++;
	pthread_mutex_unlock(&failure_count_lock);
}

static void *
thread_main(void *argp)
{
	struct thread_args *args = argp;
	unsigned char *signature;
	unsigned int signature_len, signature_alloc_len;
	int ret, i;

	signature_alloc_len = args->signature_len;
	if (RSA_size(args->rsa) > signature_alloc_len) {
		signature_alloc_len = RSA_size(args->rsa);
	}
	signature = malloc(signature_alloc_len);
	if (signature == NULL) {
		fprintf(stderr, "Skipping checks in thread %lu -- %s.\n",
			(unsigned long) pthread_self(), strerror(errno));
		pthread_exit(0);
		return NULL;
	}
	for (i = 0; i < ITERATION_COUNT; i++) {
		signature_len = signature_alloc_len;
		SIGN_LOCK();
		ret = RSA_check_key(args->rsa);
		ERR_print_errors_fp(stdout);
		if (ret != 1) {
			failure();
			break;
		}
		ret = RSA_sign(args->digest_type,
			       args->digest,
			       args->digest_len,
			       signature, &signature_len,
			       args->rsa);
		SIGN_UNLOCK();
		ERR_print_errors_fp(stdout);
		if (ret != 1) {
			failure();
			break;
		}

		VERIFY_LOCK();
		ret = RSA_verify(args->digest_type,
			         args->digest,
			         args->digest_len,
			         signature, signature_len,
			         args->rsa);
		VERIFY_UNLOCK();
		if (ret != 1) {
			fprintf(stderr,
				"Signature from thread %lu(%d) fails "
				"verification (passed in thread #%lu)!\n",
				(long) pthread_self(), i,
				(long) args->main_thread);
			ERR_print_errors_fp(stdout);
			failure();
			continue;
		}
		if (print) {
			fprintf(stderr, ">%d\n", i);
		}
	}
	free(signature);

	pthread_exit(0);

	return NULL;
}

unsigned char *
xmemdup(unsigned char *s, size_t len)
{
	unsigned char *r;
	r = malloc(len);
	if (r == NULL) {
		fprintf(stderr, "Out of memory.\n");
		ERR_print_errors_fp(stdout);
		assert(r != NULL);
	}
	memcpy(r, s, len);
	return r;
}

int
main(int argc, char **argv)
{
	RSA *rsa;
	MD5_CTX md5;
	int fd, i;
	pthread_t threads[MAX_THREAD_COUNT];
	int thread_count = 1000;
	unsigned char *message, *digest;
	unsigned int message_len, digest_len;
	unsigned char *correct_signature;
	unsigned int correct_siglen, ret;
	struct thread_args master_args, *args;
	int sync = 0, seed = 0;
	int again = 1;
#ifdef USE_ENGINE
	char *engine = NULL;
	ENGINE *e = NULL;
#endif

	pthread_mutex_init(&failure_count_lock, NULL);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--seed") == 0) {
			printf("Seeding PRNG.\n");
			seed++;
		} else
		if (strcmp(argv[i], "--sync") == 0) {
			printf("Running synchronized.\n");
			sync++;
		} else
		if ((strcmp(argv[i], "--threads") == 0) && (i < argc - 1)) {
			i++;
			thread_count = atol(argv[i]);
			if (thread_count > MAX_THREAD_COUNT) {
				thread_count = MAX_THREAD_COUNT;
			}
			printf("Starting %d threads.\n", thread_count);
			sync++;
		} else
		if (strcmp(argv[i], "--sign") == 0) {
			printf("Locking signing.\n");
			locked_sign++;
		} else
		if (strcmp(argv[i], "--verify") == 0) {
			printf("Locking verifies.\n");
			locked_verify++;
		} else
		if (strcmp(argv[i], "--print") == 0) {
			printf("Tracing.\n");
			print++;
#ifdef USE_ENGINE
		} else
		if ((strcmp(argv[i], "--engine") == 0) && (i < argc - 1)) {
			printf("Using engine \"%s\".\n", argv[i + 1]);
			engine = argv[i + 1];
			i++;
#endif
		} else {
			printf("Bad argument: %s\n", argv[i]);
			return 1;
		}
	}

	/* Get some random data to sign. */
	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Error opening /dev/urandom: %s\n",
			strerror(errno));
	}

	if (print) {
		fprintf(stderr, "Reading random data.\n");
	}
	message = malloc(message_len = 9371);
	read(fd, message, message_len);
	close(fd);

	/* Initialize the SSL library and set up thread-safe locking. */
	ERR_load_crypto_strings();
	SSL_library_init();
	mutex_locks = malloc(sizeof(pthread_mutex_t) * CRYPTO_num_locks());
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&mutex_locks[i], NULL);
	}
	CRYPTO_set_id_callback(thread_id_cb);
	CRYPTO_set_locking_callback(lock_cb);
	ERR_print_errors_fp(stdout);

	/* Seed the PRNG if we were asked to do so. */
	if (seed) {
		if (print) {
			fprintf(stderr, "Seeding PRNG.\n");
		}
		RAND_add(message, message_len, message_len);
		ERR_print_errors_fp(stdout);
	}

	/* Turn on a hardware crypto device if asked to do so. */
#ifdef USE_ENGINE
	if (engine) {
#if OPENSSL_VERSION_NUMBER  >= 0x0090700fL
		ENGINE_load_builtin_engines();
#endif
		if (print) {
			fprintf(stderr, "Initializing \"%s\" engine.\n",
				engine);
		}
		e = ENGINE_by_id(engine);
		ERR_print_errors_fp(stdout);
		if (e) {
			i = ENGINE_init(e);
			ERR_print_errors_fp(stdout);
			i = ENGINE_set_default_RSA(e);
			ERR_print_errors_fp(stdout);
		}
	}
#endif

	/* Compute the digest for the signature. */
	if (print) {
		fprintf(stderr, "Computing digest.\n");
	}
	digest = malloc(digest_len = MD5_DIGEST_LENGTH);
	MD5_Init(&md5);
	MD5_Update(&md5, message, message_len);
	MD5_Final(digest, &md5);

	/* Generate a signing key. */
	if (print) {
		fprintf(stderr, "Generating key.\n");
	}
	rsa = RSA_generate_key(4096, 3, NULL, NULL);
	ERR_print_errors_fp(stdout);
	if (rsa == NULL) {
		_exit(1);
	}

	/* Sign the data. */
	correct_siglen = RSA_size(rsa);
	correct_signature = malloc(correct_siglen);
	for (i = 0; i < MAIN_COUNT; i++) {
		if (print) {
			fprintf(stderr, "Signing data (%d).\n", i);
		}
		ret = RSA_check_key(rsa);
		ERR_print_errors_fp(stdout);
		if (ret != 1) {
			failure();
		}
		correct_siglen = RSA_size(rsa);
		ret = RSA_sign(NID_md5, digest, digest_len,
			       correct_signature, &correct_siglen,
			       rsa);
		ERR_print_errors_fp(stdout);
		if (ret != 1) {
			_exit(2);
		}
		if (print) {
			fprintf(stderr, "Verifying data (%d).\n", i);
		}
		ret = RSA_verify(NID_md5, digest, digest_len,
			         correct_signature, correct_siglen,
			         rsa);
		if (ret != 1) {
			_exit(2);
		}
	}

	/* Collect up the inforamtion which other threads will need for
	 * comparing their signature results with ours. */
	master_args.rsa = rsa;
	master_args.digest_type = NID_md5;
	master_args.digest = digest;
	master_args.digest_len = digest_len;
	master_args.signature = correct_signature;
	master_args.signature_len = correct_siglen;
	master_args.main_thread = pthread_self();
	
	fprintf(stdout, "Performing %d signatures in each of %d threads "
		"(%d, %d).\n", ITERATION_COUNT, thread_count,
		digest_len, correct_siglen);
	fflush(NULL);

	/* Start up all of the threads. */
	for (i = 0; i < thread_count; i++) {
		args = malloc(sizeof(struct thread_args));
		args->rsa = RSAPrivateKey_dup(master_args.rsa);
		args->digest_type = master_args.digest_type;
		args->digest_len = master_args.digest_len;
		args->digest = xmemdup(master_args.digest, args->digest_len);
		args->signature_len = master_args.signature_len;
		args->signature = xmemdup(master_args.signature,
					  args->signature_len);
		args->main_thread = pthread_self();
		ret = pthread_create(&threads[i], NULL, thread_main, args);
		while ((ret != 0) && (errno == EAGAIN)) {
			ret = pthread_create(&threads[i], NULL,
					     thread_main, &args);
			fprintf(stderr, "Thread limit hit at %d.\n", i);
		}
		if (ret != 0) {
			fprintf(stderr, "Unable to create thread %d: %s.\n",
				i, strerror(errno));
			threads[i] = -1;
		} else {
			if (sync) {
				ret = pthread_join(threads[i], NULL);
				assert(ret == 0);
			}
			if (print) {
				fprintf(stderr, "%d\n", i);
			}
		}
	}

	/* Wait for all threads to complete.  So long as we can find an
	 * unjoined thread, keep joining threads. */
	do {
		again = 0;
		for (i = 0; i < thread_count; i++) {
			/* If we have an unterminated thread, join it. */
			if (threads[i] != -1) {
				again = 1;
				if (print) {
					fprintf(stderr, "Joining thread %d.\n",
						i);
				}
				pthread_join(threads[i], NULL);
				threads[i] = -1;
				break;
			}
		}
	} while (again == 1);

	fprintf(stderr, "%ld failures\n", failure_count);

	return (failure_count != 0);
}
