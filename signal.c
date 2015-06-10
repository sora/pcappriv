#include "pcappriv.h"

/*
 *  set_signal
 *  @sig:
 */
void set_signal(int sig) {
	if (signal(sig, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Cannot set signal\n");
		exit(1);
	}
}

/*
 * sig_handler
 * @sig:
 */
void sig_handler(int sig) {
	if (sig == SIGINT)
		caught_signal = 1;
}

