/****************************
Author: Riad Nageh
Date: 19/08/2025
Version: 1.0
*****************************/

#include "../include/packet_parser.h"


// Use this simple approach - perfect for signal handlers
static volatile sig_atomic_t keep_running = 1;

void sigint_handler(int sig) {
    (void)sig;
    printf("\nSIGINT received. Shutting down gracefully...\n");
    pcap_close(handle);
    keep_running = 0;
}

int main(int argc, char **argv)
{
    struct itimerval timer;
    
    // Set up signal handler
    signal(SIGALRM, timer_handler);


    timer.it_value.tv_sec = _Time;      // First expiration after 5 seconds
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = _Time;   // Subsequent intervals of 5 seconds
    timer.it_interval.tv_usec = 0;

    // Set the timer
    setitimer(ITIMER_REAL, &timer, NULL);

    // Signal handler setup
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "Error: Cannot set SIGINT handler.\n");
        return EXIT_FAILURE;
    }

/* check for capture device name on command-line */
            // Parse command line arguments
    	for (int i = 1; i < argc; i++) {
        	if (strcmp(argv[i], "-i") == 0) {
            		if (i + 1 < argc) {
                		strcpy(dev,argv[++i]);
            		} else {
                		fprintf(stderr, "Error: -i requires a Device name\n");
                		return 1;
           		 }
		}
		        // Optional argument with default
	        else if (strcmp(argv[i], "-f") == 0) {
        	    if (i + 1 < argc && argv[i + 1][0] != '-') {
                	strcpy(filter_exp,argv[++i]);
            	    }	
        	}
       	 // Optional numeric argument
        	else if (strcmp(argv[i], "-t") == 0) {
            		if (i + 1 < argc && argv[i + 1][0] != '-') {
                	_Time = atoi(argv[++i]);
			    // Configure the timer
			    timer.it_value.tv_sec = _Time;      // First expiration after 5 seconds
    			    timer.it_value.tv_usec = 0;
 			    timer.it_interval.tv_sec = _Time;   // Subsequent intervals of 5 seconds
    			    timer.it_interval.tv_usec = 0;
			    setitimer(ITIMER_REAL, &timer, NULL);


			}
            		
        	}

	
	}

    while (keep_running) {
        // Do other work
	get_packet_protocol(packet);
    }
return EXIT_SUCCESS;
}
