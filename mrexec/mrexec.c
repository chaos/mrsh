
/*

  rexec.c -- Copyright 1996 by Michael Sadd (sadd@msc.cornell.edu)

  Version 1.1  Sept. 12 1996

  Permission is given to freely distribute this program
  provided this source is included and this copyright notice and
  header remain.

  This program calls the system rexec subroutine to 
  act as a rexec client.

  Please report bugs and system incompatibilities to me.

  I have compiled this under Linux 2.0.18, libc5.3.12 and gcc2.7.2, as well
  as under AIX 3.2 and 4.1 using gcc.  It is meant for Linux, however,
  and should be portable to other systems.  Please let me know if there
  are problems.
  
  Usage: rexec [ -a -c -d -h -n -s ] [--] host command
     -a: Do not set up an auxiliary channel for standard error from command;
         the remote standard error and output are then both returned on the
         local standard output.
     -c: Do not close remote standard input when local standard input closes.
     -d: Turn on debugging information.
     -h: Print this usage message.
     -n: Explicitly prompt for name and password.  Otherwise,
         $HOME/.netrc will be scanned for login information.
     -s: Do not echo signals received by the rexec onto the remote
         process.  Normally, signals which can be trapped are passed
         on to the remote process; then, when you type CNTRL-C, the remote
         process terminates as well.
     --: Signals end of options to allow options in `command`


  Example:

  ~/bin@athens% rexec othermachine -- cat ">remote_file; date" <local_file 
  Fri Sep 13 02:25:20 EDT 1996
  
  Here my password and user name are set up in $HOME/.netrc.

  The only option that is very useful is -n; even then, if you haven't
  set up a password in $HOME/.netrc, you should still be prompted.

  */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "../version.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#ifndef FD_SETSIZE
#include <sys/select.h>
#endif

#define DEFAULT_PORT 512
#define MAX_PORT IPPORT_RESERVED
#define EXTRA_PORT_LOW IPPORT_USERRESERVED
#define EXTRA_PORT_MAX (EXTRA_PORT_LOW + 10000)
#define BUFLEN 512
#ifndef EAGAIN
#ifdef EWOULDBLOCK
#define EAGAIN EWOULDBLOCK
#else
#define EAGAIN 0
#endif
#endif
#ifdef _PASSWORD_LEN
#define USERLEN _PASSWORD_LEN
#else 
#define USERLEN 256
#endif

void parse_options(char *argv[], int argc, int *debug, int *extra_error,
		   int *close_on_stdin, int *prompt, int *pass_sig,
		   char **host, char **command);
void usage(char *name);
int echo_fd(int fd_to, int fd_from, char *prog_name, int debug);
void set_signals(void);
void echo_sig(int sig);

/* These need to be global for signal passing. */
int aux_sock; /* Socket for auxiliary channel. */
int extra_error = 1; /* Setup special channel for standard error? */

int main(int argc, char *argv[])
{
  
  /* Program options and parameters. */
  int debug = 0;  /* Turn on debugging info? */
  int prompt = 0; /* Prompt for name and password? */
  int close_on_stdin = 1; /* Close socket on stdin, not on remote host. */
  int pass_sig = 1; /* Should we pass signals to the remote process? */
  char *host; /* Host name of remote machine. */
  char *command; /* Command string to be executed on remote machine. */
  /* Other variables. */
  char *user_name = NULL, *passwd = NULL, user_buf[USERLEN];
  struct servent *service; /* Returned from service datata base, give port. */
  int port_exec; /* Rexec port to use. */
  int sock; /* Rexec socket. */
  int *p_to_aux_sock; /* Pointer to socket for auxiliary channel. */
  int sock_open, stdin_open, aux_open, shut_down; /* Open file descriptor flags. */

  parse_options(argv, argc, &debug, &extra_error, &close_on_stdin, &prompt,
		&pass_sig, &host, &command);

  service = getservbyname("exec","tcp");
  if ( (port_exec = service->s_port) >= MAX_PORT )
  {
    if (debug)
    {
      fprintf(stderr,"%s: getservbyname returned port %d\n",argv[0],
	      ntohs(port_exec));
      fprintf(stderr,"Using default port number %d instead.\n",DEFAULT_PORT);
    }
    port_exec = htons(DEFAULT_PORT);
  }
  
  if ( extra_error )
  {
    int port_extra; /* Auxiliary port number. */
    struct sockaddr_in aux_name; /* Auxilliary socket name for bind. */
    int found_port = 0;

    if (debug)
      fprintf(stderr,"%s: Attempting to allocate channel for remote "
	      "standard error\n", argv[0]);
    
    if ( (aux_sock = socket(PF_INET, SOCK_STREAM , 0)) < 0)
    {
      fprintf(stderr,"%s: Error in socket call: ",argv[0]);
      perror(NULL);
      exit(1);
    }

    aux_name.sin_family = AF_INET;
    aux_name.sin_addr.s_addr = htonl(INADDR_ANY);

    for ( port_extra = EXTRA_PORT_LOW; port_extra < EXTRA_PORT_MAX; 
	  ++port_extra)
    {
      aux_name.sin_port = htons(port_extra);
      found_port = (bind(aux_sock, (struct sockaddr *) &aux_name, 
			 sizeof(aux_name)) == 0);
      if ( found_port )
	break;
      switch (errno)
      {
      case EADDRNOTAVAIL:
      case EADDRINUSE:
      case EACCES:
	if (debug) 
	{
	  fprintf(stderr,"%s: Error from bind for port No. %d: ",argv[0],
		  port_extra);
	  perror(NULL);
	  fprintf(stderr,"Will try next port...\n");
	}
	break;
      default:
	fprintf(stderr,"%s: Error binding to socket for aux. channel: ",
		argv[0]);
	perror(NULL);
	exit(1);
	break;
      }
    }
    
    if ( ! found_port )
    {
      fprintf(stderr,"%s: Could not find available port for auxiliary ",
	      argv[0]);
      fprintf(stderr,"channel in port range %d to %d.\n",EXTRA_PORT_LOW,
	      EXTRA_PORT_MAX);
      exit(1);
    }
    p_to_aux_sock = &aux_sock;
    /* listen here? */

    if (pass_sig)
      set_signals();

  }
  else /* else we just want standard error directed as standar out--no aux */
    p_to_aux_sock = NULL;

  if (prompt)
  {
    FILE *term_in,*term_out;
    
    if ( ( term_in = fopen("/dev/tty","r+")) == NULL)
    {
      term_in = stdin;
      term_out = stderr;
    }
    else
      term_out = term_in;
    fprintf(term_out,"Username at %s: ",host);
    user_name = fgets(user_buf,USERLEN,term_in);
    user_name[strlen(user_name)-1] = '\0'; /* Hopefully fgets always adds
					      a newline. */
    passwd = getpass("Password: ");
  }

  if ( (sock = rexec(&host, port_exec, user_name, passwd, command, 
		     p_to_aux_sock)) < 0 )
 {
    fprintf(stderr,"%s: Error in rexec system call: ",argv[0]);
    perror(NULL);
    exit(1);
  }

  sock_open = stdin_open = aux_open = 1;
  shut_down = 0;
  while (sock_open || ( aux_open && extra_error )) /* echo stdin -> remote host
						      remote host -> stdout
	                           until the remote host closes the socket. */
  {
    fd_set read_set;

    FD_ZERO(&read_set);
    if (stdin_open)
      FD_SET(STDIN_FILENO, &read_set);
    if (sock_open)
      FD_SET(sock, &read_set);
    if ( extra_error && aux_open )
      FD_SET(aux_sock, &read_set);


    /* Using an infinit timeout in select (last parameter = NULL). */
    if ( select(FD_SETSIZE, &read_set, NULL, NULL, NULL) < 0 )
    {
      fprintf(stderr,"%s: Error in select system call: ",argv[0]);
      perror(NULL);
      exit(1);
    }

    if ( FD_ISSET(sock, &read_set) ) /* Input available from remote host. */
      sock_open = echo_fd(STDOUT_FILENO, sock, argv[0], debug);

    if ( FD_ISSET(STDIN_FILENO, &read_set) )  /* Input available from stdin. */
      stdin_open = echo_fd(sock, STDIN_FILENO,  argv[0], debug);

    if ( extra_error && FD_ISSET(aux_sock, &read_set) )
      aux_open = echo_fd(STDERR_FILENO, aux_sock, argv[0], debug);

    if ( ! stdin_open && close_on_stdin && ! shut_down ) 
    {
      if (shutdown(sock, 1) <0)
      {
	fprintf(stderr,"%s: Error from shutdown: ",argv[0]);
	perror(NULL);
	exit(1);
      }
      shut_down = 1;
    }

  }

  return 0;
}


#define OPTIONS "dahncs"

void parse_options(char *argv[], int argc, int *debug, int *extra_error,
		   int *close_on_stdin, int *prompt, int *pass_sig,
		   char **host, char **command)
{
  int opt;
  int len = 0,ind;

  while ((opt = getopt(argc, argv, OPTIONS)) > 0)
    switch (opt)
    {
    case 'd':
      *debug = 1;
      break;
    case 'a':
      *extra_error = 0;
      break;
    case 'h':
      usage(argv[0]);
      break;
    case 'n':
      *prompt = 1;
      break;
    case 'c':
      *close_on_stdin = 0;
      break;
    case 's':
      *pass_sig = 0;
      break;
    default:
      /* fprintf(stderr,"%s: Unknown option -%c\n",argv[0],(char)optopt);*/
      usage(argv[0]);
      break;
    }
  if ( optind + 2  >  argc ) /* User must have omitted host and command. */
  {
    fprintf(stderr,"%s: Require at least a host name and command.\n",argv[0]);
    usage(argv[0]);
  }
  *host = argv[optind++];
  for ( ind = optind; ind < argc; ++ind)
    len += strlen(argv[ind])+1;
  *command = (char *) malloc((len+1)*sizeof(char));
  **command = '\0';
  for ( ind = optind; (ind < argc) && strcat(*command," "); ++ind)
    (void) strcat(*command, argv[ind]);

  if (*debug)
  {
    fprintf(stderr,"%s: Host = %s\n", argv[0], *host);
    fprintf(stderr,"%s: Command to execute = %s\n", argv[0], *command);
  }
}
      
void usage(char *name)
{
  fprintf(stderr,"Usage: %s [ -a -c -d -h -n ] [--] host command\n", name);
  fprintf(stderr,"\t-a: Do not set up an auxiliary channel for standard error\n");
  fprintf(stderr,"\t-c: Do not close remote standard in when local input closes\n");
  fprintf(stderr,"\t-d: Turn on debugging information.\n");
  fprintf(stderr,"\t-h: Print this usage message.\n");
  fprintf(stderr,"\t-n: Explicitly prompt for name and password.\n");
  fprintf(stderr,"\t-s: Do not echo signals to the remote process. \n");
  fprintf(stderr,"\t--: Signals end of options to allow options in `command`\n");
  exit(1);
}

/* Echo's available input from fd_from to fd_to.  Returns
   zero on end of file. */
int echo_fd(int fd_to, int fd_from, char *prog_name, int debug)
{
  int sock_read;
  char buffer[BUFLEN];

  (void)debug;

  if ( (sock_read = read(fd_from, buffer, BUFLEN)) < 0 )
  {
    fprintf(stderr,"%s: Error in read from remote host: ", prog_name);
    perror(NULL);
    exit(1);
  }
  
  if ( sock_read )
    write(fd_to, buffer, sock_read);

  return sock_read;
}


void set_signals(void)
{
  int sig;

  for (sig = 1; sig < NSIG; ++sig)
    signal(sig, echo_sig);
}

void echo_sig(int sig)
{
  char sigch = (char) sig;

  if (extra_error)
    write(aux_sock, &sigch, 1);

  raise(sig);
}


/*
void set_no_blocking(int fd)
{
  int old_flag = fcntl(fd, F_GETFD, 0);
  
  if (old_flag < 0)
  {
    perror("Error in fcntl(fd, F_GETFD, 0):");
    exit(1);
  }
  if ( fcntl(fd, old_flag | O_NONBLOCK) < 0 )
  {
    perror("Error in fcntl(fd, old_flag | O_NONBLOCK)");
    exit(1);
  }

}
*/
