
/* rlogind.c */
void fatal(int f, const char *msg, int syserr);

/* network.c */
char *network_init(int fd, int *hostokp);
void network_confirm(void);
void network_anticonfirm(void);
void network_close(void);

/* auth.c */
void auth_checkoptions(void);
void auth_finish(void);
int auth_checkauth(const char *remoteuser, const char *host,
		   char *localuser, size_t localusermaxsize);

/* 
 * Global flag variables 
 */

/* Do paranoid DNS confirmation on all hosts? */
extern int check_all;

/* Use TCP keepalive messages on connection? */
extern int keepalive;

/* Check ~/.rhosts? */
extern int use_rhosts;

/* Check ~root/.rhosts? */
extern int allow_root_rhosts;

/* Ignore all ~/.rhosts and /etc/hosts_equiv? */
extern int deny_all_rhosts_hequiv;
