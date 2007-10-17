/*
 * Put this here instead of including <util.h>, since Linux is messed up
 * and doesn't have <util.h>.
 */
void logwtmp(const char *_line, const char *name, const char *host);
