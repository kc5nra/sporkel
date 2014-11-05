#ifndef bscommon_H
#define bscommon_H

#ifdef HAVE_ERR
# include <err.h>
#else
# include <errno.h>
# include <string.h>
# define warnx(...) do {\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, "\n"); } while (0)
# define errx(eval, ...) do {\
    warnx(__VA_ARGS__);\
    exit(eval); } while (0)
# define warn(...) do {\
    fprintf(stderr, "%s: ", strerror(errno));\
    warnx(__VA_ARGS__); } while (0)
# define err(eval, ...) do {\
    warn(__VA_ARGS__);\
    exit(eval); } while (0)
#endif /* HAVE_ERR */

int bsdiff(int argc, const char *argv[]);
int bspatch(int argc, const char *argv[]);

#endif
