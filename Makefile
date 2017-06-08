# Make file for the PAM authentication module.

# Default pseudo target.
all: pamauth

# Release with switches disabled and no debug.
release: pamauth.c
	gcc -o pamauth pamauth.c -lpam -DDISABLESWITCHES=1

# PAM authentication executable.
pamauth: pamauth.c
	gcc -g -o pamauth pamauth.c -lpam

# Cleanup.
clean:
	rm -f pamauth
	rm -f core
	rm -f core.*
	rm -rf pamauth.dSYM

distclean: clean

