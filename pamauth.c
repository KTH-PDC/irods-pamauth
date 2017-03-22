
/* PAM authentication module. */

/* System includes. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

/* For PAM. */
#include <sys/types.h>
#include <security/pam_appl.h>

/* Exit codes. */
#define SUCCESS ((int) 0)
#define FAILURE ((int) -1)

/* Boolean. */
typedef signed int boolean;

/* Boolean values. */
#define true ((int) 1)
#define false ((int) 0)

/* Password. */
#define MAX_PASSWORD ((int) 255)

/* Globals. */

/* Debug level. */
static int debug;

/* Error exit. */

static void
err (int rc, char *format, ...)
{
	va_list args;

	/* Report error on stderr and exit. */
	va_start (args, format);
	(void) vfprintf (stderr, format, args);
	(void) fprintf (stderr, "\n");
	(void) fflush (stderr);
	va_end (args);
	exit (rc);
}

/* Print message. */

static void
msg (char *format, ...)
{
	va_list args;

	/* Print message on stdout with new line. */
	va_start (args, format);
	(void) vfprintf (stdout, format, args);
	(void) fprintf (stdout, "\n");
	(void) fflush (stdout);
	va_end (args);
}

/* Allocate with check. */

static void *
allocate (size_t s)
{
	void *r;

	r = malloc (s);
	if (r == NULL)
	{
		err (FAILURE, "Cannot allocate %llu bytes", s);
	}
	return (r);
}

/* Macro to allocate memory. */
#define new(t) ((t *) allocate (sizeof (t)))

/* Null conversation function. */

static int
null_conv (int nmsg, const struct pam_message **msgs,
	struct pam_response **resp, void *appd)
{
	char *password;
	struct pam_response *r;
	int i;
	struct pam_message *m;

	/* This function is a callback function to be used during the
	   authentication conversation. */

	/* Password passed down via the application data pointer. */
	password = (char *) appd;

	/* Check. */
	if (nmsg <= 0 || nmsg >= PAM_MAX_NUM_MSG)
	{
		*resp = NULL;
		return (PAM_CONV_ERR);
	}
	if (appd == NULL)
	{

		/* Actually this will never return. */
		err (FAILURE, "PAM conversation - appd not supplied");
		*resp = NULL;
		return (PAM_SYSTEM_ERR);
	}

	/* Allocate response. */
	r = (struct pam_response *) malloc (nmsg * sizeof (struct pam_response));
	if (r == NULL)
	{
		*resp = NULL;
		return (PAM_BUF_ERR);
	}
	if (debug > 5)
	{
		msg ("Enter conversation, %d message(s)", nmsg);
	}

	/* Process responses. */
	for (i=0; i<nmsg; i++)
	{
		m = (struct pam_message *) msgs[i];

		/* Report error when not a password. */
		switch (m->msg_style)
		{

			/* Password read, here we send the OTC string. */
			case PAM_PROMPT_ECHO_OFF:
				if (debug > 5)
				{
					msg ("PAM_PROMPT_ECHO_OFF");
				}
				break;
			case PAM_PROMPT_ECHO_ON:
				if (debug > 5)
				{
					msg ("PAM_PROMPT_ECHO_ON");
				}
				break;

			/* Error cases. */
			case PAM_ERROR_MSG:
				if (debug > 5)
				{
					msg ("PAM_ERROR_MSG - error return");
				}
				*resp = NULL;
				return (PAM_CONV_ERR);
				break;
			case PAM_TEXT_INFO:
				if (debug > 5)
				{
					msg ("PAM_TEXT_INFO - error return");
				}
				*resp = NULL;
				return (PAM_CONV_ERR);
				break;
			default:
				err (FAILURE, "PAM conversation - invalid style, exiting");
				break;
		}

		/* Fallen through so fill in password from appdata. */
		r[i].resp = strdup (password);
		r[i].resp_retcode = 0;
		if (debug > 5)
		{
			msg ("msg %d response %s", i, r[i].resp);
		}
	}

	/* Return the response. We assume PAM will release memory. */
	*resp = r;
	if (debug > 5)
	{
		msg ("Finish conversation with PAM_SUCCESS");
	}
	return (PAM_SUCCESS);
}

/* PAM authenticate with password. */

static boolean
pamauth (char *service, char *username, char *password)
{
	int status;
	struct pam_conv *conv;
	pam_handle_t *pamh;
	int endstatus;
	int r;
	char *errormsg;

	/* Create conversion info block and fill. */
	conv = new (struct pam_conv);
	conv->conv = null_conv;
	conv->appdata_ptr = password;

	/* Start. */
	status = pam_start (service, username, conv, &pamh);
	if (status != PAM_SUCCESS)
	{
		err (3, "PamAuthCheck: pam_start error");
	}
	if (debug > 5)
	{
		msg ("pam_start status %d", status);
	}

	/* Set global password and authenticate. */
	r = false;
	status = pam_authenticate (pamh, 0);
	if (debug > 5)
	{
		msg ("pam_authenticate status %d", status);
	}
	if (status == PAM_SUCCESS)
	{

		/* Success. */
		if (debug > 5)
		{
				msg ("PAM_SUCCESS");
		}
		r = true;
		msg ("Authenticated");
	}
	else
	{

		/* Failure. */
		if (debug > 5)
		{
			switch (status)
			{
			case PAM_SUCCESS:
				msg ("PAM_SUCCESS - confused");
				break;
			case PAM_ABORT:
				msg ("PAM_ABORT");
				break;
			case PAM_AUTH_ERR:
				msg ("PAM_AUTH_ERR");
				break;
			case PAM_CRED_INSUFFICIENT:
				msg ("PAM_CRED_INSUFFICIENT");
				break;
			case PAM_AUTHINFO_UNAVAIL:
				msg ("PAM_AUTHINFO_UNAVAIL");
				break;
			case PAM_MAXTRIES:
				msg ("PAM_MAXTRIES");
				break;
			case PAM_USER_UNKNOWN:
				msg ("PAM_USER_UNKNOWN");
				break;
			case PAM_PERM_DENIED:
				msg ("PAM_PERM_DENIED");
				break;
			default:
				msg ("default");
				break;
			}
			errormsg = (char *) pam_strerror (pamh, status);
			if (errormsg != NULL)
			{
				msg ("Authentication failure '%s'", errormsg);
			}
			else
			{
				msg ("Cannot retrieve error message %d", status);
			}
		}
		r = false;
		msg ("Not Authenticated");
	}

	/* Finish with PAM. */
	endstatus = pam_end (pamh, status);
	if (endstatus != PAM_SUCCESS)
	{
		err (5, "PamAuthCheck: failed to release authenticator");
	}
	if (debug > 5)
	{
		msg ("pam_end status %d", endstatus);
	}

	/* Return boolean result. */
	free (conv);
	return (r);
}

/* Print help text. */

static void
print_help (void)
{
	(void) fprintf (stdout, "\
This program is the PAM authenticator.\n\
Usage:\n\
    PamAuthCheck [-h][-d n] username\n\
where\n\
    -h              prints this help.\n\
    -s name         authentication service name.\n\
    -d n            sets debug level.\n\
    username        is the username to be authenticated.\n\
The password is taken from the standard input\n\
The program will use the stanzas in 'irods', that is the\n\
content of file 'irods' in /etc/pam.d. It will respond with\n\
output 'Authenticated' or 'Not Authenticated' accordingly.\n\
");
    exit (FAILURE);
}

/* Main.*/

int
main (int argc, char *argv[])
{

	/* Option characters and control string. */
	int ch;
	char *options = "d:hs:";

	/* Username and password. */
	char *username;
	char *password;

	/* PAM service name, the file in /etc/pam.d. */
	char *service;

	/* Input file buffer. */
	char buf[MAX_PASSWORD];

	/* Buffer length to use, one less to leave space for the terminating \0. */
	size_t buflen;

	/* Number of bytes read. */
	ssize_t status;

	/* End of line marker. New line or return. */
	char *endofline;

	/* Authentication result. */
	boolean passed;

	/* Deal with options. */
	debug = 0;
	service = "irods";
	ch = getopt (argc, argv, options);
	while (ch != EOF)
	{
		switch (ch)
		{
		case 'd':

			/* Set debug level. Zero if malformed. */
			debug = atoi (optarg);
			break;
		case 'h':

			/* Help. */
			print_help ();
			break;
		case 's':

			/* Authentication service name specified. */
			service = optarg;
			break;
		}
		ch = getopt (argc, argv, options);
	}

	/* Get the username. */
	if (optind < argc)
	{

		/* First argument is the username. */
		username = argv[optind];
		optind++;
	}
	else
	{

		/* There was no argument. */
		err (FAILURE, "Specify username");
	}

	/* Make sure we got a zero char at the end. */
	(void) memset (buf, 0, MAX_PASSWORD);
	buf[MAX_PASSWORD] = '\0';
	buflen = (size_t) (MAX_PASSWORD - 1);

	/* Get password from stdin. */
	status = read (0, buf, buflen);
	if (status < (ssize_t) 0)
	{

		/* Read error. */
		err (FAILURE, "Password read error (%d)", errno);
	}
	else if (status < (ssize_t) buflen)
	{

		/* Transform it to C string. New line and return is the end of line. */
		endofline = strchr (buf, '\n');
		if (endofline != NULL)
		{
			*endofline = '\0';
		}
		endofline = strchr (buf, '\r');
		if (endofline != NULL)
		{
			*endofline = '\0';
		}

		/* We got the password. */
		password = (char *) buf;
	}
	else
	{

		/* Password was too long, bail out. */
		err (FAILURE, "Password too long (%ld)", status);
	}

	/* Show what we got. */
	if (debug > 5)
	{
		msg ("debug level %d", debug);
		msg ("%ld bytes read buflen %ld buf '%s'", status, buflen, buf);
		msg ("'%s' '%s' '%s'", service, username, password);
	}

	/* PAM authenticate. */
	passed = pamauth (service, username, password);
	if (debug > 5)
	{
		msg ("pamauth returned %d", passed);
	}

	/* Finish. */
	if (passed)
	{

		/* Success. */
		if (debug > 5)
		{
			msg ("Finishing with success");
		}
		exit (SUCCESS);
	}
	else
	{

		/* Failure. */
		if (debug > 5)
		{
			msg ("Finishing with failure");
		}
		exit (FAILURE);
	}
}

