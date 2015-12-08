#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <syslog.h>

#include <pwd.h>

#define CODE_SIZE 16
#define MAX_CONFIG_PATH 256
#define MAX_REQ_CMD     2048
#define MAX_USERNAME 256

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS ;
}


/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
	int retval ;
	struct pam_conv *conv ;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ;
	if( retval==PAM_SUCCESS ) {
		retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
	}

	return retval ;
}

/* system() replacement */
int _pam_system(char * const *argv) {
    char *envp[] = { NULL };
    volatile int childerr;
    pid_t pid;
    int status = 0;

    	/*
	 * Fork and run the command.  By using vfork() instead of fork(),
	 * we can distinguish between an execve() failure and a non-zero
	 * exit code from the command.
	 */
	childerr = 0;
	if ((pid = vfork()) == 0) {
                struct passwd *pwd_nobody;
		/*LINTED const cast*/
                chdir("/tmp");

                if ((pwd_nobody = getpwnam("nobody")) == NULL)
                  _exit(1);
                
             if (initgroups(pwd_nobody->pw_name, pwd_nobody->pw_gid) != 0 ||
               setgid(pwd_nobody->pw_gid) != 0 || setuid(pwd_nobody->pw_uid) != 0) {
                    _exit(1);
            }

		execve(argv[0], (char * const *)argv, envp);
		childerr = errno;
		_exit(1);
	}
	if (pid == -1) {
		syslog(LOG_ERR, "pam:system:vfork(): %s", strerror(errno));
		return (PAM_SYSTEM_ERR);
	}
	if (waitpid(pid, &status, 0) == -1) {
		syslog(LOG_ERR, "pam:system:waitpid(): %s", strerror(errno));
		return (PAM_SYSTEM_ERR);
	}
	if (childerr != 0) {
		syslog(PAM_LOG_ERROR, "pam:system:execve(): %s", strerror(errno));
		return (PAM_SYSTEM_ERR);
	}
	return PAM_SUCCESS ;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval ;
	int i ;

	/* these guys will be used by converse() */
	char *input ;
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;

	/* retrieving parameters */
	int got_config_file  = 0 ;
	int got_code_size = 0 ;

	unsigned int code_size = CODE_SIZE ;
	char config_file[MAX_CONFIG_PATH] ;

        memset(config_file, 0, MAX_CONFIG_PATH);

	for( i=0 ; i<argc ; i++ ) {
		if( strncmp(argv[i], "config=", 7)==0 ) {
			strncpy( config_file, argv[i]+7, MAX_CONFIG_PATH ) ;
			got_config_file = 1 ;
		} else if( strncmp(argv[i], "code_size=", 10)==0 ) {
			char temp[4] ;
                        memset(temp, 0, 4);
			strncpy( temp, argv[i]+10, 3 ) ;
			code_size = atoi( temp ) ;
                        if (code_size >= CODE_SIZE) {
                                code_size = CODE_SIZE ;
                        }
			got_code_size = 1 ;
                }
	}
	if( got_config_file==0 || got_code_size==0 )
		return PAM_AUTH_ERR ;

	const char *username ;
	struct passwd *pwd;

	/* identify & validate username */

    if ((retval = pam_get_user(pamh, &username, "login: ")) != PAM_SUCCESS)
                  return (retval);

    if ((pwd = getpwnam(username)) == NULL)
                  return (PAM_USER_UNKNOWN);


	/* generating a random one-time code */
	char code[CODE_SIZE+1] ;
        char hex_code[CODE_SIZE*2+1];

        memset(hex_code, 0, CODE_SIZE*2+1);

        FILE *urandom = fopen( "/dev/random", "r" ) ;
	fread( &code, sizeof(char), code_size, urandom ) ;
	fclose( urandom ) ;
        for (i=0;i<code_size;i++) {
            snprintf(hex_code+i*2,3,"%02x",(unsigned char) code[i]);
        }

	/* building URL */
        // char url_with_params[strlen(base_url) + strlen("?username=") + strlen(username) + strlen("&code=") + code_size] ;
        char cmd[MAX_REQ_CMD] ;
        const char *sms_argv[5];

        memset(cmd, 0, MAX_REQ_CMD);
	strcpy( cmd, "/usr/local/bin/sendcode" ) ;
        
        //syslog(LOG_ERR, "send sms using %s ", cmd);
        sms_argv[0] = cmd;
        sms_argv[1] = config_file;
        sms_argv[2] = username;
        sms_argv[3] = hex_code;
        sms_argv[4] = NULL;

        _pam_system((char* const *)sms_argv);

	/* setting up conversation call prompting for one-time code */
        char prompt_str[64]; // hold 1=time code (xxxxxx):
        memset(prompt_str,0,64);
	strcpy(prompt_str,"1-time code (");
        strncat(prompt_str,hex_code,1);
        for (int i=0;i<code_size*2-1;i++) {
		strcat(prompt_str,"X");
	}
        strcat(prompt_str,"):");

	pmsg[0] = &msg[0] ;
	msg[0].msg_style = PAM_PROMPT_ECHO_ON ;
	//msg[0].msg = "1-time code: " ;
	msg[0].msg = prompt_str ;
	resp = NULL ;
	if( (retval = converse(pamh, 1 , pmsg, &resp))!=PAM_SUCCESS ) {
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return retval ;
	}

	/* retrieving user input */
	if( resp ) {
		if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
	    		free( resp );
	    		return PAM_AUTH_ERR;
		}
		input = resp[ 0 ].resp;
		resp[ 0 ].resp = NULL;
    	} else {
		return PAM_CONV_ERR;
	}

	/* comparing user input with known code */
	if( strcmp(input, hex_code)==0 ) {
		/* good to go! */
		free( input ) ;
		return PAM_SUCCESS ;
	} else {
		/* wrong code */
		free( input ) ;
		return PAM_AUTH_ERR ;
	}
	/* we shouldn't read this point, but if we do, we might as well return something bad */
	return PAM_AUTH_ERR ;
}
