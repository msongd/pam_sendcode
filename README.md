# pam_sendcode
pam module to send code using external progs &amp; confirm code

shameless copy code from http://ben.akrin.com/?p=1068, pam_unix.c, pam_exec.c etc.

compile:under FreeBSD: (Linux should replace clang with gcc)

$ clang -fPic -c pam_sendcode.c
$ ld -x --shared -o pam_sendcode.so pam_sendcode.o

copy pam_sendcode.so to /usr/local/lib

modify /etc/pam.d/sshd, replace pam_unix.so line with

auth  required  /usr/local/lib/pam_sendcode.so config=arg1 code_size=3

explain:
* everytime sshd request authen, pam_sendcode will run"/usr/local/bin/sendcode arg1 username random_code". When user enter correct random_code, it will success. sendcode is an external prog to send mail/sms or whatever to user. sendcode is executed under 'nobody' account.
* this requires sshd_config ChallengeResponseAuthentication set to yes & AuthenticationMethods keyboard-interactive:pam (if use with PubkeyAuthentication
