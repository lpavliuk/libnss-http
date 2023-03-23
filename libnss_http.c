#define _GNU_SOURCE
#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>		/* read, write, close */
#include <sys/socket.h>	/* socket, connect */
#include <netinet/in.h>	/* struct sockaddr_in, struct sockaddr */
#include <netdb.h>		/* struct hostent, gethostbyname */

#define NSS_MODULE_NAME "libnss_http.so"
/* for security reasons */
#define MIN_UID_NUMBER 60000
#define MIN_GID_NUMBER 60000

#define CONF_FILE_PATH "/etc/libnss-http.conf"
#define CONFIG_SIZE 256
#define HOST_SET 1
#define PORT_SET 2
#define PASSWD_ENDPOINT_SET 4
#define SHADOW_ENDPOINT_SET 8

typedef struct config {
	unsigned char	set;
	char			host[32];
	char			port[6]; // 0 - 65535
	char			passwd_endpoint[64];
	char			shadow_endpoint[64];
} t_config;

static t_config	 	*read_conf(void);
char				**ft_strsplit(char const *s, char c);
int					get_array_length(const char **array);
static const char 	*http_request(int argc, const char **argv);

/**
 * Man: https://linux.die.net/man/3/getpwnam_r
 *
 * The UNIX function reads the local shadow password file /etc/passwd
 *
 * ### The explanation of /etc/passwd record:
 *     <USERNAME>:<PASSWORD>:<USER_ID>:<GROUP_ID>:<USER_ID_INFO>:<HOME_DIR>:<COMMAND_SHELL>
 *     - PASSWORD      : An 'x' character indicates that encrypted password is
 *                       stored in /etc/shadow file
 *     - USER_ID_INFO  : The comment field. It allow you to add extra information about
 *                       the users such as user’s full name, phone number etc.
 *     - COMMAND_SHELL : The absolute path of a command or shell (/bin/bash).
 *                       Please note that it does not have to be a shell. For example,
 *                       sysadmin can use the nologin shell, which acts as
 *                       a replacement shell for the user accounts. If shell set to
 *                       /sbin/nologin and the user tries to log in to the Linux system directly,
 *                       the /sbin/nologin shell closes the connection.
 */
enum nss_status _nss_ftp_accounts_manager_getpwnam_r(
	const char *name,
	/**
	 * struct passwd {
	 *     char    *pw_name;     : user name
	 *     char    *pw_passwd;   : encrypted password
	 *     uid_t   pw_uid;       : user uid
	 *     gid_t   pw_gid;       : user gid
	 *     time_t  pw_change;    : password change time
	 *     char    *pw_class;    : user access class
	 *     char    *pw_gecos;    : Honeywell login info
	 *     char    *pw_dir;      : home directory
	 *     char    *pw_shell;    : default shell
	 *     time_t  pw_expire;    : account expiration
	 *     int     pw_fields;    : internal: fields filled in
	 * };
	 */
	struct passwd *p,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	char		endpoint[64];
	t_config	*config;

	openlog(NSS_MODULE_NAME, LOG_PID | LOG_CONS, LOG_AUTHPRIV);

	config = read_conf();

	sprintf(endpoint, "%s/%s", config->passwd_endpoint, name);

	const char *http_argv[4] = {
		config->host,
		config->port,
		"GET",
		endpoint
	};

	const char *response_data = http_request(4, http_argv);
	if (response_data == NULL)
		return NSS_STATUS_NOTFOUND;

	char **data = ft_strsplit(response_data, ':');
	if (!data)
		return NSS_STATUS_NOTFOUND;

	if (get_array_length((const char **)data) < 7)
	{
		syslog(LOG_ERR, "Wrong response data. Should be 7 arguments! Response data: %s", response_data);
		return NSS_STATUS_NOTFOUND;
	}

	p->pw_name = data[0];
	p->pw_passwd = data[1];
	p->pw_uid = atoi(data[2]);
	p->pw_gid = atoi(data[3]);
	p->pw_dir = data[5];

	// For security reason
	if (p->pw_uid < MIN_UID_NUMBER)
		p->pw_uid = MIN_UID_NUMBER;

	if (p->pw_gid < MIN_GID_NUMBER)
		p->pw_gid = MIN_GID_NUMBER;

	syslog(LOG_INFO, "User: %s", p->pw_name);
	syslog(LOG_INFO, "UID: %d", p->pw_uid);
	syslog(LOG_INFO, "GID: %d", p->pw_gid);
	syslog(LOG_INFO, "Home Directory: %s", p->pw_dir);

	closelog();
	free(config);

	return NSS_STATUS_SUCCESS;
}


/**
 * Man: https://linux.die.net/man/3/getspnam_r
 *
 * The UNIX function reads the local shadow password file /etc/shadow
 *
 * ### The explanation of /etc/shadow record:
 *     <USERNAME>:<ENCRYPTED_PASSWORD>:<LAST_PASSWORD_CHANGE>:<MIN>:<MAX>:<WARN>:<INACTIVE>:<EXPIRE>:
 *     - LAST_PASSWORD_CHANGE : The date of the last password change, expressed as the number of
 *                              days since Jan 1, 1970 (Unix time).
 *     - MIN                  : The minimum number of days required between password changes
 *     - MAX                  : The maximum number of days the password is valid
 *     - WARN                 : The number of days before password is to expire
 *     - INACTIVE             : The number of days after password expires that account is disabled
 *     - EXPIRE               : The date of expiration of the account, expressed as the number of
 *                              days since Jan 1, 1970 (Unix time).
 */
enum nss_status _nss_ftp_accounts_manager_getspnam_r(
	const char *name,
	/**
	 * struct spwd {
	 *     char *sp_namp;          : login name
	 *     char *sp_pwdp;          : Encrypted password
	 *     long  sp_lstchg;        : date of last change
	 *                               (measured in days since
	 *                               1970-01-01 00:00:00 +0000 (UTC))
	 *     long  sp_min;           : min # of days between changes
	 *     long  sp_max;           : max # of days between changes
	 *     long  sp_warn;          : # of days before password expires
	 *                               to warn user to change it
	 *     long  sp_inact;         : # of days after password expires
	 *                               until account is disabled
	 *     long  sp_expire;        : date when account expires
	 *                               (measured in days since
	 *                               1970-01-01 00:00:00 +0000 (UTC))
	 *     unsigned long sp_flag;  : reserved
	 * };
	 */
	struct spwd *s,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	openlog(NSS_MODULE_NAME, LOG_PID | LOG_CONS, LOG_AUTHPRIV);
	syslog(LOG_INFO, "_nss_ato_getspnam_r() is not implemented, dude!");
	closelog();

	return NSS_STATUS_NOTFOUND;
}


/*
 * ============================================================================== *
 *                            PRIVATE Functions                                   *
 * ============================================================================== *
 */
// Parse the buffer for config info. Return an error code or 0 for no error.
static int			parse_config(char *buf, t_config *config)
{
	char dummy[CONFIG_SIZE];

	if (
		sscanf(buf, "%s", dummy) == EOF ||  // blank line
		sscanf(buf, "%[#]", dummy) == 1     // comment
	)
		return 0;

	if (sscanf(buf, "host = %s", config->host) == 1)
	{
		if (config->set & HOST_SET)
			return 1;

		config->set |= HOST_SET;
		return 0;
	}

	if (sscanf(buf, "port = %s", config->port) == 1)
	{
		if (config->set & PORT_SET)
			return 1;

		config->set |= PORT_SET;
		return 0;
	}

	if (sscanf(buf, "passwd_endpoint = %s", config->passwd_endpoint) == 1)
	{
		if (config->set & PASSWD_ENDPOINT_SET)
			return 1;

		config->set |= PASSWD_ENDPOINT_SET;
		return 0;
	}

	if (sscanf(buf, "shadow_endpoint = %s", config->shadow_endpoint) == 1)
	{
		if (config->set & SHADOW_ENDPOINT_SET)
			return 1;

		config->set |= SHADOW_ENDPOINT_SET;
		return 0;
	}

	return 1; // syntax error
}


static t_config		*read_conf(void)
{
	FILE		*fd;
	char		buf[CONFIG_SIZE];
	t_config	*config;

	config = (t_config *)malloc(sizeof(t_config));
	memset(config, 0, sizeof(t_config));
	config->set = 0;

	if ((fd = fopen(CONF_FILE_PATH, "r")) == NULL )
		return NULL;

	int line_number = 0;
	while (fgets(buf, sizeof buf, fd))
	{
		++line_number;

		if (parse_config(buf, config) > 0)
			syslog(LOG_ERR, "Failed to read %s: error line %d (duplicate or other)\n", CONF_FILE_PATH, line_number);
	}

	fclose(fd);

	return config;
}


// argv = [ "<HOST>", "<PORT>", "<ENDPOINT>", "<DATA>", "<HEADERS>" ]
static const char	*http_request(int argc, const char **argv)
{
	int					i,
						sockfd,
						bytes,
						sent,
						received,
						total,
						message_size,
						http_port = atoi(argv[1]) > 0 ? atoi(argv[1]) : 80;
	char				*message = NULL,
						response[4096];
	const char			*host = strlen(argv[0]) > 0 ? argv[0]: "localhost";
	struct hostent		*server = NULL;
	struct sockaddr_in	serv_addr;

	if (argc < 4)
	{
		syslog(LOG_ERR, "Wrong parameters. Required parameters: <host> <port> <method> <path> [<data> [<headers>]]");
		return (NULL);
	}

	/* How big is the message? */
	message_size = 0;
	if (!strcmp(argv[2], "GET"))
	{
		message_size += strlen("%s %s%s%s HTTP/1.0\r\n");          /* method */
		message_size += strlen(argv[2]);                           /* path */
		message_size += strlen(argv[3]);                           /* headers */

		if (argc > 4)
			message_size += strlen(argv[4]);                       /* query string */

		for (i = 5; i < argc; i++)                                 /* headers */
			message_size += strlen(argv[i]) + strlen("\r\n");

		message_size += strlen("\r\n");                            /* blank line */
	}
	else
	{
		message_size += strlen("%s %s HTTP/1.0\r\n");
		message_size += strlen(argv[2]);                           /* method */
		message_size += strlen(argv[3]);                           /* path */

		for (i = 5; i < argc; i++)                                 /* headers */
			message_size += strlen(argv[i]) + strlen("\r\n");

		if (argc > 4)
			message_size += strlen("Content-Length: %d\r\n") + 10; /* content length */

		message_size += strlen("\r\n");                            /* blank line */

		if (argc > 4)
			message_size += strlen(argv[4]);                       /* body */
	}

	/* allocate space for the message */
	message = (char *)malloc(message_size);

	/* fill in the parameters */
	if (!strcmp(argv[2], "GET"))
	{
		if (argc > 4)
			sprintf(
				message,
				"%s %s%s%s HTTP/1.0\r\n",
				strlen(argv[2]) > 0 ? argv[2] : "GET",             /* method */
				strlen(argv[3]) > 0 ? argv[3] : "/",               /* path */
				strlen(argv[4]) > 0 ? "?" : "",                    /* '?' */
				strlen(argv[4]) > 0 ? argv[4] : ""                 /* query string */
			);
		else
			sprintf(
				message,
				"%s %s HTTP/1.0\r\n",
				strlen(argv[2]) > 0 ? argv[2] : "GET",             /* method */
				strlen(argv[3]) > 0 ? argv[3] : "/"                /* path */
			);

		for (i = 5; i < argc; i++)                                 /* headers */
		{
			strcat(message, argv[i]);
			strcat(message, "\r\n");
		}

		strcat(message, "\r\n");                                   /* blank line */
	}
	else
	{
		sprintf(
			message,
			"%s %s HTTP/1.0\r\n",
			strlen(argv[2]) > 0 ? argv[2] : "POST",                /* method */
			strlen(argv[3]) > 0 ? argv[3] : "/"                    /* path */
		);

		for (i = 5; i < argc; i++)                                 /* headers */
		{
			strcat(message, argv[i]);
			strcat(message, "\r\n");
		}

		if (argc > 4)
			sprintf(message + strlen(message), "Content-Length: %lu\r\n", strlen(argv[4]));

		strcat(message, "\r\n");                                   /* blank line */

		if (argc > 4)
			strcat(message, argv[4]);                              /* body */
	}

	syslog(LOG_INFO, "Request: %s", message);

	/* create the socket */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		syslog(LOG_ERR, "Failed to open the socket");
		return (NULL);
	}

	/* lookup the ip address */
	server = gethostbyname(host);
	if (server == NULL)
		syslog(LOG_ERR, "No such %s host", host);

	/* fill in the structure */
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(http_port);
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

	/* connect the socket */
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		syslog(LOG_ERR, "Failed to connect");
		return (NULL);
	}

	/* send the request */
	total = strlen(message);
	sent = 0;
	do {
		bytes = write(sockfd, message + sent, total - sent);

		if (bytes < 0)
			syslog(LOG_ERR, "Failed to write message to socket");

		if (bytes == 0)
			break;

		sent += bytes;
	}

	while (sent < total);

	/* receive the response */
	memset(response, 0, sizeof(response));

	total = sizeof(response) - 1;
	received = 0;
	do {
		bytes = read(sockfd, response + received, total - received);

		if (bytes < 0)
			syslog(LOG_ERR, "Failed to read the response from socket");

		if (bytes == 0)
			break;

		received += bytes;
	}

	while (received < total);

	/*
	* if the number of received bytes is the total size of the
	* array then we have run out of space to store the response
	* and it hasn't all arrived yet - so that's a bad thing
	*/
	if (received == total)
		syslog(LOG_ERR, "Failed to store complete response from socket");

	/* close the socket */
	close(sockfd);
	free(message);

	/* check code */
	int code;
	sscanf(response, "HTTP/1.1 %d", &code);
	syslog(LOG_INFO, "Response Status Code: %d", code);

	if (code != 200)
		return (NULL);

	/* process response */
	char *data = strstr(response, "\r\n\r\n");

	if (data != NULL)
	{
		data += 4;
		return (&(*data));
	}
	else
		return (NULL);
}


int					get_array_length(const char **array)
{
	int	i = 0;
	while (*array++)
		i++;

	return (i);
}


void				ft_bzero(void *s, size_t n)
{
	unsigned char	*dst;
	uintmax_t		*ptr;

	if (!n)
		return ;

	ptr = (uintmax_t *)s;
	while (1)
	{
		if (n < sizeof(uintmax_t))
		{
			dst = (unsigned char *)ptr;

			while (n--)
				*dst++ = 0;

			return ;
		}

		n -= sizeof(uintmax_t);
		*ptr++ = 0;
	}
}


void				ft_stralldel(char **str, size_t n)
{
	size_t i;

	i = 0;
	if (str)
	{
		while (i < n)
		{
			free(str[i]);
			str[i] = NULL;
			i++;
		}
	}
}


size_t				ft_count_words(char *str, char c)
{
	size_t i;
	size_t n;

	i = 0;
	n = 0;
	while (str[i] != '\0')
	{
		while (str[i] == c && str[i] != '\0')
			i++;
		if (str[i] == '\0')
			break ;
		n++;
		while (str[i] != '\0' && str[i] != c)
			i++;
	}
	return (n);
}


static int			count_letters(const char *g, char c)
{
	int l;

	l = 0;
	while (*g != '\0' && *g++ != c)
		l++;

	return (l);
}


static void			ft_wordscpy(char *d, const char *g, size_t l)
{
	while (l--)
		*d++ = *g++;

	*d = '\0';
}


static char			**ft_split(char **d, const char *g, char c)
{
	size_t k;
	size_t l;

	k = 0;
	l = 0;
	while (*g != '\0')
	{
		while (*g == c && *g++ != '\0')
			;

		if (*g == '\0')
			break ;

		l = count_letters(g, c);
		d[k] = (char *)malloc(sizeof(char) * (l + 1));

		if (d[k] == NULL)
		{
			ft_stralldel(d, k);
			return (NULL);
		}

		ft_bzero(d[k], (l + 1));
		ft_wordscpy(d[k], g, l);

		g += l;
		k++;
	}

	d[k] = 0;

	return (d);
}


char				**ft_strsplit(char const *s, char c)
{
	char	**d;

	if (s == NULL)
		return (NULL);

	d = (char **)malloc(sizeof(char *) * (ft_count_words((char *)s, c) + 1));

	if (d == NULL)
		return (NULL);

	d = ft_split(d, s, c);

	return (d);
}
