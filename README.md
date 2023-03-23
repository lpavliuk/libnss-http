# libnss HTTP Request

The custom NSS for SFTP/SSH authorisation. Makes request to an HTTP endpoint to get a passwd entry. 

### Compile and install
```shell
make && make install
```

### Configuration file
```shell
vim /etc/libnss_http.conf
```

### To utilise the NSS library
Add the module to `passwd` line in NSS configuration as `http` after `files`:
```shell
# passwd:     files http
vim /etc/nsswitch.conf
```
