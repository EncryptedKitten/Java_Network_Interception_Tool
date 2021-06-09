# EncryptedKitten's Java Network Interception Tool/Minecraft JavaAgent
## Features
#### Shared Features
* Disable Java ClassLoader signature verification to load classes with invalid signatures
* Disable Java public key signature checks
* Disable all Java SSL/TLS certificate checks
* Block Java URL connections
* Replace hosts of Java URL connections
* Make all Java HTTP(S) URLs fail
* Force all Java HTTPS URLs to HTTP
* Force all Java HTTP URLs to HTTPS
* Put all Java HTTP(S) URLs as a subdomain of a specified site, either with their current '.' separation or using an underscore (SSL/TLS certificate wildcards aren't multi-level)
* Force all Java HTTP(S) connections to be direct or through a specified proxy
* Set the cacerts trust store to one loaded from a URL at runtime
* Add certificates to the cacerts turst store temporarily at runtime
* Block all DNS queries
* Block all InetAddress resolutions
* Set the DNS resolver
* Block specified hosts or IP addresses from resolution
* Map a host or IP to another specified IP or host
* Set a list of hosts files to be loaded from URLs
* Set if the DNS server will respect the system hosts file mappings

#### Java Network Interception Tool Additional Features
* Replace Java Class getResourceAsStream loaded resources

#### Minecraft JavaAgent Additional Features
* Replace yggdrasil_session_pubkey at runtime
* Block the blocked servers list from loading

## Minecraft Java Agent

#### When are yggdrasil_session_pubkey patches needed?
You need to patch versions of Minecraft that are greater than, or equal to 1.7.6, or with authlib versions greater than, or equal to authlib-1.5.6.jar.

The yggdrasil_session_pubkey patches will have no effect on version that do not require it, and they will work the same without it or not.

| Component	| Minimum version that needs patches |
| ----------- | ----------- |
| Minecraft	| 1.7.6	|
| authlib | 1.5.6 |

## License
See [LICENSE.txt](LICENSE.txt)

## Building

1. Download/clone this repository, and cd into it
2. Edit build.ini and set the java_home entry in the GLOBAL section to your jva_home path.
3. Run build.py with python3
4. The JAR file will be in the build/jar directory

## Examples

#### Set the DNS resolver to localhost and disable usage of the system hosts file

{
	"respect_system_hosts": false,
	"dns_resolver": "127.0.0.1"
}

This will set the DNS resolver to 127.0.0.1, and disable usage of the system hosts file for these queries.

#### Disables SSL/TLS checks, and forces an HTTP proxy to 127.0.0.1:8080

{
	"no_ssl": true,
	"force_proxy": {"type":"http", "address":"127.0.0.1", "port": 8080}
}

This will disable all SSL/TLS certificate verification and force all URL connections to the HTTP proxy at 127.0.0.1:8080.

This can be useful if you want to send all of the Java application's web traffic through a web debugging proxy, such as [mitmproxy](https://mitmproxy.org/) or [Fiddler](https://www.telerik.com/fiddler/fiddler-classic). The disabling of certificate validation checks, or having a certificate store with their root certificate, is also need to decrypt HTTPS traffic.

#### Minecraft JavaAgent set the yggdrasil_session_pubkey and force all URLs to a domain with the subdomain having underscores

{
	"yggdrasil_session_pubkey": "http://1.0.0.127.in-addr.arpa/yggdrasil_session_pubkey.der",
	"underscore": "1.0.0.127.in-addr.arpa"
}

This will replace the yggdrasil_session_pubkey.der file in authlib to be loaded from http://1.0.0.127.in-addr.arpa/yggdrasil_session_pubkey.der. This is loaded in when the JavaAgent starts, and it will be stored in memory for the remainder of the execution.

This will also cause all of the domains, such as sessionserver.mojang.com, to be changed to sessionserver_mojang_com.1.0.0.127.in-addr.arpa, and allow you to use the wildcard certificate that you have for 1.0.0.127.in-addr.arpa, or any actual domain, on sessionserver_mojang_com.1.0.0.127.in-addr.arpa.

#### Help screen

System.out.println("The patch arguments are passed via the javaagent command line arguments, where the JavaAgent command is -javaagent:/path/to/javaagent.jar='THE_ARGUMENT_STRING_GOES_HERE'

###### Minecraft JavaAgent

They are formatted as a JSON string surrounded by single-tick quotes, such as '{"yggdrasil_session_pubkey":"https://example.com/my_fake_yggdrasil_session_pubkey.der", "debug":true}'

###### Java Network Interception Tool

They are formatted as a JSON string surrounded by single-tick quotes, such as '{"dns_resolver":"127.0.0.1", "debug":true}'

They can also be passed as an URL to a configuration file. At all of the help sections where a URL is supported, file:/// and data: URLs are included.
They will stay as the default if they are missing from the string, so you don't need to (but you can) have arguments in the argument string that are set as their listed default value.

###### Minecraft JavaAgent

| Arguments | Options | Info |
| ----------- | ----------- | ----------- |
yggdrasil_session_pubkey | URL String/(key does not exist)(default) | Can be any URL type listed in the above help segment.

###### Java Network Interception Tool

| Arguments | Options | Info |
| ----------- | ----------- | ----------- |
resource_replacements | object/{}(default) | A list of resources mapped to a URL of what their contents will be. All of the resources are loaded at start.

| Arguments | Options | Info |
| ----------- | ----------- | ----------- |
debug | true/false(default) | Enable the informational text about what each of the patches is actually doing to Java behind the scenes.
no_security_verify | true/false(default) | Disables all public key signature verification. This is not recommended, because it could falsify unintended public key signature checks.
no_classloader_signature | true(default)/false | Disables all Java ClassLoader Signature Checks, to allow Java classes with invalid signatures to be loaded. Without this it seems to crash, so it's recommended to leave this as true.
patch | true(default)/false | Sets if the patch will actually run. If you want the program to actually patch the game, leave this as true, if you don't want patches, remove the -javaagent argument, or set it to an empty json object.
printStackTrace | true(default)/false | Sets if on an error, it will print the error stack trace.
exitOnFailure | true(default)/false | Sets if on an error, it will exit and terminate the JVM process.
failureExitCode | int/2(default) | Sets exit code used when it exits of failure if enabled, the default is 2, to differentiate it's exits from other JVM error exit code 1 exits.
no_ssl | true/false(default) | Sets if it should remove all SSL/TLS Certificate Checks.
blocked_urls | list/[]\(default) | Sets a list of URLS that will be not be allowed, and blocked.
host_replacements | object/{}(default) | Sets a list of hosts that will be changed.

###### Minecraft JavaAgent

| Arguments | Options | Info |
| ----------- | ----------- | ----------- |
no_blocked_servers | true/false(default) | Makes it so https://sessionserver.mojang.com/blockedservers, the blocked servers list, will not be loaded.
		
| Arguments | Options | Info |
| ----------- | ----------- | ----------- |
url_offline | true/false(default) | Makes it so all http and https connections will throw MalformedURLException, and therefore not load.
force_http | true/false(default) | Makes it so all https connections will instead use http.
force_https | true/false(default) | Makes it so all http connections will instead use https.
subdomain | Domain String | Can be a string to have as the suffix for all URL requests. It should start with a dot, unless you want the subdomains themselves to have a suffix.
underscore | Domain String | Can be a string to have as the suffix for all URL requests, except the original host will have it's dots replaced with underscores. It should start with a dot, unless you want the subdomains themselves to have a suffix.
force_proxy | object/null/(key does not exist)(default) | Setting it to null, will force a direct connection, not setting it will disable forcing it, and an object will set the parameters as {"type":type, "address":address, "port":port} to be the settings for the proxy, with type being either http or socks.
cacerts | object/string/(key does not exist)(default) | Setting it to a string will load the cacerts file from that URL, and an object will set the parameters, all of which are optional, as {"location":cacerts_url_location, "password":cacerts_password, "certificates":["url_of_certificate_1"], "save":"after_certificate"} with the save parameter being able to be after_config, to save the cacerts file after each config, after_certificate, to save after each individual certificate is loaded, and after_load, or any other value will result in it being saved at the end of the full loading sequence.
dns_offline | true/false(default) | Makes it so all DNS name resolutions fail.
offline | true/false(default) | Makes it so all InetAddresses will throw UnknownHostException.
dns_resolver | String/(key does not exist)(default) | Sets the DNS server to use for DNS queries.
blocked_hosts | list/[]\(default) | Sets a list of hostanames or IP addresses that will make InetAddress throw UnknownHostException.
static_hosts | object/{}(default) | Sets a list of domains that will either be statically linked to an alternate IP address, or an alternate domain.
hosts_files | list/[]\(default) | Sets a list of hosts files that it will all to the static_hosts list, they can be a string literal being the hosts file, or a URL to a hosts file.
respect_system_hosts | true/false/(key does not exist)(default) | Sets if it will respect the system host file, if it is unset, it will respect the system host file only if no config disables respecting it, true will force the system hosts file to be respected, and disallow other configs from disabling respecting it, and false will make it not load the system hosts file, unless a previous config has loaded it.
