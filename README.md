# .htaccess for nginx

**.htaccess for nginx** enables the [nginx](https://nginx.org/en/) high performance webserver to deal with `.htaccess` files.

`.htaccess` files are mainly used for access control and URL rewrite instructions and are widely known across the web community. Originally designed for [Apache](https://www.apache.org/), there is no native implementation available for nginx.  While there is a [legitimate reason for this](https://www.nginx.com/resources/wiki/start/topics/examples/likeapache-htaccess/), there would be huge practical benefit if nginx was able to support this.

**.htaccess for nginx** is efficient and elegant, using micro caching and various performance tweaks right out of the box. It is effortless in its installation and usage. The plugin's deeply integrated approach is ideal for webhosters, who are looking for mixed technology solutions using only nginx and nothing else.

## Stop using Apache

*   Apache is slow.
*   Apache is wasting resources.
*   Compared to nginx, Apache is poorly and inconsistently designed.
*   Apache's monolithic design prevents it from scaling properly, while nginx is capable of handling tens of thousands of simultaneous connections with ease.
*   Switching to nginx heavily improves performance, efficiency and security.

## Reasons for .htaccess in nginx

When using nginx, there are many **legitimate reasons** to support `.htaccess` files.

*   **Mixed technology.** Imagine using NodeJS and PHP side by side, running on one stable nginx webserver. When dealing with customer webspace, using Apache and nginx together (one proxying the other) is possible, however this adds unnecessary layers of redundancy and heavily wastes valuable server resources.
*   **Ease of use.** Everybody knows how to use `.htaccess` files. As pf January 2020, [more than 24% of all active websites](https://web.archive.org/web/20200130141042/https://news.netcraft.com/archives/2020/01/21/january-2020-web-server-survey.html) are still run on Apache and thus capable of utilizing `.htaccess` files. If nginx had a way to support this feature, this number would be going down significantly, making the web faster.
*   **Legacy.** Just use your old code, without worrying if someone could access a protected directory inside any library you just forgot to handle in your nginx config.
*   **Plug and play.** No need to convert `.htaccess` files for nginx and fix all the errors, rant about unsupported or oddly mixed up auto-generated config goo coming from a random online converter.
*   **Justified.** Apache performs multiple file reads anyway, so .htaccess for nginx cannot make it worse than Apache, right? In fact, with our built-in micro caching mechanism both, CPU and I/O load are reduced drastically compared to Apache's implementation.
*   **For webhosters.** Today, webhosters still need to provide an interface for their customers to change certain aspects of their webserver's behaviour. The decades long and proven `.htaccess` file does just that.


## Performance

**.htaccess for nginx is incredibly lightweight and fast!** It is written from the ground up with performance optimizations in mind. Even with low-end hardware it adds less than 1 millisecond to your response time, despite supporting quite complex rewrite structures with server variables.

Physical memory usage of this plugin is insanely low, under 10 KB for each nginx worker process, and it doesn't increase with more requests.


## Requirements

*   Debian or Fedora environment
*   `nginx` v1.19+ with Lua module
*   `curl` command-line tool
*   Optional: `htpasswd` utility (`apache2-utils` package) for `.htpasswd` hashing functions (required for Basic HTTP Authentication)
*   Optional: `getent` utility (`libc-bin` package) for hostname lookups (e.g. `Deny from _domainname.tld_`)


## Installation

1. Install nginx (with the [Lua module](https://github.com/openresty/lua-nginx-module) if you don't already have it) and luajit.
    1. Debian: `apt-get install nginx luajit`
    1. Fedora: `yum install nginx luajit`
1. uild and install the plugin into an appropriate directory accessible by the nginx process, e.g., 
    ```bash
    luajit -b htaccess.lua /etc/nginx/lua/htaccess.lbc
    ```
1. Add the following configuration to the nginx `http {}` context:
    ```nginx
    http {
        ...
        lua_shared_dict htaccess 16m;
        ...
    }
    ```
    This represents a caching system, used on a short-term per-request basis. `.htaccess` lines are usually cached as values for less than 100 milliseconds, but kept in memory as long as there are active connections. You can choose to assign any other memory amount to it, although 16 MB should be more than enough.
1. Configure the nginx `server {}` context(s) to use the plugin:
    ```nginx
    server {
        ...
        rewrite_by_lua_file /path/to/htaccess.lua;
        # or reference the bytecode instead
        # rewrite_by_lua_file /path/to/htaccess.lbc;
        ...
    }
    ```

## Example

Create an `.htaccess` file in a directory of your host with the following content:

```apache
Order deny,allow  
Deny from all
```

When trying to access a file inside this directory through your browser, access should be denied by receiving an `HTTP 403` response.


## Supported Syntax

The following tables came from [this page](https://htaccess-for-nginx.com/features).

### Sections

| Module | Section | Supported | Notes |
| ------ | ------- | --------- | ----- |
core	|	`<Else>`	|	No	|	
core	|	`<ElseIf>`	|	No	|	
core	|	`<Files>`	|	Yes	|	
core	|	`<FilesMatch>`	|	Yes	|	
core	|	`<If>`	|	No	|	
core	|	`<IfDefine>`	|	Never	|	Impossible to be implemented. Apache specific
core	|	`<IfDirective>`	|	Yes	|	
core	|	`<IfFile>`	|	Yes	|	
core	|	`<IfModule>`	|	Yes	|	Emulating supported modules according to supported directives
core	|	`<IfSection>`	|	Yes	|	
core	|	`<Limit>`	|	Yes	|	
core	|	`<LimitExcept>`	|	Yes	|	
mod_authz_core	|	`<RequireAll>`	|	No	|	
mod_authz_core	|	`<RequireAny>`	|	No	|	
mod_authz_core	|	`<RequireNone>`	|	No	|	
mod_version	|	`<IfVersion>`	|	Yes	|	The version will be simulated as Apache 2.4.0

### Directives

Directives not listed below are not supported.

| Module | Directive | Supported | Notes |
| ------ | --------- | --------- | ----- |
core	|	`AcceptPathInfo`	|	No	|	
core	|	`AddDefaultCharset`	|	No	|	
core	|	`CGIMapExtension`	|	No	|	
core	|	`CGIPassAuth`	|	No	|	
core	|	`CGIVar`	|	No	|	
core	|	`ContentDigest`	|	No	|	
core	|	`DefaultType`	|	No	|	
core	|	`EnableMMAP`	|	No	|	
core	|	`EnableSendfile`	|	No	|	
core	|	`ErrorDocument`	|	No	|	
core	|	`FileETag`	|	No	|	
core	|	`ForceType`	|	No	|	
core	|	`LimitRequestBody`	|	No	|	
core	|	`LimitXMLRequestBody`	|	No	|	
core	|	`Options`	|	No	|	
core	|	`QualifyRedirectURL`	|	No	|	
core	|	`RLimitCPU`	|	Never	|	Rarely used and not practical for nginx
core	|	`RLimitMEM`	|	Never	|	Rarely used and not practical for nginx
core	|	`RLimitNPROC`	|	Never	|	Rarely used and not practical for nginx
core	|	`ScriptInterpreterSource`	|	No	|	
core	|	`ServerSignature`	|	No	|	
core	|	`SetHandler`	|	No	|	
core	|	`SetInputFilter`	|	No	|	
core	|	`SetOutputFilter`	|	No	|	
mod_access_compat	|	`Allow`	|	Yes	|	`Allow from domainname.tld` requires `getent` command line tool
mod_access_compat	|	`Deny`	|	Yes	|	`Deny from domainname.tld` requires `getent` command line tool
mod_access_compat	|	`Order`	|	Yes	|	
mod_access_compat	|	`Satisfy`	|	Never	|	Security reasons. `Satisfy All` assumed
mod_actions	|	`Action`	|	Never	|	Security reasons. CGI request handling must be in main host config
mod_alias	|	`Redirect`	|	Yes	|	
mod_alias	|	`RedirectMatch`	|	Yes	|	
mod_alias	|	`RedirectPermanent`	|	Yes	|	
mod_alias	|	`RedirectTemp`	|	Yes	|	
mod_auth_basic	|	`AuthBasicAuthoritative`	|	No	|	
mod_auth_basic	|	`AuthBasicFake`	|	No	|	
mod_auth_basic	|	`AuthBasicProvider`	|	No	|	
mod_auth_basic	|	`AuthBasicUseDigestAlgorithm`	|	No	|	
mod_auth_digest	|	`*`	|	No	|	
mod_auth_form	|	`*`	|	No	|	
mod_authn_anon	|	`*`	|	No	|	
mod_authn_core	|	`AuthName`	|	Yes	|	
mod_authn_core	|	`AuthType`	|	Partially	|	Only `AuthType Basic` supported
mod_authn_dbm	|	`*`	|	No	|	
mod_authn_file	|	`AuthUserFile`	|	Yes	|	
mod_authn_socache	|	`*`	|	No	|	
mod_authnz_ldap	|	`*`	|	No	|	
mod_authz_core	|	`AuthMerging`	|	No	|	
mod_authz_core	|	`Require`	|	Partially	|	Require group, host, expr not supported
mod_authz_dbm	|	`*`	|	No	|	
mod_authz_groupfile	|	`*`	|	No	|	
mod_autoindex	|	`AddAlt`	|	No	|	
mod_autoindex	|	`AddAltByEncoding`	|	No	|	
mod_autoindex	|	`AddAltByType`	|	No	|	
mod_autoindex	|	`AddDescription`	|	No	|	
mod_autoindex	|	`AddIcon`	|	No	|	
mod_autoindex	|	`AddIconByEncoding`	|	No	|	
mod_autoindex	|	`AddIconByType`	|	No	|	
mod_autoindex	|	`DefaultIcon`	|	No	|	
mod_autoindex	|	`HeaderName`	|	No	|	
mod_autoindex	|	`IndexHeadInsert`	|	No	|	
mod_autoindex	|	`IndexIgnore`	|	No	|	
mod_autoindex	|	`IndexIgnoreReset`	|	No	|	
mod_autoindex	|	`IndexOptions`	|	No	|	
mod_autoindex	|	`IndexOrderDefault`	|	No	|	
mod_autoindex	|	`IndexStyleSheet`	|	No	|	
mod_autoindex	|	`ReadmeName`	|	No	|	
mod_cern_meta	|	`*`	|	No	|	Rarely used
mod_charset_lite	|	`CharsetDefault`	|	No	|	
mod_charset_lite	|	`CharsetOptions`	|	No	|	
mod_charset_lite	|	`CharsetSourceEnc`	|	No	|	
mod_dir	|	`DirectoryCheckHandler`	|	No	|	
mod_dir	|	`DirectoryIndex`	|	No	|	
mod_dir	|	`DirectoryIndexRedirect`	|	No	|	
mod_dir	|	`DirectorySlash`	|	No	|	
mod_dir	|	`FallbackResource`	|	No	|	
mod_env	|	`PassEnv`	|	No	|	
mod_env	|	`SetEnv`	|	No	|	
mod_env	|	`UnsetEnv`	|	No	|	
mod_expires	|	`ExpiresActive`	|	No	|	
mod_expires	|	`ExpiresByType`	|	No	|	
mod_expires	|	`ExpiresDefault`	|	No	|	
mod_filter	|	`AddOutputFilterByType`	|	No	|	
mod_filter	|	`FilterChain`	|	No	|	
mod_filter	|	`FilterDeclare`	|	No	|	
mod_filter	|	`FilterProtocol`	|	No	|	
mod_filter	|	`FilterProvider`	|	No	|	
mod_headers	|	`Header`	|	No	|	
mod_headers	|	`RequestHeader`	|	No	|	
mod_imagemap	|	`*`	|	No	|	
mod_include	|	`SSIErrorMsg`	|	No	|	
mod_include	|	`SSITimeFormat`	|	No	|	
mod_include	|	`SSIUndefinedEcho`	|	No	|	
mod_include	|	`XBitHack`	|	No	|	
mod_isapi	|	`*`	|	No	|	
mod_ldap	|	`*`	|	No	|	
mod_logio	|	`*`	|	No	|	
mod_lua	|	`*`	|	No	|	
mod_mime	|	`AddCharset`	|	No	|	
mod_mime	|	`AddEncoding`	|	No	|	
mod_mime	|	`AddHandler`	|	No	|	
mod_mime	|	`AddInputFilter`	|	No	|	
mod_mime	|	`AddLanguage`	|	No	|	
mod_mime	|	`AddOutputFilter`	|	No	|	
mod_mime	|	`AddType`	|	Yes	|	
mod_mime	|	`DefaultLanguage`	|	No	|	
mod_mime	|	`MultiviewsMatch`	|	No	|	
mod_mime	|	`RemoveCharset`	|	No	|	
mod_mime	|	`RemoveEncoding`	|	No	|	
mod_mime	|	`RemoveHandler`	|	No	|	
mod_mime	|	`RemoveInputFilter`	|	No	|	
mod_mime	|	`RemoveLanguage`	|	No	|	
mod_mime	|	`RemoveOutputFilter`	|	No	|	
mod_mime	|	`RemoveType`	|	No	|	
mod_negotiation	|	`ForceLanguagePriority`	|	No	|	
mod_negotiation	|	`LanguagePriority`	|	No	|	
mod_reflector	|	`*`	|	Never	|	Security reasons
mod_rewrite	|	`RewriteBase`	|	Yes	|	
mod_rewrite	|	`RewriteCond`	|	Yes	|	
mod_rewrite	|	`RewriteEngine`	|	Yes	|	
mod_rewrite	|	`RewriteOptions`	|	No	|	
mod_rewrite	|	`RewriteRule`	|	Yes	|	
mod_session	|	`*`	|	No	|	
mod_setenvif	|	`BrowserMatch`	|	No	|	
mod_setenvif	|	`BrowserMatchNoCase`	|	No	|	
mod_setenvif	|	`SetEnvIf`	|	No	|	
mod_setenvif	|	`SetEnvIfExpr`	|	No	|	
mod_setenvif	|	`SetEnvIfNoCase`	|	No	|	
mod_speling	|	`CheckCaseOnly`	|	No	|	
mod_speling	|	`CheckSpelling`	|	No	|	
mod_ssl	|	`SSLCipherSuite`	|	No	|	
mod_ssl	|	`SSLOptions`	|	No	|	
mod_ssl	|	`SSLRenegBufferSize`	|	No	|	
mod_ssl	|	`SSLRequire`	|	No	|	
mod_ssl	|	`SSLRequireSSL`	|	No	|	
mod_ssl	|	`SSLUserName`	|	No	|	
mod_ssl	|	`SSLVerifyClient`	|	No	|	
mod_ssl	|	`SSLVerifyDepth`	|	No	|	
mod_substitute	|	`Substitute`	|	No	|	
mod_substitute	|	`SubstituteInheritBefore`	|	No	|	
mod_substitute	|	`SubstituteMaxLineLength`	|	No	|	
mod_usertrack	|	`CookieDomain`	|	No	|	
mod_usertrack	|	`CookieExpires`	|	No	|	
mod_usertrack	|	`CookieHTTPOnly`	|	No	|	
mod_usertrack	|	`CookieName`	|	No	|	
mod_usertrack	|	`CookieSameSite`	|	No	|	
mod_usertrack	|	`CookieSecure`	|	No	|	
mod_usertrack	|	`CookieStyle`	|	No	|	
mod_usertrack	|	`CookieTracking`	|	No	|	

### Variables

Variables not listed below are not supported.

| Variable | Supported | Notes |
| ------ | --------- | --------- | ----- |
`HTTP_*`	|	Yes | all standard and non-standard HTTP header fields are supported
`HTTPS`	|	Yes
`DOCUMENT_ROOT`	|	Yes
`SERVER_ADDR`	|	Yes
`SERVER_NAME`	|	Yes
`SERVER_PORT`	|	Yes
`SERVER_PROTOCOL`	|	Yes
`REMOTE_ADDR`	|	Yes
`REMOTE_HOST`	|	Yes
`REMOTE_USER`	|	Yes
`REMOTE_PORT`	|	Yes
`REQUEST_METHOD`	|	Yes
`REQUEST_FILENAME`	|	Yes
`REQUEST_URI`	|	Yes
`QUERY_STRING`	|	Yes
`SCRIPT_FILENAME`	|	Yes
`REQUEST_SCHEME`	|	Yes
`THE_REQUEST`	|	Yes
`IPV6`	|	Yes
`TIME`	|	Yes
`TIME_YEAR`	|	Yes
`TIME_MON`	|	Yes
`TIME_DAY`	|	Yes
`TIME_HOUR`	|	Yes
`TIME_MIN`	|	Yes
`TIME_SEC`	|	Yes
`TIME_WDAY`	|	Yes


## Tips

*   This plugin tries to make things as secure as possible. **Wherever an unclear situation occurs, access will be denied** to prevent unintended access, e.g. if unsupported, security-critical directives are being used (HTTP 500 response). Unsupported, non-security-related directives will be ignored.
*   Global configuration within your `http {}` context is technically possible. However, you are encouraged to use this plugin only in the `server {}` contexts that will need it.
*   To make your life easier, you can create a config snippet and include it in the `server {}` config:
    ```nginx
    server {
        ...
        include snippets/htaccess.conf
        ...
    }
    ```

* * *

_Roadfamily LLC  
412 N Main St 100  
Buffalo, WY 82834  
USA_

[**📱 24/7 Support** via WhatsApp: +60-13-8675656](https://wa.me/60138675656)
