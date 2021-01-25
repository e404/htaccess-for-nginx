.htaccess for nginx
===================

**.htaccess for nginx** enables [nginx](https://nginx.org/en/) high performance webserver to deal with `.htaccess` files.

`.htaccess` files are mainly used for access control and URL rewrite instructions and are widely known across the web community. Originally designed for [Apache](https://www.apache.org/), there is no native implementation available for nginx.

**.htaccess for nginx** is efficient and elegant, using micro caching and various performance tweaks right out of the box. It is effortless in its installation and usage. The plugin's deeply integrated approach is ideal for webhosters, who are looking for mixed technology solutions using only nginx and nothing else.

Stop Using Apache
-----------------

*   Apache is slow.
*   Apache is wasting resources.
*   Compared to nginx, Apache is poorly and inconsistently designed.
*   Apache's monolithic design prevents it from scaling properly, while nginx is capable of handling tens of thousands of simultaneous connections with ease.
*   Switching to nginx heavily improves performance, efficiency and security.

* * *

Reasons for .htaccess in nginx
------------------------------

When using nginx, there are many **legitimate reasons** to support `.htaccess` files.

*   **Mixed technology.** Imagine using NodeJS and PHP side by side, running on one stable nginx webserver. When dealing with customer webspace, using Apache and nginx together (one proxying the other) is possible, however this adds unnecessary layers of redundancy and heavily wastes valuable server resources.
*   **Ease of use.** Everybody knows how to use `.htaccess` files. [January 2020, more than 24% of all active websites out there are still run by Apache's webserver](https://web.archive.org/web/20200130141042/https://news.netcraft.com/archives/2020/01/21/january-2020-web-server-survey.html), capable of utilizing `.htaccess` files. If nginx had a way to support this feature, this number would be going down significantly, making the web faster.
*   **Legacy.** Just use your old code, without worrying if someone could access a protected directory inside any library you just forgot to handle in your nginx config.
*   **Plug'n'play.** No need to convert `.htaccess` files for nginx and fix all the errors, rant about unsupported or oddly mixed up auto-generated config goo coming from a random online converter.
*   **Justified.** Apache performs multiple file reads anyway, so .htaccess for nginx cannot make it worse than Apache, right? In fact, with our built-in micro caching mechanism both, CPU and I/O load are reduced drastically compared to Apache's implementation.
*   **For webhosters.** Today, webhosters still need to provide an interface for their customers to change certain aspects of their webserver's behaviour. The decades long and proven `.htaccess` file does just that.

* * *

Performance
-----------

**.htaccess for nginx is incredibly lightweight and fast!** It is writting from ground up with performance optimizations in mind. Even with low-end hardware it **adds less than 1 millisecond to your response time**, also for quite complex rewrite structures with server variables.

Physical **memory usage** of this plugin is insanely low, just **less than 10 KB** for each nginx worker process, and it doesn't increase with more requests.

* * *

Requirements
------------

*   Unix environment
*   `nginx` with Lua module
*   `curl` command-line tool

### Optional Dependencies

*   `htpasswd` utility (`apache2-utils` package) for .htpasswd hashing functions (required for Basic HTTP Authentication)
*   `getent` utility (`libc-bin` package) for hostname lookups (e.g. `Deny from _domainname.tld_`)

* * *

Installation
------------

*   Install nginx **with Lua module**: `apt-get install nginx`
*   Install [Lua](https://www.lua.org/download.html): `apt-get install lua5.2`
*   Save this plugin directory into `/etc/nginx/`, so that you can access `/etc/nginx/htaccess-for-nginx/htaccess.lua`
*   Add the following configuration to your `http {}` context: `lua_shared_dict htaccess 16m;`
*   Configure your hosts (within the `server {}` context): `rewrite_by_lua_file /etc/nginx/htaccess-for-nginx/htaccess.lua;`

### Hints and Common Practice

*   Depending on your operating system, the installation process may vary.
*   Make sure to have **Lua version 5.2** installed on your system.
*   You can clone this repository to any directory of your choice. Just make sure to adjust the paths accordingly.
*   If you don't set the `lua_shared_dict` setting in `http {}`, this plugin will refuse to work. It represents a caching system, used on a short-term per-request basis. Values (`.htaccess` lines) are usually cached less than 100 milliseconds, but kept in memory as long as there are active connections. You can choose to assign any other memory amount to it, although 16 MB should be more than enough.
*   ⚠️ Note that global configuration within your `http {}` context is technically possible. However, if you want to keep the good nginx performance for your new, non-legacy projects, you are **highly encouraged** to use this plugin in `server {}` context only.
*   To make your life easier, just create a config snipped and write e.g. `include snippets/htaccess.conf` in the `server {}` config.

* * *

Usage — Testing it
------------------

Create an `.htaccess` file in a directory of your host with the following content:

`Order deny,allow  
Deny from all`

When trying to access a file inside this directory through your browser, access should be denied by receiving an `HTTP 403` response.

* * *

Supported Features
------------------

**We compiled a [complete list of implemented `.htaccess` directives and variables](https://htaccess-for-nginx.com/features).**

This plugin tries to make things as secure as possible. **Wherever an unclear situation occurs, access will be denied** to prevent unintended access, e.g. if unsupported, security-critical directives are being used (HTTP 500 response). Unsupported, non-security-related directives will be ignored.

* * *

_Roadfamily LLC  
412 N Main St 100  
Buffalo, WY 82834  
USA_

[**📱 24/7 Support** via WhatsApp: +60-13-8675656](https://wa.me/60138675656)
