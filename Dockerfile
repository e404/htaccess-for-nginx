# Nginx/Lua on AlmaLinux

FROM fabiocicerchia/nginx-lua:1.23.2-almalinux8.7-20221201

# Build the EmmyLuaDebugger from source for debugging Lua via IntelliJ IDEA
RUN curl https://github.com/EmmyLua/EmmyLuaDebugger/archive/refs/tags/1.0.16.tar.gz \
         -L -o EmmyLuaDebugger-1.0.16.tar.gz && \
    tar -xzvf EmmyLuaDebugger-1.0.16.tar.gz && \
    cd EmmyLuaDebugger-1.0.16 && \
        mkdir -p build && \
        cd build && \
            cmake -DCMAKE_BUILD_TYPE=Release ../ && \
            make install && \
            mkdir -p /usr/local/emmy && \
            cp install/bin/emmy_core.so /usr/local/emmy/ && \
        cd .. && \
    cd .. 

# Set the lua_shared_dict, set the nginx root to ./web and load the `htaccess.lua` script (without caching)
RUN sed -i "s@http {@http {\n    lua_shared_dict htaccess 16m;\n@g" /etc/nginx/nginx.conf \
    && sed -i "s@root   /usr/share/nginx/html;@root   /docker/web;@g" /etc/nginx/conf.d/default.conf \
    && sed -i "s@server {@\nserver {\n    lua_code_cache off;\n    rewrite_by_lua_file /docker/htaccess.lua;\n@g" /etc/nginx/conf.d/default.conf