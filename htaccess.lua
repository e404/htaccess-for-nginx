-- htaccess for nginx
-- Version: 1.2.1
-- Copyright (c) 2017-2021 by Gerald Schittenhelm, Roadfamily LLC
-- MIT License
-- Compilation: luajit -b htaccess.lua htaccess-bytecode.lua

-- TODO: Sometimes code is executed 4 times for each request due to the way nginx handles requests. Make sure it is cached accordingly.

-- Uncomment the following to enable remote debugging
-- Note that if the container volume path contains dashes, they will need to be escaped - e.g., /path/to/htaccess%-for%-nginx
-- _G.emmy = {}
-- _G.emmy.fixPath = function(path)
-- 	return path:gsub('/docker/', 'C:/path/to/project/on/windows')
-- end

-- package.cpath = package.cpath .. ';/usr/local/emmy/?.so'
-- local dbg = require('emmy_core')
-- dbg.tcpListen('localhost', 9966)
-- dbg.waitIDE()
-- dbg.breakHere()

-- Error function, returns HTTP 500 and logs an error message
local fail = function(msg)
	if msg then
		ngx.log(ngx.ERR, msg)
	end
	ngx.exit(500)
end

-- Halts the script execution
local die = function()
	ngx.exit(0) -- os.exit(0) leads to timeouts in nginx
end

-- Pull some nginx functions to local scope
local decode_base64 = ngx.decode_base64
local unescape_uri = ngx.unescape_uri

-- Initialize cache
local cache_dict = ngx.shared['htaccess']
if not cache_dict then
	fail('Shared storage DICT "htaccess" not set; define "lua_shared_dict htaccess 16m;" within http configuration block')
end

-- Calculate a unique request tracing id which remains the same across all subrequests
local trace_id = ngx.var.connection..'.'..ngx.var.connection_requests

-- Get a cache value
local cache_get = function(key)
	return cache_dict:get_stale(key)
end

-- Set/delete a cache value
local cache_set = function(key, value, expiry_sec)
	if not value then
		return cache_dict:delete(key)
	end
	if not expiry_sec or expiry_sec < 0.001 then
		expiry_sec = 1 -- expire in 1 second (default)
	elseif expiry_sec > 3600 then
		expiry_sec = 3600 -- don't allow expire values > 1 hour
	end
	return cache_dict:set(key, value, expiry_sec)
end

-- Define request status values
local C_STATUS_SUBREQUEST = 1
local C_STATUS_VOID = 9

-- Define directory identified placeholder
local C_DIR = '__dir__'

-- Get request status from shared storage
local request_status = cache_get(trace_id)

-- Detect void flag (e.g. from RewriteRule flag [END])
if request_status == C_STATUS_VOID then
	die()
end

-- Determine whether or not this is a subrequest
local is_subrequest
if request_status then
	is_subrequest = true
else
	is_subrequest = false
	cache_set(trace_id, C_STATUS_SUBREQUEST) -- Write subrequest status to cache for any following subrequest
end

-- The original requested URI including query string
local org_request_uri = ngx.var.request_uri
local org_request_uri_path = org_request_uri:match('^[^%?]+') -- Make sure uri doesn't end on '?', as request_uri will never match that
if org_request_uri:len() > org_request_uri_path:len() then
	org_request_uri = unescape_uri(org_request_uri_path)..org_request_uri:sub(org_request_uri_path:len()+1)
else
	org_request_uri = unescape_uri(org_request_uri_path)
end

-- The actual requested URI, not including query string
local request_uri = ngx.var.uri

-- Backup subrequest detection, in case shared storage failed
if request_uri ~= org_request_uri then
	is_subrequest = true
end

local ip = ngx.var.remote_addr -- The client's real IP address
local rootpath = ngx.var.realpath_root..'/' -- The root directory of the current host
local request_filepath = ngx.var.request_filename -- The requested full file path resolved to the root directory
local request_filename = ngx.var.request_filename:match('/([^/]+)$') -- The requested filename
local request_fileext = ngx.var.request_filename:lower():match('%.([^%./]+)$') -- The requested filename's extension (lower case)
local request_relative_filepath = request_filepath:sub(rootpath:len()) -- the requested relative file path with leading / (might match the request_uri)

if request_filepath:match('/%.htaccess$') or request_filepath:match('/%.htpasswd$') then
	-- Deny access to any .htaccess or .htpasswd file
	-- Stick to Apache's default behaviour and return HTTP code 403, even if such a file doesn't exist
	ngx.exit(403)
end

-- Check if file is inside document root
local in_doc_root = function(filepath)
	local doc_root = ngx.var.document_root
	return (filepath:sub(1, doc_root:len()) == doc_root)
end

-- Make sure all file operations are contained inside document root, fails when not
local ensure_doc_root = function(filepath)
	if not in_doc_root(filepath) then
		fail(C_SECURITY_VIOLATION_ERROR..': Trying to read file outside of server root directory ("'..doc_root..'"): "'..filepath..'"')
	end
end

-- Check if a path exists at the file system
-- filepath .... the filename
-- soft_fail ... if true, no fail error will be triggered when not in doc root
local path_exists = function(filepath, soft_fail)
	if soft_fail then
		if not in_doc_root(filepath) then
			return false
		end
	else
		ensure_doc_root(filepath) -- Security: enforce document root
	end
	local ok, _, code = os.rename(filepath, filepath)
	if not ok then
		if code == 13 then
			return true -- Permission denied, but it exists
		end
	end
	return ok
end

-- Get the type of a file system object
-- @param filepath .... the filename
-- @return file_type .. One of (directory|link|file), or nil if the path is invalid
local get_file_type = function(filepath)
	local lfs = require "lfs"
	local file_type = nil
	if (lfs.symlinkattributes (filepath) ~= nil) then
		local attr = lfs.symlinkattributes (filepath);
		assert (type(attr) == "table")
		if attr.mode == "directory" then
			file_type = 'directory'
		elseif attr['target'] ~= nil then
			-- print ("*** symlink found   "..attr['target'])
			file_type = 'link'
		else
			file_type = 'file'
		end
	end
	return file_type
end

-- Read contents of any file
local get_file_contents = function(name)
	ensure_doc_root(name) -- Security: enforce document root
	local file = io.open(name, 'r')
	if file == nil then
		return nil
	end
	local content = file:read('*all')
	file:close()
	return content
end

-- Check IP address against given IP mask (or a full IP address)
local ip_matches_mask = function(ip, mask)
	if ip == mask then
		return true
	end
	if not mask:match('%.$') then
		return false
	end
	if ip:match('^'..mask:gsub('%.', '%.')) then
		return true
	else
		return false
	end
end

-- Check IP address against given host name
local ip_matches_host = function(ip, host)
	local hosts_proc = assert(io.popen('getent ahosts '..shell_escape_arg(host)..' | awk \'{ print $1 }\' | sort -u')) -- get all associated IP addresses (IPv4 and IPv6) for host
	for res_ip in hosts_proc:lines() do
		if ip:match('^'..res_ip..'%s*$') then
			return true
		end
	end
	return false
end

-- Trim string (remove whitespace or other characters at the beginning and the end)
local trim = function(str, what)
	if what == nil then
		what = '%s'
	end
	return tostring(str):gsub('^'..what..'+', '', 1):gsub(''..what..'+$', '', 1)
end

-- shell escape argument
local shell_escape_arg = function(s)
	if s:match("[^A-Za-z0-9_/:=-]") then
		s = "'"..s:gsub("'", "'\\''").."'"
	end
	return s
end

-- Make sure the request_filepath is based on the root path (directory security)
if request_filepath:sub(1, rootpath:len()) ~= rootpath then
	die()
end

-- Try to fetch htaccess lines from cache
local htaccess_cache_key = trace_id..'.h'
local htaccess = cache_get(htaccess_cache_key)
if not htaccess then
	-- Walk through the path and try to find .htaccess files
	local last_htaccess_dir = rootpath
	htaccess = ''
	-- Tries to process .htaccess in last_htaccess_dir
	-- Soft fails: If there is no .htaccess file, no error will be triggered
	local read_htaccess = function()
		local filename = last_htaccess_dir..'.htaccess'
		local current_htaccess = get_file_contents(filename)
		if current_htaccess then
			current_htaccess = current_htaccess:gsub('^%s*#[^\n]+\n', '', 1):gsub('\n%s*#[^\n]+', '', 1) -- Strip comments
			if current_htaccess:match(C_DIR) then
				fail(C_SECURITY_VIOLATION_ERROR)
			end
			local relative_dir = last_htaccess_dir:sub(rootpath:len()+1)
			htaccess = C_DIR..' '..relative_dir..'\n'..htaccess..current_htaccess..'\n'
		end
	end
	read_htaccess() -- process file in root directory first
	local next_dir
	for part in request_filepath:sub(rootpath:len()+1):gmatch('[^/\\]+') do
		-- Walk through directories and try to process .htaccess file
		next_dir = last_htaccess_dir..part..'/'
		if path_exists(last_htaccess_dir) then
			last_htaccess_dir = next_dir
			read_htaccess()
		else
			break
		end
	end
end

-- Some constants
local C_VALUE = -11
local C_CTX_INDEX = -12
local C_INDEXED = -21
local C_MULTIPLE = -22
local C_TYPE = -31
local C_ATTR = -32

-- Initialize global parsed htaccess directives with context flags
-- INDEXED means that instead of having integer based content, each directive type holds a key based map with integer based content tables
-- EXCLUSIVE returns only the last value for a directive within a context stack, which means that this directive cannot hold multiple values
local cdir = {
	['allowfirst'] = {},
	['deny'] = {},
	['auth'] = {},
	['authuserfile'] = {},
	['authname'] = {},
	['authcredentials'] = {[C_INDEXED] = true},
	['errordocs'] = {[C_INDEXED] = true},
	['rewritebase'] = {},
	['rewriterules'] = {[C_MULTIPLE] = true},
	['rewrite'] = {},
	['contenttypes'] = {[C_INDEXED] = true}
}

-- Directive context stack, using mapped table assignments to save memory and table copies
local ctx_i = 1
local ctx_map = {{}}
local ctx_used = false

-- Identifies attributes, even within single or double quotes; returns table of attributes
local parse_attributes = function(input_str)
	local working_str = ''
	local output = {}
	local mode = 0 -- 0 = standard, 1 = single quotes, 2 = double quotes
	for i = 1, string.len(input_str), 1 do
		local byte = input_str:sub(i,i)
		if byte:match('%s') then
			if mode == 0 then
				if working_str ~= '' then
					table.insert(output, working_str)
				end
				working_str = ''
			else
				working_str = working_str..byte
			end
		elseif byte == "'" then
			if mode == 0 then
				mode = 1
			elseif mode == 1 then
				table.insert(output, working_str)
				working_str = ''
				mode = 0
			else
				working_str = working_str..byte
			end
		elseif byte == '"' then
			if mode == 0 then
				mode = 2
			elseif mode == 2 then
				table.insert(output, working_str)
				working_str = ''
				mode = 0
			else
				working_str = working_str..byte
			end
		else
			working_str = working_str..byte
		end
	end
	if working_str ~= '' then
		table.insert(output, working_str)
	end
	return output
end

-- Add a directive to the global cdir collection
-- directive_type ... e.g. 'rewrite' --or-- {'a', 'b'} for indexed parsed directives, e.g. {'authcredentials', username}
-- value ............ e.g. true
local push_cdir = function(directive_type, value)
	ctx_used = true
	local value_to_push = {
		[C_VALUE] = value,
		[C_CTX_INDEX] = ctx_i
	}
	if type(directive_type)=='table' then
		local real_type = directive_type[1]
		local index = directive_type[2]
		if not cdir[real_type][index] then
			cdir[real_type][index] = {}
		end
		table.insert(cdir[real_type][index], value_to_push)
	else
		table.insert(cdir[directive_type], value_to_push)
	end
end

-- Helper function to get computed directive value and actual context table
-- local resolve_cdir_value = function(value_table)
-- 	if not value_table then
-- 		return nil
-- 	end
-- 	return value_table[C_VALUE], ctx_map[value_table[C_CTX_INDEX]]
-- end

-- Return computed directive by type
-- directive_type ... string of requested type (lowercase), e.g. 'rewriterules'
-- index_or_flag .... index of indexed directive (e.g. 'username') or C_MULTIPLE, for which the entire computed table will be returned
local get_cdir = function(directive_type, index_or_flag)
	local has_multiple = (cdir[directive_type][C_MULTIPLE]~=nil)
	local is_indexed = (cdir[directive_type][C_INDEXED]~=nil)
	local dataset
	if index_or_flag and index_or_flag ~= C_MULTIPLE then
		if not is_indexed then
			fail(C_SECURITY_VIOLATION_ERROR)
		end
		dataset = cdir[directive_type][index_or_flag]
	else
		if is_indexed then
			fail(C_SECURITY_VIOLATION_ERROR)
		end
		dataset = cdir[directive_type]
	end
	if not dataset then
		return nil
	end
	local computed_list = {}
	for _, directive in ipairs(dataset) do
		table.insert(computed_list, directive[C_VALUE])
	end
	if index_or_flag == C_MULTIPLE then
		if not has_multiple then
			fail(C_SECURITY_VIOLATION_ERROR)
		end
		return computed_list -- return entire list of values
	else
		return computed_list[#computed_list] -- return single element (last)
	end
end

-- Add context to current directive context stack
local push_ctx = function(ctx_type, ctx)
	local i = ctx_i
	if ctx_used then
		i = i + 1
		if i > 1 then
			ctx_map[i] = {}
			for _, item in ipairs(ctx_map[i-1]) do
				table.insert(ctx_map[i], {
					[C_TYPE] = item[C_TYPE],
					[C_ATTR] = item[C_ATTR]
				})
			end
		end
		table.insert(ctx_map[i], {
			[C_TYPE] = ctx_type,
			[C_ATTR] = ctx
		})
		ctx_i = i
	end
	table.insert(ctx_map[i], {
		[C_TYPE] = ctx_type,
		[C_ATTR] = ctx
	})
	ctx_used = false
end

-- Remove last context from current directive context stack
local pop_ctx = function()
	ctx_map[ctx_i+1] = ctx_map[ctx_i-1]
	ctx_i = ctx_i + 1
	ctx_used = true -- Make sure that if a new context is added right after this call, the stack gets copied and a new index is assigned
end

-- Remove all contexts; used with new htaccess file
local reset_ctx = function()
	local i = ctx_i
	ctx_map[i+1] = {}
	ctx_i = i + 1
	ctx_used = false
end

-- Parse one line of RewriteRule or RewriteCond
local parse_rewrite_directive = function(params_cs, is_cond)
	local result = {}
	local i = 1
	local stub = false
	local quoted = false
	for param in params_cs:gmatch('[^%s]+') do
		if param:sub(1,1) == '"' then
			quoted = true
		end
		if quoted then
			if not stub then
				stub = param
			else
				stub = stub..' '..param
			end
		else
			result[i] = param
		end
		if param:sub(param:len(),param:len()) == '"' then
			quoted = false
			result[i] = trim(stub, '"')
			stub = false
		end
		if not quoted then
			i = i + 1
		end
	end
	if #result < 3 then
		result[3] = false
	else
		-- Flag separation
		local flags = trim(result[3], '[%[%]]')
		result[3] = {}
		for match in flags:gmatch('[^,]+') do
			table.insert(result[3], match)
		end
	end
	if not is_cond and result[1]:sub(1,1) == '!' then
		result[4] = true -- Invertion flag (RewriteRule)
		result[1] = result[1]:sub(2)
	elseif is_cond and result[2]:sub(1,1) == '!' then
		result[4] = true -- Invertion flag (RewriteCond)
		result[2] = result[2]:sub(2)
	else
		result[4] = false
	end
	return result
end

local parsed_rewritebase
local parsed_rewriteconds = {}

-- Parse and execute one .htaccess directive
local parse_htaccess_directive = function(instruction, params_cs, current_dir)
	local params = params_cs:lower() -- case insensitive directive parameters
	if instruction == 'allow' then
		if params:match('from%s+all') then
			push_cdir('deny', false)
		else
			for mask in params:match('from%s+(.*)'):gmatch('[^%s]+') do
				if (mask:match('%a') and ip_matches_host(ip, mask)) or ip_matches_mask(ip, mask) then
					push_cdir('deny', false)
				elseif not get_cdir('allowfirst') then
					push_cdir('deny', true)
				end
			end
		end
	elseif instruction == 'deny' then
		if params:match('from%s+all') then
			push_cdir('deny', true)
		else
			for mask in params:match('from%s+(.*)'):gmatch('[^%s]+') do
				if (mask:match('%a') and ip_matches_host(ip, mask)) or ip_matches_mask(ip, mask) then
					push_cdir('deny', true)
				elseif get_cdir('allowfirst') then
					push_cdir('deny', false)
				end
			end
		end
	elseif instruction == 'order' then
		if params:match('allow%s*,%s*deny') then
			push_cdir('allowfirst', true)
		else
			push_cdir('allowfirst', false)
		end
	elseif instruction == 'authuserfile' then
		push_cdir('auth', true)
		htpasswd = get_file_contents(params_cs) -- this also checks if file is within root directory; fails on error
		push_cdir('authuserfile', params_cs)
		if not htpasswd then
			fail('AuthUserFile "'..params_cs..'" not found')
		end
		for line in htpasswd:gmatch('[^\r\n]+') do
			line = trim(line)
			username, password = line:match('([^:]*):(.*)')
			if username then
				push_cdir({'authcredentials', username}, password)
			end
		end
	elseif instruction == 'authname' then
		push_cdir('auth', true)
		push_cdir('authname', params_cs)
	elseif instruction == 'authtype' then
		push_cdir('auth', true)
		if not params == 'basic' then
			fail('HTTP Authentication only implemented with AuthType "Basic", requesting "'..params_cs..'"')
		end
	elseif instruction == 'require' then
		if params:match('^all%s+granted') then
			push_cdir('deny', false)
		elseif params:match('^all%s+denied') then
			push_cdir('deny', true)
		elseif params:match('^valid.+user') then
			-- HTTP Basic Authentication
			push_cdir('auth', true)
			local auth_success = false
			if ngx.var['http_authorization'] then
				local type, credentials = ngx.var['http_authorization']:match('([^%s]+)%s+(.*)')
				if type:lower() == 'basic' then
					credentials = decode_base64(credentials)
					local username, password = credentials:match('([^:]+):(.*)')
					local parsed_passwd = get_cdir('authcredentials', username)
					if username and password and parsed_passwd then
						if parsed_passwd == password then
							-- Plain text password
							auth_success = true
						else
							-- Hashed password; use htpasswd command line tool to verify
							-- xxx
							local htpasswd_proc = assert(io.popen('htpasswd -bv '..shell_escape_arg(get_cdir('authuserfile'))..' '..shell_escape_arg(username)..' '..shell_escape_arg(password)..' 2>&1'))
							for line in htpasswd_proc:lines() do
								if line:match('^Password for user .* correct.%s*$') then
									auth_success = true
								end
							end
						end
					end
				end
			end
			if auth_success == false then
				ngx.header['WWW-Authenticate'] = 'Basic realm='..get_cdir('authname')
				ngx.exit(401)
			end
		elseif params:match('^group') then
			fail('"Require group" is unsupported') -- Deny access to avoid false positives
		else
			local inverted = false
			if params:match('^not%s') then
				inverted = true
				params = params:gsub('^not%s+', ' ', 1)
			end
			if params:match('^ip%s') then
				for mask in params:match('^ip%s+(.*)'):gmatch('[^%s]+') do
					if ip_matches_mask(ip, mask) then
						if inverted then
							push_cdir('deny', false)
						else
							push_cdir('deny', true)
						end
					elseif get_cdir('allowfirst') then
						if inverted then
							push_cdir('deny', true)
						else
							push_cdir('deny', false)
						end
					end
				end
			elseif params:match('^host%s') then
				fail('"Require host" unsupported') -- Hostnames are unsupported. Deny access to avoid false positives
			elseif params:match('^expr%s') then
				fail('"Require expr" unsupported') -- TODO: Require expr "%{VAR} != 'XYZ'"; check if inverted==true
			else
				fail('Unrecognized parameters ("Require '..params_cs..'")')
			end
		end
	elseif instruction == 'redirect' or instruction == 'redirectmatch' or instruction == 'redirectpermanent' or instruction == 'redirecttemp' then
		local attr = parse_attributes(params_cs)
		local status = 302
		local source, destination
		local regex = false
		local three_attrs_possible = true
		if instruction == 'redirectpermanent' then
			status = 301
			three_attrs_possible = false
		elseif instruction == 'redirecttemp' then
			three_attrs_possible = false
		else
			if instruction == 'redirectmatch' then
				regex = true
			end
		end
		local parse_status = function(status_test)
			local test_number = tonumber(possible_status)
			if test_number then
				return test_number
			end
			status_test = tostring(status_test)
			if status_test:match('^[0-9]+$') then
				return tonumber(status_test)
			elseif status_test == 'permanent' then
				return 301
			elseif status_test == 'temp' then
				return 302
			elseif status_test == 'seeother' then
				return 303
			elseif status_test == 'gone' then
				return 410
			end
			return nil
		end
		local first_status = parse_status(attr[1])
		if three_attrs_possible and attr[3] then
			status = first_status
			source = attr[2]
			destination = attr[3]
		elseif attr[2] then
			if three_attrs_possible and first_status then
				status = first_status
				if status<300 or status>399 then
					ngx.exit(status)
				end
				destination = attr[2]
			else
				source = attr[1]
				destination = attr[2]
			end
		elseif first_status then
			ngx.exit(first_status)
		else
			destination = attr[1]
		end
		if destination then
			local redirect = true
			if source then
				redirect = false
				if regex then
					if ngx.re.match(request_uri, source) then
						redirect = true
					end
				elseif request_uri == source then
					redirect = true
				end
			end
			if redirect then
				ngx.redirect(destination, status)
			end
		end
	elseif instruction == 'errordocument' then
		status, message = params_cs:match('^([0-9]+)%s+(.*)')
		if message ~= nil then
			push_cdir({'errordocs', tonumber(status)}, message)
		end
	elseif instruction == 'addtype' then
		local attr = parse_attributes(params)
		if attr[1] and attr[2] then
			local contenttype = attr[1]
			i = 2
			while attr[i] do
				local ext = attr[i]
				if ext:sub(1,1) == '.' then
					ext = ext:sub(2)
				end
				push_cdir({'contenttypes', attr[i]}, attr[1])
				i = i + 1
			end
		end
	elseif instruction == 'rewriteengine' then
		if params == 'on' then
			push_cdir('rewrite', true)
		else
			push_cdir('rewrite', false)
		end
	elseif instruction == 'rewritebase' then
		parsed_rewritebase = trim(params_cs, '/')..'/'
		if parsed_rewritebase == '/' then
			parsed_rewritebase = nil
		end
	elseif instruction == 'rewritecond' then
		local rewrite_parsed = parse_rewrite_directive(params_cs, true)
		if rewrite_parsed then
			table.insert(parsed_rewriteconds, rewrite_parsed)
		end
	elseif instruction == 'rewriterule' then
		local rewrite_parsed = parse_rewrite_directive(params_cs, false)
		if rewrite_parsed then
			push_cdir('rewriterules', {current_dir, parsed_rewritebase, parsed_rewriteconds, rewrite_parsed})
		end
		parsed_rewriteconds = {} -- Reset for next occurence of RewriteCond/RewriteRule; RewriteCond scope is only next RewriteRule
	elseif instruction == 'rewritemap' then
		fail('RewriteMap is currently unsupported')
		-- TODO
	elseif instruction == 'rewriteoptions' then
		fail('RewriteOptions is not yet implemented')
		-- TODO
	elseif instruction == 'acceptpathinfo' then
		if params == 'on' then
			-- TODO
		elseif params == 'off' and request_uri ~= request_relative_filepath then
			ngx.exit(404)
		end
	end
end

-- Replace server variables with their content
local replace_server_vars = function(str, track_used_headers)
	local result = str
	local svar, replace, first_five
	local used_headers = {}
	local whitelist = {
		['document_root'] = true,    -- %{DOCUMENT_ROOT}
		['server_addr'] = true,      -- %{SERVER_ADDR}
		['server_name'] = true,      -- %{SERVER_NAME}
		['server_port'] = true,      -- %{SERVER_PORT}
		['server_protocol'] = true,  -- %{SERVER_PROTOCOL}
		['https'] = true,            -- %{HTTPS}
		['remote_addr'] = true,      -- %{REMOTE_ADDR}
		['remote_host'] = true,      -- %{REMOTE_HOST}
		['remote_user'] = true,      -- %{REMOTE_USER}
		['remote_port'] = true,      -- %{REMOTE_PORT}
		['request_method'] = true,   -- %{REQUEST_METHOD}
		['request_filename'] = true, -- %{REQUEST_FILENAME}
		['query_string'] = true      -- %{QUERY_STRING}
	}
	for org_svar in str:gmatch('%%{([^}]+)}') do
		svar = org_svar:lower() -- Make it lowercase, which is nginx convention
		first_five = svar:sub(1,5):lower()
		replace = '' -- If variable is not found, use an empty string
		if first_five == 'http_' then -- %{HTTC_*}, e.g. %{HTTC_HOST}
			replace = ngx.var[svar] or ''
			if track_used_headers then
				table.insert(used_headers, (svar:sub(6):gsub('_', '-'):lower()))
			end
		elseif first_five == 'http:' then -- %{HTTP:*}, e.g. %{HTTP:Content-Type}
			svar = svar:sub(6):gsub('-','_'):lower()
			replace = ngx.var['http_'..svar] or ''
			if track_used_headers then
				table.insert(used_headers, (svar:gsub('_', '-')))
			end
		elseif first_five == 'time_' then -- %{TIME_*}, e.g. %{TIME_YEAR}
			svar = svar:sub(6)
			if svar == 'year' then
				replace = os.date('%Y')
			elseif svar == 'mon' then
				replace = os.date('%m')
			elseif svar == 'day' then
				replace = os.date('%d')
			elseif svar == 'hour' then
				replace = os.date('%H')
			elseif svar == 'min' then
				replace = os.date('%M')
			elseif svar == 'sec' then
				replace = os.date('%S')
			elseif svar == 'wday' then
				replace = os.date('%w')
			end
		elseif whitelist[svar] then
			replace = ngx.var[svar] or ''
		elseif svar == 'request_uri' then -- %{REQUEST_URI}
			-- Use ngx.var['uri'] to match the Apache convention since it doesn't contain the query string
			replace = ngx.var['uri']
		elseif svar == 'script_filename' then -- %{SCRIPT_FILENAME}
			replace = ngx.var['fastcgi_script_name']
			if not replace or replace == '' then
				replace = ngx.var['request_filename']
			else
				replace = (ngx.var['document_root']..'/'..script_filename):gsub('/+', '/')
			end
			replace = script_filename
		elseif svar == 'request_scheme' then -- %{REQUEST_SCHEME}
			replace = ngx.var['scheme']
		elseif svar == 'the_request' then -- %{THE_REQUEST}
			replace = ngx.var['request']
		elseif svar == 'ipv6' then -- %{IPV6}
			if not ngx.var['remote_addr']:match('^[0-9]+%.[0-9]+%.[0-9]+%.[0-9]+$') then
				replace = 'on'
			end
		elseif svar == 'time' then -- %{TIME}
			replace = os.date('%Y%m%d%H%M%S')
		end
		result = result:gsub('%%{'..org_svar..'}', replace)..''
	end
	if track_used_headers then
		return result, used_headers
	else
		return result
	end
end

-- Walk through all htaccess statements collected from all directories
local block_stack = {}
local block_level = 0
local block_ignore_mode = false
local block_ignore_until = 0
local tag_name, the_rest, last_tag
local current_dir
local stat_instructions_used = {}
local stat_blocks_used = {}
for statement in htaccess:gmatch('[^\r\n]+') do
	-- Trim leading whitespace
	statement = statement:gsub("^%s*", "");

	if statement:sub(1,1) == '#' then
		-- Comment, so ignore it
	elseif statement:sub(1,1) == '<' then
		-- handle blocks
		if statement:sub(2,2) ~= '/' then
			-- opening tag <...>
			tag_name = statement:match('^<([^%s>]+)'):lower()
			local attr = parse_attributes(statement:sub(string.len(tag_name)+2, string.len(statement)-1))
			local use_block = false
			if not block_ignore_mode then
				local inverted = false
				stat_blocks_used[tag_name] = true
				if tag_name == 'ifmodule' then
					local module = attr[1]:lower()
					if module:sub(1,1) == '!' then
						inverted = true
						module = module:sub(2)
					end
					local supported_modules = {
						['rewrite'] = true,
						['alias'] = true,
						['mime'] = true,
						['core'] = true,
						['authn_core'] = true,
						['authn_file'] = true,
						['authz_core'] = true,
						['access_compat'] = true,
						['version'] = true
					}
					module = module:gsub('^mod_', ''):gsub('_module$', ''):gsub('%.c$', '')
					if supported_modules[module] then
						use_block = true
					else
						use_block = false
					end
				elseif tag_name == 'ifdirective' then
					local directive = attr[1]:lower()
					if directive:sub(1,1) == '!' then
						inverted = true
						directive = directive:sub(2)
					end
					if directive and stat_instructions_used[directive] then
						use_block = true
					else
						use_block = false
					end
				elseif tag_name == 'ifsection' then
					local block = attr[1]:lower()
					if block:sub(1,1) == '!' then
						inverted = true
						block = block:sub(2)
					end
					if block and stat_blocks_used[block] then
						use_block = true
					else
						use_block = false
					end
				elseif tag_name == 'iffile' then
					local file = attr[1]
					if file:sub(1,1) == '!' then
						inverted = true
						file = file:sub(2)
					end
					if path_exists(file, true) then
						use_block = true
					else
						use_block = false
					end
				elseif tag_name == 'files' or tag_name == 'filesmatch' then
					use_block = false
					local regex = false
					local test = attr[1]
					if tag_name == 'filesmatch' then
						regex = true
					elseif attr[1] == '~' then
						regex = true
						test = attr[2]
					end
					if regex then
						if ngx.re.match(request_filename, test) then
							use_block = true
							-- TODO: Add match as environment variable
							-- <FilesMatch "^(?<sitename>[^/]+)"> ==> %{env:MATCH_SITENAME}
						end
					elseif request_filename == test or request_filename:match(test:gsub('%.', '%.'):gsub('%?', '.'):gsub('*', '.+')) then
						use_block = true
					end
				elseif tag_name == 'limit' or tag_name == 'limitexcept' then
					if tag_name == 'limitexcept' then
						inverted = true
					end
					local method = ngx.var['request_method']
					local matches = false
					for _, limit in ipairs(attr) do
						if limit == method then
							matches = true
							break
						end
					end
					use_block = matches
				elseif tag_name == 'ifversion' then
					local simulated_version = '2.4.0' -- Assume Apache version
					local cmp = '='
					local test = attr[1]
					if attr[2] then
						cmp = attr[1]
						test = attr[2]
						if cmp:sub(1,1) == '!' then
							inverted = true
							cmp = cmp:sub(2)
						end
					end
					local regex = false
					if test:match('^/') and test:match('/$') then
						regex = true
						test = test:sub(2):sub()
					elseif cmp == '~' then
						regex = true
					end
					if regex then
						use_block = ngx.re.match(simulated_version, test)
					else
						local convert_version = function(version) -- calculate a single number out of version string
							version = tostring(version):gmatch('[0-9]+')
							local i = 0
							local total_version = 0
							for num in version do
								i = i + 1
								total_version = total_version + tonumber(num) * 1000000000 * (10 ^ -(i * 3))
							end
							return total_version
						end
						local my_version = convert_version(simulated_version)
						local test_version = convert_version(test)
						if cmp == '=' or cmp == '==' then
							use_block = (my_version == test_version)
						elseif cmp == '>' then
							use_block = (my_version > test_version)
						elseif cmp == '>=' then
							use_block = (my_version >= test_version)
						elseif cmp == '<' then
							use_block = (my_version < test_version)
						elseif cmp == '<=' then
							use_block = (my_version <= test_version)
						end
					end
				end
				if inverted then
					use_block = not use_block
				end
			end
			if use_block then
				push_ctx(tag_name, attr)
			elseif not block_ignore_mode then
				block_ignore_mode = true
				block_ignore_until = block_level
			end
			table.insert(block_stack, tag_name) -- push tag to block stack for tracking opening and closing tags (syntax check)
			block_level = block_level + 1
		else
			-- closing tag </...>
			tag_name = statement:match('^</([^>%s]+)'):lower()
			last_tag = table.remove(block_stack) -- pop last tag from block stack
			if last_tag ~= tag_name then
				fail('.htaccess syntax error: Closing </'..tag_name..'> without opening tag')
			end
			block_level = block_level - 1
			if block_ignore_mode then
				if block_level == block_ignore_until then
					block_ignore_mode = false
					block_ignore_until = 0
				end
			else
				pop_ctx()
			end
		end

	else
		local instruction = statement:match('^[^%s]+')
		if instruction then
			instruction = instruction:lower() -- directive (lower case)
			local params_cs = trim(statement:sub(instruction:len()+1)) -- case sensitive directive parameters
			if instruction == C_DIR then -- virtual directive handing over file path of original .htaccess file
				-- new .htaccess file - reset all block awareness features
				block_stack = {}
				block_level = 0
				block_ignore_mode = false
				block_ignore_until = 0
				reset_ctx() -- start with blank contexts
				push_ctx(C_DIR, params_cs)
				current_dir = params_cs
			elseif not block_ignore_mode then
				stat_instructions_used[instruction] = true
				parse_htaccess_directive(instruction, params_cs, current_dir)
			end
		end
	end
end

-- Execute parsed instructions
if get_cdir('deny') then
	ngx.exit(403)
end

-- Actual rewriting
local parsed_rewriterules = get_cdir('rewriterules', C_MULTIPLE)
-- Skip rewrite handling if no rules found
if get_cdir('rewrite') and #parsed_rewriterules > 0 then

	-- Rewrite handling
	local uri = request_uri:sub(2) -- Remove leading '/' to match RewriteRule behaviour within .htaccess files
	local dir, base, relative_uri, conds, regex, dst, flags, inverted, matches, cond_met, cond_test, cond_expr, cond_pattern, cond_flags, cond_inverted, cond_matches, cond_vary_headers, used_headers, flag, flag_value, regex_options
	local redirect = false
	local always_matches = {['^']=true, ['.*']=true, ['^.*']=true, ['^.*$']=true}
	local skip = 0
	for _, ruleset in ipairs(parsed_rewriterules) do
		if skip > 0 then
			skip = skip - 1
			goto next_ruleset
		end
		dir = ruleset[1]
		base = ruleset[2] or dir
		if uri:sub(1, base:len()) ~= base then
			goto next_ruleset
		end
		redirect = false
		relative_uri = uri:sub(base:len()+1)
		conds = ruleset[3]
		regex = ruleset[4][1]
		dst = ruleset[4][2]:gsub('%?$', '', 1) -- Make sure destination doesn't end on '?', as request_uri will never match that
		flags = ruleset[4][3]
		inverted = ruleset[4][4]
		-- RewriteCond handling
		cond_met = true
		cond_vary_headers = {}
		if conds then
			for _, condset in ipairs(conds) do
				cond_test = condset[1]
				if cond_test:lower() == 'expr' then
					cond_expr = true
				else
					cond_expr = false
					cond_test, used_headers = replace_server_vars(cond_test, true)
					if used_headers and #used_headers > 0 then
						for _, h in pairs(used_headers) do
							cond_vary_headers[h] = true
						end
					end
				end
				cond_pattern = condset[2]
				cond_inverted = condset[4]
				cond_flags = {}
				regex_options = ''
				if condset[3] then
					for _, flag in pairs(condset[3]) do
						flag = flag:lower()
						if flag == 'nocase' then -- [NC]
							flag = 'nc'
						elseif flag == 'ornext' then -- [OR]
							flag = 'or'
						elseif flag == 'novary' then -- [NV]
							flag = 'nv'
						end
						cond_flags[flag] = true
					end
				end
				if cond_flags['nc'] then
					regex_options = 'i'
				end
				if cond_expr then -- 'expr' conditions
					fail('RewriteCond expressions ("expr ...") are unsupported') -- We don't support expr style conditions due to their weird complexity and redundancy
				elseif cond_pattern:sub(1,1) == '-' then -- File attribute tests or integer comparisons (case sensitive)
					local filepath = cond_test:gsub('/$','',1)
					local file_type = get_file_type(filepath)

					cond_matches = false

					if cond_pattern == '-d' then -- is directory
						cond_matches = file_type == 'directory'
					elseif cond_pattern == '-f' or cond_pattern == '-F' then -- is file
						cond_matches = file_type == 'file'
					elseif cond_pattern == '-l' or cond_pattern == '-L' then -- is symlink
						cond_matches = file_type == 'link'
					else
						fail('RewriteCond pattern unsupported: '..cond_pattern)
					end
				elseif cond_pattern:match('^[<>=]') then -- Lexicographical string comparisons
					local comparison_operator = cond_pattern:match('^([=<>]+)');
					local expression_to_compare = cond_pattern:gsub('^([=<>]+)', '');
					if (comparison_operator == '=') then
						cond_matches = cond_test == expression_to_compare
					elseif (comparison_operator == '<') then
						cond_matches = cond_test < expression_to_compare
					elseif (comparison_operator == '>') then
						cond_matches = cond_test > expression_to_compare
					elseif (comparison_operator == '<=') then
						cond_matches = cond_test <= expression_to_compare
					elseif (comparison_operator == '>=') then
						cond_matches = cond_test >= expression_to_compare
					else
						fail('RewriteCond lexicographical string pattern unsupported: '..cond_pattern)
					end
				else
					cond_matches = ngx.re.match(cond_test, cond_pattern, regex_options)
				end
				if cond_inverted then
					cond_matches = not cond_matches
				end
				if cond_matches then
					cond_met = true
					if cond_flags['or'] then
						goto handle_conds
					end
				else
					cond_met = false
					if not cond_flags['or'] then
						goto next_ruleset
					end
				end
				-- Add "Vary" header if no [NV] flag is present and headers have been used
				if not cond_flags['nv'] then
					local vary = false
					for h, _ in pairs(cond_vary_headers) do
						h = h:sub(1, 1):upper()..h:sub(2):gsub('-%l', string.upper) -- Uppercase header words
						if vary then
							vary = vary..', '..h
						else
							vary = h
						end
					end
					if vary then
						ngx.header['Vary'] = vary
					end
				end
			end
		end
		::handle_conds::
		if not cond_met then
			goto next_ruleset
		end
		-- Flag handling
		regex_options = ''
		local flag_fns = {} -- These functions are being called once rule is matched
		if flags then
			for _, rawflag in pairs(flags) do
				flag = rawflag:match('^[^=]+'):lower() -- flags are case insensitive
				flag_value = ''
				if flag then
					if flag:len() < rawflag:len() then
						flag_value = rawflag:sub(flag:len()+2)
					end
					if flag == 'nc' or flag == 'nocase' then -- [NC]
						regex_options = regex_options..'i'
					elseif flag == 'co' or flag == 'cookie' then -- [CO=NAME:VALUE:DOMAIN:lifetime:path:secure:httponly]
						table.insert(flag_fns, {
							val = flag_value,
							fn = function(val)
								if not val then
									return
								end
								local separator = ':'
								if val:sub(1,1) == ';' then
									separator = ';'
									val = val:sub(2)
								end
								stubs = {}
								for stub in val:gmatch('[^'..separator..']+') do
									table.insert(stubs, stub)
								end
								if not stubs[1] or not stubs[2] then return end
								local cookie = stubs[1]..'='..stubs[2]
								if not stubs[3] then goto set_cookie end
								cookie = cookie..'; Domain='..stubs[3]
								if not stubs[4] then goto set_cookie end
								cookie = cookie..'; Expires='..ngx.cookie_time(ngx.time() + stubs[4]*60)
								if not stubs[5] then goto set_cookie end
								cookie = cookie..'; Path='..stubs[5]
								if not stubs[6] then goto set_cookie end
								if ({['1'] = true, ['secure'] = true, ['true'] = true})[stubs[6]:lower()] then
									cookie = cookie..'; Secure'
								end
								if not stubs[7] then goto set_cookie end
								if ({['1'] = true, ['httponly'] = true, ['true'] = true})[stubs[7]:lower()] then
									cookie = cookie..'; HttpOnly'
								end
								::set_cookie::
								ngx.header['Set-Cookie'] = cookie
							end
						})
					elseif flag == 'l' or flag == 'last' then -- [L]
						-- TODO: Jump to next htaccess in any subdirectory
						table.insert(flag_fns, {
							fn = function()
								cache_set(trace_id, C_STATUS_VOID) -- Mark request as void
							end
						})
					elseif flag == 'end' then -- [END]
						table.insert(flag_fns, {
							fn = function()
								cache_set(trace_id, C_STATUS_VOID) -- Mark request as void
							end
						})
					elseif flag == 'bnp' or flag == 'backrefnoplus' then -- [BNP]
						-- Do nothing, we're gonna use '%20' instead of '+' anyway
					elseif flag == 'f' or flag == 'forbidden' then -- [F]
						redirect = 403
					elseif flag == 'g' or flag == 'gone' then -- [F]
						redirect = 410
					elseif flag == 'r' or flag == 'redirect' then -- [R]
						if flag_value:match('^[0-9]+$') then
							redirect = tonumber(flag_value)
						else
							redirect = 302
						end
					elseif flag == 'qsa' or flag == 'qsappend' then -- [QSA]
						local qs = org_request_uri:match('%?.*')
						if qs then
							local new_qs = dst:match('%?.*')					
							if new_qs then
								dst = dst:gsub('%?.*', '', 1)..qs..'&'..new_qs:sub(2)
							end
						end
					elseif flag == 'qsd' or flag == 'qsdiscard' then -- [QSD]
						-- No-op, since relative_uri doesn't contain the query string anyway
					elseif flag == 's' or flag == 'skip' then -- [S=n]
						if flag_value:match('^[0-9]+$') then
							skip = flag_value
						else
							fail('Invalid flag value: ['..rawflag..'], expecting a number')
						end
					elseif flag == 'e' then -- [E=]
						-- Trying to set or unset an environment variable
						-- https://httpd.apache.org/docs/2.4/rewrite/flags.html
						fail('RewriteRule flag E is unsupported')
					else
						fail('Unsupported RewriteRule flag: '..flag)
					end
				end
			end
		end
		-- Match handling
		if always_matches[regex] then
			matches = true
		else
			matches = ngx.re.match(relative_uri, regex, regex_options)
		end
		if inverted then
			matches = not matches -- Invert matches
		end
		if matches then
			-- Perform flag operations on match
			for _, flag in pairs(flag_fns) do
				flag['fn'](flag['val'])
			end
			if dst ~= '-' then -- '-' means don't perform a rewrite
				dst = replace_server_vars(dst) -- Apply server variables
				if type(matches) == 'table' then
					-- Replace captured strings from RewriteRule ($n) in dst
					for i, match in ipairs(matches) do
						dst = dst:gsub('%$'..i, match:gsub('%%', '%%%%')..'') -- make sure no capture indexes are being used as replacement
					end
				end
				if type(cond_matches) == 'table' then
					-- Replace captured strings from RewriteCond (%n) in dst
					for i, match in ipairs(cond_matches) do
						dst = dst:gsub('%%'..i, match:gsub('%%', '%%%%')..'') -- make sure no capture indexes are being used as replacement
					end
				end
				if (not redirect or not dst:match('^https?://')) and dst:sub(1,1) ~= '/' then
					dst = '/'..base..dst
				end
				if dst:match('%.%.') then
					fail('Parent directory selector /../ not allowed in RewriteRule for security reasons')
				end
				if request_uri ~= dst then
					if redirect then
						-- Perform an external redirect or final HTTP status
						if redirect > 300 and redirect < 400 then
							ngx.redirect(dst, redirect)
						else
							ngx.exit(redirect)
						end
					else
						-- Perform an internal subrequest
						cache_set(htaccess_cache_key, htaccess, 0.1) -- Cache htaccess lines right before subrequest
						ngx.exec(dst)
					end
				end
			end
		end
		::next_ruleset::
	end

end

-- Execute directives other than RewriteRule

-- Add Content-Type header according to AddType
if request_fileext ~= nil then
	local contenttype = get_cdir('contenttypes', request_fileext)
	if contenttype ~= nil then
		ngx.header['Content-Type'] = contenttype
	end
end

-- ErrorDocument handling
if false then -- TODO: Check if file exists or access denied... how to do that?
	local status = 404
	local response = get_cdir('errordocs', status)
	if response then
		if response:sub(1,1) == '/' then
			-- URI request
			ngx.exec(response)
		else
			if response:match('^https?://') and not response:match('%s') then
				-- Internal redirect
				ngx.status = status
				ngx.redirect(response)
			else
				-- String output
				ngx.status = status
				ngx.print(response)
				ngx.exit(status)
			end
		end
	else
		ngx.exit(status)
	end
end
