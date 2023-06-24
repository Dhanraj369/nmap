local http = require "http"
local io = require "io"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
local target = require "target"

description = [[
Discovers hostnames that resolve to the target's IP address by querying the online database at http://www.bfk.de/bfk_dnslogger.html.

The script is in the "external" category because it sends target IPs to a third party in order to query their database.

This script was formerly (until April 2012) known as hostmap.nse.
]]

author = "Ange Gutek"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external", "discovery"}

-- Define the hostmap server
local HOSTMAP_SERVER = "www.bfk.de"

-- Function to write contents to a file
local function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end

-- Host selection rule: exclude private IP addresses
hostrule = function(host)
  return not ipOps.isPrivate(host.ip)
end

-- Main action function for querying hostnames
action = function(host)
  local query = "/bfk_dnslogger.html?query=" .. host.ip
  local response
  local output_tab = stdnse.output_table()
  response = http.get(HOSTMAP_SERVER, 80, query, { any_af = true })
  if not response.status then
    stdnse.debug1("Error: could not GET http://%s%s", HOSTMAP_SERVER, query)
    return nil
  end
  local hostnames = {}
  local hosts_log = {}
  for entry in string.gmatch(response.body, "#result\" rel=\"nofollow\">(.-)</a></tt>") do
    if not hostnames[entry] then
      if target.ALLOW_NEW_TARGETS then
        local status, err = target.add(entry)
      end
      hostnames[entry] = true
      hosts_log[#hosts_log + 1] = entry
    end
  end

  if #hosts_log == 0 then
    if not string.find(response.body, "<p>The server returned no hits.</p>") then
      stdnse.debug1("Error: found no hostnames but not the marker for \"no hostnames found\" (pattern error?)")
    end
    return nil
  end
  output_tab.hosts = hosts_log
  local hostnames_str = table.concat(hostnames, "\n")

  local filename_prefix = stdnse.get_script_args("hostmap-bfk.prefix")
  if filename_prefix then
    local filename = filename_prefix .. stringaux.filename_escape(host.targetname or host.ip)
    local status, err = write_file(filename, hostnames_str .. "\n")
    if status then
      output_tab.filename = filename
    else
      stdnse.debug1("Error saving to %s: %s\n", filename, err)
    end
  end

  return output_tab
end
