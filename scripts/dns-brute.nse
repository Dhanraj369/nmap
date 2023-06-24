 local coroutine = require "coroutine"
local dns = require "dns"
local io = require "io"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
local target = require "target"
local rand = require "rand"

description = [[
Attempts to enumerate DNS hostnames by brute force guessing of common
subdomains. With the `dns-brute.srv` argument, dns-brute will also
try to enumerate common DNS SRV records.

Wildcard records are listed as "*A" and "*AAAA" for IPv4 and IPv6 respectively.
]]

author = "Cirrus"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery"}

-- Pre-scan rule to check if the necessary script argument is provided
prerule = function()
  if not stdnse.get_script_args("dns-brute.domain") then
    stdnse.debug1("Skipping '%s' %s, 'dns-brute.domain' argument is missing.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end
  return true
end

-- Host selection rule, all hosts are selected
hostrule = function(host)
  return true
end

-- Function to extract the domain name from the host
local function extract_domain_name(host)
  local name = stdnse.get_hostname(host)
  if name and name ~= host.ip then
    return string.match(name, "%.([^.]+%..+)%.?$") or string.match(name, "^([^.]+%.[^.]+)%.?$")
  else
    return nil
  end
end

-- Function to perform a DNS query for a specific record type
local function resolve(host, dtype)
  local status, result = dns.query(host, { dtype = dtype, retAll = true })
  return status and result or false
end

-- Iterator function to iterate over an array with start and end indices
local function array_iterator(array, start_index, end_index)
  return coroutine.wrap(function()
    for i = start_index, end_index do
      coroutine.yield(array[i])
    end
  end)
end

-- Metatable for DNS records
local record_mt = {
  __tostring = function(t)
    return ("%s - %s"):format(t.hostname, t.address)
  end
}

-- Function to create a DNS record object
local function create_record(hostname, address)
  local record = {
    hostname = hostname,
    address = address
  }
  setmetatable(record, record_mt)
  return record
end

-- Main function for thread execution to brute force hostnames
local function thread_main(domainname, results, name_iter)
  local condvar = nmap.condvar(results)
  for name in name_iter do
    for _, dtype in ipairs({"A", "AAAA"}) do
      local res = resolve(name .. '.' .. domainname, dtype)
      if res then
        table.sort(res)
        if results["*" .. dtype] ~= res[1] then
          for _, addr in ipairs(res) do
            local hostname = name .. '.' .. domainname
            if target.ALLOW_NEW_TARGETS then
              stdnse.debug1("Added target: " .. hostname)
              local status, err = target.add(hostname)
            end
            stdnse.debug2("Hostname: " .. hostname .. " IP: " .. addr)
            results[#
