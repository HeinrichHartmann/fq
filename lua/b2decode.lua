local ffi = require 'ffi'
local noitll = ffi.load 'noit'

ffi.cdef [[
  int noit_check_log_b_to_sm(const char *, int, char ***, int);
  void free(void *);
]]


local log_nr = 0
function log(msg)
   log_nr = log_nr + 1
   print(string.format("%3.d: %s", log_nr, msg))
end

local function compose(A,B)
   return processor(function(msg, send)
      A(msg, function(Amsg) B(msg, send) end)
   end)
end

local function distribute(...)
   funcs = {...}
   return processor(function(msg, send)
      for _, f in ipairs(funcs) do
         f(msg, send)
      end
   end)
end

function processor(f)
   local o = {}
   local mt = {}
   mt.__add = distribute
   mt.__mul = compose
   mt.__call = function(self, msg, send)
      send = send or log
      return f(msg, send)
   end
   setmetatable(o, mt)
   return o
end

function filter(pattern)
   return processor(function(msg,send)
         if msg:match(pattern) then send(msg) end
   end)
end

function prefix(head)
   return processor(function(msg,send)
         send(head .. msg)
   end)
end

function prt()
   return processor(function(msg, send)
         print(msg) send(msg)
   end)
end

p = prefix(".") * filter("Y") * prefix(".") * filter("X")
p("AYXA")
p("AXA")
p("AYA")

function map(f)
   return processor(function(msg, send) send(f(msg)) end)
end

function mgsub(pattern, replacement)
   return map(function(msg) return string.gsub(msg, pattern, replacement) end)
end

mprint = processor(function(msg,send) print(msg) end)

local extend = function(record, IP) return record:gsub("^([^\t]+)\t", "%1\t".. IP .. "\t") end
local decode_b2 = function(msg, send)
   if msg:match("^B2\t") then
      local IP = msg:gsub("^[^\t]+\t([^\t]+)\t.*", "%1") -- extract IP, 2nd field
      local charptrptr = ffi.new("char**[?]", 1)
      local cnt = noitll.noit_check_log_b_to_sm(msg, msg:len(), charptrptr, 1)
      for i = 0, cnt-1 do
         send(extend(ffi.string(charptrptr[0][i]), IP))
         ffi.C.free(charptrptr[0][i])
      end
      if cnt > 0 then ffi.C.free(charptrptr[0]) end
   else
      send(msg)
   end
end

-- return mult(add(match("X"), prt), add(match("Y"), prt))
-- return msub("^","Hi")
return decode_b2
