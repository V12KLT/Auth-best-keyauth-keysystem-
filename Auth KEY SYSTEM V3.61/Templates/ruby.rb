require 'socket'
require 'openssl'
require 'digest'

XK = [0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33].freeze
H_ENC = [0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82].freeze
PORT = 3389
PROJECT_ID = 'ENTER_PROJECT_ID_HERE'

def xd(data)
  data.each_with_index.map { |b, i| (b ^ XK[i % XK.length]).chr }.join
end

def xe(input)
  input.bytes.each_with_index.map { |b, i| b ^ XK[i % XK.length] }
end

def fnv1a(data)
  h = 0x811C9DC5
  data.each { |b| h ^= b; h = (h * 0x01000193) & 0xFFFFFFFF }
  (h ^ 0xDEADBEEF) & 0xFFFFFFFF
end

$enc_token = nil
$token_canary = 0
$token_present = false
$token_mutex = Mutex.new

def store_token(token)
  $token_mutex.synchronize do
    $enc_token = xe(token)
    $token_canary = fnv1a($enc_token)
    $token_present = true
  end
end

def get_token
  $token_mutex.synchronize do
    return nil unless $token_present && $enc_token
    exit(0) if fnv1a($enc_token) != $token_canary
    xd($enc_token)
  end
end

def token_valid?
  token = get_token
  return false if token.nil? || token.empty?
  return false unless token.start_with?('AUTH_TOKEN_V2|')
  token.length > 22
end

def host
  xd(H_ENC)
end

def get_hwid
  case RUBY_PLATFORM
  when /mingw|mswin/
    begin
      uuid = `powershell -Command "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"`.strip
      return uuid unless uuid.empty? || uuid == 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'
      reg = `reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid`
      match = reg.match(/MachineGuid\s+REG_SZ\s+(.+)/)
      return match[1].strip if match
    rescue
    end
  when /linux/
    ['/sys/class/dmi/id/product_uuid', '/etc/machine-id'].each do |p|
      begin
        return File.read(p).strip if File.exist?(p)
      rescue
      end
    end
  when /darwin/
    begin
      output = `system_profiler SPHardwareDataType | grep "Hardware UUID"`
      match = output.match(/Hardware UUID: (.+)/)
      return match[1].strip if match
    rescue
    end
  end
  Socket.gethostname
rescue
  "UNKNOWN"
end

def check_bad_processes
  return unless RUBY_PLATFORM =~ /mingw|mswin/
  bad = %w[x64dbg x32dbg ollydbg ida ida64 wireshark fiddler charles
           httpdebugger processhacker procmon procexp dnspy de4dot cheatengine]
  begin
    output = `tasklist /FO CSV /NH`.downcase
    bad.each { |b| exit(0) if output.include?(b) }
  rescue
  end
end

def hmac_sha256(key, data)
  OpenSSL::HMAC.hexdigest('SHA256', key, data)
end

def authenticate(key)
  check_bad_processes

  h = host
  socket = TCPSocket.new(h, PORT)
  ssl_context = OpenSSL::SSL::SSLContext.new
  ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
  ssl_socket.hostname = h
  ssl_socket.connect

  ssl_socket.write("2")
  sleep(0.2)

  auth_data = "#{PROJECT_ID}|#{key}|#{get_hwid}"
  ssl_socket.write(auth_data)

  response = ssl_socket.readpartial(4096)

  if response.start_with?("CHALLENGE|")
    parts = response.split("|")
    if parts.length != 3
      ssl_socket.close
      return false
    end
    sig = hmac_sha256(key, parts[2])
    ssl_socket.write("RESPONSE|#{parts[1]}|#{sig}")
    response = ssl_socket.readpartial(4096)
  end

  ssl_socket.close

  if response.start_with?("ACCESS|")
    server_data = response[7..]
    raw_token = "AUTH_TOKEN_V2|#{server_data}|#{hmac_sha256(key, server_data)}"
    store_token(raw_token)
    return true
  end
  false
rescue
  false
end

def verify_session(key)
  return false unless token_valid?

  h = host
  socket = TCPSocket.new(h, PORT)
  ssl_context = OpenSSL::SSL::SSLContext.new
  ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
  ssl_socket.hostname = h
  ssl_socket.connect

  ssl_socket.write("3")
  sleep(0.1)
  verify_data = "#{PROJECT_ID}|#{key}|#{get_hwid}"
  ssl_socket.write(verify_data)
  response = ssl_socket.readpartial(1024)
  ssl_socket.close
  response.start_with?("VALID")
rescue
  false
end

def start_session_validation(key)
  Thread.new do
    failures = 0
    loop do
      sleep(60)
      check_bad_processes
      if verify_session(key)
        failures = 0
      else
        failures += 1
        exit(0) if failures >= 3
      end
    end
  end
end

check_bad_processes
print "Enter your license key: "
key = gets.chomp

if authenticate(key)
  puts "Authenticated."
  start_session_validation(key)
  sleep
else
  exit(1)
end