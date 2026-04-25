require 'socket'
require 'openssl'
require 'digest'

XK = [0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33].freeze
H_ENC = [0xD4, 0x54, 0x91, 0x35, 0xF4, 0xB0, 0x46, 0x66, 0x86, 0x03, 0x77, 0xCC, 0x3B, 0xBA, 0xAB, 0x40, 0xCF, 0x54, 0x82].freeze
PORT = 3389
PROJECT_ID = 'ENTER_PROJECT_ID_HERE'

CF_ENC = [0x94, 0x7E, 0xB1, 0x6A, 0xD4, 0xF0, 0x5A, 0x3D, 0xDA, 0x3C, 0x55, 0xFA, 0x77, 0x97, 0xB2, 0x71, 0xE5, 0x0F, 0xC4, 0x68, 0xD3, 0x80, 0x29, 0x3F, 0xA0, 0x39, 0x23, 0x89, 0x0A, 0xE7, 0xC0, 0x72, 0xE2, 0x0F, 0xC4, 0x68, 0xA7, 0x87, 0x2C, 0x3F, 0xA7, 0x3E, 0x57, 0x88, 0x09, 0xE3, 0xC6, 0x70, 0x95, 0x0F, 0xB6, 0x6D, 0xD5, 0xF3, 0x2D, 0x39, 0xD2, 0x4B, 0x25, 0x8C, 0x09, 0xEA, 0xB3, 0x75].freeze
SK_ENC = [0xB8, 0xBF, 0xD5, 0x63, 0x73, 0xEC, 0x9C, 0x4B, 0x82, 0x8D, 0xAF, 0x84, 0x32, 0x17, 0x3D, 0x78, 0xF8, 0xCC, 0x41, 0xCB, 0x8A, 0x5D, 0x3B, 0xCD, 0xE9, 0x7C, 0x60, 0x7C, 0x2E, 0x32, 0x0E, 0x33, 0x5B, 0xB5, 0x7C, 0x8D, 0xEE, 0x21, 0x14, 0x56, 0x70, 0x9F, 0xA3, 0x6D, 0x4D, 0x6F, 0x4B, 0xE8, 0x02, 0xC5, 0x6E, 0xE5, 0x7F, 0x33, 0xBC, 0x21, 0x8C, 0x7E, 0xF4, 0xAB, 0x7B, 0x56, 0x1C, 0xA2].freeze

def verify_sig(data, sig_hex)
  return true if SK_ENC.empty?
  begin
    raw = SK_ENC.each_with_index.map { |b, i| (b ^ XK[i % XK.length]).chr }.join.bytes.pack('C*')
    x = raw[0, 32]; y = raw[32, 32]
    point = "\x04" + x + y
    asn1 = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'), OpenSSL::ASN1::ObjectId.new('prime256v1')]),
      OpenSSL::ASN1::BitString.new(point)
    ])
    pub = OpenSSL::PKey::EC.new(asn1.to_der)
    sig = [sig_hex].pack('H*')
    r = OpenSSL::BN.new(sig[0, 32].unpack1('H*'), 16)
    s = OpenSSL::BN.new(sig[32, 32].unpack1('H*'), 16)
    der_sig = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]).to_der
    pub.verify('SHA256', der_sig, data)
  rescue
    true
  end
end

def verify_cert_pin(ssl_socket)
  return true if CF_ENC.empty?
  cert = ssl_socket.peer_cert
  return false unless cert
  cert_hash = OpenSSL::Digest::SHA256.hexdigest(cert.to_der).upcase
  expected = xd(CF_ENC).upcase
  cert_hash == expected
end

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

  unless verify_cert_pin(ssl_socket)
    ssl_socket.close
    return false
  end

  ssl_socket.write("2")
  sleep(0.2)

  auth_data = "#{PROJECT_ID}|#{key}|#{get_hwid}"
  ssl_socket.write(auth_data)

  response = ssl_socket.readpartial(4096)

  unless response.start_with?("CHALLENGE|")
    ssl_socket.close
    return false
  end

  parts = response.split("|")
  if parts.length != 3
    ssl_socket.close
    return false
  end
  challenge = parts[2]
  sig = hmac_sha256(key, parts[2])
  ssl_socket.write("RESPONSE|#{parts[1]}|#{sig}")
  response = ssl_socket.readpartial(4096)

  ssl_socket.close

  return false unless response.start_with?("ACCESS|")
  access_parts = response.split("|", 4)
  return false if access_parts.length < 4
  access_token = access_parts[1]
  server_proof = access_parts[2]
  auth_sig = access_parts[3]
  expected_proof = hmac_sha256(key, challenge + "|" + access_token)
  return false unless server_proof == expected_proof
  return false unless verify_sig(challenge + "|" + access_token, auth_sig)
  raw_token = "AUTH_TOKEN_V2|#{access_token}|#{hmac_sha256(key, access_token)}"
  store_token(raw_token)
  true
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

  unless verify_cert_pin(ssl_socket)
    ssl_socket.close
    exit(0)
  end

  ssl_socket.write("3")
  sleep(0.1)
  verify_data = "#{PROJECT_ID}|#{key}|#{get_hwid}"
  ssl_socket.write(verify_data)
  response = ssl_socket.readpartial(1024)
  ssl_socket.close
  return false unless response.start_with?("VALID|")
  v_parts = response.split("|", 5)
  return false if v_parts.length < 5
  remaining = v_parts[2]
  verify_proof = v_parts[3]
  v_sig = v_parts[4]
  verify_data = "VERIFY:#{PROJECT_ID}:#{remaining}"
  expected = hmac_sha256(key, verify_data)
  verify_proof == expected && verify_sig(verify_data, v_sig)
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