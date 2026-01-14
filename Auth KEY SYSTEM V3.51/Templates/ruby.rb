require 'socket'
require 'openssl'
require 'digest'

SERVER_HOST = 'socket.keyauth.shop'
SERVER_PORT = 3389
PROJECT_ID = 'ENTER_PROJECT_ID_HERE'

def get_hwid
  case RUBY_PLATFORM
  when /mingw|mswin/
    begin
      uuid = `powershell "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"`.strip
      return uuid unless uuid.empty? || uuid == 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'
      
      reg = `reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid`
      match = reg.match(/MachineGuid\s+REG_SZ\s+(.+)/)
      return match[1].strip if match
    rescue
    end
  when /linux/
    begin
      return File.read('/sys/class/dmi/id/product_uuid').strip if File.exist?('/sys/class/dmi/id/product_uuid')
      return `dmidecode -s system-uuid`.strip
    rescue
      return File.read('/etc/machine-id').strip if File.exist?('/etc/machine-id')
    end
  when /darwin/
    begin
      output = `system_profiler SPHardwareDataType | grep "Hardware UUID"`
      match = output.match(/Hardware UUID: (.+)/)
      return match[1].strip if match
    rescue
    end
  end
  require 'socket'
  Socket.gethostname
rescue
  "UNKNOWN"
end

def authenticate(key)
  begin
    socket = TCPSocket.new(SERVER_HOST, SERVER_PORT)
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
    ssl_socket.connect

    ssl_socket.write("2")
    sleep(0.2)

    hwid = get_hwid
    auth_data = "#{PROJECT_ID}|#{key}|#{hwid}"
    ssl_socket.write(auth_data)

    response = ssl_socket.read(1024)

    if response.start_with?("CHALLENGE|")
      parts = response.split("|")
      if parts.length == 3
        challenge_id = parts[1]
        challenge = parts[2]

        signature = OpenSSL::HMAC.hexdigest("SHA256", key, challenge)

        response_msg = "RESPONSE|#{challenge_id}|#{signature}"
        ssl_socket.write(response_msg)

        final_result = ssl_socket.read(1024)

        if final_result.start_with?("ACCESS|")
          puts "[KeyAuth] Authenticated."
          return true
        else
          puts "[KeyAuth] Refused: #{final_result}"
          return false
        end
      else
        puts "[KeyAuth] Invalid challenge format"
        return false
      end
    elsif response.start_with?("ACCESS|")
      puts "[KeyAuth] Authenticated."
      return true
    else
      puts "[KeyAuth] Refused: #{response}"
      return false
    end
  rescue => e
    puts "[KeyAuth] Connection error: #{e}"
    return false
  ensure
    ssl_socket.close if ssl_socket
  end
end

print "Enter your license key: "
key = gets.chomp

if authenticate(key)
  # Your program code here
else
  exit(1)
end