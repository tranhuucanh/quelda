require "json"
require "open3"

# Scans one file with the quelda CLI. Only exit code 0 means valid.
def quelda_scan(path, policy: nil, timeout: 30)
  args = ["quelda", "scan", path]
  args += ["--policy", policy] if policy
  Open3.popen3(*args) do |stdin, stdout, stderr, wait|
    stdin.close
    out = Thread.new { stdout.read }
    Thread.new { stderr.read }
    unless wait.join(timeout)
      Process.kill("KILL", wait.pid)
      return { "valid" => false, "status" => "TIMEOUT" }
    end
    code = wait.value.exitstatus
    verdict = begin
      JSON.parse(out.value)
    rescue JSON::ParserError
      { "status" => "EXIT #{code}" }
    end
    verdict.merge("valid" => code == 0)
  end
end

if __FILE__ == $PROGRAM_NAME
  v = quelda_scan(ARGV.fetch(0))
  puts "valid=#{v['valid']} status=#{v['status']}"
end
