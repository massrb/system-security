#!/usr/bin/env ruby
require 'open3'
require 'json'

require 'optparse'

# Default: do not run sudo commands
options = {}

OptionParser.new do |opts|
  opts.banner = "Usage: security_audit.rb [options]"

  opts.on("-s", "--sudo", "Run privileged checks (requires sudo)") do
    options[:use_sudo] = true
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
end.parse!


##############################################
# CONFIGURATION
##############################################

SCREEN_KEYWORDS = [
  "screenshare", "screen share", "screen sharing",
  "screencapture", "screen capture",
  "CGDisplayStream", "CGDisplay",
  "control session"
]

HID_KEYWORDS = [
  "IOHIDPostEvent", "HID", "keystroke", "keyboard", "mouse",
  "input monitoring"
]

LOG_KEYWORDS = SCREEN_KEYWORDS + HID_KEYWORDS

##############################################
# TCC PERMISSIONS AUDIT
##############################################

TCC_DB = "/Library/Application Support/com.apple.TCC/TCC.db"
USER_TCC_DB = File.expand_path("~/Library/Application Support/com.apple.TCC/TCC.db")


##############################################
# UTILITIES
##############################################

def section(title)
  puts "\n\n=== #{title} ==="
end


##############################################
# 1. UNIFIED LOG SCAN (last 12h)
##############################################


LOG_OUTPUT = "unified_capture_audit.log"

class Audit

  def initialize(options)
    @use_sudo = options[:use_sudo]
  end

  def run(command)
    if !@use_sudo && command.strip.start_with?("sudo")
      return "[INFO] Skipped privileged command because @use_sudo is false: #{command}"
    end

    stdout, stderr, status = Open3.capture3(command)
    stdout
  end

  def analyze_log_dump
    section("Analyzing Unified Log Dump...")

    unless File.exist?(LOG_OUTPUT)
      puts "No log file found."
      return
    end

    size = File.size(LOG_OUTPUT)

    puts "Log file size: #{size} bytes"

    if size < 5000
      puts "Unified log output is small. Probably no suspicious activity."
      return
    end

    puts "Searching for suspicious entries..."

    process_counts = Hash.new(0)
    keyword_counts = Hash.new(0)

    File.foreach(LOG_OUTPUT) do |line|
      LOG_KEYWORDS.each do |kw|
        keyword_counts[kw] += 1 if line =~ /#{Regexp.escape(kw)}/i
      end
    end

    keyword_counts.each do |kw, count|
      puts " - '#{kw}' => #{count} matches" if count > 0
    end

    File.foreach("unified_capture_audit.log") do |line|
      if line =~ /\s+([\w.-]+)\[\d+\]\s+.*(HID|keyboard|mouse|screenshare|screencapture)/i
        process = $1
        process_counts[process] += 1
      end
    end

    puts "Top processes generating suspicious events:"
    process_counts.sort_by { |_,v| -v }.first(20).each do |proc, count|
      puts "#{proc}: #{count}"
    end
  end

  def scan_logs
    predicate = LOG_KEYWORDS.map {|k| %Q(eventMessage CONTAINS[c] "#{k}") }.join(" OR ")
    cmd = %Q(log show --last 12h --predicate '#{predicate}' > #{LOG_OUTPUT})

    section("Dumping Unified Log to #{LOG_OUTPUT}...")
    system(cmd)
    analyze_log_dump
  end

  def query_tcc(service)
    if File.exist?(USER_TCC_DB)
      return run(%Q(sqlite3 "#{USER_TCC_DB}" 'SELECT client FROM access WHERE service="#{service}" AND allowed=1;'))
    elsif File.exist?(TCC_DB)
      return run(%Q(sqlite3 "#{TCC_DB}" 'SELECT client FROM access WHERE service="#{service}" AND allowed=1;'))
    else
      return "(TCC database not accessible)"
    end
  end

  def audit_tcc
    section("TCC Permission Audit")

    {
      "Screen Recording" => "kTCCServiceScreenCapture",
      "Input Monitoring" => "kTCCServiceListenEvent",
      "Accessibility"    => "kTCCServiceAccessibility"
    }.each do |label, svc|
      puts "\n#{label}:"
      puts query_tcc(svc).strip
    end
  end

  ##############################################
  # PROCESS INSPECTION
  ##############################################

  def inspect_processes
    section("Running Processes + Unsigned Binary Detection")
    ps = run("ps aux")

    ps.each_line do |line|
      next if line =~ /USER|Google|Safari|kernel|WindowServer/
      if line =~ /\s([\w\/\.-]+)$/
        bin = $1
        next unless File.exist?(bin)

        sig = run(%Q(codesign -dv "#{bin}" 2>&1))
        if bin.match(/^\/Users\/laruenceguild\/Library\/Developer\/CoreSimulator\/Devices\/[^\/]+\/data\/var\/run\/launchd_bootstrap\.plist$/)
          note = "(xCode simulator - OK)"
        end


        if sig =~ /code object is not signed/
          puts "[UNSIGNED] #{bin} #{note}"
        end
      end
    end
  end

  ##############################################
  # ACTIVE EVENT TAP DETECTION
  ##############################################

  def detect_event_taps
    section("Active Event Taps (possible key/mouse monitoring)")
    output = run("ioreg -l | grep -i EventTap")

    if output.strip.empty?
      puts "No suspicious Event Taps detected"
    else
      puts output
    end
  end

  ##############################################
  # NETWORK CONNECTION AUDIT
  ##############################################

  def audit_network
    section("Network Connections (process → remote host)")
    conns = run("lsof -iTCP -sTCP:ESTABLISHED -nP")

    conns.each_line do |line|
      next if line =~ /Safari|Music|Cloud|mdns|Dropbox|Google|Teams/
      puts line
    end
  end

  ##############################################
  # PERSISTENCE CHECK
  ##############################################

  def check_persistence
    section("Persistence Mechanisms (LaunchAgents / Daemons / Login Items)")

    dirs = [
      "/Library/LaunchAgents",
      "/Library/LaunchDaemons",
      File.expand_path("~/Library/LaunchAgents"),
      File.expand_path("~/Library/LaunchDaemons")
    ]

    dirs.each do |dir|
      puts "\n#{dir}:"
      if Dir.exist?(dir)
        Dir.children(dir).each { |f| puts " - #{f}" }
      else
        puts "  (not found)"
      end
    end

    puts "\nLogin Items:"
    puts run("osascript -e 'tell application \"System Events\" to get the name of every login item'")
  end

  def check_sip
    section("System Integrity Protection (SIP)")
    sip_status = run("csrutil status").strip
    puts sip_status
  end

  def check_system_files
    section("System File Integrity Check")
    output = run("sudo /usr/libexec/repair_packages --verify --standard-pkgs /")
    if output.empty?
      puts "System files verified"
    else
      puts output
    end
  end

  def check_gatekeeper
    section("Gatekeeper Status")
    status = run("spctl --status").strip
    puts status
  end

  def check_unsigned_apps
    section("Unsigned Applications")
    apps = Dir.glob("/Applications/**/*.app")
    apps.each do |app|
      bin = File.join(app, "Contents/MacOS", File.basename(app, ".app"))
      next unless File.exist?(bin)
      sig = run(%Q(codesign -dv "#{bin}" 2>&1))
      puts "[UNSIGNED] #{bin}" if sig =~ /code object is not signed/
    end

    def audit_all_tcc
      section("Full TCC Permissions")
      db = File.expand_path("~/Library/Application Support/com.apple.TCC/TCC.db")
      return puts "TCC DB not found" unless File.exist?(db)
      query = "SELECT service, client, allowed FROM access;"
      output = run(%Q(sqlite3 "#{db}" '#{query}'))
      puts output
    end

    def audit_open_ports
      section("Listening TCP Ports")
      puts run("sudo lsof -iTCP -sTCP:LISTEN -nP")
    end

    def audit_active_connections
      section("Active TCP Connections")
      puts run("lsof -iTCP -sTCP:ESTABLISHED -nP")
    end

    def check_firewall
      section("Firewall Status")
      puts run("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
    end

    def check_cron
      section("User & System Cron Jobs")
      puts "User cron:"
      puts run("crontab -l")
      puts "\nSystem cron:"
      puts run("sudo crontab -l")
    end

    def check_known_adware
      section("Known Adware / PUP Paths")
      suspicious_paths = [
        "/Library/Application Support/Adobe",
        "/Library/LaunchAgents/com.genericadware.*",
        "~/Library/LaunchAgents/com.genericadware.*"
      ]
      suspicious_paths.each do |path|
        puts Dir.glob(path)
      end
    end

    def recent_launches
      section("Recent Launch Events (last 24h)")
      puts run("log show --last 1d --predicate 'eventMessage CONTAINS[c] \"launchd\"' | grep -v '(com.apple|Google|Adobe|Zoom)'")
    end

  end



  def exec
    ##############################################
    # MASTER EXECUTION
    ##############################################

    scan_logs
    audit_tcc
    inspect_processes
    detect_event_taps
    audit_network
    check_persistence
    check_sip
    check_system_files
    check_gatekeeper
    check_unsigned_apps
    audit_all_tcc
    audit_open_ports
    audit_active_connections
    check_firewall
    check_cron
    check_sip
    check_known_adware
    recent_launches

    puts "\n\n=== AUDIT COMPLETE ==="
  end

end

auditor = Audit.new(options)
auditor.exec




