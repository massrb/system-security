#!/usr/bin/env ruby
require 'open3'
require 'json'

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

def run(command)
  stdout, stderr, status = Open3.capture3(command)
  stdout
end

##############################################
# 1. UNIFIED LOG SCAN (last 12h)
##############################################


LOG_OUTPUT = "unified_capture_audit.log"

class Audit

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

    puts "\n\n=== AUDIT COMPLETE ==="
  end

  auditor = Audit.new
  auditor.exec

end




