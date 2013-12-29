require 'whois'
require 'trollop'
require 'httpclient'
require 'net/smtp'
require 'domainatrix'

class DomainChecker

  def whois(time,sites)
    cnt = 0
    domMsg=[]
    siteList=[]
    if sites.count == 1 && File.exists?(sites.first)
      File.open(sites.first,"r") do |file|
        while line = file.gets
        siteList << line.chomp
        end
       end
    else
      siteList = sites
    end

    siteList.each do |s|
    begin
      r = Whois::whois(s)
    rescue Errno::ETIMEDOUT
      next
    rescue Errno::ECONNRESET
      next
    end
      puts r.expires_on

    p "#{s}: #{r.expires_on}"
    if r.expires_on - Time.now > time*24*60*60
        domMsg << "#{s} is ok (Whois reports: #{r.expires_on})\n"
    else
        cnt += 1
        p cnt
        domMsg << "#{s} IS EXPIRING IN LESS THAN #{time} days (Whois reports: #{r.expires_on})\n"
      end
    end
    return cnt,domMsg
  end

  def certCheck(time,sites)
    cnt = 0
    certMsg=[]
    sites.each do |s|
      begin
        expiry = HTTPClient.new.get("https://#{s}").peer_cert.not_after
      rescue Errno::ETIMEDOUT
        next
      rescue Errno::ECONNRESET
        next
      end
     expiry = HTTPClient.new.get("https://#{s}").peer_cert.not_after
     if expiry - Time.now > time*24*60*60
        certMsg << "#{s} certificate is ok (Certificate reports #{expiry})\n"
     else
       cnt += 1
        certMsg << "#{s} CERTIFICATE EXPIRING EXPIRING IN LESS THAN #{time} days (Certificate reports #{expiry})\n"
      end


    end
    return cnt,certMsg
  end

  def mailer(domCount,domMsg,certCount,certMsg,arrDst)
    recpients = arrDst.join(",")
    domains = domMsg.join("\r")
    certs = certMsg.join("\r")
    smtp = Net::SMTP.start('localhost',25)
    msgstr = <<EOM
From: Prodege Domain Alerts <domalerts@prodege.com>
To: #{recpients}
Subject: #{domCount} Domains and #{certCount} Certificates Expiring Soon

DOMAINS
#{domains}

CERTIFICATES
#{certs}
EOM
    smtp.send_message msgstr,'domalerts@prodege.com',arrDst
    smtp.finish
    end
end

opts = Trollop::options do
  opt :sites, 'Enter domain to test', :type=> :string, :short=>'d', :multi=>true
  opt :time, 'Enter time till warn in days', :type=> :integer, :short => '-t', :default=> 60
  opt :dest, 'Enter recipients', :type => :string, :multi => true, :short=> '-r'
  opt :cert, 'Enter domain or cert file to test', :type=> :string, :multi => true, :short=> '-s'
end

app = DomainChecker.new
s = app.whois(opts[:time],opts[:sites])
t = app.certCheck(opts[:time],opts[:cert])
m = app.mailer(s[0],s[1],t[0],t[1],opts[:dest])

