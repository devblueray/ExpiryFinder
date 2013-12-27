require 'whois'
require 'trollop'
require 'httpclient'
require 'net/smtp'
require 'domainatrix'

class DomainChecker

  def whois(time,sites)
    domMsg=[]
    sites.each do |s|
      url = Domainatrix.parse(s)
        if Whois::whois(url.domain_with_public_suffix).expires_on - Time.now > time*24*60*60
        domMsg << "#{url.domain_with_tld} is ok"
      else
        domMsg << "#{url.domain_with_public_suffix} IS EXPIRING IN LESS THAN #{time} days\n"
      end
    end
    return domMsg
  end

  def certCheck(time,sites)
    certMsg=[]
    sites.each do |s|
     if HTTPClient.new.get("https://#{s}").peer_cert.not_after - Time.now > time*24*60*60
        certMsg << "#{s} certificate is ok"
      else
        certMsg << "#{s} CERTIFICATE EXPIRING EXPIRING IN LESS THAN #{time} days\n"
      end
    end
    return certMsg
  end

  def mailer(domMsg,certMsg,arrDst)
    recpients = arrDst.join(",")
    domains = domMsg.join("\r")
    certs = certMsg.join("\r")
    smtp = Net::SMTP.start('localhost',25)
    msgstr = <<EOM
From: Prodege Domain Alerts <domalerts@prodege.com>
To: #{recpients}
Subject: Domains and/or Certificates Expiring Soon

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

m = app.mailer(s,t,opts[:dest]) unless [s,t].all? {|m| m.empty?}

