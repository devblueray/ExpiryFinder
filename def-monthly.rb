require 'whois'
require 'trollop'
require 'httpclient'
require 'net/smtp'
require 'domainatrix'

def mailer(domMsg,certMsg,domain,user,pass,*arrDst)
  smtp = Net::SMTP.new 'smtp.gmail.com', 587
  smtp.enable_starttls
  smtp.start(domain,user,pass, :login) do |smtp|
    smtp.open_message_stream(user,arrDst) do |f|
      f.puts 'Subject: Domains and/or Certificates Expiring soon'
      f.puts "DOMAINS\n\n"
      domMsg.each {|d| f.puts d}
      f.puts "\n\nCERTIFICATES\n\n"
      certMsg.each {|c| f.puts c}
    end
  end
end

opts = Trollop::options do
  opt :sites, 'Enter domain to test', :type=> :string, :short=>'-s', :multi=>true
  opt :time, 'Enter time till warn in days', :type=> :integer, :short => '-t', :default=> 60
  opt :domain, 'Enter gapps domain', :type => :string, :short=> '-d'
  opt :user, 'enter gmail username', :type=> :string, :short => '-u'
  opt :pass, 'enter gmail password', :type=> :string, :short => '-p'
  opt :dest, 'Enter recipients', :type => :string, :multi => true, :short=> '-r'
end
domMsg=[]
certMsg=[]


opts[:sites].each do |d|
  begin
    url = Domainatrix.parse(d)
    if Whois::whois(url.domain_with_public_suffix).expires_on - Time.now > opts[:time] *24*60*60
      domMsg << "#{url} is ok"
    else
      domMsg << "#{url.domain_with_public_suffix} IS EXPIRING IN LESS THAN #{opts[:time]} days\n"
    end

    if HTTPClient.new.get("https://#{d}").peer_cert.not_after - Time.now > opts[:time]*24*60*60
      certMsg << "#{d} is ok"
    else
      certMsg << "#{d} CERTIFICATE EXPIRING EXPIRING IN LESS THAN #{opts[:time]} days\n"
    end
  rescue Errno::ETIMEDOUT

  end
end

mailer(domMsg,certMsg,opts[:domain],opts[:user],opts[:pass],opts[:dest]) unless [domMsg,certMsg].all? {|m| m.empty?}






