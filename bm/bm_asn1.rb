require 'krypt'
require_relative 'resources'
require 'stringio'
require 'openssl'
require 'benchmark'

Benchmark.bm do |bm|

  cert = Resources.certificate
  [1000, 10_000, 100_000].each do |n|
    bm.report("Krypt::Asn1.decode String(n=#{n})") { n.times { Krypt::Asn1.decode(cert) } }
    bm.report("OpenSSL::Asn1.decode String(n=#{n})") { n.times { OpenSSL::ASN1.decode(cert) } }
    bm.report("Krypt::Asn1.decode File IO(n=#{n})") do 
      n.times do
        io = Resources.certificate_io
        Krypt::Asn1.decode(io)
        io.close
      end
    end
    bm.report("Krypt::Asn1.decode String from File IO(n=#{n})") do
      n.times do
        io = Resources.certificate_io
        Krypt::Asn1.decode(io.read)
        io.close
      end
    end
    bm.report("OpenSSL::X509::Certificate String(n=#{n})") { n.times { OpenSSL::X509::Certificate.new(Resources.certificate) } }
    puts
  end

end

