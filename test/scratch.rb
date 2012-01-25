require 'krypt'
require_relative 'resources'
require 'stringio'
require 'pp'

t = Time.utc(2012, 1, 24, 0, 0, 0).to_i
#t = Time.utc(2012, 1, 25, 0, 0, 0)
puts t
asn1 = Krypt::ASN1::UTCTime.new(t)

pp asn1
pp asn1.to_der

