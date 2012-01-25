require 'krypt'
require_relative 'resources'
require 'stringio'
require 'pp'

value = '01010101'
asn1 = Krypt::ASN1::BitString.new([value.reverse].pack('b*').reverse)
pp asn1
pp asn1.value
puts asn1.unused_bits
pp asn1.to_der
puts asn1.to_der == "\x03\x02\x00\x55" 
