require 'krypt'
require_relative 'resources'
require 'stringio'
require 'pp'

int1 = Krypt::ASN1::Integer.new(1)
int2 = Krypt::ASN1::Integer.new(2)
int3 = Krypt::ASN1::Integer.new(3)

seq = Krypt::ASN1::Sequence.new([int1, int2, int3])

pp seq
pp seq.value
der = seq.to_der
pp der

asn1 = Krypt::ASN1.decode(der)
pp asn1
pp asn1.value
puts der == asn1.to_der
