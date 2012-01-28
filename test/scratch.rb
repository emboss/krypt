require 'krypt'
require_relative 'resources'
require 'openssl'
require 'stringio'
require 'pp'

asn1 = Krypt::ASN1::Sequence.new([])
pp asn1.to_der

