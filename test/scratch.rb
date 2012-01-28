require 'krypt'
require_relative 'resources'
require 'openssl'
require 'stringio'
require 'pp'

pp Krypt::ASN1::EndOfContents.new(nil)
#-27066 "\x0A\x02\x96\x46"
#2**62-1 "\x0A\x08\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF" 

