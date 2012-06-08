require 'krypt'
require_relative 'resources'
require 'openssl'
require 'stringio'
require 'pp'

io = StringIO.new("test")
codec = Krypt::Hex::Encoder.new(Krypt::Hex::Decoder.new(io))
result = ""
while (c = codec.read(1))
  result << c
end
p result

