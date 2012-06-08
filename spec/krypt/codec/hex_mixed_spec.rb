require 'rspec'
require 'krypt'
require 'stringio'

describe "Krypt::Hex integration" do 

  let(:dec) { Krypt::Hex::Decoder }
  let(:enc) { Krypt::Hex::Encoder }

  require_relative 'identity_shared'

  describe "Encoder and Decoder stacked on top of each other" do
    it_behaves_like "Identity codec", Krypt::Hex::Encoder, Krypt::Hex::Decoder
  end
end

