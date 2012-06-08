require 'rspec'
require 'krypt-core'

describe Krypt::Base64 do 

  let(:mod) { Krypt::Base64 }

  describe "encode" do
    context "single parameter data" do
      context "RFC 4648 test vectors" do
        specify "empty string" do
          mod.encode("").should == ""
        end

        specify "f" do
          mod.encode("f").should == "Zg=="
        end

        specify "fo" do
          mod.encode("fo").should == "Zm8="
        end

        specify "foo" do
          mod.encode("foo").should == "Zm9v"
        end

        specify "foob" do
          mod.encode("foob").should == "Zm9vYg=="
        end

        specify "fooba" do
          mod.encode("fooba").should == "Zm9vYmE="
        end

        specify "foobar" do
          mod.encode("foobar").should == "Zm9vYmFy"
        end
      end

      it "should return a string with binary encoding" do
        mod.encode("test").encoding.should == Encoding::BINARY
      end

      it "should return a string with binary encoding even if
          the underlying encoding is not" do
        auml = [%w{ C3 A4 }.join('')].pack('H*')
        auml.force_encoding(Encoding::UTF_8)
        mod.encode(auml).encoding.should == Encoding::BINARY
      end
    end
  end
end unless RUBY_PLATFORM =~ /java/ # TODO

