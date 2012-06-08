require 'rspec'
require 'krypt-core'

describe Krypt::Hex do 

  let(:mod) { Krypt::Hex }

  describe "encode" do
    context "single parameter data" do
      context "RFC 4648 test vectors" do
        specify "empty string" do
          mod.encode("").should == ""
        end

        specify "f" do
          mod.encode("f").should == "66"
        end

        specify "fo" do
          mod.encode("fo").should == "666f"
        end

        specify "foo" do
          mod.encode("foo").should == "666f6f"
        end

        specify "foob" do
          mod.encode("foob").should == "666f6f62"
        end

        specify "fooba" do
          mod.encode("fooba").should == "666f6f6261"
        end

        specify "foobar" do
          mod.encode("foobar").should == "666f6f626172"
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
