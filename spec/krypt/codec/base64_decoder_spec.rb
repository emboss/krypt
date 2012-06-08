require 'rspec'
require 'krypt'
require 'stringio'

describe Krypt::Base64::Decoder do 

  let(:klass) { Krypt::Base64::Decoder }

  def write_string(s)
    io = StringIO.new
    b64 = klass.new(io)
    b64 << s
    b64.close
    io.string
  end

  describe "new" do
    it "mandates a single parameter, the underlying IO" do
      klass.new(StringIO.new).should be_an_instance_of klass
    end
  end

  describe "#write" do
    context "RFC 4648 test vectors" do
      specify "empty string" do
        write_string("").should == ""
      end

      specify "f" do
        write_string("Zg==").should == "f"
      end

      specify "fo" do
        write_string("Zm8=").should == "fo"
      end

      specify "foo" do
        write_string("Zm9v").should == "foo"
      end

      specify "foob" do
        write_string("Zm9vYg==").should == "foob"
      end

      specify "fooba" do
        write_string("Zm9vYmE=").should == "fooba"
      end

      specify "foobar" do
        write_string("Zm9vYmFy").should == "foobar"
      end
    end
  end

end unless RUBY_PLATFORM =~ /java/ # TODO
