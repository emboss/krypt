require 'rspec'
require 'krypt'
require 'stringio'

describe Krypt::Base64::Encoder do 

  let(:klass) { Krypt::Base64::Encoder }

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
        write_string("f").should == "Zg=="
      end

      specify "fo" do
        write_string("fo").should == "Zm8="
      end

      specify "foo" do
        write_string("foo").should == "Zm9v"
      end

      specify "foob" do
        write_string("foob").should == "Zm9vYg=="
      end

      specify "fooba" do
        write_string("fooba").should == "Zm9vYmE="
      end

      specify "foobar" do
        write_string("foobar").should == "Zm9vYmFy"
      end
    end
  end

end unless RUBY_PLATFORM =~ /java/ # TODO
