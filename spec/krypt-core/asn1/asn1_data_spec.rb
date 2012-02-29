require 'rspec'
require 'krypt-core'
require 'openssl'
require_relative './resources'
require_relative '../resources'

describe Krypt::ASN1::ASN1Data do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::ASN1Data }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::ASN1Data
    class << self
      alias old_new new
      def new(*args)
        if args.size > 1
          args = [args[0], args[1], :IMPLICIT, args[2]]
        end
        old_new(*args)
      end
    end
  end

  describe "#new" do
    context "requires exactly 3 arguments" do
      subject { klass.new(value, tag, tag_class) }

      context "accepts any object as value" do
        let(:value) { Object.new }
        let(:tag) { 14 }
        let(:tag_class) { :UNIVERSAL }
        its(:tag) { should == 14 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context "accepts nil as value" do
        let(:value) { nil }
        let(:tag) { 14 }
        let(:tag_class) { :UNIVERSAL }
        its(:tag) { should == 14 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == nil }
        its(:infinite_length) { should == false }
      end
    end

    context "raises ArgumentError for more or less arguments" do
      it { -> { klass.new }.should raise_error ArgumentError }
      it { -> { klass.new(5) }.should raise_error ArgumentError }
      it { -> { klass.new(5, 2) }.should raise_error ArgumentError }
      it { -> { klass.new(5, 2, :UNIVERSAL, 17) }.should raise_error ArgumentError }
    end

    context "gets explicit tag number as the 2nd argument" do
      subject { klass.new(nil, tag, :PRIVATE) }

      context "accepts tags in the UNIVERSAL range" do
        let(:tag) { Krypt::ASN1::BOOLEAN }
        its(:tag) { should == tag }
      end

      context "accepts custom tags" do
        let(:tag) { 42 }
        its(:tag) { should == tag }
      end

      context "does not accept nil as tag" do
        let(:tag) { nil }
        it { -> { subject }.should raise_error asn1error }
      end

      context "does not accept a non-Number as tag" do
        let(:tag) { Object.new }
        it { -> { subject }.should raise_error asn1error }
      end

    end

    context "gets tag class symbol as the 3rd argument" do
      subject { klass.new(true, 14, tag_class) }

      context "accepts :UNIVERSAL" do
        let(:tag_class) { :UNIVERSAL }
        its(:tag_class) { should == tag_class }
      end

      context "accepts :APPLICATION" do
        let(:tag_class) { :APPLICATION }
        its(:tag_class) { should == tag_class }
      end

      context "accepts :CONTEXT_SPECIFIC" do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        its(:tag_class) { should == tag_class }
      end

      context "accepts :PRIVATE" do
        let(:tag_class) { :PRIVATE }
        its(:tag_class) { should == tag_class }
      end

      context "does not accept unknown tag classes" do
        let(:tag_class) { :IMAGINARY }
        it { -> { subject }.should raise_error asn1error }
      end

      context "does not accept non-Symbols as tag class" do
        let(:tag_class) { 7 }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context "returns an instance of ASN1Data, despite of an 
             UNIVERSAL tag and tag class" do
      subject { klass.new("test", Krypt::ASN1::OCTET_STRING, :UNIVERSAL) }
      it { subject.should be_an_instance_of klass }
    end
  end

  describe Krypt::ASN1::Constructive, "#new" do
    let(:klazz) { mod::Constructive }

    context "requires exactly 3 arguments" do
      subject { klazz.new(value, tag, tag_class) }

      context "accepts any object as value" do
        let(:value) { Object.new }
        let(:tag) { 14 }
        let(:tag_class) { :UNIVERSAL }
        its(:tag) { should == 14 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context "accepts nil as value" do
        let(:value) { nil }
        let(:tag) { 14 }
        let(:tag_class) { :UNIVERSAL }
        its(:tag) { should == 14 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == nil }
        its(:infinite_length) { should == false }
      end
    end

    context "raises ArgumentError for more or less arguments" do
      it { -> { klazz.new }.should raise_error ArgumentError }
      it { -> { klazz.new(5) }.should raise_error ArgumentError }
      it { -> { klazz.new(5, 2) }.should raise_error ArgumentError }
      it { -> { klazz.new(5, 2, :UNIVERSAL, 17) }.should raise_error ArgumentError }
    end
  end

  describe Krypt::ASN1::Primitive, "#new" do
    let(:klazz) { mod::Primitive }

    context "requires exactly 3 arguments" do
      subject { klazz.new(value, tag, tag_class) }

      context "accepts any object as value" do
        let(:value) { Object.new }
        let(:tag) { 14 }
        let(:tag_class) { :UNIVERSAL }
        its(:tag) { should == 14 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context "accepts nil as value" do
        let(:value) { nil }
        let(:tag) { 14 }
        let(:tag_class) { :UNIVERSAL }
        its(:tag) { should == 14 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == nil }
        its(:infinite_length) { should == false }
      end
    end

    context "raises ArgumentError for more or less arguments" do
      it { -> { klazz.new }.should raise_error ArgumentError }
      it { -> { klazz.new(5) }.should raise_error ArgumentError }
      it { -> { klazz.new(5, 2) }.should raise_error ArgumentError }
      it { -> { klazz.new(5, 2, :UNIVERSAL, 17) }.should raise_error ArgumentError }
    end
  end

  describe "#to_der" do
    context "encodes UNIVERSAL tag values as if the equivalent primitive
             class was used" do
      subject { klass.new(value, tag, :UNIVERSAL).to_der }

      context "END_OF_CONTENTS" do
        let(:tag) { Krypt::ASN1::END_OF_CONTENTS }
        let(:value) { nil }
        it { should == Krypt::ASN1::EndOfContents.new().to_der }
      end

      context "BOOLEAN" do
        let(:tag) { Krypt::ASN1::BOOLEAN }
        let(:value) { true }
        it { should == Krypt::ASN1::Boolean.new(true).to_der }
      end

      context "PRINTABLE_STRING" do
        let(:tag) { Krypt::ASN1::PRINTABLE_STRING }
        let(:value) { "test" }
        it { should == Krypt::ASN1::PrintableString.new("test").to_der }
      end

      context "SEQUENCE" do
        let(:tag) { Krypt::ASN1::SEQUENCE }
        let(:value) { [Krypt::ASN1::Integer.new(1)] }
        it { should == Krypt::ASN1::Sequence.new([Krypt::ASN1::Integer.new(1)]).to_der }
      end

      context "SET" do
        let(:tag) { Krypt::ASN1::SET }
        let(:value) { [Krypt::ASN1::Integer.new(1)] }
        it { should == Krypt::ASN1::Set.new([Krypt::ASN1::Integer.new(1)]).to_der }
      end
    end

    context "expects raw byte strings for non-universal tags" do
      subject { klass.new(value, tag, tag_class).to_der }

      context ":PRIVATE tag class" do
        let(:tag_class) { :PRIVATE }
        let(:value) { "\xC0\xFF\xEE\xBA\xBE" }

        context "tag < 30" do
          let(:tag) { Krypt::ASN1::BOOLEAN }
          it { should == "\xC1\x05\xC0\xFF\xEE\xBA\xBE" }
        end

        context "tag > 30" do
          let(:tag) { 42 }
          it { should == "\xDF\x2A\x05\xC0\xFF\xEE\xBA\xBE" }
        end
      end

      context ":APPLICATION tag class" do
        let(:tag_class) { :APPLICATION }
        let(:value) { "\xC0\xFF\xEE\xBA\xBE" }

        context "tag < 30" do
          let(:tag) { Krypt::ASN1::BOOLEAN }
          it { should == "\x41\x05\xC0\xFF\xEE\xBA\xBE" }
        end

        context "tag > 30" do
          let(:tag) { 42 }
          it { should == "\x5F\x2A\x05\xC0\xFF\xEE\xBA\xBE" }
        end
      end

      context ":CONTEXT_SPECIFIC tag class" do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        let(:value) { "\xC0\xFF\xEE\xBA\xBE" }

        context "tag < 30" do
          let(:tag) { Krypt::ASN1::BOOLEAN }
          it { should == "\x81\x05\xC0\xFF\xEE\xBA\xBE" }
        end

        context "tag > 30" do
          let(:tag) { 42 }
          it { should == "\x9F\x2A\x05\xC0\xFF\xEE\xBA\xBE" }
        end
      end
    end

    context "decides dynamically whether to encode non-UNIVERSAL data
             as as constructed or a primitive encoding" do
      it "when constructing an implicitly 0-tagged BOOLEAN" do
        klass.new("\xFF", 0, :CONTEXT_SPECIFIC).to_der.should == "\x80\x01\xFF"
      end

      it "when constructing an explicitly 0-tagged BOOLEAN" do
        asn1 = klass.new([Krypt::ASN1::Boolean.new(true)], 0, :CONTEXT_SPECIFIC)
        asn1.to_der.should == "\xA0\x03\x01\x01\xFF"
      end

      it "when setting the value from a primitive value to an Enumerable" do
        asn1 = klass.new("\xFF", 0, :CONTEXT_SPECIFIC)
        asn1.to_der.should == "\x80\x01\xFF"
        asn1.value = [Krypt::ASN1::Boolean.new(true)]
        asn1.to_der.should == "\xA0\x03\x01\x01\xFF"
      end

      it "when setting the value from an Enumerable to a primitive value" do
        asn1 = klass.new([Krypt::ASN1::Boolean.new(true)], 0, :CONTEXT_SPECIFIC)
        asn1.to_der.should == "\xA0\x03\x01\x01\xFF"
        asn1.value = "\xFF"
        asn1.to_der.should == "\x80\x01\xFF"
      end
    end

    context "decides dynamically how to encode UNIVERSAL data" do
      subject { klass.new("\x01", 0, :CONTEXT_SPECIFIC) } 
      
      it "when resetting tag and value with a Primitive" do
        subject.to_der.should == "\x80\x01\x01"
        subject.tag = Krypt::ASN1::INTEGER
        subject.to_der.should == "\x82\x01\x01"
        subject.tag_class = :UNIVERSAL
        subject.value = 1
        subject.to_der.should == "\x02\x01\x01"
      end

      it "when resetting tag and value with a Constructive" do
        subject.to_der.should == "\x80\x01\x01"
        subject.tag = Krypt::ASN1::SEQUENCE
        subject.to_der.should == "\x90\x01\x01"
        subject.tag_class = :UNIVERSAL
        subject.value = [ Krypt::ASN1::EndOfContents.new ]
        subject.to_der.should == "\x30\x02\x00\x00"
      end
    end

    context "encodes infinite length tagged values" do
      subject do
        asn1 = klass.new(value, 0, :CONTEXT_SPECIFIC) 
        asn1.infinite_length = true
        asn1.to_der
      end

      context "SEQUENCE" do
        let(:value) { [mod::Integer.new(1), mod::EndOfContents.new] }
        it { subject.should == "\xA0\x80\x02\x01\x01\x00\x00" }
      end

      context "OCTET STRING" do
        let(:value) { [mod::OctetString.new("\x00"), mod::OctetString.new("\x01"), mod::EndOfContents.new] }
        it { subject.should == "\xA0\x80\x04\x01\x00\x04\x01\x01\x00\x00" }
      end
    end

    context "all STRING classes except BIT STRING and UTF8 STRING behave like OCTET STRING" do
      subject { decoder.decode(klazz.new("test").to_der).value == "test" }

      context "OCTET STRING" do
        let(:klazz) { mod::OctetString }
        it { should == true }
      end

      context "NUMERIC STRING" do
        let(:klazz) { mod::NumericString }
        it { should == true }
      end
      
      context "PRINTABLE STRING" do
        let(:klazz) { mod::PrintableString }
        it { should == true }
      end

      context "T61 STRING" do
        let(:klazz) { mod::T61String }
        it { should == true }
      end

      context "VIDEOTEX STRING" do
        let(:klazz) { mod::VideotexString }
        it { should == true }
      end

      context "IA5 STRING" do
        let(:klazz) { mod::IA5String }
        it { should == true }
      end

      context "GRAPHIC STRING" do
        let(:klazz) { mod::GraphicString }
        it { should == true }
      end

      context "ISO64 STRING" do
        let(:klazz) { mod::ISO64String }
        it { should == true }
      end

      context "GENERAL STRING" do
        let(:klazz) { mod::GeneralString }
        it { should == true }
      end

      context "UNIVERSAL STRING" do
        let(:klazz) { mod::UniversalString }
        it { should == true }
      end

      context "BMP STRING" do
        let(:klazz) { mod::BMPString }
        it { should == true }
      end
    end

    context "rejects UNIVERSAL tags > 30" do
      it { -> { klass.new("\xFF", 31, :UNIVERSAL).to_der }.should raise_error asn1error }
    end

    it "rejects constructed primitive values that are not infinite length" do
      asn1 = mod::OctetString.new [mod::OctetString.new("\x00"), mod::EndOfContents.new]
      -> { asn1.to_der }.should raise_error asn1error
    end

    it "allows to encode constructed primitive values that are infinite length" do
      asn1 = mod::OctetString.new [mod::OctetString.new("\x00"), mod::EndOfContents.new]
      asn1.infinite_length = true
      asn1.to_der.should == "\x24\x80\x04\x01\x00\x00\x00"
    end

    it "rejects primitive SEQUENCE values" do
      asn1 = mod::Sequence.new(1)
      -> { asn1.to_der }.should raise_error asn1error
    end

    it "rejects primitive SET values" do
      asn1 = mod::Set.new(1)
      -> { asn1.to_der }.should raise_error asn1error
    end
  end

  describe "#encode_to" do
    context "encodes to an IO" do
      subject { klass.new("\xFF", 0, :CONTEXT_SPECIFIC).encode_to(io); io }

      context "StringIO" do
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x80\x01\xFF" }
      end

      context "Object responds to :write" do
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x80\x01\xFF" }
      end

      it "encodes to File IO" do
        #io = File.open(IO::NULL, "wb") # not defined in JRuby yet
        io = File.open("/dev/null", "wb")
        begin
          klass.new("\xFF", 0, :CONTEXT_SPECIFIC).encode_to(io)
        ensure
          io.close
        end
      end if File.exists?("/dev/null")
        
      context "raise IO error transparently" do
        let(:io) { io_error_object }
        it { -> { subject }.should raise_error } # TODO EOFError }
      end
    end

    it "returns self" do
      obj = klass.new(nil, Krypt::ASN1::END_OF_CONTENTS, :UNIVERSAL)
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe "extracted from ASN1.decode" do
    subject { decoder.decode("#{tag}#{length}#{value}") }

    context "for all non-UNIVERSAL primitive values" do
      let(:length) { "\x01" }
      let(:value) { "\xFF" }
      
      context ":PRIVATE" do
        let(:tag) { "\xC0" }
        its(:tag) { should == 0 }
        its(:tag_class) { should == :PRIVATE }
        its(:value) { should == value }
        it { subject.should be_an_instance_of klass }
      end

      context ":APPLICATION" do
        let(:tag) { "\x40" }
        its(:tag) { should == 0 }
        its(:tag_class) { should == :APPLICATION }
        its(:value) { should == value }
        it { subject.should be_an_instance_of klass }
      end

      context ":CONTEXT_SPECIFIC" do
        let(:tag) { "\x80" }
        its(:tag) { should == 0 }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
        its(:value) { should == value }
        it { subject.should be_an_instance_of klass }
      end
    end

    context "ASN1Constructive is returned for all non-UNIVERSAL constructed values" do
      context "implicitly 0-tagged sequence" do
        let(:tag) { "\xA0" }
        let(:length) { "\x03" }
        let(:value) { "\x02\x01\x00" }
        its(:tag) { should == 0 }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
        it "" do
          subject.value.should respond_to :each
          subject.value.size.should == 1
          int = subject.value.first
          int.tag.should == Krypt::ASN1::INTEGER
          int.tag_class.should == :UNIVERSAL
          int.value.should == 0
          subject.should be_an_instance_of mod::Constructive
        end
      end
      
      context "explicitly 1-tagged integer" do
        let(:tag) { "\xA1" }
        let(:length) { "\x03" }
        let(:value) { "\x02\x01\x00" }
        its(:tag) { should == 1 }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
        it "" do
          subject.should be_an_instance_of mod::Constructive
          subject.value.should respond_to :each
          subject.value.size.should == 1
          int = subject.value.first
          int.tag.should == Krypt::ASN1::INTEGER
          int.tag_class.should == :UNIVERSAL
          int.value.should == 0
        end
      end

      context "infinite-length 0-tagged octet string" do
        let(:tag) { "\xA0" }
        let(:length) { "\x80" }
        let(:value) { "\x04\x01\x00\x04\x01\x01\x00\x00" }
        its(:tag) { should == 0 }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
        its(:infinite_length) { should == true }
        it "" do
          subject.should be_an_instance_of mod::Constructive
          subject.value.should respond_to :each
          subject.value.size.should == 3
          oct1 = subject.value[0]
          oct2 = subject.value[1]
          eoc = subject.value[2]
          [oct1, oct2].each do |oct|
            oct.tag.should == Krypt::ASN1::OCTET_STRING
            oct.tag_class.should == :UNIVERSAL
          end
          oct1.value.should == "\x00"
          oct2.value.should == "\x01"
          eoc.tag.should == Krypt::ASN1::END_OF_CONTENTS
          eoc.value.should be_nil
        end
      end
    end

    context "rejects infinite length primitive values" do
      let(:tag) { "\x80" }
      let(:length) { "\x80" }
      let(:value) { "\x01\x01\xFF\x00\x00" }
      it { -> { subject }.should raise_error asn1error }
    end

    context "rejects UNIVERSAL tags > 30" do
      let(:tag) { "\x1F\x42" }
      let(:length) { "\x01" }
      let(:value) { "\x00" }
      it { -> { subject }.should raise_error asn1error }
    end
    
    context "raises ParseError if premature EOF is detected" do
      let(:tag) { "\x02" }
      let(:length) { "\x02" }
      let(:value) { "\x00" }
      it { -> { subject }.should raise_error asn1error }
    end

    context "raises ParseError if header ends prematurely" do
      let(:tag) { "" }
      let(:length) { "" }
      let(:value) { "" }
      it { -> { subject }.should raise_error asn1error }
    end

    it "decodes arbitrary objects that respond to #to_der" do
      o = Object.new
      def o.to_der
        "\x02\x01\x01"
      end
      asn1 = decoder.decode(o)
      asn1.tag.should == mod::INTEGER
      asn1.value.should == 1
    end

    it "decodes files" do
      io = Resources.certificate_io
      begin
        asn1 = decoder.decode(io)
        asn1.tag.should == mod::SEQUENCE
        asn1.to_der.should == Resources.certificate
      ensure
        io.close
      end
    end

    context "handles 'unknown' tag number (13) as binary content" do
      context "primitive" do
        let(:tag) { "\x0D" }
        let(:length) { "\x01" }
        let(:value) { "\x01" }
        its(:tag) { should == 13 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == "\x01" }
      end

      context "constructive" do
        let(:tag) { "\x2D" }
        let(:length) { "\x03" }
        let(:value) { "\x02\x01\x01" }
        its(:tag) { should == 13 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should be_an_instance_of Array }
        it do
          content = subject.value
          content.size.should == 1
          int = content[0]
          int.tag.should == Krypt::ASN1::INTEGER
          int.tag_class.should == :UNIVERSAL
          int.value.should == 1
        end
      end
    end
    
    it "should handle IO as an IO" do
      io = StringIO.new(
        [
          Krypt::ASN1::Null.new,
          Krypt::ASN1::Integer.new(0)
        ].map { |e| e.to_der }.join
      )
      decoder.decode_der(io).should be_an_instance_of Krypt::ASN1::Null
      decoder.decode_der(io).should be_an_instance_of Krypt::ASN1::Integer
    end

    # TODO: Fails for JRuby - bug?
    it "should handle generic IOs as an IO" do
      stringio = StringIO.new(
        [
          Krypt::ASN1::Null.new,
          Krypt::ASN1::Integer.new(0)
        ].map { |e| e.to_der }.join
      )
      c = Class.new do
        def initialize(io)
          @io = io
        end

        def read(len=nil, buf=nil)
          @io.read(len, buf)
        end
      end
      generic = c.new(stringio)
      decoder.decode_der(generic).should be_an_instance_of Krypt::ASN1::Null
      decoder.decode_der(generic).should be_an_instance_of Krypt::ASN1::Integer
    end unless RUBY_PLATFORM =~ /java/

    it "should parse indefinite length constructive" do
      raw = "\x30\x80\x02\x01\x01\x80\x01\x02\x00\x00"
      decoder.decode(raw).value.size.should == 3
    end
  end
end
