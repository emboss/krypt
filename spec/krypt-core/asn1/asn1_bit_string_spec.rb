require 'rspec'
require 'krypt-core'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::BitString do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::BitString }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::BitString
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

  def _B(bin_encode)
    [bin_encode.reverse].pack('b*').reverse
  end

  describe '#new' do
    context 'gets value for construct' do
      subject { klass.new(value) }

      context 'accepts binary packed 01010101 := "\x55"' do
        let(:value) { _B('01010101') }
        its(:tag) { should == Krypt::ASN1::BIT_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts (empty)' do
        let(:value) { '' }
        its(:tag) { should == Krypt::ASN1::BIT_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == '' }
        its(:infinite_length) { should == false }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new(_B('01010101'), tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::BIT_STRING }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new(_B('01010101'), Krypt::ASN1::BIT_STRING, tag_class) }

      context 'accepts :UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :APPLICATION' do
        let(:tag_class) { :APPLICATION }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :PRIVATE' do
        let(:tag_class) { :PRIVATE }
        its(:tag_class) { should == tag_class }
      end
    end

    context 'when the 2nd argument is given but 3rd argument is omitted' do
      subject { klass.new(_B('01010101'), Krypt::ASN1::BIT_STRING) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts binary packed 01010101 := "\x55"' do
        let(:value) { _B('01010101') }
        its(:value) { should == value }
      end

      context 'accepts (empty)' do
        let(:value) { '' }
        its(:value) { should == '' }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::BIT_STRING }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    describe '#tag_class' do
      subject { o = klass.new(nil); o.tag_class = tag_class; o }

      context 'accepts :UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :APPLICATION' do
        let(:tag_class) { :APPLICATION }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        its(:tag_class) { should == tag_class }
      end

      context 'accepts :PRIVATE' do
        let(:tag_class) { :PRIVATE }
        its(:tag_class) { should == tag_class }
      end
    end
  end

  describe '#to_der' do
    context 'encodes a given value' do
      subject { klass.new(value).to_der }

      context '01010101' do
        let(:value) { _B('01010101') }
        it { should == "\x03\x02\x00\x55" }
      end

      context '010101010' do
        let(:value) { _B('010101010') }
        it { should == "\x03\x03\x00\x00\xAA" }
      end

      context '(empty)' do
        let(:value) { '' }
        it { should == "\x03\x01\x00" }
      end

      context '999 octets' do
        let(:value) { _B('1' * 8 * 999) }
        it { should == "\x03\x82\x03\xE8\x00" + "\xFF" * 999 }
      end

      context '1000 octets' do
        let(:value) { _B('0' * 8 * 1000) }
        it { should == "\x03\x82\x03\xE9\x00" + "\x00" * 1000 }
      end

      context '1001 octets' do
        let(:value) { _B('1' * 8 * 1001) }
        it { should == "\x03\x82\x03\xEA\x00" + "\xFF" * 1001 }
      end

      context 'nil' do
        let(:value) { nil }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag number' do
      subject { klass.new(_B('01010101'), tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::BIT_STRING }
        it { should == "\xC3\x02\x00\x55" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x02\x00\x55" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      subject { klass.new(_B('01010101'), Krypt::ASN1::BIT_STRING, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x03\x02\x00\x55" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x43\x02\x00\x55" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x83\x02\x00\x55" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC3\x02\x00\x55" }
      end

      context nil do
        let(:tag_class) { nil }
        it { -> { subject }.should raise_error asn1error } # TODO: ossl does not check nil
      end

      context :no_such_class do
        let(:tag_class) { :no_such_class }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes values set via accessors' do
      subject {
        o = klass.new(nil)
        o.value = value if defined? value
        o.tag = tag if defined? tag
        o.tag_class = tag_class if defined? tag_class
        o.to_der
      }

      context 'value: 01010101' do
        let(:value) { _B('01010101') }
        it { should == "\x03\x02\x00\x55" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:value) { _B('01010101') }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == "\xCE\x02\x00\x55" }
      end

      context 'tag_class' do
        let(:value) { _B('01010101') }
        let(:tag_class) { :APPLICATION }
        it { should == "\x43\x02\x00\x55" }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { _B('01010101') }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x03\x02\x00\x55" }
      end

      context "Object responds to :write" do
        let(:value) { _B('01010101') }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x03\x02\x00\x55" }
      end

      context "raise IO error transparently" do
        let(:value) { _B('01010101') }
        let(:io) { io_error_object }
        it { -> { subject }.should raise_error EOFError }
      end
    end

    it 'returns self' do
      obj = klass.new(_B('01010101'))
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context '01010101' do
        let(:der) { "\x03\x02\x00\x55" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BIT_STRING }
        its(:value) { should == _B('01010101') }
      end

      context '010101010' do
        let(:der) { "\x03\x03\x00\x00\xAA" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BIT_STRING }
        its(:value) { should == "\x00\xAA" }
      end

      context '(empty)' do
        let(:der) { "\x03\x01\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BIT_STRING }
        its(:value) { should == '' }
      end

      context '999 octets' do
        let(:der) { "\x03\x82\x03\xE8\x00" + "\xFF" * 999 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BIT_STRING }
        its(:value) { should == "\xFF" * 999 }
      end

      context '1000 octets' do
        let(:der) { "\x03\x82\x03\xE9\x00" + "\x00" * 1000 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BIT_STRING }
        its(:value) { should == "\x00" * 1000 }
      end

      context '1001 octets' do
        let(:der) { "\x03\x82\x03\xEA\x00" + "\xFF" * 1001 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BIT_STRING }
        its(:value) { should == "\xFF" * 1001 }
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x03\x03\x00\x00\xAA" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x43\x03\x00\x00\xAA" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x83\x03\x00\x00\xAA" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC3\x03\x00\x00\xAA" }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
