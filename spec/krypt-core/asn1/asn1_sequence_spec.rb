require 'rspec'
require 'krypt-core'
require 'openssl'
require_relative './resources'

describe Krypt::ASN1::Sequence do 
  include Krypt::ASN1::Resources

  let(:mod) { Krypt::ASN1 }
  let(:klass) { mod::Sequence }
  let(:decoder) { mod }
  let(:asn1error) { mod::ASN1Error }

  # For test against OpenSSL
  #
  #let(:mod) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::Sequence
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

  describe '#new' do
    context 'gets value for construct' do
      subject { klass.new(value) }

      context 'accepts SEQUENCE as Array' do
        let(:value) { [s('hello'), i(42), s('world')] }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts SEQUENCE OF as Array' do
        let(:value) { [s('hello'), s(','), s('world')] }
        its(:value) { should == value }
      end

      context 'accepts empty Array' do
        let(:value) { [] }
        its(:value) { should == [] }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      let(:value) { [s('hello')] }
      subject { klass.new(value, tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::SEQUENCE }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      let(:value) { [s('hello')] }
      subject { klass.new(value, Krypt::ASN1::SEQUENCE, tag_class) }

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
      subject { klass.new([s('hello')], Krypt::ASN1::SEQUENCE) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts SEQUENCE as Array' do
        let(:value) { [s('hello'), i(42), s('world')] }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'accepts SEQUENCE OF as Array' do
        let(:value) { [s('hello'), s(','), s('world')] }
        its(:value) { should == value }
      end

      context 'accepts empty Array' do
        let(:value) { [] }
        its(:value) { should == [] }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::SEQUENCE }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag (allowed?)' do
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

      context 'SEQUENCE' do
        let(:value) { [s('hello'), i(42), s('world')] }
        it { should == "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end

      context 'SEQUENCE OF OctetString' do
        let(:value) { [s(''), s(''), s('')] }
        it { should == "\x30\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'SEQUENCE OF Integer' do
        let(:value) { [i(-1), i(0), i(1)] }
        it { should == "\x30\x0C\x02\x04\xFF\xFF\xFF\xFF\x02\x01\x00\x02\x01\x01" }
      end

      context '(empty)' do
        let(:value) { [] }
        it { should == "\x30\x00" }
      end

      context '1000 elements' do
        let(:value) { [i(0)] * 1000 }
        it { should == "\x30\x82\x0B\xB8" + "\x02\x01\x00" * 1000 }
      end

      context 'responds to :each' do
        let(:value) {
          o = BasicObject.new
          def o.each
            yield Krypt::ASN1::OctetString.new('hello')
            yield Krypt::ASN1::Integer.new(42)
            yield Krypt::ASN1::OctetString.new('world')
          end
          o
        }
        it { should == "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end

      context 'nil' do
        let(:value) { nil }
        it { -> { subject }.should raise_error asn1error }
      end

      context 'does not respond to :each' do
        let(:value) { '123' }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag number' do
      let(:value) { [s(''), s(''), s('')] }
      subject { klass.new(value, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::SEQUENCE }
        it { should == "\xF0\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xEE\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'nil' do
        let(:tag) { nil }
        it { -> { subject }.should raise_error asn1error }
      end
    end

    context 'encodes tag class' do
      let(:value) { [s(''), s(''), s('')] }
      subject { klass.new(value, Krypt::ASN1::SEQUENCE, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x30\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x70\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\xB0\x06\x04\x00\x04\x00\x04\x00" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xF0\x06\x04\x00\x04\x00\x04\x00" }
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

      context 'value: SEQUENCE' do
        let(:value) { [s('hello'), i(42), s('world')] }
        it { should == "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:value) { [s('hello'), i(42), s('world')] }
        let(:tag) { 14 }
        let(:tag_class) { :PRIVATE }
        it { should == "\xEE\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end

      context 'tag_class' do
        let(:value) { [s('hello'), i(42), s('world')] }
        let(:tag_class) { :APPLICATION }
        it { should == "\x70\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
      end
    end
  end

  describe '#encode_to' do
    context 'encodes to an IO' do
      subject { klass.new(value).encode_to(io); io }

      context "StringIO" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { string_io_object }
        its(:written_bytes) { should == "\x30\x06\x04\x00\x04\x00\x04\x00" }
      end

      context "Object responds to :write" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { writable_object }
        its(:written_bytes) { should == "\x30\x06\x04\x00\x04\x00\x04\x00" }
      end

      context "raise IO error transparently" do
        let(:value) { [s(''), s(''), s('')] }
        let(:io) { io_error_object }
        it { -> { subject }.should raise_error EOFError }
      end
    end

    it 'returns self' do
      obj = klass.new([s(''), s(''), s('')])
      obj.encode_to(string_io_object).should == obj
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 'SEQUENCE' do
        let(:der) { "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        it 'contains decoded value' do
          value = subject.value
          value.size.should == 3
          value[0].value == 'hello'
          value[1].value == 42
          value[2].value == 'world'
        end
      end

      context 'SEQUENCE OF Integer' do
        let(:der) { "\x30\x0C\x02\x04\xFF\xFF\xFF\xFF\x02\x01\x00\x02\x01\x01" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        it 'contains decoded value' do
          value = subject.value
          value.size.should == 3
          value[0].value == -1
          value[1].value == 0
          value[2].value == 1
        end
      end

      context '(empty)' do
        let(:der) { "\x30\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:value) { should == [] }
      end

      context '1000 elements' do
        let(:der) { "\x30\x82\x0B\xB8" + "\x02\x01\x00" * 1000 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        it 'contains decoded value' do
          value = subject.value
          value.size == 1000
          value.each do |v|
            v.value.should == 0
          end
        end
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x30\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x70\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\xB0\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xF0\x11\x04\x05hello\x02\x01\x2A\x04\x05world" }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
