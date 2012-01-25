require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::ASN1::Sequence do 
  let(:klass) { Krypt::ASN1::Sequence }
  let(:decoder) { Krypt::ASN1 }
  def s(str)
    Krypt::ASN1::OctetString.new(str)
  end
  def i(num)
    Krypt::ASN1::Integer.new(num)
  end

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::Sequence }
  #let(:decoder) { OpenSSL::ASN1 }
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

      context 'for SEQUENCE' do
        let(:value) { [s('hello'), i(42), s('world')] }

        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'for SEQUENCE OF' do
        let(:value) { [s('hello'), s(','), s('world')] }

        its(:tag) { should == Krypt::ASN1::SEQUENCE }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context '(empty)' do
        let(:value) { [] }

        its(:value) { should == [] }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      let(:value) { [s('hello')] }
      subject { klass.new(value, tag, :PRIVATE) }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::SEQUENCE }
        its(:tag) { should == tag }
      end

      context 'custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      let(:value) { [s('hello')] }
      subject { klass.new(value, Krypt::ASN1::SEQUENCE, tag_class) }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        its(:tag_class) { should == tag_class }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        its(:tag_class) { should == tag_class }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        its(:tag_class) { should == tag_class }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        its(:tag_class) { should == tag_class }
      end

      context 'unknown tag_class' do
        context nil do
          let(:tag_class) { nil }
          it { -> { subject }.should raise_error ArgumentError } # TODO: ossl does not check value
        end

        context :no_such_class do
          let(:tag_class) { :no_such_class }
          it { -> { subject }.should raise_error ArgumentError } # TODO: ossl does not check value
        end
      end
    end

    context 'when the 2nd argument is given but 3rd argument is omitted' do
      subject { klass.new([s('hello')], Krypt::ASN1::SEQUENCE) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
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
