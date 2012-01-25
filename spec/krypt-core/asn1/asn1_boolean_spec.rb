require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::ASN1::Boolean do 
  let(:klass) { Krypt::ASN1::Boolean }
  let(:decoder) { Krypt::ASN1 }

  # For test against OpenSSL
  #
  let(:klass) { OpenSSL::ASN1::Boolean }
  let(:decoder) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::Boolean
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

      context 'true' do
        let(:value) { true }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == true }
        its(:infinite_length) { should == false }
      end

      context 'false' do
        let(:value) { false }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == false }
        its(:infinite_length) { should == false }
      end

      it { -> { klass.new(nil) }.should raise_error ArgumentError } # TODO: ossl does not check value
      it { -> { klass.new('hi!') }.should raise_error ArgumentError } # TODO: ossl does not check value
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new(true, tag, :PRIVATE) }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::BOOLEAN }
        its(:tag) { should == tag }
      end

      context 'custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new(true, Krypt::ASN1::BOOLEAN, tag_class) }

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
      subject { klass.new(true, Krypt::ASN1::BOOLEAN) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe '#to_der' do
    context 'encodes a given value' do
      subject { klass.new(value).to_der }

      context 'true' do
        let(:value) { true }
        it { should == "\x01\x01\xFF" }
      end

      context 'false' do
        let(:value) { false }
        it { should == "\x01\x01\x00" }
      end
    end

    context 'encodes tag number' do
      subject { klass.new(true, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::BOOLEAN }
        it { should == "\xC1\x01\xFF" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x01\xFF" }
      end
    end

    context 'encodes tag class' do
      subject { klass.new(true, Krypt::ASN1::BOOLEAN, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x01\x01\xFF" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x41\x01\xFF" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x81\x01\xFF" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC1\x01\xFF" }
      end
    end

    it "preserves a BER-encoded value when encoding it again" do
      ber = "\x01\x01\x01"
      decoder.decode(ber).to_der.should == ber
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 'true' do
        let(:der) { "\x01\x01\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        its(:value) { should == true }
      end

      context 'false' do
        let(:der) { "\x01\x01\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::BOOLEAN }
        its(:value) { should == false }
      end

      context 'allow to decode non-DER true' do
        let(:der) { "\x01\x01\x01" } # non 0xFF is true in BER
        its(:class) { should == klass }
        its(:value) { should == true }
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x01\x01\xFF" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x41\x01\xFF" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x81\x01\xFF" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC1\x01\xFF" }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
