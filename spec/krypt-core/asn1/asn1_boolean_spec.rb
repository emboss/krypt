require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::Asn1::Boolean do 
  let(:klass) { Krypt::Asn1::Boolean }
  let(:decoder) { Krypt::Asn1 }

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::Boolean }
  #let(:decoder) { OpenSSL::ASN1 }
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
    context 'constructs as true' do
      subject { klass.new(true) }

      its(:tag) { should == 1 }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == true }
      its(:infinite_length) { should == false }
    end

    context 'constructs as false' do
      subject { klass.new(false) }

      its(:tag) { should == 1 }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == false }
      its(:infinite_length) { should == false }
    end

    context 'explicit construct' do
      subject { klass.new(true, 1, :UNIVERSAL) }

      its(:tag) { should == 1 }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == true }
    end

    context 'private tag handling' do
      subject { klass.new(true, tag, :PRIVATE) }

      context 'default tag' do
        let(:tag) { 1 }
        its(:tag) { should == tag }
      end

      context 'custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'tag_class handling' do
      subject { klass.new(true, 1, tag_class) }

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
    end
  end

  describe '#to_der' do
    subject { klass.new(value).to_der }

    context 'value' do
      context 'true' do
        let(:value) { true }
        it { should == "\x01\x01\xFF" }
      end

      context 'false' do
        let(:value) { false }
        it { should == "\x01\x01\x00" }
      end
    end

    context 'private tag handling' do
      subject { klass.new(true, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { 1 }
        it { should == "\xC1\x01\xFF" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x01\xFF" }
      end
    end

    context 'tag_class handling' do
      subject { klass.new(true, 1, tag_class).to_der }

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
  end

  describe 'decoding' do
    subject { decoder.decode(der) }

    context 'value' do
      context 'true' do
        let(:der) { "\x01\x01\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == 1 }
        its(:value) { should == true }
      end

      context 'false' do
        let(:der) { "\x01\x01\x00" }
        its(:class) { should == klass }
        its(:tag) { should == 1 }
        its(:value) { should == false }
      end

      context 'TODO: do we allow to decode non-DER true?' do
        let(:der) { "\x01\x01\x01" } # non 0xFF is true in BER
        its(:class) { should == klass }
        its(:value) { should == true }
      end
    end

    context 'tag_class handling' do
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
