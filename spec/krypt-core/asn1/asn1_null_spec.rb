require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::Asn1::Null do 
  let(:klass) { Krypt::Asn1::Null }
  let(:decoder) { Krypt::Asn1 }

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::Null }
  #let(:decoder) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::Null
    class << self
      alias old_new new
      def new(*args)
        if args.size == 1
          # nothing to do
        elsif args.size > 0
          args = [args[0], args[1], :IMPLICIT, args[2]]
        else
          args = [nil]
        end
        old_new(*args)
      end
    end
  end

  describe '#new' do
    context 'constructs' do
      subject { klass.new(nil) }

      its(:tag) { should == 5 }
      its(:tag_class) { should == :UNIVERSAL }
      # SEGV its(:value) { should == nil }
      its(:infinite_length) { should == false }
    end

    context 'constructs without value' do
      subject { klass.new }

      its(:tag) { should == 5 }
      its(:tag_class) { should == :UNIVERSAL }
      # SEGV its(:value) { should == nil }
      its(:infinite_length) { should == false }
    end

    context 'explicit construct' do
      subject { klass.new(nil, 5, :UNIVERSAL) }

      its(:tag) { should == 5 }
      its(:tag_class) { should == :UNIVERSAL }
      # SEGV its(:value) { should == nil }
      its(:infinite_length) { should == false }
    end

    context 'private tag handling' do
      subject { klass.new(nil, tag, :PRIVATE) }

      context 'default tag' do
        let(:tag) { 5 }
        its(:tag) { should == tag }
      end

      context 'custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'tag_class handling' do
      subject { klass.new(nil, 5, tag_class) }

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
    context 'values' do
      subject { klass.new.to_der }

      it { should == "\x05\x00" }
    end

    context 'private tag handling' do
      subject { klass.new(nil, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { 5 }
        it { should == "\xC5\x00" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x00" }
      end
    end

    context 'tag_class handling' do
      subject { klass.new(nil, 5, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x05\x00" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x45\x00" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x85\x00" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC5\x00" }
      end
    end
  end

  describe 'decoding' do
    subject { decoder.decode(der) }

    context 'value' do
      let(:der) { "\x05\x00" }
      its(:class) { should == klass }
      its(:tag) { should == 5 }
      its(:value) { should == nil }
    end

    context 'tag_class handling' do
      context 'UNIVERSAL' do
        let(:der) { "\x05\x00" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x45\x00" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x85\x00" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC5\x00" }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
