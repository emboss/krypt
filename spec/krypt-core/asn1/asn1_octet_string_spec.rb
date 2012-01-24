require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::Asn1::OctetString do 
  let(:klass) { Krypt::Asn1::OctetString }
  let(:decoder) { Krypt::Asn1 }

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::OctetString }
  #let(:decoder) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::OctetString
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
    context 'constructs with value' do
      subject { klass.new(value) }

      context 'hello,world!' do
        let(:value) { 'hello,world!' }

        its(:tag) { should == 4 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == 'hello,world!' }
        its(:infinite_length) { should == false }
      end

      context '(empty)' do
        let(:value) { '' }

        its(:value) { should == '' }
      end
    end

    context 'explicit construct' do
      subject { klass.new('hello,world!', 4, :UNIVERSAL) }

      its(:tag) { should == 4 }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 'hello,world!' }
    end

    context 'private tag handling' do
      subject { klass.new('hello,world!', tag, :PRIVATE) }

      context 'default tag' do
        let(:tag) { 4 }
        its(:tag) { should == tag }
      end

      context 'custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'tag_class handling' do
      subject { klass.new('hello,world!', 4, tag_class) }

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
    context 'value' do
      subject { klass.new(value).to_der }

      context 'hello,world!' do
        let(:value) { 'hello,world!' }
        it { should == "\x04\x0Chello,world!" }
      end

      context '(empty)' do
        let(:value) { '' }
        it { should == "\x04\x00" }
      end

      context '999 octets' do
        let(:value) { 'x' * 999 }
        it { should == "\x04\x82\x03\xE7" + 'x' * 999 }
      end

      context '1000 octets' do
        let(:value) { 'x' * 1000 }
        it { should == "\x04\x82\x03\xE8" + 'x' * 1000 }
      end

      context '1001 octets' do
        let(:value) { 'x' * 1001 }
        it { should == "\x04\x82\x03\xE9" + 'x' * 1001 }
      end
    end

    context 'private tag handling' do
      subject { klass.new('hello,world!', tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { 4 }
        it { should == "\xC4\x0Chello,world!" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x0Chello,world!" }
      end
    end

    context 'tag_class handling' do
      subject { klass.new('hello,world!', 4, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x04\x0Chello,world!" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x44\x0Chello,world!" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x84\x0Chello,world!" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC4\x0Chello,world!" }
      end
    end
  end

  describe 'decoding' do
    subject { decoder.decode(der) }

    context 'value' do
      context 'hello,world!' do
        let(:der) { "\x04\x0Chello,world!" }
        its(:class) { should == klass }
        its(:tag) { should == 4 }
        its(:value) { should == 'hello,world!' }
      end

      context '(empty)' do
        let(:der) { "\x04\x00" }
        its(:class) { should == klass }
        its(:tag) { should == 4 }
        its(:value) { should == '' }
      end

      context '999 octets' do
        let(:der) { "\x04\x82\x03\xE7" + 'x' * 999 }
        its(:class) { should == klass }
        its(:tag) { should == 4 }
        its(:value) { should == 'x' * 999 }
      end

      context '1000 octets' do
        let(:der) { "\x04\x82\x03\xE8" + 'x' * 1000 }
        its(:class) { should == klass }
        its(:tag) { should == 4 }
        its(:value) { should == 'x' * 1000 }
      end

      context '1001 octets' do
        let(:der) { "\x04\x82\x03\xE9" + 'x' * 1001 }
        its(:class) { should == klass }
        its(:tag) { should == 4 }
        its(:value) { should == 'x' * 1001 }
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
