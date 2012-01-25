require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::ASN1::OctetString do 
  let(:klass) { Krypt::ASN1::OctetString }
  let(:decoder) { Krypt::ASN1 }

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
    context 'gets value for construct' do
      subject { klass.new(value) }

      context 'accepts "hello,world!"' do
        let(:value) { 'hello,world!' }

        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == 'hello,world!' }
        its(:infinite_length) { should == false }
      end

      context 'accepts (empty)' do
        let(:value) { '' }
        its(:value) { should == '' }
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new('hello,world!', tag, :PRIVATE) }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::OCTET_STRING }
        its(:tag) { should == tag }
      end

      context 'accepts custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new('hello,world!', Krypt::ASN1::OCTET_STRING, tag_class) }

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

      context 'does not accept unknown tag_class' do
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
      subject { klass.new('hello,world!', Krypt::ASN1::OCTET_STRING) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe 'accessors' do
    describe '#value' do
      subject { o = klass.new(nil); o.value = value; o }

      context 'accepts "hello,world!"' do
        let(:value) { 'hello,world!' }

        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == 'hello,world!' }
        its(:infinite_length) { should == false }
      end

      context 'accepts (empty)' do
        let(:value) { '' }
        its(:value) { should == '' }
      end
    end

    describe '#tag' do
      subject { o = klass.new(nil); o.tag = tag; o }

      context 'accepts default tag' do
        let(:tag) { Krypt::ASN1::OCTET_STRING }
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

      context 'does not accept unknown tag_class' do
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
  end

  describe '#to_der' do
    context 'encodes a given value' do
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

    context 'encodes tag number' do
      subject { klass.new('hello,world!', tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::OCTET_STRING }
        it { should == "\xC4\x0Chello,world!" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x0Chello,world!" }
      end
    end

    context 'encodes tag class' do
      subject { klass.new('hello,world!', Krypt::ASN1::OCTET_STRING, tag_class).to_der }

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

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context 'hello,world!' do
        let(:der) { "\x04\x0Chello,world!" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == 'hello,world!' }
      end

      context '(empty)' do
        let(:der) { "\x04\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        #its(:value) { should == '' }
        its(:value) { should == nil } #TODO: discuss
      end

      context '999 octets' do
        let(:der) { "\x04\x82\x03\xE7" + 'x' * 999 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == 'x' * 999 }
      end

      context '1000 octets' do
        let(:der) { "\x04\x82\x03\xE8" + 'x' * 1000 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == 'x' * 1000 }
      end

      context '1001 octets' do
        let(:der) { "\x04\x82\x03\xE9" + 'x' * 1001 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OCTET_STRING }
        its(:value) { should == 'x' * 1001 }
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x04\x0Chello,world!" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x44\x0Chello,world!" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x84\x0Chello,world!" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC4\x0Chello,world!" }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
