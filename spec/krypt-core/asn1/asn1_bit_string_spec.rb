require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::ASN1::BitString do 
  let(:klass) { Krypt::ASN1::BitString }
  let(:decoder) { Krypt::ASN1 }

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::BitString }
  #let(:decoder) { OpenSSL::ASN1 }
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

  describe '#new' do
    context 'constructs with value' do
      subject { klass.new([value.reverse].pack('b*').reverse) }

      context '01010101' do
        let(:value) { '01010101' }

        its(:tag) { should == 3 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == "\x55" }
        its(:infinite_length) { should == false }
      end

      context '(empty)' do
        let(:value) { '' }

        its(:value) { should == '' }
      end
    end

    context 'explicit construct' do
      subject { klass.new("\x55", 3, :UNIVERSAL) }

      its(:tag) { should == 3 }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == "\x55" }
    end

    context 'private tag handling' do
      subject { klass.new("0x55", tag, :PRIVATE) }

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
      subject { klass.new("0x55", 4, tag_class) }

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
      subject { klass.new([value.reverse].pack('b*').reverse).to_der }

      context '01010101' do
        let(:value) { '01010101' }
        it { should == "\x03\x02\x00\x55" }
      end

      context '010101010' do
        let(:value) { '010101010' }
        it { should == "\x03\x03\x00\x00\xAA" }
      end

      context '(empty)' do
        let(:value) { '' }
        it { should == "\x03\x01\x00" }
      end

      context '999 octets' do
        let(:value) { '1' * 8 * 999 }
        it { should == "\x03\x82\x03\xE8\x00" + "\xFF" * 999 }
      end

      context '1000 octets' do
        let(:value) { '0' * 8 * 1000 }
        it { should == "\x03\x82\x03\xE9\x00" + "\x00" * 1000 }
      end

      context '1001 octets' do
        let(:value) { '1' * 8 * 1001 }
        it { should == "\x03\x82\x03\xEA\x00" + "\xFF" * 1001 }
      end
    end

    context 'private tag handling' do
      subject { klass.new("\x55", tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { 3 }
        it { should == "\xC3\x02\x00\x55" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x02\x00\x55" }
      end
    end

    context 'tag_class handling' do
      subject { klass.new("\x55", 3, tag_class).to_der }

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
    end
  end

  describe 'decoding' do
    subject { decoder.decode(der) }

    context 'value' do
      context '01010101' do
        let(:der) { "\x03\x02\x00\x55" }
        its(:class) { should == klass }
        its(:tag) { should == 3 }
        its(:value) { should == "\x55" }
      end

      context '010101010' do
        let(:der) { "\x03\x03\x00\x00\xAA" }
        its(:class) { should == klass }
        its(:tag) { should == 3 }
        its(:value) { should == "\x00\xAA" }
      end

      context '(empty)' do
        let(:der) { "\x03\x01\x00" }
        its(:class) { should == klass }
        its(:tag) { should == 3 }
        its(:value) { should == '' }
      end

      context '999 octets' do
        let(:der) { "\x03\x82\x03\xE8\x00" + "\xFF" * 999 }
        its(:class) { should == klass }
        its(:tag) { should == 3 }
        its(:value) { should == "\xFF" * 999 }
      end

      context '1000 octets' do
        let(:der) { "\x03\x82\x03\xE9\x00" + "\x00" * 1000 }
        its(:class) { should == klass }
        its(:tag) { should == 3 }
        its(:value) { should == "\x00" * 1000 }
      end

      context '1001 octets' do
        let(:der) { "\x03\x82\x03\xEA\x00" + "\xFF" * 1001 }
        its(:class) { should == klass }
        its(:tag) { should == 3 }
        its(:value) { should == "\xFF" * 1001 }
      end
    end

    context 'tag_class handling' do
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
