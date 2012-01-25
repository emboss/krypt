# -*- encoding: utf-8 -*-

require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::ASN1::UTF8String do 
  let(:klass) { Krypt::ASN1::UTF8String }
  let(:decoder) { Krypt::ASN1 }

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::UTF8String }
  #let(:decoder) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::UTF8String
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
  
  def _A(str)
    str.force_encoding("ASCII-8BIT")
  end

  describe '#new' do
    context 'constructs with value' do
      subject { klass.new(value) }

      context 'こんにちは、世界！' do
        let(:value) { 'こんにちは、世界！' }

        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == 'こんにちは、世界！' }
        its(:infinite_length) { should == false }
      end

      context '(empty)' do
        let(:value) { '' }

        its(:value) { should == '' }
      end
    end

    context 'explicit construct' do
      subject { klass.new('こんにちは、世界！', Krypt::ASN1::UTF8_STRING, :UNIVERSAL) }

      its(:tag) { should == Krypt::ASN1::UTF8_STRING }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 'こんにちは、世界！' }
    end

    context 'private tag handling' do
      subject { klass.new('こんにちは、世界！', tag, :PRIVATE) }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::UTF8_STRING }
        its(:tag) { should == tag }
      end

      context 'custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'tag_class handling' do
      subject { klass.new('こんにちは、世界！', Krypt::ASN1::UTF8_STRING, tag_class) }

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

      context 'こんにちは、世界！' do
        let(:value) { 'こんにちは、世界！' }
        it { should == _A("\x0C\x18" + value) }
      end

      context '(empty)' do
        let(:value) { '' }
        it { should == "\x0C\x00" }
      end

      context '1000 octets' do
        let(:value) { 'あ' * 1000 }
        it { should == _A("\x0C\x82\x1F\x40" + value) }
      end
    end

    context 'private tag handling' do
      let(:value) { 'こんにちは、世界！' }
      subject { klass.new(value, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::UTF8_STRING }
        it { should == _A("\xCC\x18" + value) }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == _A("\xCE\x18" + value) }
      end
    end

    context 'tag_class handling' do
      let(:value) { 'こんにちは、世界！' }
      subject { klass.new(value, Krypt::ASN1::UTF8_STRING, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == _A("\x0C\x18" + value) }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == _A("\x4C\x18" + value) }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == _A("\x8C\x18" + value) }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == _A("\xCC\x18" + value) }
      end
    end
  end

  describe 'decoding' do
    subject { decoder.decode(der) }

    context 'value' do
      context 'こんにちは、世界！' do
        let(:value) { 'こんにちは、世界！' }
        let(:der) { _A("\x0C\x18" + value) }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        its(:value) { should == value }
      end

      context '(empty)' do
        let(:der) { "\x0C\x00" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        #its(:value) { should == '' }
        its(:value) { should == nil } #TODO: discuss
      end

      context '1000 octets' do
        let(:value) { 'あ' * 1000 }
        let(:der) { _A("\x0C\x82\x1F\x40" + value) }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::UTF8_STRING }
        its(:value) { should == value }
      end
    end

    context 'tag_class handling' do
      let(:value) { 'こんにちは、世界！' }

      context 'UNIVERSAL' do
        let(:der) { _A("\x0C\x18" + value) }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { _A("\x4C\x18" + value) }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { _A("\x8C\x18" + value) }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { _A("\xCC\x18" + value) }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
