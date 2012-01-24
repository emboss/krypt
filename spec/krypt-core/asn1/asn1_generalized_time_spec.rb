require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::ASN1::GeneralizedTime do 
  let(:klass) { Krypt::ASN1::GeneralizedTime }
  let(:decoder) { Krypt::ASN1 }

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::GeneralizedTime }
  #let(:decoder) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::GeneralizedTime
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

      context 'Time' do
        let(:value) { Time.now }

        its(:tag) { should == 24 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value }
        its(:infinite_length) { should == false }
      end

      context 'Numeric' do
        let(:value) { 0 + Time.now.to_i }

        its(:tag) { should == 24 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value } # TODO: Should be a Time?
        its(:infinite_length) { should == false }
      end

      context 'String' do
        let(:value) { '' + Time.now.to_i.to_s }

        its(:tag) { should == 24 }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == value } # TODO: Should be a Time?
        its(:infinite_length) { should == false }
      end
    end

    context 'explicit construct' do
      subject { klass.new(0, 24, :UNIVERSAL) }

      its(:tag) { should == 24 }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 0 } # TODO: Should be a Time?
    end

    context 'private tag handling' do
      subject { klass.new(Time.now, tag, :PRIVATE) }

      context 'default tag' do
        let(:tag) { 24 }
        its(:tag) { should == tag }
      end

      context 'custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'tag_class handling' do
      subject { klass.new(Time.now, 24, tag_class) }

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

      context 'Time' do
        let(:value) { Time.mktime(2012, 1, 24, 0, 0, 0) }
        it { should == "\x18\x0F20120123150000Z" }
      end

      context 'Numeric' do
        let(:value) { Time.mktime(2012, 1, 24, 0, 0, 0).to_i }
        it { should == "\x18\x0F20120123150000Z" }
      end

      context 'String' do
        let(:value) { Time.mktime(2012, 1, 24, 0, 0, 0).to_i }
        it { should == "\x18\x0F20120123150000Z" }
      end

      context 'Min time representation' do
        let(:value) { Time.mktime(2000, 1, 1, 9, 0, 0).to_i }
        it { should == "\x18\x0F20000101000000Z" }
      end

      context 'Max time representation' do
        let(:value) { Time.mktime(2000, 1, 1, 8, 59, 59).to_i }
        it { should == "\x18\x0F19991231235959Z" }
      end

      context 'second fraction' do
        pending 'ossl does not support this'
      end

      context 'timezone' do
        pending 'ossl does not support this'
      end

      context '(empty)' do
        let(:value) { '' }
        pending 'When do we check the error?'
      end

      context 'Bignum' do
        let(:value) { 2**64 - 1 }
        pending 'When do we check the error?'
      end
    end

    context 'private tag handling' do
      subject { klass.new(1327330800, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { 24 }
        it { should == "\xD8\x0F20120123150000Z" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x0F20120123150000Z" }
      end
    end

    context 'tag_class handling' do
      subject { klass.new(1327330800, 24, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x18\x0F20120123150000Z" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x58\x0F20120123150000Z" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x98\x0F20120123150000Z" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xD8\x0F20120123150000Z" }
      end
    end
  end

  describe 'decoding' do
    subject { decoder.decode(der) }

    context 'value' do
      context 'Time' do
        let(:der) { "\x18\x0F20120123150000Z" }
        its(:class) { should == klass }
        its(:tag) { should == 24 }
        its(:value) { should == Time.mktime(2012, 1, 24, 0, 0, 0) }
      end

      context 'with fraction' do
        let(:der) { "\x18\x1620120123150000.012345Z" }
        its(:class) { should == klass }
        its(:tag) { should == 24 }
        its(:value) { subject.usec.should == 12345 } # TODO: ossl does not support decoding usec
      end

      context 'Min time representation' do
        let(:der) { "\x18\x0F20000101000000Z" }
        its(:class) { should == klass }
        its(:tag) { should == 24 }
        its(:value) { should == Time.mktime(2000, 1, 1, 9, 0, 0) }
      end

      context 'Max time representation' do
        let(:der) { "\x18\x0F19991231235959Z" }
        its(:class) { should == klass }
        its(:tag) { should == 24 }
        its(:value) { Time.mktime(2000, 1, 1, 8, 59, 59) }
      end

      context 'timezone' do
        context '+' do
          let(:der) { "\x18\x1320000101085959+0900" }
          its(:class) { should == klass }
          its(:tag) { should == 24 }
          its(:value) { Time.mktime(2000, 1, 1, 8, 59, 59) }
        end

        context '-' do
          let(:der) { "\x18\x1319991231145959-0900" }
          its(:class) { should == klass }
          its(:tag) { should == 24 }
          its(:value) { Time.mktime(2000, 1, 1, 8, 59, 59) }
        end

        context '+0' do
          let(:der) { "\x18\x1319991231235959+0000" }
          its(:class) { should == klass }
          its(:tag) { should == 24 }
          its(:value) { Time.mktime(2000, 1, 1, 8, 59, 59) }
        end

        context '-0' do
          let(:der) { "\x18\x1319991231235959-0000" }
          its(:class) { should == klass }
          its(:tag) { should == 24 }
          its(:value) { Time.mktime(2000, 1, 1, 8, 59, 59) }
        end
      end
    end

    context 'tag_class handling' do
      context 'UNIVERSAL' do
        let(:der) { "\x18\x0F20120123150000Z" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x48\x0F20120123150000Z" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x88\x0F20120123150000Z" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC8\x0F20120123150000Z" }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
