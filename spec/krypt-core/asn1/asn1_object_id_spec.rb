require 'rspec'
require 'krypt-core'
require 'openssl'

describe Krypt::ASN1::ObjectId do 
  let(:klass) { Krypt::ASN1::ObjectId }
  let(:decoder) { Krypt::ASN1 }

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::ObjectId }
  #let(:decoder) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::ObjectId
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

      context 'accepts 1.0.8571.2' do
        let(:value) { '1.0.8571.2' }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:tag_class) { should == :UNIVERSAL }
        its(:value) { should == '1.0.8571.2' }
        its(:infinite_length) { should == false }
      end

      context 'does not accept (empty)' do
        let(:value) { '' }
        it { -> { subject }.should raise_error ArgumentError } # TODO: ossl does not check value
      end

      context 'does not accept non OID format' do
        let(:value) { '1,0:1' }
        it { -> { subject }.should raise_error ArgumentError } # TODO: ossl does not check value
      end

      context 'does not accept non number id' do
        let(:value) { '1.0.ABC' }
        it { -> { subject }.should raise_error ArgumentError } # TODO: ossl does not check value
      end

      context 'does not accept illegal first octet (must be 0..2)' do
        let(:value) { '3.0.8571.2' }
        it { -> { subject }.should raise_error ArgumentError } # TODO: ossl does not check value
      end

      context 'does not accept illegal second octet (must be 0..3)' do
        let(:value) { '1.4.8571.2' }
        it { -> { subject }.should raise_error ArgumentError } # TODO: ossl does not check value
      end
    end

    context 'gets explicit tag number as the 2nd argument' do
      subject { klass.new('1.0.8571.2', tag, :PRIVATE) }

      context 'default tag' do
        let(:tag) { Krypt::ASN1::OBJECT_ID }
        its(:tag) { should == tag }
      end

      context 'custom tag (allowed?)' do
        let(:tag) { 14 }
        its(:tag) { should == tag }
      end
    end

    context 'gets tag class symbol as the 3rd argument' do
      subject { klass.new('1.0.8571.2', Krypt::ASN1::OBJECT_ID, tag_class) }

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
      subject { klass.new('1.0.8571.2', Krypt::ASN1::OBJECT_ID) }
      its(:tag_class) { should == :CONTEXT_SPECIFIC }
    end
  end

  describe '#to_der' do
    context 'encodes a given value' do
      subject { klass.new(value).to_der }

      context '1.0.8571.2' do
        let(:value) { '1.0.8571.2' }
        it { should == "\x06\x04\x28\xC2\x7B\x02" }
      end

      context '(empty)' do
        let(:value) { '' }
        pending 'When do we check the error?'
      end

      context '1' do
        let(:value) { '1' }
        pending 'When do we check the error?'
      end

      # oid[0] ::= 0, 1, 2
      # oid[1] ::= 0, 1, 2, 3
      # v[0] ::= oid[0] * 40 + oid[1]
      context '2 octets optimization' do
        context '0.0' do
          let(:value) { '0.0' }
          it { should == "\x06\x01\x00" }
        end

        context '0.3' do
          let(:value) { '0.3' }
          it { should == "\x06\x01\x03" }
        end

        context '1.0' do
          let(:value) { '1.0' }
          it { should == "\x06\x01\x28" }
        end

        context '1.3' do
          let(:value) { '1.3' }
          it { should == "\x06\x01\x2B" }
        end
      end

      context '0.0.0.....0' do
        let(:value) { (['0'] * 999).join('.') }
        it { should == "\x06\x82\x03\xE6\x00" + "\x00" * 997 }
      end

      context '1.1.1.....1' do
        let(:value) { (['1'] * 1000).join('.') }
        it { should == "\x06\x82\x03\xE7\x29" + "\x01" * 998 }
      end
    end

    context 'encodes tag number' do
      subject { klass.new('1.0.8571.2', tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { 6 }
        it { should == "\xC6\x04\x28\xC2\x7B\x02" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x04\x28\xC2\x7B\x02" }
      end
    end

    context 'encodes tag class' do
      subject { klass.new('1.0.8571.2', Krypt::ASN1::OBJECT_ID, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x06\x04\x28\xC2\x7B\x02" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x46\x04\x28\xC2\x7B\x02" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x86\x04\x28\xC2\x7B\x02" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xC6\x04\x28\xC2\x7B\x02" }
      end
    end
  end

  describe 'extracted from ASN1.decode' do
    subject { decoder.decode(der) }

    context 'extracted value' do
      context '1.0.8571.2' do
        let(:der) { "\x06\x04\x28\xC2\x7B\x02" }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:value) { should == '1.0.8571.2' }
      end

      context '2 octets optimization' do
        context '0.0' do
          let(:der) { "\x06\x01\x00" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::OBJECT_ID }
          its(:value) { should == '0.0' } # "ITU-T" in OpenSSL
        end

        context '0.3' do
          let(:der) { "\x06\x01\x03" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::OBJECT_ID }
          its(:value) { should == '0.3' }
        end

        context '1.0' do
          let(:der) { "\x06\x01\x28" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::OBJECT_ID }
          its(:value) { should == '1.0' } # "ISO" in OpenSSL
        end

        context '1.3' do
          let(:der) { "\x06\x01\x2B" }
          its(:class) { should == klass }
          its(:tag) { should == Krypt::ASN1::OBJECT_ID }
          its(:value) { should == '1.3' } # "identified-organization" in OpenSSL
        end
      end

      context '0.0.0.....0' do
        let(:der) { "\x06\x82\x03\xE6\x00" + "\x00" * 997 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:value) { should == (['0'] * 999).join('.') }
      end

      context '1.1.1.....1' do
        let(:der) { "\x06\x82\x03\xE7\x29" + "\x01" * 998 }
        its(:class) { should == klass }
        its(:tag) { should == Krypt::ASN1::OBJECT_ID }
        its(:value) { should == (['1'] * 1000).join('.') }
      end
    end

    context 'extracted tag class' do
      context 'UNIVERSAL' do
        let(:der) { "\x06\x04\x28\xC2\x7B\x02" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x46\x04\x28\xC2\x7B\x02" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x86\x04\x28\xC2\x7B\x02" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xC6\x04\x28\xC2\x7B\x02" }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
