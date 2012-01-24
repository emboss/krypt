require 'rspec'
require 'krypt-core'
require 'openssl'

# Almost similar to the spec for Krypt::Asn1::Enumerated
describe Krypt::Asn1::Enumerated do 
  let(:klass) { Krypt::Asn1::Enumerated }
  let(:decoder) { Krypt::Asn1 }

  # For test against OpenSSL
  #
  #let(:klass) { OpenSSL::ASN1::Enumerated }
  #let(:decoder) { OpenSSL::ASN1 }
  #
  # OpenSSL stub for signature mismatch
  class OpenSSL::ASN1::Enumerated
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
      subject { klass.new(72) }

      its(:tag) { should == 10 }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 72 }
      its(:infinite_length) { should == false }
    end

    context 'explicit construct' do
      subject { klass.new(72, 10, :UNIVERSAL) }

      its(:tag) { should == 10 }
      its(:tag_class) { should == :UNIVERSAL }
      its(:value) { should == 72 }
    end

    context 'private tag handling' do
      subject { klass.new(72, tag, :PRIVATE) }

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
      subject { klass.new(72, 10, tag_class) }

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

      context 0 do
        let(:value) { 0 }
        it { should == "\x0A\x01\x00" }
      end

      context 72 do
        let(:value) { 72 }
        it { should == "\x0A\x01\x48" }
      end

      context 127 do
        let(:value) { 127 }
        it { should == "\x0A\x01\x7F" }
      end

      context -128 do
        let(:value) { -128 }
        it { should == "\x0A\x01\x80" }
      end

      context 128 do
        let(:value) { 128 }
        it { should == "\x0A\x02\x00\x80" }
      end

      context -27066 do
        let(:value) { -27066 }
        it { should == "\x0A\x02\x96\x46" }
      end

      context 'max Fixnum on 32bit box' do
        let(:value) { 2**30-1 }
        it { should == "\x0A\x04\x3F\xFF\xFF\xFF" }
      end

      context 'max Fixnum on 64bit box' do
        let(:value) { 2**62-1 }
        it { should == "\x0A\x08\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF" }
      end
    end

    context 'private tag handling' do
      subject { klass.new(72, tag, :PRIVATE).to_der }

      context 'default tag' do
        let(:tag) { 10 }
        it { should == "\xCA\x01\x48" }
      end

      context 'custom tag (TODO: allowed?)' do
        let(:tag) { 14 }
        it { should == "\xCE\x01\x48" }
      end
    end

    context 'tag_class handling' do
      subject { klass.new(72, 10, tag_class).to_der }

      context 'UNIVERSAL' do
        let(:tag_class) { :UNIVERSAL }
        it { should == "\x0A\x01\x48" }
      end

      context 'APPLICATION' do
        let(:tag_class) { :APPLICATION }
        it { should == "\x4A\x01\x48" }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:tag_class) { :CONTEXT_SPECIFIC }
        it { should == "\x8A\x01\x48" }
      end

      context 'PRIVATE' do
        let(:tag_class) { :PRIVATE }
        it { should == "\xCA\x01\x48" }
      end
    end
  end

  describe 'decoding' do
    subject { decoder.decode(der) }

    context 'value' do
      context 0 do
        let(:der) { "\x0A\x01\x00" }
        its(:class) { should == klass }
        its(:tag) { should == 10 }
        its(:value) { should == 0 }
      end

      context 72 do
        let(:der) { "\x0A\x01\x48" }
        its(:class) { should == klass }
        its(:tag) { should == 10 }
        its(:value) { should == 72 }
      end

      context 127 do
        let(:der) { "\x0A\x01\x7F" }
        its(:class) { should == klass }
        its(:tag) { should == 10 }
        its(:value) { should == 127 }
      end

      context -128 do
        let(:der) { "\x0A\x01\x80" }
        its(:class) { should == klass }
        its(:tag) { should == 10 }
        its(:value) { should == -128 } # TODO: ossl returns 128 (positive value)
      end

      context 128 do
        let(:der) { "\x0A\x02\x00\x80" }
        its(:class) { should == klass }
        its(:tag) { should == 10 }
        its(:value) { should == 128 }
      end

      context -27066 do
        let(:der) { "\x0A\x02\x96\x46" }
        its(:class) { should == klass }
        its(:tag) { should == 10 }
        its(:value) { should == -27066 } # TODO: ossl returns 27066 (positive value)
      end

      context 'max Fixnum on 32bit box' do
        let(:der) { "\x0A\x04\x3F\xFF\xFF\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == 10 }
        its(:value) { should == 2**30-1 }
      end

      context 'max Fixnum on 64bit box' do
        let(:der) { "\x0A\x08\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF" }
        its(:class) { should == klass }
        its(:tag) { should == 10 }
        its(:value) { should == 2**62-1 }
      end
    end

    context 'tag_class handling' do
      context 'UNIVERSAL' do
        let(:der) { "\x0A\x02\x00\x80" }
        its(:tag_class) { should == :UNIVERSAL }
      end

      context 'APPLICATION' do
        let(:der) { "\x4A\x02\x00\x80" }
        its(:tag_class) { should == :APPLICATION }
      end

      context 'CONTEXT_SPECIFIC' do
        let(:der) { "\x8A\x02\x00\x80" }
        its(:tag_class) { should == :CONTEXT_SPECIFIC }
      end

      context 'PRIVATE' do
        let(:der) { "\xCA\x02\x00\x80" }
        its(:tag_class) { should == :PRIVATE }
      end
    end
  end
end
