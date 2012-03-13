require 'rspec'
require 'krypt'
require_relative '../resources'


shared_examples_for "a primitive declaration" do |func|
  let(:asn1error) { Krypt::ASN1::ASN1Error }
  subject do
    n = name
    o = opts
    c = Class.new do
      include Krypt::ASN1::Template::Sequence
        send(func, n, o)
    end
    c.new
  end

  context "rejects declaration with no name" do
    let(:name) { nil }
    let(:opts) { nil }
    it { -> { subject }.should raise_error ArgumentError }
  end

  context "declararation with no options" do
    let(:name) { :test }
    let(:opts) { nil }
    it { subject.should respond_to name }
  end

  context "declaration with options" do
    let(:name) { :test }

    context "allows to mark as optional" do
      let(:opts) { {optional: true} }
      it { subject.should respond_to name }
    end

    context "allows to set a tag" do
      let(:opts) { {tag: 42} }
      it { subject.should respond_to name }
    end

    context "allows to set tagging" do
      let(:opts) { {tagging: :EXPLICIT} }
      it { subject.should respond_to name }
    end

    context "allows to set tagging" do
      let(:opts) { {tagging: :EXPLICIT} }
      it { subject.should respond_to name }
    end

    context "allows to set arbitrary default value" do
      let(:opts) { {default: Object.new} }
    end
  end
end

shared_examples_for "Krypt::ASN1::Template" do
  context "inclusion enables a set of DSL class methods" do
    subject do
      c = Class.new do
        include Krypt::ASN1::Template::Sequence
        send(dsl_method, name, opts)
      end
      c.new
    end
    
    context "asn1_boolean" do
      it_behaves_like "a primitive declaration", :asn1_boolean
    end

    context "asn1_integer" do
      it_behaves_like "a primitive declaration", :asn1_integer
    end

    context "asn1_bit_string" do
      it_behaves_like "a primitive declaration", :asn1_bit_string
    end

    context "asn1_octet_string" do
      it_behaves_like "a primitive declaration", :asn1_octet_string
    end

    context "asn1_null" do
      it_behaves_like "a primitive declaration", :asn1_null
    end

    context "asn1_object_id" do
      it_behaves_like "a primitive declaration", :asn1_object_id
    end

    context "asn1_enumerated" do
      it_behaves_like "a primitive declaration", :asn1_enumerated
    end

    context "asn1_utf8_string" do
      it_behaves_like "a primitive declaration", :asn1_utf8_string
    end

    context "asn1_numeric_string" do
      it_behaves_like "a primitive declaration", :asn1_numeric_string
    end

    context "asn1_printable_string" do
      it_behaves_like "a primitive declaration", :asn1_printable_string
    end

    context "asn1_t61_string" do
      it_behaves_like "a primitive declaration", :asn1_t61_string
    end

    context "asn1_videotex_string" do
      it_behaves_like "a primitive declaration", :asn1_videotex_string
    end

    context "asn1_ia5_string" do
      it_behaves_like "a primitive declaration", :asn1_ia5_string
    end

    context "asn1_utc_time" do
      it_behaves_like "a primitive declaration", :asn1_utc_time
    end

    context "asn1_generalized_time" do
      it_behaves_like "a primitive declaration", :asn1_generalized_time
    end

    context "asn1_graphic_string" do
      it_behaves_like "a primitive declaration", :asn1_graphic_string
    end

    context "asn1_iso64_string" do
      it_behaves_like "a primitive declaration", :asn1_iso64_string
    end

    context "asn1_general_string" do
      it_behaves_like "a primitive declaration", :asn1_general_string
    end

    context "asn1_universal_string" do
      it_behaves_like "a primitive declaration", :asn1_universal_string
    end

    context "asn1_bmp_string" do
      it_behaves_like "a primitive declaration", :asn1_bmp_string
    end
  end
end
      
describe "Krypt::ASN1::Template::Sequence" do
  it_behaves_like "Krypt::ASN1::Template"
end

describe "Krypt::ASN1::Template::Set" do
  it_behaves_like "Krypt::ASN1::Template"
end
