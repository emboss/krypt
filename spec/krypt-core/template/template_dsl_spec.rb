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
      it { subject.should respond_to name }
    end

    context "allows to set optional, tag, tagging and default at once" do
      let(:opts) { {optional: true, tag: 42, tagging: :IMPLICIT, default: Object.new} }
      it { subject.should respond_to name }
    end
  end
end

shared_examples_for "a typed declaration" do |func|
  let(:template) do
    Class.new do
      include Krypt::ASN1::Template::Sequence
      asn1_integer :version
    end
  end

  subject do
    n = name
    t = type
    o = opts
    c = Class.new do
      include Krypt::ASN1::Template::Sequence
      send(func, n, t, o)
    end
    c.new
  end

  context "rejects declaration with no name" do
    let(:name) { nil }
    let(:type) { template }
    let(:opts) { nil }
    it { -> { subject }.should raise_error ArgumentError }
  end

  context "rejects declaration with no type" do
    let(:name) { :test }
    let(:type) { nil }
    let(:opts) { nil }
    it { -> { subject }.should raise_error ArgumentError }
  end

  context "declararation with no options" do
    let(:name) { :test }
    let(:type) { template }
    let(:opts) { nil }
    it { subject.should respond_to name }
  end

  context "declaration with options" do
    let(:name) { :test }
    let(:type) { template }

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
      it { subject.should respond_to name }
    end

    context "allows to set optional, tag, tagging and default at once" do
      let(:opts) { {optional: true, tag: 42, tagging: :IMPLICIT, default: Object.new} }
      it { subject.should respond_to name }
    end
  end
end

shared_examples_for "Krypt::ASN1::Template" do
  context "inclusion enables a set of DSL class methods" do
    context("asn1_boolean")          { it_behaves_like "a primitive declaration", :asn1_boolean }
    context("asn1_integer")          { it_behaves_like "a primitive declaration", :asn1_integer } 
    context("asn1_bit_string")       { it_behaves_like "a primitive declaration", :asn1_bit_string }
    context("asn1_octet_string")     { it_behaves_like "a primitive declaration", :asn1_octet_string }
    context("asn1_null")             { it_behaves_like "a primitive declaration", :asn1_null }
    context("asn1_object_id")        { it_behaves_like "a primitive declaration", :asn1_object_id }
    context("asn1_enumerated")       { it_behaves_like "a primitive declaration", :asn1_enumerated }
    context("asn1_utf8_string")      { it_behaves_like "a primitive declaration", :asn1_utf8_string }
    context("asn1_numeric_string")   { it_behaves_like "a primitive declaration", :asn1_numeric_string }
    context("asn1_printable_string") { it_behaves_like "a primitive declaration", :asn1_printable_string }
    context("asn1_t61_string")       { it_behaves_like "a primitive declaration", :asn1_t61_string }
    context("asn1_videotex_string")  { it_behaves_like "a primitive declaration", :asn1_videotex_string }
    context("asn1_ia5_string")       { it_behaves_like "a primitive declaration", :asn1_ia5_string }
    context("asn1_utc_time")         { it_behaves_like "a primitive declaration", :asn1_utc_time }
    context("asn1_generalized_time") { it_behaves_like "a primitive declaration", :asn1_generalized_time }
    context("asn1_graphic_string")   { it_behaves_like "a primitive declaration", :asn1_graphic_string }
    context("asn1_iso64_string")     { it_behaves_like "a primitive declaration", :asn1_iso64_string }
    context("asn1_general_string")   { it_behaves_like "a primitive declaration", :asn1_general_string }
    context("asn1_universal_string") { it_behaves_like "a primitive declaration", :asn1_universal_string }
    context("asn1_bmp_string")       { it_behaves_like "a primitive declaration", :asn1_bmp_string }
    context("asn1_any")              { it_behaves_like "a primitive declaration", :asn1_any }

    context("asn1_template")         { it_behaves_like "a typed declaration",     :asn1_template }
    context("asn1_sequence_of")      { it_behaves_like "a typed declaration",     :asn1_sequence_of }
    context("asn1_set_of")           { it_behaves_like "a typed declaration",     :asn1_set_of }
  end
end

shared_examples_for "constructed type constructor" do |type|
  let (:template) do
    Class.new do
      include type
      asn1_integer :a
    end
  end

  it "takes no-args" do
    template.new.should be_an_instance_of template
  end

  it "takes a block and yields the new instance" do
    template.new do |o|
      o.should be_an_instance_of template
    end
  end

  context "rejects blocks with arity != 1" do
    context "0" do
      it { -> { template.new { Object.new } }.should raise_error ArgumentError }
    end

    context ">1" do
      it { -> { template.new { |a,b| Object.new } }.should raise_error ArgumentError }
    end
  end

  it "allows assignment to its fields once instantiated" do
    o = template.new
    o.a = 42
    o.a.should == 42
  end

  it "allows assignment to its fields inside the block" do
    obj = template.new do |o|
      o.a = 42
    end
    obj.a.should == 42
  end
end
      
describe "Krypt::ASN1::Template::Sequence" do
  it_behaves_like "Krypt::ASN1::Template"
  it_behaves_like "constructed type constructor", Krypt::ASN1::Template::Sequence
end

describe "Krypt::ASN1::Template::Set" do
  it_behaves_like "Krypt::ASN1::Template"
  it_behaves_like "constructed type constructor", Krypt::ASN1::Template::Set
end

describe "Krypt::ASN1::Template::Choice" do
  let (:choice_value) { Krypt::ASN1::Template::ChoiceValue }
  let (:template) do
    Class.new do
      include Krypt::ASN1::Template::Choice
      asn1_integer 
      asn1_boolean
    end
  end

  it "takes no-args" do
    template.new.should be_an_instance_of template
  end

  it "takes a block and yields the new instance" do
    template.new do |o|
      o.should be_an_instance_of template
    end
  end

  context "rejects blocks with arity != 1" do
    context "0" do
      it { -> { template.new { Object.new } }.should raise_error ArgumentError }
    end

    context ">1" do
      it { -> { template.new { |a,b| Object.new } }.should raise_error ArgumentError }
    end
  end

  it "allows assignment to 'value' once instantiated" do
    o = template.new
    o.value = choice_value.new(Krypt::ASN1::INTEGER)
    o.value.should be_an_instance_of choice_value
  end

  it "allows assignment to 'value' inside the block" do
    obj = template.new do |o|
      o.value = choice_value.new(Krypt::ASN1::INTEGER)
    end
    obj.value.should be_an_instance_of choice_value 
  end

end

