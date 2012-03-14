require 'rspec'
require 'krypt'
require_relative '../resources'


describe "Krypt::ASN1::Template::Sequence" do
  SEQ = Krypt::ASN1::Template::Sequence
  let(:asn1error) { Krypt::ASN1::ASN1Error }
  
  context "extracted from parse_der" do
    subject { template.parse_der(der) }

    context "single field" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :version
        end
      end
      let(:der) { "\x30\x03\x02\x01\x01" }
      its(:version) { should == 1 }
      it { subject.should be_an_instance_of template }
    end

    context "two fields" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :version
          asn1_boolean :works?
        end
      end
      let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
      its(:version) { should == 1 }
      its(:works?) { should == true }
      it { subject.should be_an_instance_of template }
    end

    context "optional first field" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a, optional: true
          asn1_boolean :b
          asn1_octet_string :c
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
      end

      context "absent" do
        let(:der) { "\x30\x06\x01\x01\xFF\x04\x01a" }
        its(:a) { should be_nil }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
      end
    end

    context "optional field between others" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b, optional: true
          asn1_octet_string :c
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
      end

      context "absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should be_nil }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
      end
    end

    context "optional field at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b
          asn1_octet_string :c, optional: true
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
      end

      context "absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should be_nil }
        it { subject.should be_an_instance_of template }
      end
    end

    context "multiple optional fields at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b
          asn1_octet_string :c, optional: true
          asn1_t61_string :d, optional: true
          asn1_ia5_string :e, optional: true
        end
      end
      
      context "all present" do
        let(:der) { "\x30\x0F\x02\x01\x01\x01\x01\xFF\x04\x01a\x14\x01b\x16\x01c" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should == "b" }
        its(:e) { should == "c" }
        it { subject.should be_an_instance_of template }
      end

      context "first absent" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x14\x01b\x16\x01c" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should be_nil }
        its(:d) { should == "b" }
        its(:e) { should == "c" }
        it { subject.should be_an_instance_of template }
      end

      context "absent between others" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x04\x01a\x16\x01c" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should be_nil }
        its(:e) { should == "c" }
        it { subject.should be_an_instance_of template }
      end

      context "last absent" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x04\x01a\x14\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should == "b"}
        its(:e) { should be_nil }
        it { subject.should be_an_instance_of template }
      end

      context "all absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should be_nil }
        its(:d) { should be_nil }
        its(:e) { should be_nil }
        it { subject.should be_an_instance_of template }
      end
    end

    context "single first default value field" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a, default: 42
          asn1_boolean :b
        end
      end
      
      context "present" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        it { subject.should be_an_instance_of template }
      end

      context "absent" do
        let(:der) { "\x30\x03\x01\x01\xFF" }
        its(:a) { should == 42 }
        its(:b) { should == true }
        it { subject.should be_an_instance_of template }
      end
    end

    context "default value field between others" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b, default: false
          asn1_octet_string :c
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
      end

      context "absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == false }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
      end
    end

    context "default value field at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b 
          asn1_octet_string :c, default: "b"
        end
      end
      
      context "present" do
        let(:der) { "\x30\x09\x02\x01\x01\x01\x01\xFF\x04\x01a" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        it { subject.should be_an_instance_of template }
      end

      context "absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "b" }
        it { subject.should be_an_instance_of template }
      end
    end
  end
end
