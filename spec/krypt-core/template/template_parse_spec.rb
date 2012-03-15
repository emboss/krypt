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
      context "accepts correct encoding" do
        let(:der) { "\x30\x03\x02\x01\x01" }
        its(:version) { should == 1 }
        it { subject.should be_an_instance_of template }
      end
      context "rejects wrong encoding" do
        let(:der) { "\x30\x03\x04\x01\x01" }
        it { -> { subject.version }.should raise_error asn1error }
      end
      context "rejects encoding that is too long" do
        let(:der) { "\x30\x06\x04\x01\x01\x04\x01\x01" }
        it { -> { subject.version }.should raise_error asn1error }
      end
      context "rejects encoding that is not complete" do
        let(:der) { "\x30\x03\x04\x01" }
        it { -> { subject.version }.should raise_error asn1error }
      end
    end

    context "two fields" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :version
          asn1_boolean :works?
        end
      end
      context "accepts correct encoding do" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:version) { should == 1 }
        its(:works?) { should == true }
        it { subject.should be_an_instance_of template }
      end
      context "rejects encodings where either field is missing" do
        context "(first)" do
          let(:der) { "\x30\x03\x01\x01\xFF" }
          it { -> { subject.version }.should raise_error asn1error }
        end
        context "(second)" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          it { -> { subject.version }.should raise_error asn1error }
        end
      end
    end

    context "tagged field" do
      let(:template) do
        t = tag
        tg = tagging
        Class.new do
          include SEQ
          asn1_integer :a, tag: t, tagging: tg 
          asn1_boolean :b
        end
      end

      shared_examples_for "a non-constructed encoding" do |tagging, tag_byte|
        context "accepts correct encoding" do
          let(:der) { "\x30\x06#{tag_byte}\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { tagging }
          its(:a) { should == 1 }
          its(:b) { should == true }
        end

        context "reject wrong encoding" do
          let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { tagging }
          it { -> { subject.a }.should raise_error asn1error }
        end
      end

      context ":IMPLICIT" do
        it_behaves_like "a non-constructed encoding", :IMPLICIT, "\x80"
      end

      context ":EXPLICIT" do
        context "accepts correct encoding" do
          let(:der) { "\x30\x08\xA0\x03\x02\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { :EXPLICIT }
          its(:a) { should == 1 }
          its(:b) { should == true }
        end

        context "reject wrong encoding (non-constructed)" do
          let(:der) { "\x30\x08\x80\x03\x02\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { :EXPLICIT }
          it { -> { subject.a }.should raise_error asn1error }
        end

        context "reject wrong encoding" do
          let(:der) { "\x30\x06\x80\x01\x01\x01\x01\xFF" }
          let(:tag) { 0 }
          let(:tagging) { :EXPLICIT }
          it { -> { subject.a }.should raise_error asn1error }
        end
      end

      context ":CONTEXT_SPECIFIC" do
        it_behaves_like "a non-constructed encoding", :IMPLICIT, "\x80"
      end

      context ":APPLICATION" do
        it_behaves_like "a non-constructed encoding", :APPLICATION, "\x40"
      end

      context ":PRIVATE" do
        it_behaves_like "a non-constructed encoding", :PRIVATE, "\xC0"
      end
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

    context "multiple default value fields at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_boolean :b
          asn1_octet_string :c, default: "a"
          asn1_t61_string :d, default: "a"
          asn1_ia5_string :e, default: "a"
        end
      end
      
      context "all present" do
        let(:der) { "\x30\x0F\x02\x01\x01\x01\x01\xFF\x04\x01b\x14\x01b\x16\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "b" }
        its(:d) { should == "b" }
        its(:e) { should == "b" }
        it { subject.should be_an_instance_of template }
      end

      context "first absent" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x14\x01b\x16\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should == "b" }
        its(:e) { should == "b" }
        it { subject.should be_an_instance_of template }
      end

      context "absent between others" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x04\x01b\x16\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "b" }
        its(:d) { should == "a" }
        its(:e) { should == "b" }
        it { subject.should be_an_instance_of template }
      end

      context "last absent" do
        let(:der) { "\x30\x0C\x02\x01\x01\x01\x01\xFF\x04\x01b\x14\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "b" }
        its(:d) { should == "b"}
        its(:e) { should == "a" }
        it { subject.should be_an_instance_of template }
      end

      context "all absent" do
        let(:der) { "\x30\x06\x02\x01\x01\x01\x01\xFF" }
        its(:a) { should == 1 }
        its(:b) { should == true }
        its(:c) { should == "a" }
        its(:d) { should == "a" }
        its(:e) { should == "a" }
        it { subject.should be_an_instance_of template }
      end
    end

    context "default value and optional fields mixed at beginning" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_octet_string :a, optional: true
          asn1_t61_string :b, default: "a"
          asn1_ia5_string :c, default: "a"
          asn1_integer :d
        end
      end

      context "all present" do
        let(:der) { "\x30\x0C\x04\x01b\x14\x01b\x16\x01b\x02\x01\x01" }
        its(:a) { should == "b" }
        its(:b) { should == "b" }
        its(:c) { should == "b" }
        its(:d) { should == 1 }
      end

      context "all absent" do
        let(:der) { "\x30\x03\x02\x01\x01" }
        its(:a) { should be_nil }
        its(:b) { should == "a" }
        its(:c) { should == "a" }
        its(:d) { should == 1 }
      end

      context "rejects otherwise correct encoding if stream is not consumed" do
        let(:der) { "\x30\x06\x02\x01\x01\x04\x01\x01" } # :d is matched, all others optional or default
        it { -> { subject.a }.should raise_error asn1error }
      end

      context "rejects when wrong encoding is given for an optional field" do
        let(:der) { "\x30\x0C\x01\x01\x00\x14\x01b\x16\x01b\x02\x01\x01" }
        it { -> { subject.a }.should raise_error asn1error }
      end

      context "rejects when wrong encoding is given for a default field" do
        let(:der) { "\x30\x0C\x04\x01\x01\x04\x01b\x16\x01b\x02\x01\x01" }
        it { -> { subject.a }.should raise_error asn1error }
      end

      context "rejects when wrong encoding is given for a default field and the
               optional field is omitted" do
        let(:der) { "\x30\x09\x01\x01\xFF\x16\x01b\x02\x01\x01" }
        it { -> { subject.a }.should raise_error asn1error }
      end
    end

    context "default value and optional fields mixed at end" do
      let(:template) do
        Class.new do
          include SEQ
          asn1_integer :a
          asn1_octet_string :b, optional: true
          asn1_t61_string :c, default: "a"
          asn1_ia5_string :d, default: "a"
        end
      end

      context "all present" do
        let(:der) { "\x30\x0C\x02\x01\x01\x04\x01b\x14\x01b\x16\x01b" }
        its(:a) { should == 1 }
        its(:b) { should == "b" }
        its(:c) { should == "b" }
        its(:d) { should == "b" }
      end

      context "all absent" do
        let(:der) { "\x30\x03\x02\x01\x01" }
        its(:a) { should == 1 }
        its(:b) { should be_nil }
        its(:c) { should == "a" }
        its(:d) { should == "a" }
      end
    end

    context "inner template" do
      let(:template2) do
        Class.new do
          include SEQ
          asn1_boolean :a
        end
      end

      context "at beginning" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_template :a, t
            asn1_integer :b
          end
        end

        context "accepts valid encoding" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x30\x06\x01\x01\xFF\x02\x01\x01" }
          it { -> { subject.a }.should raise_error asn1error }
        end
      end

      context "at end" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_integer :a
            asn1_template :b, t
          end
        end

        context "accepts valid encoding" do
          let(:der) { "\x30\x08\x02\x01\x01\x30\x03\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of template2 }
          it { subject.b.a.should == true }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x31\x08\x02\x01\x01\x30\x03\x01\x01\xFF" }
          it { -> { subject.a }.should raise_error asn1error }
        end
      end

      context "with implicit tagging" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_template :a, t, tag: 0, tagging: :IMPLICIT
            asn1_integer :b
          end
        end

        context "accepts valid encoding" do
          let(:der) { "\x30\x08\xA0\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          it { -> { subject.a }.should raise_error asn1error }
        end
      end

      context "with explicit tagging" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_template :a, t, tag: 0, tagging: :EXPLICIT
            asn1_integer :b
          end
        end

        context "accepts valid encoding" do
          let(:der) { "\x30\x0A\xA0\x05\x30\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
        end

        context "rejects wrong encoding" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          it { -> { subject.a }.should raise_error asn1error }
        end
      end

      context "optional" do
        let(:template) do
          t = template2
          Class.new do
            include SEQ
            asn1_template :a, t, optional: true
            asn1_integer :b
          end
        end

        context "present" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
        end

        context "absent" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          its(:a) { should be_nil }
          its(:b) { should == 1 }
        end
      end

      context "with default value at beginning" do
        let(:template) do
          t = template2
          obj = t.new
          obj.a = false
          Class.new do
            include SEQ
            asn1_template :a, t, default: obj
            asn1_integer :b
          end
        end

        context "present" do
          let(:der) { "\x30\x08\x30\x03\x01\x01\xFF\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == true }
          its(:b) { should == 1 }
        end

        context "absent" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          its(:a) { should be_an_instance_of template2 }
          it { subject.a.a.should == false }
          its(:b) { should == 1 }
        end
      end

      context "with default value at end" do
        let(:template) do
          t = template2
          obj = t.new
          obj.a = false
          Class.new do
            include SEQ
            asn1_integer :a
            asn1_template :b, t, default: obj
          end
        end

        context "present" do
          let(:der) { "\x30\x08\x02\x01\x01\x30\x03\x01\x01\xFF" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of template2 }
          it { subject.b.a.should == true }
        end

        context "absent" do
          let(:der) { "\x30\x03\x02\x01\x01" }
          its(:a) { should == 1 }
          its(:b) { should be_an_instance_of template2 }
          it { subject.b.a.should == false }
        end
      end
    end
  end
end
