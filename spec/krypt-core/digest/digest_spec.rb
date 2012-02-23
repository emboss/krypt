require 'rspec'
require 'krypt-core'
require 'stringio'
require 'base64'
require_relative '../resources'

describe Krypt::Digest do
  let(:klass) { Krypt::Digest }
  let(:digesterror) { Krypt::Digest::DigestError }

  describe "#new" do
    context "accepts a String representing an algorithm" do
      subject { klass.new(algo) }

      context "SHA1" do
        context "uppercase" do
          let(:algo) { "SHA1" }
          its(:name) { should == algo }
        end 

        describe "although algorithms can be requested in lowercase, the name
                  will always be returned in uppercase" do
          context "lowercase" do
            let(:algo) { "sha1" }
            its(:name) { should == "SHA1" }
          end 
        end
      end

      context "SHA224" do
        context "uppercase" do
          let(:algo) { "SHA224" }
          its(:name) { should == algo }
        end 

        context "lowercase" do
          let(:algo) { "sha224" }
          its(:name) { should == "SHA224" }
        end 
      end

      context "SHA256" do
        context "uppercase" do
          let(:algo) { "SHA256" }
          its(:name) { should == algo }
        end 

        context "lowercase" do
          let(:algo) { "sha256" }
          its(:name) { should == "SHA256" }
        end 
      end

      context "SHA384" do
        context "uppercase" do
          let(:algo) { "SHA384" }
          its(:name) { should == algo }
        end 

        context "lowercase" do
          let(:algo) { "sha384" }
          its(:name) { should == "SHA384" }
        end 
      end

      context "SHA512" do
        context "uppercase" do
          let(:algo) { "SHA512" }
          its(:name) { should == algo }
        end 

        context "lowercase" do
          let(:algo) { "sha512" }
          its(:name) { should == "SHA512" }
        end 
      end

#     context "RIPEMD160" do
#        context "uppercase" do
#          let(:algo) { "RIPEMD160" }
#          its(:name) { should == algo }
#        end 
#
#        context "lowercase" do
#          let(:algo) { "ripemd160" }
#          its(:name) { should == "RIPEMD160" }
#        end 
#      end

      context "MD5" do
        context "uppercase" do
          let(:algo) { "MD5" }
          its(:name) { should == algo }
        end 

        context "lowercase" do
          let(:algo) { "md5" }
          its(:name) { should == "MD5" }
        end 
      end
    end

    it "rejects an unknown algorithm" do
      -> { klass.new("HAS1") }.should raise_error digesterror 
    end

    context "accepts an algorithm oid String" do
      subject { klass.new(oid) }

      context "SHA-1" do
        let(:oid) { "1.3.14.3.2.26" }
        its(:name) { should == "SHA1" }
      end

      context "SHA-224" do
        let(:oid) { "2.16.840.1.101.3.4.2.4" }
        its(:name) { should == "SHA224" }
      end

      context "SHA-256" do
        let(:oid) { "2.16.840.1.101.3.4.2.1" }
        its(:name) { should == "SHA256" }
      end

      context "SHA-384" do
        let(:oid) { "2.16.840.1.101.3.4.2.2" }
        its(:name) { should == "SHA384" }
      end

      context "SHA-512" do
        let(:oid) { "2.16.840.1.101.3.4.2.3" }
        its(:name) { should == "SHA512" }
      end

#      context "RIPEMD-160" do
#        let(:oid) { "1.3.36.3.2.1" }
#        its(:name) { should == "RIPEMD160" }
#      end

      context "MD5" do
        let(:oid) { "1.2.840.113549.2.5" }
        its(:name) { should == "MD5" }
      end
    end

    it "rejects an unknown oid" do
      -> { klass.new("1.2.3.4.5") }.should raise_error digesterror
    end
  end

  describe "#update" do
    it "takes a String as an argument and returns self" do
      md = klass.new("SHA1")
      md.update("test").should be_equal md
    end

    it "<< is an alias" do
      algo = "SHA1"
      md = klass.new(algo)
      md.update("test")
      digest = md.digest

      md = klass.new(algo)
      md << "test"
      md.digest.should == digest
    end

    it "treats multiple updates equivalently to one single call to #digest" do
      algo = "SHA1"
      data = "a" * 64
      n = 3
      h1 = klass.new(algo)
      h2 = klass.new(algo)
      n.times { h1 << data }
      h2 << (data * n)
      h1.digest.should == h2.digest
    end
  end

  describe "#digest" do
    subject { klass.new("SHA1") }

    it "outputs the digest of everything hashed so far when given no
        arguments" do
      subject.update("test").digest.should be_an_instance_of String
    end

    it "updates itself with a given String argument and returns the
        final digest" do
      h = klass.new("SHA1")
      h << "test"
      subject.digest("test").should == h.digest
    end

    it "resets its internal state after no-args call" do
      data = "test"
      digest = subject.digest(data)
      h = klass.new("SHA1")
      h << data
      h.digest
      h << data 
      digest.should == h.digest
      # in case we found a collision ;)
      digest.should_not == klass.new("SHA1").<<(data).<<(data).digest
    end

    it "doesn't alter internal state when called with argument" do
      data = "test"
      digest = subject.digest(data)
      h = klass.new("SHA1")
      h.digest(data)
      h << data
      digest.should == h.digest
    end
  end

  describe "#reset" do
    it "takes no arguments and returns self" do
      h = klass.new("SHA1")
      h.reset.should be_equal h
    end

    it "resets the internal state of an instance" do
      algo = "SHA1"
      data = "test"
      noise = "abcd"
      h = klass.new(algo)
      h << noise 
      digest = h.reset.digest(data)
      digest.should == klass.new(algo).digest(data)
      # in case we found a collision ;)
      digest.should_not == klass.new(algo).update(noise).digest(data)
    end
  end

  context "#name" do
    subject { klass.new(value) }
    
    context "returns the algorithm name of an instance in uppercase letters" do
      context "when created from uppercase algorithm" do
        let(:value) { "SHA1" }
        its(:name) { should == value }
      end

      context "when created from lowercase algorithm" do
        let(:value) { "sha1" }
        its(:name) { should == "SHA1" }
      end

      context "when created from an OID" do
        let(:value) { "1.3.14.3.2.26" }
        its(:name) { should == "SHA1" }
      end
    end
  end
  
  describe "#digest_length" do
    context "returns the size of the final digest in bytes" do
      subject { klass.new(algo) }

      context "SHA1" do
        let(:algo) { "SHA1" }
        its(:digest_length) { should == 20 }
      end

      context "SHA224" do
        let(:algo) { "SHA224" }
        its(:digest_length) { should == 28 }
      end

      context "SHA256" do
        let(:algo) { "SHA256" }
        its(:digest_length) { should == 32 }
      end

      context "SHA384" do
        let(:algo) { "SHA384" }
        its(:digest_length) { should == 48 }
      end

      context "SHA512" do
        let(:algo) { "SHA512" }
        its(:digest_length) { should == 64 }
      end

#      context "RIPEMD160" do
#        let(:algo) { "RIPEMD160" }
#        its(:digest_length) { should == 20 }
#      end

      context "MD5" do
        let(:algo) { "MD5" }
        its(:digest_length) { should == 16 }
      end
    end
  end

  describe "#block_length" do
    context "returns the size of one input message block in bytes" do
      subject { klass.new(algo) }

      context "SHA1" do
        let(:algo) { "SHA1" }
        its(:block_length) { should == 64 }
      end

      context "SHA224" do
        let(:algo) { "SHA224" }
        its(:block_length) { should == 64 }
      end

      context "SHA256" do
        let(:algo) { "SHA256" }
        its(:block_length) { should == 64 }
      end

      context "SHA384" do
        let(:algo) { "SHA384" }
        its(:block_length) { should == 128 }
      end

      context "SHA512" do
        let(:algo) { "SHA512" }
        its(:block_length) { should == 128 }
      end

#      context "RIPEMD160" do
#        let(:algo) { "RIPEMD160" }
#        its(:block_length) { should == 64 }
#      end

      context "MD5" do
        let(:algo) { "MD5" }
        its(:block_length) { should == 64 }
      end
    end
  end

  describe "explicit constructors" do
    context "behave exactly like the equivalent Digest instance" do
      let(:data) { "test" }
      let(:expected) { klass.new(algo).digest(data) }

      context "SHA1" do
        let(:algo) { "SHA1" }
        it { klass::SHA1.new.digest(data).should == expected }
      end

      context "SHA224" do
        let(:algo) { "SHA224" }
        it { klass::SHA224.new.digest(data).should == expected }
      end

      context "SHA256" do
        let(:algo) { "SHA256" }
        it { klass::SHA256.new.digest(data).should == expected }
      end

      context "SHA384" do
        let(:algo) { "SHA384" }
        it { klass::SHA384.new.digest(data).should == expected }
      end

      context "SHA512" do
        let(:algo) { "SHA512" }
        it { klass::SHA512.new.digest(data).should == expected }
      end

#      context "RIPEMD160" do
#        let(:algo) { "RIPEMD160" }
#        it { klass::RIPEMD160.new.digest(data).should == expected }
#      end

      context "MD5" do
        let(:algo) { "MD5" }
        it { klass::MD5.new.digest(data).should == expected }
      end
    end
  end

  # taken from FIPS 180-2
  # empty string vectors taken from http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
  context "conforms to NIST test vectors" do
    context "SHA-1" do
      subject { klass::SHA1.new.digest(data) }

      context "one block message sample" do
        let(:data) { "abc" }
        let(:expected) { ["A9993E364706816ABA3E25717850C26C9CD0D89D"].pack("H*") }
        it { subject.should == expected }
      end

      context "two block message sample" do
        let(:data) { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
        let(:expected) { ["84983E441C3BD26EBAAE4AA1F95129E5E54670F1"].pack("H*") }
        it { subject.should == expected }
      end

      context "multi-block message sample" do
        let(:data) { "a" * 10**6 }
        let(:expected) { ["34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"].pack("H*") }
        it { subject.should == expected }
      end

      context "empty string" do
        let(:data) { "" }
        let(:expected) { ["DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"].pack("H*") }
        it { subject.should == expected }
      end
    end

    context "SHA-256" do
      subject { klass::SHA256.new.digest(data) }

      context "one block message sample" do
        let(:data) { "abc" }
        let(:expected) { ["BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"].pack("H*") }
        it { subject.should == expected }
      end

      context "two block message sample" do
        let(:data) { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
        let(:expected) { ["248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"].pack("H*") }
        it { subject.should == expected }
      end

      context "multi-block message sample" do
        let(:data) { "a" * 10**6 }
        let(:expected) { ["CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"].pack("H*") }
        it { subject.should == expected }
      end

      context "empty string" do
        let(:data) { "" }
        let(:expected) { ["E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"].pack("H*") }
        it { subject.should == expected }
      end
    end

    context "SHA-512" do
      subject { klass::SHA512.new.digest(data) }

      context "one block message sample" do
        let(:data) { "abc" }
        let(:expected) { ["DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"].pack("H*") }
        it { subject.should == expected }
      end

      context "two block message sample" do
        let(:data) { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" }
        let(:expected) { ["8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909"].pack("H*") }
        it { subject.should == expected }
      end

      context "multi-block message sample" do
        let(:data) { "a" * 10**6 }
        let(:expected) { ["E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B"].pack("H*") }
        it { subject.should == expected }
      end

      context "empty string" do
        let(:data) { "" }
        let(:expected) { ["CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"].pack("H*") }
        it { subject.should == expected }
      end
    end

    context "SHA-384" do
      subject { klass::SHA384.new.digest(data) }

      context "one block message sample" do
        let(:data) { "abc" }
        let(:expected) { ["CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"].pack("H*") }
        it { subject.should == expected }
      end

      context "two block message sample" do
        let(:data) { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" }
        let(:expected) { ["09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039"].pack("H*") }
        it { subject.should == expected }
      end

      context "multi-block message sample" do
        let(:data) { "a" * 10**6 }
        let(:expected) { ["9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B07B8B3DC38ECC4EBAE97DDD87F3D8985"].pack("H*") }
        it { subject.should == expected }
      end

      context "empty string" do
        let(:data) { "" }
        let(:expected) { ["38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"].pack("H*") }
        it { subject.should == expected }
      end
    end

    context "SHA-224" do
      subject { klass::SHA224.new.digest(data) }

      context "one block message sample" do
        let(:data) { "abc" }
        let(:expected) { ["23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"].pack("H*") }
        it { subject.should == expected }
      end

      context "two block message sample" do
        let(:data) { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
        let(:expected) { ["75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525"].pack("H*") }
        it { subject.should == expected }
      end

      context "multi-block message sample" do
        let(:data) { "a" * 10**6 }
        let(:expected) { ["20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67"].pack("H*") }
        it { subject.should == expected }
      end

      context "empty string" do
        let(:data) { "" }
        let(:expected) { ["D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"].pack("H*") }
        it { subject.should == expected }
      end
    end
  end

  # taken from http://homes.esat.kuleuven.be/~bosselae/ripemd160.html
#  context "RIPEMD-160 implementation conforms to test vectors" do
#    subject { klass::RIPEMD160.new.digest(data) }
#
#    context "empty string" do
#      let(:data) { "" }
#      let(:expected) { ["9C1185A5C5E9FC54612808977EE8F548B2258D31"].pack("H*") }
#      it { subject.should == expected }
#    end
#
#    context "a" do
#      let(:data) { "a" }
#      let(:expected) { ["0BDC9D2D256B3EE9DAAE347BE6F4DC835A467FFE"].pack("H*") }
#      it { subject.should == expected }
#    end
#
#    context "abc" do
#      let(:data) { "abc" }
#      let(:expected) { ["8EB208F7E05D987A9B044A8E98C6B087F15A0BFC"].pack("H*") }
#      it { subject.should == expected }
#    end
#
#    context "message digest" do
#      let(:data) { "message digest" }
#      let(:expected) { ["5D0689EF49D2FAE572B881B123A85FFA21595F36"].pack("H*") }
#      it { subject.should == expected }
#    end
#
#    context "a to z" do
#      let(:data) { "abcdefghijklmnopqrstuvwxyz" }
#      let(:expected) { ["F71C27109C692C1B56BBDCEB5B9D2865B3708DBC"].pack("H*") }
#      it { subject.should == expected }
#    end
#
#    context "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" do
#      let(:data) { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
#      let(:expected) { ["12A053384A9C0C88E405A06C27DCF49ADA62EB2B"].pack("H*") }
#      it { subject.should == expected }
#    end
#
#    context "A...Za...z0...9" do
#      let(:data) { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" }
#      let(:expected) { ["B0E20B6E3116640286ED3A87A5713079B21F5189"].pack("H*") }
#      it { subject.should == expected }
#    end
#
#    context "8 times 1 to 0" do
#      let(:data) { "1234567890" * 8 }
#      let(:expected) { ["9B752E45573D4B39F4DBD3323CAB82BF63326BFB"].pack("H*") }
#      it { subject.should == expected }
#    end
#
#    context "million times 'a'" do
#      let(:data) { "a" * 10**6 }
#      let(:expected) { ["52783243C1697BDBE16D37F97F68F08325DC1528"].pack("H*") }
#      it { subject.should == expected }
#    end
#  end

  # taken from http://www.nsrl.nist.gov/testdata/
  context "MD5 implementation conforms to test vectors" do
    subject { klass::MD5.new.digest(data) }

    context "one block message sample" do
      let(:data) { "abc" }
      let(:expected) { ["900150983CD24FB0D6963F7D28E17F72"].pack("H*") }
      it { subject.should == expected }
    end

    context "two block message sample" do
      let(:data) { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
      let(:expected) { ["8215EF0796A20BCAAAE116D3876C664A"].pack("H*") }
      it { subject.should == expected }
    end

    context "multi-block message sample" do
      let(:data) { "a" * 10**6 }
      let(:expected) { ["7707D6AE4E027C70EEA2A935C2296F21"].pack("H*") }
      it { subject.should == expected }
    end

    context "empty string" do
      let(:data) { "" }
      let(:expected) { ["D41D8CD98F00B204E9800998ECF8427E"].pack("H*") }
      it { subject.should == expected }
    end
  end
end

