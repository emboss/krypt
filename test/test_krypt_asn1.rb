require_relative 'helper'
require 'stringio'

class Krypt::Asn1Test < Test::Unit::TestCase

  def test_parse_encode_equality_file
    io = Resources.certificate_io
    begin
      asn1 = Krypt::Asn1.decode(io)
      cert = Resources.certificate
      assert_equal(cert, asn1.to_der)
      assert_equal_streaming(cert, asn1)
    ensure
      io.close
    end
  end

  def test_parse_encode_equality_string_io
    io = StringIO.new(Resources.certificate)
    asn1 = Krypt::Asn1.decode(io)
    cert = Resources.certificate
    assert_equal(cert, asn1.to_der)
    assert_equal_streaming(cert, asn1)
  end

  def test_parse_encode_equality_string
    asn1 = Krypt::Asn1.decode(Resources.certificate)
    cert = Resources.certificate
    assert_equal(cert, asn1.to_der)
    assert_equal_streaming(cert, asn1)
  end

  def test_attributes
    raw = [%w{30 06 04 01 01 02 01 01}.join("")].pack("H*")
    asn1 = Krypt::Asn1.decode(raw)
    assert_universal(Krypt::Asn1::SEQUENCE, asn1)
    seq = asn1.value
    assert_equal(2, seq.size)
    octet = seq[0]
    assert_universal(Krypt::Asn1::OCTET_STRING, octet)
    assert_equal("\1", octet.value)
    integer = seq[1]
    assert_universal(Krypt::Asn1::INTEGER, integer)
    assert_equal(1, integer.value)
    
    assert_equal(raw, asn1.to_der)
  end

  private

  def assert_universal(tag, asn1)
    assert_equal(tag, asn1.tag)
    assert_equal(:UNIVERSAL, asn1.tag_class)
    assert_equal(false, asn1.infinite_length)
  end

  def assert_equal_streaming(raw, asn1)
    io = StringIO.new
    asn1.encode_to(io)
    assert_equal(raw, io.string.force_encoding("ASCII-8BIT"))
  end

end

