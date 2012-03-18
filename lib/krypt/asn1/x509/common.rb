module Krypt::ASN1
  module X509

    class Extension
      include Krypt::ASN1::Template::Sequence

      asn1_object_id :id
      asn1_boolean :critical, default: false
      asn1_octet_string :value
    end

    class Time
      include Krypt::ASN1::Template::Choice

      asn1_utc_time
      asn1_generalized_time
    end

    class Validity
      include Krypt::ASN1::Template::Sequence

      asn1_template :not_before, X509::Time
      asn1_template :not_after, X509::Time
    end

  end
end
