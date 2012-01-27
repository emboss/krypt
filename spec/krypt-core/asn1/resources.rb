require 'stringio'

module Krypt
  module ASN1
    module Resources
      def string_io_object
        obj = StringIO.new("".encode("BINARY"))
        def obj.written_bytes
          string
        end
        obj
      end

      def writable_object
        obj = Object.new
        def obj.write(str)
          (@buf ||= "") << str
          str.size
        end
        def obj.written_bytes; @buf; end
        obj
      end

      def io_error_object
        obj = Object.new
        def obj.write(str)
          raise EOFError, 'bark'
        end
        obj
      end

      def s(str)
        Krypt::ASN1::OctetString.new(str)
      end

      def i(num)
        Krypt::ASN1::Integer.new(num)
      end

      def eoc
        Krypt::ASN1::EndOfContents.new
      end

      def yielded_value_from_each(obj)
        all = []
        obj.each do |element|
          all << element
        end
        all
      end
    end
  end
end
