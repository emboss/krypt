module Krypt::Base64

  # Base64-encodes any data written or read from it in the process.
  #
  class Encoder < Krypt::IOFilter

    #
    # call-seq:
    #    in.read([len=nil], [buf=nil]) -> String or nil
    #
    # Reads from the underlying IO and Base64-encodes the data.
    # Please see IO#read for details.
    #
    def read(len=nil, buf=nil)
    end

    #
    # call-seq:
    #    out.write(string) -> Integer
    #
    # Base64-encodes +string+ and writes it to the underlying IO.
    # Please see IO#write for further details.
    #
    def write(data)
    end
    alias << write

  end
  
  # Base64-decodes any data written or read from it in the process.
  #
  class Decoder < Krypt::IOFilter

    #
    # call-seq:
    #    in.read([len=nil], [buf=nil]) -> String or nil
    #
    # Reads from the underlying IO and Base64-decodes the data.
    # Please see IO#read for further details.
    #
    def read(len=nil, buf=nil)
    end

    #
    # call-seq:
    #    out.write(string) -> Integer 
    #
    # Base64-decodes string and writes it to the underlying IO.
    # Please see IO#write for further details.
    #
    def write(data)
    end
    alias << write

  end
end
