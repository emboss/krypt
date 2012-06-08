module Krypt::Hex

  # Hex-encodes any data written or read from it in the process.
  #
  # === Example: Hex-encoded data and writing it to a file
  # f = File.open("hex", "wb")
  # hex = Krypt::Hex::Encoder.new(f)
  # hex << "one"
  # hex << "two"
  # hex.close # => contents in file will be encoded
  #
  # === Example: Reading from a file and hex-encoding the data
  # f = File.open("document", "rb")
  # hex = Krypt::Hex::Encoder.new(f)
  # hexdata = hex.read # => result is encoded
  # hex.close
  #
  class Encoder < Krypt::IOFilter

    #
    # call-seq:
    #    in.read([len=nil], [buf=nil]) -> String or nil
    #
    # Reads from the underlying IO and hex-encodes the data.
    # Please see IO#read for details.
    #
    def read(len=nil, buf=nil)
      data = @io.read(len, buf)
      Krypt::Hex.encode(data)
    end

    #
    # call-seq:
    #    out.write(string) -> Integer
    #
    # Hex-encodes +string+ and writes it to the underlying IO.
    # Please see IO#write for further details.
    #
    def write(data)
      @io.write(Krypt::Hex.encode(data))
    end
    alias << write

  end
  
  # Hex-decodes any data written or read from it in the process.
  #
  # === Example: Reading and decoding hex-encoded data from a file
  # f = File.open("hex", "rb")
  # hex = Krypt::Hex::Decoder.new(f)
  # plain = hex.read # => result is decoded
  # hex.close
  #
  # === Example: Writing to a file while hex-decoding the data
  # f = File.open("document", "wb")
  # hex = Krypt::Hex::Decoder.new(f)
  # hexdata = ... #some hex-encoded data
  # hex << hexdata
  # hex.close # => contents in file will be decoded
  #
  class Decoder < Krypt::IOFilter

    #
    # call-seq:
    #    in.read([len=nil], [buf=nil]) -> String or nil
    #
    # Reads from the underlying IO and hex-decodes the data.
    # Please see IO#read for further details.
    #
    def read(len=nil, buf=nil)
      len *=2 if len #hex length is twice the original length
      data = @io.read(len, buf)
      return nil unless data
      if (prefix = preprocess(data))
        prefix << Krypt::Hex.decode(data)
      else
        Krypt::Hex.decode(data)
      end
    end

    #
    # call-seq:
    #    out.write(string) -> Integer 
    #
    # Hex-decodes string and writes it to the underlying IO.
    # Please see IO#write for further details.
    #
    def write(data)
      return 0 unless data
      if (prefix = preprocess(data))
        @io.write(prefix)
      end
      @io.write(Krypt::Hex.decode(data))
      data.size
    end
    alias << write

    def close
      raise HexError.new("Remaining byte in buffer") if @buf
      super
    end

    private

    def preprocess(data)
      ret = nil
      if @buf
        @buf << data.slice!(0)
        ret = Krypt::Hex.decode(@buf)
        @buf = nil
      end
      len = data.size
      if len % 2 == 1
        @buf = data.slice!(len - 1)
      end
      ret
    end

  end
end
