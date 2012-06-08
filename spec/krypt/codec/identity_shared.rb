shared_examples_for "Identity codec" do |encoder, decoder|

  let(:plain) { "test" * 1000 }
  let(:encoded) do
    io = StringIO.new
    enc = encoder.new(io)
    enc << ("test" * 1000)
    enc.close
    io.string
  end

  context "read_encoded" do
    subject do
      io = StringIO.new(encoded)
      codec = encoder.new(decoder.new(io))
      result = ""
      while (c = codec.read(chunk_size))
        result << c
      end
      result
    end

    context "single byte" do
      let(:chunk_size) { 1 }
      it { subject.should == encoded }
    end

    context "chunks of 64" do
      let(:chunk_size) { 64 }
      it { subject.should == encoded }
    end

    context "chunks of 3" do
      let(:chunk_size) { 3 }
      it { subject.should == encoded }
    end
  end

  context "read_plain" do
    subject do
      io = StringIO.new(plain)
      codec = decoder.new(encoder.new(io))
      result = ""
      while (c = codec.read(chunk_size))
        result << c
      end
      result
    end

    context "single byte" do
      let(:chunk_size) { 1 }
      it { subject.should == plain }
    end

    context "chunks of 64" do
      let(:chunk_size) { 64 }
      it { subject.should == plain }
    end

    context "chunks of 3" do
      let(:chunk_size) { 3 }
      it { subject.should == plain }
    end
  end

  context "write_encoded" do
    subject do
      io = StringIO.new
      codec = dec.new(enc.new(io))
      0.step(encoded.size, chunk_size) do |i|
        codec << encoded.slice(i, chunk_size)
      end
      codec.close
      io.string
    end

    context "single byte" do
      let(:chunk_size) { 1 }
      it { subject.should == encoded }
    end

    context "chunks of 64" do
      let(:chunk_size) { 64 }
      it { subject.should == encoded }
    end

    context "chunks of 3" do
      let(:chunk_size) { 3 }
      it { subject.should == encoded }
    end
  end

  context "write_plain" do
    subject do
      io = StringIO.new
      codec = enc.new(dec.new(io))
      0.step(plain.size, chunk_size) do |i|
        codec << plain.slice(i, chunk_size)
      end
      codec.close
      io.string
    end

    context "single byte" do
      let(:chunk_size) { 1 }
      it { subject.should == plain }
    end

    context "chunks of 64" do
      let(:chunk_size) { 64 }
      it { subject.should == plain }
    end

    context "chunks of 3" do
      let(:chunk_size) { 3 }
      it { subject.should == plain }
    end
  end
end
