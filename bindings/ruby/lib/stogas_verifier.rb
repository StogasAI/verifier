# frozen_string_literal: true

require 'fiddle/import'
require 'json'
require 'rbconfig'

module Stogas
  class VerificationError < StandardError
    attr_reader :code
    def initialize(message, code)
      @code = code
      super(message)
    end
  end

  module Native
    extend Fiddle::Importer
    library = case RbConfig::CONFIG.fetch('host_os')
              when /darwin/ then 'libstogas_verifier_ffi.dylib'
              when /mswin|mingw/ then 'stogas_verifier_ffi.dll'
              else 'libstogas_verifier_ffi.so'
              end
    dlload File.join(__dir__, 'stogas', 'native', library)
    extern 'unsigned int stogas_verifier_abi_version()'
    extern 'void* stogas_transport_start(void*, size_t, void*)'
    extern 'void* stogas_transport_refresh(void*)'
    extern 'void stogas_transport_close(void*)'
    extern 'void stogas_transport_free(void*)'
    extern 'void stogas_verifier_string_free(void*)'

    def self.result(pointer)
      raise 'Native transport returned no result.' if pointer.null?
      begin
        envelope = JSON.parse(pointer.to_s)
        unless envelope.fetch('ok')
          raise VerificationError.new(envelope.fetch('error'), envelope.fetch('code'))
        end
        envelope.fetch('value')
      ensure
        stogas_verifier_string_free(pointer)
      end
    end
  end
  private_constant :Native

  class Transport
    attr_reader :base_url

    def self.open(**options)
      transport = new(**options)
      return transport unless block_given?
      begin
        yield transport
      ensure
        transport.close
      end
    end

    def initialize(environment: 'prod', security: 'tls', max_connections: 4, base_url: nil)
      raise 'Unsupported Stogas native ABI.' unless Native.stogas_verifier_abi_version == 1
      @mutex = Mutex.new
      bytes = JSON.generate({environment: environment, security: security,
                             max_connections: max_connections, base_url: base_url})
      Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE) do |output|
        output[0, Fiddle::SIZEOF_VOIDP] = [0].pack('J')
        raw = Native.stogas_transport_start(bytes, bytes.bytesize, output)
        address = output[0, Fiddle::SIZEOF_VOIDP].unpack1('J')
        @handle = Fiddle::Pointer.new(address, 0, Native['stogas_transport_free'])
        begin
          value = Native.result(raw)
          raise 'Native transport returned no handle.' if @handle.null?
          @base_url = value.fetch('base_url').freeze
        rescue Exception
          @handle.call_free
          raise
        end
      end
    end

    def refresh
      @mutex.synchronize do
        raise IOError, 'Transport is closed.' if @handle.freed?
        Native.result(Native.stogas_transport_refresh(@handle))
      end
    end

    def close
      @mutex.synchronize do
        unless @handle.freed?
          Native.stogas_transport_close(@handle)
          @handle.call_free
        end
      end
    end
  end
end
