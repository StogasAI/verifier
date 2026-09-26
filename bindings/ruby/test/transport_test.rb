require 'minitest/autorun'
require 'stogas_verifier'

class TransportTest < Minitest::Test
  def test_invalid_options_preserve_native_error_codes
    [{security: 'unsupported'}, {environment: 'unsupported'}, {max_connections: 0}].each do |options|
      error = assert_raises(Stogas::VerificationError) { Stogas::Transport.new(**options) }
      refute_empty error.code
    end
  end

  def test_native_transport_lifetime
    skip 'requires explicit staging evidence qualification' unless ENV['STOGAS_NATIVE_STAGING_TEST'] == '1'
    transport = nil
    assert_raises(RuntimeError) do
      Stogas::Transport.open(environment: 'staging', security: 'e2ee') do |opened|
        transport = opened
        assert_match(%r{\Ahttp://127\.0\.0\.1:\d+/}, transport.base_url)
        threads = 3.times.map { Thread.new { transport.refresh } }
        threads.each(&:value)
        raise 'application failed'
      end
    end
    transport.close
    assert_raises(IOError) { transport.refresh }
    GC.start
  end
end
