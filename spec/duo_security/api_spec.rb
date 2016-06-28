require 'minitest/autorun'
require 'vcr'
require_relative "../../lib/duo_security/api"

VCR.configure do |c|
  c.cassette_library_dir = "fixtures/vcr"
  c.hook_into :webmock
  c.allow_http_connections_when_no_cassette = true
  c.before_http_request(:real?) do |request|
    puts "Cassette #{VCR.current_cassette.name} being recorded. Take appropriate actions on your phone."
  end
end

module DuoSecurity
  versions = [1, 2]
  versions.each do |v|
    describe API do
      let(:host) { ENV["DUO_HOST"] }
      let(:skey) { ENV["DUO_SKEY"] }
      let(:ikey) { ENV["DUO_IKEY"] }

      describe '#ping' do
        it 'succeeds' do
          VCR.use_cassette("api_ping_success") do
            duo = API.new(host, skey, ikey, v)
            duo.ping.must_equal true
          end
        end
      end

      describe '#check' do
        it 'succeeds with correct credentials' do
          VCR.use_cassette("api_check_success") do
            duo = API.new(host, skey, ikey, v)
            duo.check.must_equal true
          end
        end

        it 'fails with incorrect skey' do
          VCR.use_cassette("api_check_wrong_skey") do
            duo = API.new(host, "wrong", ikey, v)
            duo.check.must_equal false
          end
        end

        it 'fails with incorrect ikey' do
          VCR.use_cassette("api_check_wrong_ikey") do
            duo = API.new(host, skey, "wrong", v)
            duo.check.must_equal false
          end
        end
      end

      describe '#preauth' do
        it 'returns a list of possible factors' do
          VCR.use_cassette("api_preauth") do
            duo = API.new(host, skey, ikey, v)
            result = duo.preauth("marten")
            result["factors"].must_equal({"1"=>"push1", "2"=>"sms1", "default"=>"push1"})
            result["result"].must_equal("auth")
          end
        end

        it 'raises when user does not exist' do
          VCR.use_cassette("api_preauth_unknown_user") do
            duo = API.new(host, skey, ikey, v)
            -> { duo.preauth("unknown") }.must_raise(API::UnknownUser)
          end
        end
      end

      describe '#auth' do
        let(:duo) { API.new(host, skey, ikey, v) }

        it 'returns true if user OKs the request' do
          VCR.use_cassette("api_auth_user_accepts") do
            result = duo.auth("slyons", "push", "phone" => "phone1")
            result.must_equal(true)
          end
        end

        it 'returns false if the user denies the request as a mistake' do
          VCR.use_cassette("api_auth_user_denies_mistake") do
            result = duo.auth("slyons", "push", "phone" => "phone1")
            result.must_equal(false)
          end
        end

        it 'returns false if the user denies the request as a fraudulent attack' do
          VCR.use_cassette("api_auth_user_denies_fraud") do
            result = duo.auth("slyons", "push", "phone" => "phone1")
            result.must_equal(false)
          end
        end

        it 'raises an exception when factor is unknown' do
          -> { duo.auth("slyons", "something") }.must_raise(ArgumentError)
        end
      end
    end
  end
end
