require 'octokit'
require 'json'
require 'openssl'
require 'jwt'
require 'time'
require 'open-uri'

APP_NAME = 'Compare Branches'
COMPARE_BRANCH = 'unstable'
PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))
WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']
APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

Handler = Proc.new do |req, res|
  res.status = 200

  if req.request_method === 'POST'
    get_payload_request(req)
    if !verify_webhook_signature(req)
      res.status = 401
    else
      authenticate_app
      authenticate_installation
      handle_event_handler(req)
    end
  end
end

def handle_event_handler(req)
  case req['X-Github-Event']
  when 'check_suite'
    if @payload['check_suite']['app']['id'].to_s === APP_IDENTIFIER
      case @payload['action']
      when 'requested', 'rerequested'
        create_check_run
      end
    end
  when 'check_run'
    if @payload['check_run']['app']['id'].to_s === APP_IDENTIFIER
      case @payload['action']
      when 'created'
        initiate_check_run
      when 'rerequested'
        create_check_run
      end
    end
  end
end

def create_check_run
  check_run = @installation_client.post(
    "repos/#{@payload['repository']['full_name']}/check-runs",
    {
      accept: 'application/vnd.github.v3+json',
      name: APP_NAME,
      head_sha: @payload['check_run'].nil? ? @payload['check_suite']['head_sha'] : @payload['check_run']['head_sha']
    }
  )
end

def initiate_check_run
  updated_check_run = @installation_client.patch(
    "repos/#{@payload['repository']['full_name']}/check-runs/#{@payload['check_run']['id']}",
    {
      accept: 'application/vnd.github.v3+json',
      name: APP_NAME,
      status: 'in_progress',
      started_at: Time.now.utc.iso8601
    }
  )

  summary = "#{COMPARE_BRANCH}...#{@payload['check_run']['check_suite']['head_branch']}"
  response = URI.parse("https://github.com/#{@payload['repository']['full_name']}/branches/pre_mergeable/#{summary}").read

  updated_check_run = @installation_client.patch(
    "repos/#{@payload['repository']['full_name']}/check-runs/#{@payload['check_run']['id']}",
    {
      accept: 'application/vnd.github.v3+json',
      name: APP_NAME,
      status: 'completed',
      conclusion: (response.include? 'green') ? 'success' : 'failure',
      completed_at: Time.now.utc.iso8601,
      output: {
        title: APP_NAME,
        summary: summary,
        text: response
      }
    }
  )
end

def get_payload_request(req)
  @payload_raw = req.body()
  begin
    @payload = JSON.parse @payload_raw
  rescue => e
    fail  'Invalid JSON (#{e}): #{@payload_raw}'
  end
end

def authenticate_app
  payload = {
    iat: Time.now.to_i,
    exp: Time.now.to_i + (10 * 60),
    iss: APP_IDENTIFIER
  }

  jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

  @app_client ||= Octokit::Client.new(bearer_token: jwt)
end

def authenticate_installation
  @installation_id = @payload['installation']['id']
  @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
  @installation_client = Octokit::Client.new(bearer_token: @installation_token)
end

def verify_webhook_signature(req)
  their_signature_header = req['X-Hub-Signature'] || 'sha1='
  method, their_digest = their_signature_header.split('=')
  our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
  their_digest == our_digest
end
