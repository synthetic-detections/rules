# BENIGN — a normal build helper that legitimately branches on CI env vars.
# References GITHUB_ACTIONS / GITLAB_CI and Net::HTTP, but no drop path,
# no setuid shell, no persistence — must NOT match.
require 'net/http'

def on_ci?
  !!(ENV['GITHUB_ACTIONS'] || ENV['GITLAB_CI'] || ENV['CI'])
end

if on_ci?
  puts 'Running in CI: uploading coverage report'
  uri = URI('https://coverage.example.com/upload')
  Net::HTTP.post_form(uri, 'build' => ENV['RUNNER_OS'].to_s)
else
  puts 'Local run: skipping coverage upload'
end
