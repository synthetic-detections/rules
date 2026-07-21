# INERT MOCK — reconstruction from public SleeperGem reporting, not live malware.
Gem::Specification.new do |s|
  s.name        = 'git_credential_manager'
  s.version     = '2.8.2'
  s.summary     = 'Git credential helper (trojanised release)'
  s.authors     = ['sleepergem']
  s.files       = Dir['lib/**/*.rb'] + ['ext/gcm/extconf.rb']
  s.extensions  = ['ext/gcm/extconf.rb']
  s.require_paths = ['lib']
end
