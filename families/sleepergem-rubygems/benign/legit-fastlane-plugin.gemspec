# BENIGN — a normal fastlane plugin gemspec. Structurally similar (gem name
# collides with the SleeperGem family) but carries no payload artifacts.
Gem::Specification.new do |s|
  s.name        = 'fastlane-plugin-run_tests_firebase_testlab'
  s.version     = '0.4.1'
  s.summary     = 'Run tests on Firebase Test Lab from fastlane'
  s.authors     = ['A Real Maintainer']
  s.homepage    = 'https://github.com/example/fastlane-plugin-run_tests_firebase_testlab'
  s.license     = 'MIT'
  s.files       = Dir['lib/**/*.rb']
  s.require_paths = ['lib']
  s.add_dependency 'fastlane', '>= 2.0.0'
end
