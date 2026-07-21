# BENIGN — an ordinary Ruby C-extension extconf.rb. No network fetch,
# no drop path, no CI-evasion, no setuid shell.
require 'mkmf'

have_header('ruby.h')
have_library('z', 'inflate')
create_makefile('mygem/native')
