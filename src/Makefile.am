# Copyright (C) 2022  ll4il <ll4il@ilorentz.org>

# This file is part of pam_deviceauthgrant

# Makefile.am is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

pammoddir = $(PAMDIR)
pammod_LTLIBRARIES = pam_deviceauthgrant.la
pam_deviceauthgrant_la_SOURCES = deviceauthgrant.c qr.c jsmn.h
pam_deviceauthgrant_la_LDFLAGS = -module -avoid-version -lm -lqrencode -lcurl -lssl -lcrypto
