# Copyright (C) 2022  ll4il <ll4il@lorentz.org>

# This file is part of pam_deviceauthgrant

# configure.ac is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


AC_INIT([pam_deviceauthgrant],[0.2], [ll4il@ilorentz.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AM_PROG_AR
LT_INIT([disable-static])
AC_CONFIG_HEADERS([config.h])


# headers checks
AC_CHECK_HEADERS([sys/wait.h sys/types.h],[],
	[AC_MSG_ERROR([[sys/wait and types headers not found.]])])

AC_CHECK_HEADER([math.h],[],
	[AC_MSG_ERROR([[math headers not found.]])])

AC_CHECK_HEADER([curl/curl.h],[],
	[AC_MSG_ERROR([[curl headers not found.]])])
	
AC_CHECK_HEADER([openssl/pem.h],[],
	[AC_MSG_ERROR([[openssl headers not found.]])])	
	
AC_CHECK_HEADERS([security/pam_appl.h security/pam_modules.h security/pam_ext.h], [],
	[AC_MSG_ERROR([[pam headers not found.]])])     

AC_CHECK_HEADER([qrencode.h],[],
	[AC_MSG_ERROR([[qrencode headers not found.]])])

# libs checks
AC_CHECK_LIB(m, sqrt,[],
		  [AC_MSG_ERROR([[math lib not found.]])])
AC_CHECK_LIB(pam, pam_get_item,[],
		  [AC_MSG_ERROR([[pam lib not found.]])])		  
AC_CHECK_LIB(crypto, BIO_new,[],
		  [AC_MSG_ERROR([[openssl crypto lib not found.]])])
AC_CHECK_LIB(qrencode, QRcode_encodeString,[],
		  [AC_MSG_ERROR([[qrencode lib not found.]])])


# custom pam module dir option
AC_SUBST(PAMDIR, "\$(exec_prefix)/lib64/security")
AC_ARG_WITH(pam-mod-dir,
	AC_HELP_STRING([--with-pam-mod-dir=DIR],
	[Where to install PAM module [[PREFIX/lib64/security]]]),
	[case "${withval}" in
	/*) PAMDIR="${withval}";;
	./*|../*) AC_MSG_ERROR(Bad value for --with-pam-mod-dir);;
	*)  PAMDIR="\$(exec_prefix)/lib64/${withval}";;
	esac])


AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
