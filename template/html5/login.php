<?php
/*
 * Copyright (c) 2011, Josef Kufner  <jk@frozen-doe.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

function TPL_html5__user__login($t, $id, $d, $so)
{
	extract($d);

	echo "<div class=\"user_login\" id=\"", $id, "\">\n";

	if ($id_user) {
		printf(_('Logged in as: %s (%s)'), html_link_user($username), htmlspecialchars($role));
		echo " [<a href=\"", $logout_link, "\">", _('logout'), "</a>]\n";
	} else {
		echo _('not logged in'), " [<a href=\"https://",$_SERVER['SERVER_NAME'] ,"/login\">", _('login'), "</a>]\n";
	   /*
		echo	"<form action=\"\" method=\"post\">\n",
			"<select name=\"login_id_user\" onchange=\"this.form.submit();\">\n",
			"<option value=\"\">", _('login'), "</option>\n";
		foreach ($accounts as $id => $a) {
			echo "<option value=\"", $a['id'], "\">", $a['name'], "</option>\n";
		}
		echo	"</select>\n",
		   "</form>\n";
	    */
	}

	echo "</div>\n";
}

