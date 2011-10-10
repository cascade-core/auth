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

namespace Auth;

class Auth implements \IAuth
{
	private $user_info = null;


	public function __construct()
	{
		// Read auth cookies
		$id    = @ $_COOKIE['auth_user_id'];
		$token = @ $_COOKIE['auth_user_token'];

		debug_msg('Cookies: user id = "%s", token = "%s"', $id, $token);

		// Get user info and refresh login
		if ($id != '' && $token != '') {
			$r = \dibi::select('`u`.*')
				->from('`T_User` `u`, `T_UserAuthToken` `uat`')
				->where('`u.IDUser` = `uat.IDUser`')
				->where('`u.IDUser` = %s', $id)
				->where('`uat.Token` = %s', $token)
				->where('`uat.Expires` >= NOW()')
				->fetch();
			if ($r) {
				// valid token
				$this->user_info = (array) $r;

				\dibi::query('
					UPDATE `T_UserAuthToken`
					SET
						`Expires` = NOW() + INTERVAL 1 WEEK,
						`LastAddress` = %s', $_SERVER['REMOTE_ADDR'], '
					WHERE
						`IDUser` = %s', $id, '
						AND `Token` = %s', $token, '
					LIMIT 1
				');

				if (\dibi::affectedRows() == 1) {
					$this->refresh_cookies($id, $token);
				}

				debug_msg('User ID: %s', $this->user_info['IDUser']);
			}
		}
	}


	public function login($mail, $password)
	{
		// Check if user exists in database
		$match = \dibi::query('
				SELECT `up.IDUser`, `up.RemainingUses`, `up.Password`
				FROM `T_User` `u`
				LEFT JOIN `T_UserPassword` `up` ON up.IDUser = u.IDUser
				WHERE `u.Mail` = %s', $mail, '
					AND `up.Password` = SHA1(CONCAT(%s', $password, ', `up.IDUser`, UNIX_TIMESTAMP(`up.Created`)))
				LIMIT 1
			')->fetch();
			
		if (!$match || !$match['IDUser']) {
			error_msg('Login failed: user e-mail = "%s"; password = "%s"; remote address = "%s".',
					$mail, $password, $_SERVER['REMOTE_ADDR']);
			return false;
		}

		// create token and update cookies
		$token = $this->generate_token();

		\dibi::query('
			INSERT IGNORE INTO `T_UserAuthToken`
			SET
				`IDUser` = %s', $match['IDUser'], ',
				`Token`   = %s', $token, ',
				`Expires` = NOW() + INTERVAL 1 WEEK,
				`Created`   = NOW(),
				`Modified`   = NOW(),
				`LastAddress` = %s', $_SERVER['REMOTE_ADDR'], '
		');
		if (\dibi::affectedRows() == 1) {
			$this->refresh_cookies($match['IDUser'], $token);

			if ($match['RemainingUses'] !== null) {
				if ($match['RemainingUses'] <= 1) {
					\dibi::query('
						DELETE FROM `T_UserPassword`
						WHERE
							`IDUser` = %s', $match['IDUser'], '
							AND `Password` = %s', $match['Password'], '
						LIMIT 1
					');
				} else if ($match['RemainingUses'] > 1) {
					\dibi::query('
						UPDATE `T_UserPassword`
						WHERE
							`IDUser` = %s', $match['IDUser'], '
							AND `Password` = %s', $match['Password'], '
						SET
							`RemainingUses` = `RemainingUses` - 1
						LIMIT 1
					');
				}
			}

			return true;
		} else {
			return false;
		}
	}


	public function logout($id = false)
	{
		\dibi::query('
			DELETE FROM `T_UserAuthToken`
			WHERE
				`IDUser` = %s', $id === false ? $this->user_info['IDUser'] : $id, '
		');
		$this->refresh_cookies($id, null);
	}


	public function get_id()
	{
		return (isset($this->user_info)) ? $this->user_info['IDUser'] : null;
	}


	public function get_info()
	{
		return $this->user_info;
	}


	public function is_allowed($module_name, & $details = null)
	{
		return true;
	}


	private function refresh_cookies($id, $token)
	{
		$cookie_expire = strtotime('+1 year');
		$secure = isset($_SERVER['HTTPS']);

		setcookie('auth_user_id',    $id,    $cookie_expire, '/', null, $secure, true);
		setcookie('auth_user_token', $token, $cookie_expire, '/', null, $secure, true);
	}


	private function generate_token()
	{
		return sha1(time().mt_rand().serialize($_SERVER));
	}

};

