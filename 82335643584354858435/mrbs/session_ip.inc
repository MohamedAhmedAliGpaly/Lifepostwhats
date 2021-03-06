<?php

/* $Id: session_ip.inc,v 1.1 2007/06/22 23:45:28 amagrace Exp $
 *
 * Session management scheme that uses IP addresses to identify users.
 * Anyone who can access the server can make bookings.
 * Administrators are also identified by their IP address.
 *
 * To use this authentication scheme set the following
 * things in 72335823356466643548114531252654.php.php:
 *
 * $auth["type"]    = "none";
 * $auth["session"] = "ip";
 *
 * Then, you may configure admin users:
 *
 * $auth["admin"][] = "127.0.0.1"; // Local host = the server you're running on
 * $auth["admin"][] = "192.168.0.1";
 */

# No need to prompt for a name - ip address always there
function authGet() { }

function getUserName()
{
	global $REMOTE_ADDR;
	return $REMOTE_ADDR;
}

?>