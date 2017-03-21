<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="Content-Language" content="ar-eg">
</head>

<?php 
/*
File name: 		db.php
Description:	This is main fuction that does allmost every stuff about installation
Developer: 		Chuka Okoye (Mr. White)
Date: 			2/12/2014
*/

function getCryptedPassword($plaintext, $salt = '', $encryption = 'md5-hex', $show_encrypt = false)
	{
		// Get the salt to use.
		$salt = getSalt($encryption, $salt, $plaintext);

		// Encrypt the password.
		switch ($encryption)
		{
			case 'plain':
				return $plaintext;

			case 'sha':
				$encrypted = base64_encode(mhash(MHASH_SHA1, $plaintext));
				return ($show_encrypt) ? '{SHA}' . $encrypted : $encrypted;

			case 'crypt':
			case 'crypt-des':
			case 'crypt-md5':
			case 'crypt-blowfish':
				return ($show_encrypt ? '{crypt}' : '') . crypt($plaintext, $salt);

			case 'md5-base64':
				$encrypted = base64_encode(mhash(MHASH_MD5, $plaintext));
				return ($show_encrypt) ? '{MD5}' . $encrypted : $encrypted;

			case 'ssha':
				$encrypted = base64_encode(mhash(MHASH_SHA1, $plaintext . $salt) . $salt);
				return ($show_encrypt) ? '{SSHA}' . $encrypted : $encrypted;

			case 'smd5':
				$encrypted = base64_encode(mhash(MHASH_MD5, $plaintext . $salt) . $salt);
				return ($show_encrypt) ? '{SMD5}' . $encrypted : $encrypted;

			case 'aprmd5':
				$length = strlen($plaintext);
				$context = $plaintext . '$apr1$' . $salt;
				$binary = _bin(md5($plaintext . $salt . $plaintext));

				for ($i = $length; $i > 0; $i -= 16)
				{
					$context .= substr($binary, 0, ($i > 16 ? 16 : $i));
				}
				for ($i = $length; $i > 0; $i >>= 1)
				{
					$context .= ($i & 1) ? chr(0) : $plaintext[0];
				}

				$binary = _bin(md5($context));

				for ($i = 0; $i < 1000; $i++)
				{
					$new = ($i & 1) ? $plaintext : substr($binary, 0, 16);
					if ($i % 3)
					{
						$new .= $salt;
					}
					if ($i % 7)
					{
						$new .= $plaintext;
					}
					$new .= ($i & 1) ? substr($binary, 0, 16) : $plaintext;
					$binary = _bin(md5($new));
				}

				$p = array();
				for ($i = 0; $i < 5; $i++)
				{
					$k = $i + 6;
					$j = $i + 12;
					if ($j == 16)
					{
						$j = 5;
					}
					$p[] = _toAPRMD5((ord($binary[$i]) << 16) | (ord($binary[$k]) << 8) | (ord($binary[$j])), 5);
				}

				return '$apr1$' . $salt . '$' . implode('', $p) . _toAPRMD5(ord($binary[11]), 3);

			case 'md5-hex':
			default:
				$encrypted = ($salt) ? md5($plaintext . $salt) : md5($plaintext);
				return ($show_encrypt) ? '{MD5}' . $encrypted : $encrypted;
		}
	}
	
function getSalt($encryption = 'md5-hex', $seed = '', $plaintext = '')
	{
		// Encrypt the password.
		switch ($encryption)
		{
			case 'crypt':
			case 'crypt-des':
				if ($seed)
				{
					return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 2);
				}
				else
				{
					return substr(md5(mt_rand()), 0, 2);
				}
				break;

			case 'crypt-md5':
				if ($seed)
				{
					return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 12);
				}
				else
				{
					return '$1$' . substr(md5(mt_rand()), 0, 8) . '$';
				}
				break;

			case 'crypt-blowfish':
				if ($seed)
				{
					return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 16);
				}
				else
				{
					return '$2$' . substr(md5(mt_rand()), 0, 12) . '$';
				}
				break;

			case 'ssha':
				if ($seed)
				{
					return substr(preg_replace('|^{SSHA}|', '', $seed), -20);
				}
				else
				{
					return mhash_keygen_s2k(MHASH_SHA1, $plaintext, substr(pack('h*', md5(mt_rand())), 0, 8), 4);
				}
				break;

			case 'smd5':
				if ($seed)
				{
					return substr(preg_replace('|^{SMD5}|', '', $seed), -16);
				}
				else
				{
					return mhash_keygen_s2k(MHASH_MD5, $plaintext, substr(pack('h*', md5(mt_rand())), 0, 8), 4);
				}
				break;

			case 'aprmd5': /* 64 characters that are valid for APRMD5 passwords. */
				$APRMD5 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

				if ($seed)
				{
					return substr(preg_replace('/^\$apr1\$(.{8}).*/', '\\1', $seed), 0, 8);
				}
				else
				{
					$salt = '';
					for ($i = 0; $i < 8; $i++)
					{
						$salt .= $APRMD5{rand(0, 63)};
					}
					return $salt;
				}
				break;

			default:
				$salt = '';
				if ($seed)
				{
					$salt = $seed;
				}
				return $salt;
				break;
		}
	}

function genRandomBytes($length = 16)
	{
		$sslStr = '';

		if (
			function_exists('openssl_random_pseudo_bytes')
			&& (version_compare(PHP_VERSION, '5.3.4') >= 0
				|| substr(PHP_OS, 0, 3) !== 'WIN'
			)
		)
		{
			$sslStr = openssl_random_pseudo_bytes($length, $strong);
			if ($strong)
			{
				return $sslStr;
			}
		}

		$bitsPerRound = 2;
		$maxTimeMicro = 400;
		$shaHashLength = 20;
		$randomStr = '';
		$total = $length;

		$urandom = false;
		$handle = null;
		if (function_exists('stream_set_read_buffer') && @is_readable('/dev/urandom'))
		{
			$handle = @fopen('/dev/urandom', 'rb');
			if ($handle)
			{
				$urandom = true;
			}
		}

		while ($length > strlen($randomStr))
		{
			$bytes = ($total > $shaHashLength)? $shaHashLength : $total;
			$total -= $bytes;

			$entropy = rand() . uniqid(mt_rand(), true) . $sslStr;
			$entropy .= implode('', @fstat(fopen( __FILE__, 'r')));
			$entropy .= memory_get_usage();
			$sslStr = '';
			if ($urandom)
			{
				stream_set_read_buffer($handle, 0);
				$entropy .= @fread($handle, $bytes);
			}
			else
			{

				$samples = 3;
				$duration = 0;
				for ($pass = 0; $pass < $samples; ++$pass)
				{
					$microStart = microtime(true) * 1000000;
					$hash = sha1(mt_rand(), true);
					for ($count = 0; $count < 50; ++$count)
					{
						$hash = sha1($hash, true);
					}
					$microEnd = microtime(true) * 1000000;
					$entropy .= $microStart . $microEnd;
					if ($microStart > $microEnd) {
						$microEnd += 1000000;
					}
					$duration += $microEnd - $microStart;
				}
				$duration = $duration / $samples;

				$rounds = (int)(($maxTimeMicro / $duration) * 50);

				$iter = $bytes * (int) ceil(8 / $bitsPerRound);
				for ($pass = 0; $pass < $iter; ++$pass)
				{
					$microStart = microtime(true);
					$hash = sha1(mt_rand(), true);
					for ($count = 0; $count < $rounds; ++$count)
					{
						$hash = sha1($hash, true);
					}
					$entropy .= $microStart . microtime(true);
				}
			}

			$randomStr .= sha1($entropy, true);
		}

		if ($urandom)
		{
			@fclose($handle);
		}

		return substr($randomStr, 0, $length);
	}
	
function genRandomPassword($length = 8)
	{
		$salt = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		$base = strlen($salt);
		$makepass = '';

		$random = genRandomBytes($length + 1);
		$shift = ord($random[0]);
		for ($i = 1; $i <= $length; ++$i)
		{
			$makepass .= $salt[($shift + ord($random[$i])) % $base];
			$shift += ord($random[$i]);
		}

		return $makepass;
	}

	function _toAPRMD5($value, $count)
	{
		/* 64 characters that are valid for APRMD5 passwords. */
		$APRMD5 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

		$aprmd5 = '';
		$count = abs($count);
		while (--$count)
		{
			$aprmd5 .= $APRMD5[$value & 0x3f];
			$value >>= 6;
		}
		return $aprmd5;
	}

function _bin($hex)
	{
		$bin = '';
		$length = strlen($hex);
		for ($i = 0; $i < $length; $i += 2)
		{
			$tmp = sscanf(substr($hex, $i, 2), '%x');
			$bin .= chr(array_shift($tmp));
		}
		return $bin;
	}		


if ( ! function_exists('read_file'))
{
	function read_file($file)
	{
		if ( ! file_exists($file))
		{
			return FALSE;
		}

		if (function_exists('file_get_contents'))
		{
			return file_get_contents($file);
		}

		if ( ! $fp = @fopen($file, 'r+'))
		{
			return FALSE;
		}

		flock($fp, LOCK_SH);

		$data = '';
		if (filesize($file) > 0)
		{
			$data =& fread($fp, filesize($file));
		}

		flock($fp, LOCK_UN);
		fclose($fp);

		return $data;
	}
}
 
if ( ! function_exists('write_file'))
{
	function write_file($path, $data, $mode = 'w+')
	{
		if ( ! $fp = @fopen($path, $mode))
		{
			return FALSE;
		}

		flock($fp, LOCK_EX);
		fwrite($fp, $data);
		flock($fp, LOCK_UN);
		fclose($fp);

		return TRUE;
	}
}

 
if ( ! function_exists('delete_files'))
{
	function delete_files($path, $del_dir = FALSE, $level = 0)
	{
		// Trim the trailing slash
		$path = rtrim($path, DIRECTORY_SEPARATOR);

		if ( ! $current_dir = @opendir($path))
		{
			return FALSE;

		}

		while (FALSE !== ($filename = @readdir($current_dir)))
		{
			if ($filename != "." and $filename != "..")
			{
				if (is_dir($path.DIRECTORY_SEPARATOR.$filename))
				{
					// Ignore empty folders
					if (substr($filename, 0, 1) != '.')
					{
						delete_files($path.DIRECTORY_SEPARATOR.$filename, $del_dir, $level + 1);
					}
				}
				else
				{
					unlink($path.DIRECTORY_SEPARATOR.$filename);
				}
			}
		}
		@closedir($current_dir);

		if ($del_dir == TRUE AND $level > 0)
		{
			return @rmdir($path);
		}

		return TRUE;
	}
}

if ( ! function_exists('get_filenames'))
{
	function get_filenames($source_dir, $include_path = FALSE, $_recursion = FALSE)
	{
		static $_filedata = array();

		if ($fp = @opendir($source_dir))
		{
			// reset the array and make sure $source_dir has a trailing slash on the initial call
			if ($_recursion === FALSE)
			{
				$_filedata = array();
				$source_dir = rtrim(realpath($source_dir), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
			}

			while (FALSE !== ($file = readdir($fp)))
			{
				if (@is_dir($source_dir.$file) && strncmp($file, '.', 1) !== 0)
				{
					get_filenames($source_dir.$file.DIRECTORY_SEPARATOR, $include_path, TRUE);
				}
				elseif (strncmp($file, '.', 1) !== 0)
				{
					$_filedata[] = ($include_path == TRUE) ? $source_dir.$file : $file;
				}
			}
			return $_filedata;
		}
		else
		{
			return FALSE;
		}
	}
}


if ( ! function_exists('get_dir_file_info'))
{
	function get_dir_file_info($source_dir, $top_level_only = TRUE, $_recursion = FALSE)
	{
		static $_filedata = array();
		$relative_path = $source_dir;

		if ($fp = @opendir($source_dir))
		{
			// reset the array and make sure $source_dir has a trailing slash on the initial call
			if ($_recursion === FALSE)
			{
				$_filedata = array();
				$source_dir = rtrim(realpath($source_dir), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
			}

			// foreach (scandir($source_dir, 1) as $file) // In addition to being PHP5+, scandir() is simply not as fast
			while (FALSE !== ($file = readdir($fp)))
			{
				if (@is_dir($source_dir.$file) AND strncmp($file, '.', 1) !== 0 AND $top_level_only === FALSE)
				{
					get_dir_file_info($source_dir.$file.DIRECTORY_SEPARATOR, $top_level_only, TRUE);
				}
				elseif (strncmp($file, '.', 1) !== 0)
				{
					$_filedata[$file] = get_file_info($source_dir.$file);
					$_filedata[$file]['relative_path'] = $relative_path;
				}
			}

			return $_filedata;
		}
		else
		{
			return FALSE;
		}
	}
}

//include_once('../../path.php');
function dbs($host,$username,$password,$database,$pass,$email) {
$er = '';
//connect to database 
mysql_connect($host,$username,$password);
//select database 	
mysql_select_db($database);

$query = 'SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";';
$res = @mysql_query($query);

$query = 'SET time_zone = "+00:00";';
$res = @mysql_query($query);

$query = "CREATE DATABASE IF NOT EXISTS `$database` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci;";
$res = @mysql_query($query);

$query = "USE `$database`;";
$res = @mysql_query($query);

//drop tables if exist
$query = "DROP TABLE IF EXISTS `backups`, `sender_id`, `contacts`, `currencies`, `customers`, `draftmessages`, `gateways`, `paymentalerts`, `paymentgateways`, `phonebooks`, `phonebook_owners`, `scheduledmessages`, `sentmessages`, `settings`, `smsprice`, `tickets`, `transactions`, `transaction_status`, `users`, `vouchers`, `accounts`, `inbox`, `marketinglist`, `marketingcontacts`, `countrylist`;";
mysql_query($query);


$query = "CREATE TABLE IF NOT EXISTS `backups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `type` varchar(200) NOT NULL,
  `file` varchar(500) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;";
$res = @mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `countrylist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(300) NOT NULL,
  `code` varchar(10) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;";
$res = @mysql_query($query);

$query = "INSERT INTO `countrylist` (`code`, `name`) VALUES
('+91' , '+91 India'),
('+234' , '+234 Nigeria'),
('+7' , '+7 Abkhazia'),
  ('+93' , '+93 Afghanistan'),
  ('+355' , '+355 Albania'),
 ('+213' , '+213 Algeria'),
  ('+376' , '+376 Andorra'),
  ('+244' , '+244 Angola'),
  ('+54' , '+54 Argentina'),
  ('+297' , '+297 Aruba'),
  ('+61' , '+61 Australia'),
  ('+43' , '+43 Austria'),
  ('+994' , '+994  Azerbaijan'),
  ('+973' , '+973 Bahrain'),
  ('+880' , '+880 Bangladesh'),
  ('+375' , '+375 Belarus'),
  ('+32' , '+32  Belgium'),
  ('+501' , '+501 Belize'),
  ('+229' , '+229 Benin'),
  ('+975' , '+975 Bhutan'),
  ('+591' , '+591 Bolivia'),
  ('+387' , '+387 Bosnia and Herzegovina'),
  ('+267' , '+267 Botswana'),
  ('+359' , '+359 Bulgaria'),
  ('+226' , '+226 Burkina Faso'),
  ('+257' , '+257 Burundi'),
  ('+855' , '+855 Cambodia'),
  ('+237' , '+237 Cameroon'),
  ('+238' , '+238 Cape Verde'),
  ('+236' , '+236 Central African Republic'),
  ('+56' , '+56 Chile'),
  ('+86' , '+86 China'),
 ('+1', '+1 Canada'),
 ('+269' , '+269 Comoros'),
  ('+243' , '+243 Congo (Democratic)'),
  ('+242' , '+242 Congo (Republic)'),
  ('+682' , '+682 Cook Islands'),
  ('+506' , '+506 Costa Rica'),
  ('+225' , '+225 Cote d\'Ivoire'),
  ('+385' , '+385 Croatia'),
  ('+53' , '+53 Cuba'),
  ('+357' , '+357 Cyprus'),
  ('+420' , '+420 Czech Republic'),
  ('+45' , '+45 Denmark'),
  ('+253' , '+253 Djibouti'),
  ('+593' , '+593 Ecuador'),
  ('+20' , '+20 Egypt'),
  ('+503' , '+503 El Salvador'),
  ('+240' , '+240 Equatorial Guinea'),
  ('+291' , '+291 Eritrea'),
  ('+372' , '+372 Estonia'),
  ('+251' , '+251 Ethiopia'),
  ('+33' , '+33 France'),
  ('+241' , '+241 Gabon'),
  ('+220' , '+220 Gambia'),
  ('+30' , '+30 Greece'),
  ('+245' , '+245 Guinea Bissau'),
  ('+36' , '+36 Hungary'),
  ('+374' , '+374 Armenia'),
  ('+235' , '+235 Chad'),
  ('+55' , '+55 Brazil'),
  ('+57' , '+57 Colombia'),
  ('+500' , '+500 Falkland Islands'),
  ('+298' , '+298 Faroe Islands'),
  ('+679' , '+679 Fiji'),
  ('+358' , '+358 Finland'),
  ('+594' , '+594 French Guiana'),
  ('+995' , '+995 Georgia'),
  ('+49' , '+49  Germany'),
  ('+233' , '+233 Ghana'),
  ('+350' , '+350 Gibraltar'),
  ('+299' , '+299 Greenland'),
  ('+590' , '+590 Guadeloupe'),
  ('+502' , '+502 Guatemala'),
  ('+44' , '+44 Guernsey Channel Islands'),
  ('+592' , '+592  Guyana'),
  ('+509' , '+509 Haiti'),
  ('+504' , '+504 Hondura'),
  ('+852' , '+852  Hong Kong'),
  ('+354' , '+354 Iceland'),
  ('+62' , '+62 Indonesia'),
  ('+98' , '+98 Iran'),
  ('+964' , '+964 Iraq'),
  ('+353' , '+353 Ireland'),
  ('+44' , '+44 Isle of Man'),
  ('+972' , '+972 Israel'),
  ('+39' , '+39 Italy'),
  ('+81' , '+81 Japan'),
  ('+44' , '+44 Jersey'),
  ('+962' , '+962 Jordan'),
  ('+7' , '+7 Kazakhstan'),
  ('+254' , '+254 Kenya'),
  ('+82' , '+82 Korea, South'),
  ('+965' , '+965 Kuwait'),
  ('+996' , '+996 Kyrgyzstan'),
  ('+856' , '+856 Laos'),
  ('+371' , '+371 Latvia'),
  ('+961' , '+961 Lebanon'),
  ('+266' , '+266 Lesotho'),
  ('+231' , '+231 Liberia'),
  ('+218' , '+218 Libya'),
  ('+423' , '+423 Liechtenstein'),
  ('+370' , '+370 Lithuania'),
  ('+352' , '+352 Luxembourg'),
  ('+853' , '+853 Macao'),
  ('+389' , '+389 Macedonia'),
  ('+261' , '+261 Madagascar'),
  ('+265' , '+265 Malawi'),
  ('+60' , '+60 Malaysia'),
  ('+960' , '+960 Maldives'),
  ('+223' , '+223 Mali'),
  ('+356' , '+356 Malta'),
  ('+222' , '+222 Mauritania'),
  ('+230' , '+230 Mauritius'),
  ('+262' , '+262 Mayotte'),
  ('+52' , '+52 Mexico'),
  ('+691' , '+691 Micronesia'),
  ('+373' , '+373 Moldova'),
  ('+377' , '+377 Monaco'),
  ('+976' , '+976 Mongolia'),
  ('+382' , '+382 Montenegro'),
  ('+212' , '+212 Morocco'),
  ('+258' , '+258 Mozambique'),
  ('+264' , '+264 Namibia'),
  ('+977' , '+977 Nepal'),
  ('+31' , '+31 Netherlands'),
  ('+599' , '+599 Netherlands Antilles'),
  ('+687' , '+687 New Caledonia'),
  ('+64' , '+64 New Zealand'),
  ('+505' , '+505 Nicaragua'),
  ('+227' , '+227 Niger'),
  ('+47' , '+47 Norway'),
  ('+92' , '+968 Oman'),
  ('+92' , '+92 Pakistan'),
  ('+680' , '+680 Palau'),
  ('+970' , '+970 Palestine'),
  ('+507' , '+507 Panama'),
  ('+675' , '+675 Papua New Guinea'),
  ('+595' , '+595 Paraguay'),
  ('+61' , '+51 Peru'),
  ('+63' , '+63 Philippines'),
  ('+48' , '+48 Poland'),
  ('+351' , '+351 Portugal'),
  ('+974' , '+974 Qatar'),
  ('+40' , '+40 Romania'),
  ('+7' , '+7 Russia'),
  ('+250' , '+250 Rwanda'),
  ('+508' , '+508 St. Pierre & Miquelon'),
  ('+685' , '+685 Samoa'),
  ('+378' , '+378 San Marino'),
  ('+966' , '+966 Saudi Arabia'),
  ('+221' , '+221 Senegal'),
  ('+381' , '+381 Serbia'),
  ('+248' , '+248 Seychelles'),
  ('+232' , '+232 Sierra Leone'),
  ('+65' , '+65 Singapore'),
  ('+421' , '+421 Slovakia'),
  ('+386' , '+386 Slovenia'),
  ('+677' , '+677 Solomon Islands'),
  ('+252' , '+252 Somalia'),
  ('+27' , '+27 South Africa'),
  ('+34' , '+34 Spain'),
  ('+94' , '+94 Sri Lanka'),
  ('+249' , '+249 Sudan'),
  ('+597' , '+597 Suriname'),
  ('+268' , '+268 Swaziland'),
  ('+46' , '+46 Sweden'),
  ('+41' , '+41 Switzerland'),
  ('+963' , '+963 Syria'),
  ('+886' , '+886 Taiwan'),
  ('+992' , '+992 Tajikistan'),
  ('+255' , '+255 Tanzania'),
  ('+66' , '+66 Thailand'),
  ('+228' , '+228 Togo'),
  ('+676' , '+676 Tonga'),
  ('+216' , '+216 Tunisia'),
  ('+90' , '+90 Turkey'),
  ('+993' , '+993 Turkmenistan'),
  ('+256' , '+256 Uganda'),
  ('+380' , '+380 Ukraine'),
  ('+971' , '+971 United Arab Emirates'),
('+44' , '+44 United Kingdom'),
('+1', '+1 USA'),
 ('+598' , '+598 Uruguay'),
  ('+998' , '+998 Uzbekistan'),
  ('+678' , '+678 Vanuatu'),
  ('+58' , '+58 Venezuela'),
  ('+84' , '+84 Vietnam'),
  ('+967' , '+967 Yemen'),
  ('+260' , '+260 Zambia'),
  ('+263' , '+263 Zimbabwe'),
  ('+95' , '+95 Myanmar');";
mysql_query($query);			

$query = "CREATE TABLE IF NOT EXISTS `contacts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(40) NOT NULL DEFAULT 'No Name',
  `phone` varchar(20) NOT NULL,
  `phonebook` int(11) NOT NULL,
  `birthday` date NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);


$query = "CREATE TABLE IF NOT EXISTS `currencies` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `symbul` varchar(100) NOT NULL,
  `rate` decimal(11,5) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;";
mysql_query($query);


$query = "INSERT INTO `currencies` (`id`, `name`, `symbul`, `rate`) VALUES
(1, 'Naira', '&#8358;', '1.00000'),
(2, 'US Dollar', '$', '0.00603'),
(3, 'Euro', '&#8364;', '0.00436');";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `inbox` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer` int(11) NOT NULL,
  `sender` text NOT NULL,
  `date` datetime NULL,
  `message` text NOT NULL,
  `read`  int(5) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `customers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(200) NOT NULL,
  `fb_id` varchar(300) NOT NULL,
  `phone` varchar(30) NOT NULL,
  `username` varchar(20) NOT NULL,
  `password` varchar(200) NOT NULL,
  `address` varchar(300) NOT NULL,
  `city` varchar(300) NOT NULL,
  `state` varchar(300) NOT NULL,
  `country` varchar(100) NOT NULL,
  `senderID` varchar(15) NOT NULL,
  `picture` varchar(200) NOT NULL,
  `timeZone` varchar(300) NOT NULL,
  `smsPurchase` decimal(11,2) NOT NULL,
  `smsBalance` decimal(11,2) NOT NULL,
  `smsBorrowed` decimal(11,2) NOT NULL,
  `isReseller` int(11) NULL DEFAULT '0',
  `reseller` int(11) NULL DEFAULT '0',
  `allow_2way` int(11) NULL DEFAULT '0',
  `inbox_number` varchar(15) NOT NULL,
  `lastLogin` datetime NOT NULL,
  `lastIP` varchar(50) NOT NULL,
  `phoneVerified` int(11) NOT NULL DEFAULT '0',
  `emailVerified` int(11) NOT NULL DEFAULT '0',
  `verificationCode` int(11) NOT NULL,
  `verificationCode2` varchar(50) NOT NULL,
  `order_limit` varchar(50) NOT NULL DEFAULT '1',
  `currency` int(11) NOT NULL,
  `gateway` int(11) NOT NULL,
  `creditLimit` decimal(11,2) NOT NULL,
  `custom_rate` text NOT NULL,
  `custom_price` varchar(15) NOT NULL DEFAULT '0',
  `keyword` varchar(30) NOT NULL,
  `suspended` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 COMMENT='Keeps details of all SMS customers' AUTO_INCREMENT=10 ;";
mysql_query($query);


$query = "CREATE TABLE IF NOT EXISTS `draftmessages` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message` text NOT NULL,
  `recipient` text NOT NULL,
  `customer` int(11) NOT NULL,
  `reseller` int(11) NOT NULL,
  `is_unicode` int(11) NOT NULL DEFAULT '0',
   `is_mms` int(11) NOT NULL DEFAULT '0',
  `title` varchar(200) NOT NULL DEFAULT 'Untitled',
  `media` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `gateways` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `sendAPI` varchar(500) NOT NULL,
  `unicodeAPI` varchar(500) NOT NULL,
  `mmsAPI` varchar(500) NOT NULL,
  `balanceAPI` varchar(500) NOT NULL DEFAULT '',
  `deliveryAPI` varchar(500) NOT NULL DEFAULT '',
  `successWord` varchar(300) NOT NULL,
  `batchSize` int(11) NOT NULL DEFAULT '100',
  `isSMPP` int(11) NOT NULL DEFAULT '0',
  `smppServer` varchar(200) NOT NULL,
  `port` varchar(50) NOT NULL,
  `smppUsername` varchar(200) NOT NULL,
  `smppPassword` varchar(200) NOT NULL,
  `64_encode` varchar(10) NOT NULL DEFAULT '0',
  `method` varchar(30) NOT NULL DEFAULT 'GET',
  `inboxAPI` varchar(500) NOT NULL,
  `auth_key` varchar(500) NOT NULL,
  `param3` varchar(500) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=4 ;";
mysql_query($query);

$query = "INSERT INTO `gateways` (`id`, `name`, `sendAPI`, `unicodeAPI`, `balanceAPI`, `deliveryAPI`, `successWord`, `batchSize`,`isSMPP`,`auth_key`,`mmsAPI`,`inboxAPI`) VALUES
(1, 'SMSKit', 'http://www.smskit.net/SMSC/API/index.php?username=&password=&sender=[SENDER]&recipient=[TO]&message=[MESSAGE]', 'http://www.smskit.net/SMSC/API/index.php?unicode=1&username=&password=&sender=[SENDER]&recipient=[TO]&message=[MESSAGE]', '', '', 'Message Sent Successfully', 100,0,'','',''),
(2, 'Twilio (2-Way)', 'https://api.twilio.com/2010-04-01/Accounts/[Your-SID]/SMS/Messages?From=[SENDER]&To=[TO]&Body=[MESSAGE]', 'https://api.twilio.com/2010-04-01/Accounts/[Your-SID]/SMS/Messages?From=[SENDER]&To=[TO]&Body=[MESSAGE]', '', '', 'Sent Successfully', 100,0,'[Your_Account_SID]:[Your_Auth_Token]','https://api.twilio.com/2010-04-01/Accounts/[Your-SID]/Messages?From=[SENDER]&To=[TO]&Body=[MESSAGE]&MediaUrl=[MEDIA]',''),
(3, 'Infobip (2-Way)', 'https://api.infobip.com/sms/1/text/single?from=[SENDER]&to=[TO]&text=[MESSAGE]', 'https://api.infobip.com/sms/1/binary/single?from=[SENDER]&to=[TO]&hex=[MESSAGE]&dataCoding=8', '', '', 'sent', 60,0,'[Your_Username]:[Your_Password]','','https://api.infobip.com/sms/1/inbox/reports/'),
(4, 'Nexmo (2-Way)', 'https://rest.nexmo.com/sms/json?api_key=[Your_Nexmo_Key]&api_secret=[Your_Nexmo_Secret]&from=[SENDER]&to=[TO]&text=[MESSAGE]', '', '', '', 'network', 50,0,'','','');";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `paymentalerts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `depositor` varchar(200) NOT NULL,
  `transaction` int(11) NOT NULL,
  `method` varchar(100) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'Pending',
  `reference` varchar(30) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `blacklist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `phone` varchar(30) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `paymentgateways` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(200) NOT NULL,
  `username` varchar(300) NOT NULL,
  `alias` varchar(100) NOT NULL,
  `status` int(11) NOT NULL DEFAULT '0',
  `custom` int(11) NOT NULL DEFAULT '1',
  `text` text NOT NULL,
  `image` varchar(300) NOT NULL DEFAULT 'custom.png',
  `url` varchar(300) NOT NULL,
  `param1` varchar(300) NOT NULL,
  `param2` varchar(500) NOT NULL,
  `vat` varchar(300) NOT NULL,
  `handling` varchar(500) NOT NULL,  
  `processingFeeFixed` varchar(500) NOT NULL,
  `processingFeePerc` varchar(500) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=6 ;";
mysql_query($query);

$query = "INSERT INTO `paymentgateways` (`id`, `name`, `username`, `alias`, `status`, `custom`, `text`, `image`, `url`, `param1`, `processingFeeFixed`, `processingFeePerc`) VALUES
(1, 'Interswitch (MasterCard/Visa/Verve)', '', 'webpay', 0, 0, '', 'webpay.png', 'https://connect.interswitchng.com/documentation/getting-started/','','',''),
(2, 'GTPay (MasterCard/Visa/Verve)', '', 'gtpay', 0, 0, '', 'gtpay.png', 'http://www.gtbank.com/gtpay','','',''),
(3, 'SimplePay (MasterCard/Visa/Verve)', '', 'simplepay', 0, 0, '', 'simplepay.png', 'https://www.simplepay.ng','','',''),
(4, 'PayPal (MasterCard/Visa)', '', 'paypal', 0, 0, '', 'paypal.png', 'https://www.paypal.com','','',''),
(6, '2Checkout (MasterCard/Visa)', '', '2checkout', 0, 0, '', '2checkout.png', 'https://www.2checkout.com','','',''),
(7, 'Quickteller (MasterCard/Visa)', '', 'quickteller', 0, 0, '', 'quickteller.png', 'https://connect.interswitchng.com/documentation/how-to-get-listed/','','',''),
(8, 'VoguePay (MasterCard/Visa)', '', 'voguepay', 0, 0, '', 'voguepay.png', 'https://www.voguepay.com','','',''),
(9, 'Stripe', '', 'stripe', 0, 0, '', 'stripe.png', 'https://www.stripe.com','','',''),
(5, 'Custom Gateway', '', 'custom', 1, 1, 'Pay total invoice amount into our bank account. ', 'custom.png', '','','','');";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `phonebooks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(100) NOT NULL,
  `customer` int(11) NOT NULL,
  `reseller` int(11) NOT NULL,
  `description` varchar(300) NOT NULL,
  `birthday_sms` varchar(500) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `accounts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` varchar(100) NOT NULL,
  `description` varchar(300) NOT NULL,
  `income` varchar(100) NOT NULL,
  `expense` varchar(100) NOT NULL,
  `processed_by` varchar(300) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `marketinglist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(100) NOT NULL,
  `keyword` varchar(100) NOT NULL,
  `customer` int(11) NOT NULL,
  `description` varchar(300) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `marketingcontacts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL DEFAULT 'No Name',
  `phone` varchar(20) NOT NULL,
  `marketinglist` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `phonebook_owners` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `phonebook` int(11) NOT NULL,
  `customer` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `scheduledmessages` (
  `message` text NOT NULL,
  `senderID` varchar(15) NOT NULL,
  `recipient` text NOT NULL,
  `date` datetime NOT NULL,
  `customer` int(11) NOT NULL,
  `reseller` int(11) NOT NULL,
  `pages` int(11) NOT NULL,
  `is_unicode` int(11) NOT NULL DEFAULT '0',
  `is_mms` int(11) NOT NULL DEFAULT '0',
  `status` varchar(50) NOT NULL DEFAULT 'Pending',
  `error` varchar(300) NOT NULL DEFAULT '',
  `media` varchar(500) NOT NULL DEFAULT '',
  `scheduleDate` datetime NOT NULL,
  `IP` varchar(30) NOT NULL,
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `sentmessages` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message` text NOT NULL,
  `senderID` varchar(15) NOT NULL,
  `recipient` text NOT NULL,
  `date` datetime NOT NULL,
  `customer` int(11) NOT NULL,
  `reseller` int(11) NOT NULL,
  `pages` int(11) NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'Sending',
  `units` DECIMAL(11, 2) NOT NULL,
  `sentFrom` varchar(50) NOT NULL DEFAULT 'Panel',
  `is_mms` int(11) NOT NULL DEFAULT '0',
  `is_unicode` int(11) NOT NULL DEFAULT '0',
  `IP` varchar(20) NOT NULL DEFAULT 'Unknown',
  `gateway_id` varchar(500) NOT NULL DEFAULT '',
  `dlr` varchar(200) NOT NULL DEFAULT '',
  `media` varchar(500) NOT NULL DEFAULT '',
  `error` varchar(100) NOT NULL DEFAULT 'Message Status Not Available',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `messagedetails` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `queue_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `recipient` text NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'Sending',
  `gateway` varchar(100) NOT NULL,
  `country` varchar(100) NOT NULL,
  `operator` varchar(100) NOT NULL DEFAULT 'Unknown',
  `date` varchar(20) NOT NULL,
  `sender` varchar(20) NOT NULL,
  `units` DECIMAL(11, 2) NOT NULL,
  `is_mms` int(11) NOT NULL DEFAULT '0',
  `is_unicode` int(11) NOT NULL DEFAULT '0',
  `error` varchar(200) NOT NULL DEFAULT 'Sent Successfully',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `resellers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer` int(11) NOT NULL,
  `business_name` text NOT NULL,
  `business_email` text NOT NULL,
  `website` text NOT NULL,
  `background_url`  text NOT NULL,
  `logo_url` text NOT NULL,
  `welcome_sms` text NOT NULL,
  `welcome_email` text NOT NULL,
  `welcome_email_subject` text NOT NULL,
  `menu_colour` text NOT NULL,
  `header_colour` text NOT NULL,
  `menu_font` text NOT NULL,
  `header_font` text NOT NULL,  
  `allowed_domain` varchar(500) NOT NULL,
  `default_timezone` varchar(500) NOT NULL,
  `sms_sender` varchar(500) NOT NULL,
  `test_units` varchar(500) NOT NULL,
  `email_sender` varchar(500) NOT NULL,
  `smtp_user` varchar(500) NOT NULL,
  `smtp_password` varchar(500) NOT NULL,
  `smtp_server` varchar(500) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `custom_rates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer` int(11) NOT NULL,
  `rates` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `field` varchar(100) NOT NULL,
  `value` text NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `field` (`field`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=35 ;";
mysql_query($query);

$query = "INSERT INTO `settings` (`id`, `field`, `value`) VALUES
(1, 'siteBackground', 'background.jpg'),
(2, 'backgroundColor', '#f8f8f8'),
(3, 'headerColor', '#222222'),
(4, 'footerColor', ''),
(5, 'siteLogo', ''),
(6, 'siteName', 'LifePost System MOhamedgpaly'),
(7, 'forbiddenID', ''),
(8, 'activeGateway', '1'),
(9, 'smsCost', '1=1\r\n2=1\r\n22=1\r\n234=1'),
(10, 'defaultCost', '1'),
(11, 'defaultUnitCost', '1.00'),
(12, 'resellerUnitCost', '1.00'),
(13, 'companyName', ''),
(14, 'companyAddress', ''),
(15, 'companyEmail', ''),
(16, 'companyPhone', ''),
(17, 'defaultCurrency', '1'),
(18, 'smsSender', 'SMS Centre'),
(19, 'emailSender', 'SMS Customer Service'),
(20, 'newAccountSMS', 'Hi [CUSTOMER NAME].\r\nYour SMS account has been created. Your username is [USERNAME] and your password is [PASSWORD].'),
(21, 'newAccountEmail', '<p>Hi [CUSTOMER NAME].</p>\r\n\r\n<p><br />\r\nYour SMS account has been created.</p>\r\n\r\n<p>Your username is [USERNAME] and your password is [PASSWORD].</p>\r\n'),
(22, 'newAccountEmailSubject', 'Welcome To Your New SMS Account'),
(23, 'newPasswordEmailSubject', 'Your Password Has Been Recovered'),
(24, 'newPasswordSMS', 'Hi [CUSTOMER NAME].\r\nYour login details has been recovered. Your username is [USERNAME] and your new password is [PASSWORD].'),
(25, 'newPasswordEmail', '<p>Hi [CUSTOMER NAME].</p>\r\n\r\n<p><br />\r\nYour login details has been recovered.</p>\r\n\r\n<p>&nbsp;</p>\r\n\r\n<p>Your username is [USERNAME] and your new password is [PASSWORD].</p>\r\n'),
(26, 'testUnits', '5'),
(27, 'defaultTimeZone', 'Europe/Paris'),
(28, 'orderApproveSMS', 'Hi [CUSTOMER NAME].\r\nYour SMS account has been credited with [UNITS] SMS units. Your new balance is [BALANCE].'),
(29, 'orderApproveEmail', '<p>Dear [CUSTOMER NAME].</p>\r\n\r\n<p><br />\r\nYour SMS account has been credited with [UNITS] SMS units.</p>\r\n\r\n<p>Your new balance is [BALANCE].</p>\r\n'),
(30, 'orderApproveEmailSubject', 'Your Order for SMS Units Has Been Approved'),
(31, 'newAdminPasswordEmailSubject', 'Your Fome SMS Portal Admin Password'),
(32, 'newAdminPasswordEmail', '<p>Hi [CUSTOMER NAME],</p>\r\n\r\n<p>&nbsp;</p>\r\n\r\n<p>Your Fome SMS Portal Admin access details have been recovered. Here are your new login details:</p>\r\n\r\n<p><strong>Username: </strong>[USER NAME]</p>\r\n\r\n<p><strong>Password: </strong>[PASSWORD]</p>\r\n\r\n<p>&nbsp;</p>\r\n\r\n<p>&nbsp;</p>\r\n'),
(33, 'acompanyEmail', 'non-reply@fomesmsportal.com'),
(34, 'term', ''),
(35, 'menuColor', '#333333'),
(36, 'fontColor', '#eeeeee'),
(37, 'dynamicSender', '1'),
(38, 'localEncode', '1'),
(39, 'taxAmount', '0.00'),
(40, 'vatAmount', '0.00'),
(41, 'smppEnabled', '0'),
(42, 'forbiddenCountry', ''),
(43, 'menuFontColor', '#ffffff'),
(44, 'companyWebsite', ''),
(45, 'redirectToSite', '0'),
(46, 'emailClient', 'php'),
(47, 'smtpServer', ''),
(48, 'smtpUsername', ''),
(49, 'smtpPassword', ''),
(50, 'unicodeSMS', '1'),
(51, '2WaySMSEnabled', '1'),
(52, 'MMSEnabled', '1'),
(53, 'language', 'en'),
(54, 'param', ''),
(55, 'Customer2WaySMSEnabled', '1'),
(56, 'activeUnicodeGateway', ''),
(57, 'activeMMSGateway', ''),
(58, 'defaultCountry', 'Nigeria'),
(59, 'active2WaySMSGateway', ''),
(60, 'headerFontColor', '#FFFFFF'),
(61, 'phone_verify', '0'),
(62, 'facebook_secrete', ''),
(63, 'blackListKeyword', 'BLACKLIST ME'),
(64, 'facebook_api', ''),
(65, 'email_verify', '1'),
(66, 'activeTheme', 'default'),
(67, 'incomingXML', '0'),
(68, 'incomingFrom', ''),
(69, 'incomingTo', ''),
(70, 'incomingBody', '');";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `smsprice` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `minValue` decimal(11,2) NOT NULL,
  `maxValue` decimal(11,2) NOT NULL,
  `cost` decimal(11,4) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=4 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `sender_id` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer` int(11) NOT NULL,
  `reseller` int(11) NOT NULL DEFAULT '0',
  `senderID` varchar(20) NOT NULL,
  `approved` int(2) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=4 ;";
mysql_query($query);

$query = "INSERT INTO `smsprice` (`id`, `minValue`, `maxValue`, `cost`) VALUES
(1, '0.00', '1000.00', '1.00'),
(2, '1001.00', '5000.00', '1.00'),
(3, '5001.00', '10000.00', '1.00');";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `tickets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer` int(11) NOT NULL,
  `from` int(11) NOT NULL,
  `reseller` int(11) NOT NULL,
  `subject` varchar(200) NOT NULL,
  `message` text NOT NULL,
  `date` datetime NOT NULL,
  `status` varchar(50) NOT NULL,
  `department` varchar(200) NOT NULL,
  `adminstatus` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `resellertickets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer` int(11) NOT NULL,
  `sub_customer` int(11) NOT NULL,
  `subject` varchar(200) NOT NULL,
  `message` text NOT NULL,
  `date` datetime NOT NULL,
  `status` varchar(50) NOT NULL,
  `department` varchar(200) NOT NULL,
  `adminstatus` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `transactions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer` int(11) NOT NULL,
  `reseller` int(11) NOT NULL,
  `units` decimal(11,2) NOT NULL,
  `cost` decimal(11,4) NOT NULL,
  `price` decimal(11,4) NOT NULL,
  `date` datetime NOT NULL,
  `status` varchar(100) NOT NULL,
  `gateway` varchar(100) NOT NULL,
  `approvedBy` varchar(200) NOT NULL,
  `transaction_reference` varchar(400) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COMMENT='Holds details of all purchases on the panel' AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `transaction_status` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 COMMENT='Definition of the various transaction status' AUTO_INCREMENT=5 ;";
mysql_query($query);

$query = "INSERT INTO `transaction_status` (`id`, `value`) VALUES
(1, 'Pending'),
(2, 'Pending'),
(3, 'Completed'),
(4, 'Failed');";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `users` (
  `firstName` varchar(200) NOT NULL,
  `lastName` varchar(200) NOT NULL,
  `username` varchar(20) NOT NULL,
  `password` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `lastLogin` datetime NOT NULL,
  `lastIP` varchar(30) NOT NULL,
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `vouchers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pin` varchar(20) NOT NULL,
  `units` int(11) NOT NULL,
  `cost` decimal(11,4) NOT NULL,
  `used` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$query = "CREATE TABLE IF NOT EXISTS `themes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `alias` varchar(100) NOT NULL,
  `author` varchar(100) NOT NULL,
  `image` varchar(300) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;";
mysql_query($query);

$add = mysql_query("INSERT INTO themes (`id`, `name`, `alias`, `author`, `image`) 
	VALUES (NULL, 'Sendroid Default', 'default', 'Ynet Interactive', '../themes/default/preview.png');");		

//encript password 
		$password2 = $pass;
		$salt = genRandomPassword(32);
		$crypt = getCryptedPassword($password2, $salt);
		$pass = $crypt.':'.$salt;	

$last_login_date = date('Y-m-d h:i:s');		
//insert new adin details 
		$add = mysql_query("INSERT INTO `users` (`firstName`, `lastName`, `username`, `password`, `email`, `lastLogin`, `lastIP`, `id`, `customer`) VALUES ('Supper Admin', '', 'admin', '$pass', '$email', '$last_login_date', '', 1, 1);");

//add new customer for admin
$query = "INSERT INTO `customers` (`id`, `name`, `email`, `phone`, `username`, `password`, `address`, `country`, `senderID`, `picture`, `timeZone`, `smsPurchase`, `smsBalance`, `smsBorrowed`, `isReseller`, `reseller`, `lastLogin`, `lastIP`, `phoneVerified`, `emailVerified`, `verificationCode`, `currency`, `creditLimit`, `suspended`) VALUES
(1, 'Supper Admin', '$email', '', 'admin', '$pass', '', '', '', '', 'Europe/Paris', '5.00', '0.00', '0.00', 1, 0, '', '', 1, 1, 66546, 1, '0.00', 0);";
mysql_query($query);

//check if all went well 
	if($res) {
	$er = '';	
	} else {
	$res = 'Incomplete Database Setup';	
	}
//Update Config file
$file_path = DOCUMENT_ROOT.'82335643564354858435/includes/72335823356466643548114531252654.php';
$resultsd = @chmod($file_path, 0777);

include($file_path);		
$h = $sconfig['host'];
$d = $sconfig['database'];
$u = $sconfig['user'];
$p = $sconfig['password'];
$i = $sconfig['installed'];

$data3 = read_file($file_path);
$data3 = str_replace($h, $host, $data3);
$data3 = str_replace($d, $database, $data3);
$data3 = str_replace($u, $username, $data3);
$data3 = str_replace($p, $password, $data3);
$data3 = str_replace($i, 'INSTALLED', $data3);
write_file($file_path, $data3);	

if(empty($er)) {
return true;	
} else {
return false;	
}

}

?>