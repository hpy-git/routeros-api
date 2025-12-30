<?php
/*****************************
 *
 * RouterOS PHP API class v1.6
 * Author: Denis Basta
 * Contributors:
 *    Nick Barnes
 *    Ben Menking (ben [at] infotechsc [dot] com)
 *    Jeremy Jefferson (http://jeremyj.com)
 *    Cristian Deluxe (djcristiandeluxe [at] gmail [dot] com)
 *    Mikhail Moskalev (mmv.rus [at] gmail [dot] com)
 *
 * http://www.mikrotik.com
 * http://wiki.mikrotik.com/wiki/API_PHP_class
 *
 * 
 * Modified for mTik_Ops by Ervin S. (hpy-git) - (esoliven [at] mtikops [dot] com)
 ******************************/

class RouterosAPI
{
    var $debug     = false; //  Show debug information
    var $connected = false; //  Connection state
    var $port      = 8728;  //  Port to connect to (default 8729 for ssl)
    var $ssl       = false; //  Connect using SSL (must enable api-ssl in IP/Services)
    var $timeout   = 3;     //  Connection attempt timeout and data read timeout
    var $attempts  = 5;     //  Connection attempt count
    var $delay     = 3;     //  Delay between connection attempts in seconds

    var $conn      = false; //  Test connection

    var $socket;            //  Variable for storing socket resource
    var $error_no;          //  Variable for storing connection error number, if any
    var $error_str;         //  Variable for storing connection error text, if any

    /* Check, can be var used in foreach  */
    public function isIterable($var)
    {
        return $var !== null
                && (is_array($var)
                || $var instanceof Traversable
                || $var instanceof Iterator
                || $var instanceof IteratorAggregate
                );
    }

    public function debug($text)
    {
        if ($this->debug) {
            if ($this->conn){
                if(strstr($text, "invalid user name or password")){
                    echo "Invalid username or password,";

                }else if(strstr($text, "Connected")){
                    echo "Connected,";

                }else if(strstr($text, "Error")){
                    echo "Error,";
                }
            }else{
                echo $text . "\n";
            }
        }
    }

    public function encodeLength($length)
    {
        if ($length < 0x80) {
            $length = chr($length);
        } elseif ($length < 0x4000) {
            $length |= 0x8000;
            $length = chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } elseif ($length < 0x200000) {
            $length |= 0xC00000;
            $length = chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } elseif ($length < 0x10000000) {
            $length |= 0xE0000000;
            $length = chr(($length >> 24) & 0xFF) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } elseif ($length >= 0x10000000) {
            $length = chr(0xF0) . chr(($length >> 24) & 0xFF) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        }

        return $length;
    }

    public function connect($ip, $login, $password)
    {
        for ($ATTEMPT = 1; $ATTEMPT <= $this->attempts; $ATTEMPT++) {
            $this->connected = false;
            $PROTOCOL = ($this->ssl ? 'ssl://' : '' );
            $context = stream_context_create(array('ssl' => array('ciphers' => 'ADH:ALL', 'verify_peer' => false, 'verify_peer_name' => false)));
            $this->debug('Connection attempt #' . $ATTEMPT . ' to ' . $PROTOCOL . $ip . ':' . $this->port . '...');
            $this->socket = @stream_socket_client($PROTOCOL . $ip.':'. $this->port, $this->error_no, $this->error_str, $this->timeout, STREAM_CLIENT_CONNECT,$context);
            if ($this->socket) {
                socket_set_timeout($this->socket, $this->timeout);
                $this->write('/login', false);
                $this->write('=name=' . $login, false);
                $this->write('=password=' . $password);
                $RESPONSE = $this->read(false);
                if (isset($RESPONSE[0])) {
                    if ($RESPONSE[0] == '!done') {
                        if (!isset($RESPONSE[1])) {
                            $this->connected = true;
                            break;
                        } else {
                            $MATCHES = array();
                            if (preg_match_all('/[^=]+/i', $RESPONSE[1], $MATCHES)) {
                                if ($MATCHES[0][0] == 'ret' && strlen($MATCHES[0][1]) == 32) {
                                    $this->write('/login', false);
                                    $this->write('=name=' . $login, false);
                                    $this->write('=response=00' . md5(chr(0) . $password . pack('H*', $MATCHES[0][1])));
                                    $RESPONSE = $this->read(false);
                                    if (isset($RESPONSE[0]) && $RESPONSE[0] == '!done') {
                                        $this->connected = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                fclose($this->socket);
            }
            sleep($this->delay);
        }

        if ($this->connected) {
            $this->debug('Connected...');
        } else {
            $this->debug('Error...');

        }
        return $this->connected;
    }

    public function disconnect()
    {
        if( is_resource($this->socket) ) {
            fclose($this->socket);
        }
        $this->connected = false;
        $this->debug('Disconnected...');
    }

    public function parseResponse($response)
    {
        if (is_array($response)) {
            $PARSED      = array();
            $CURRENT     = null;
            $singlevalue = null;
            foreach ($response as $x) {
                if (in_array($x, array('!fatal','!re','!trap'))) {
                    if ($x == '!re') {
                        $CURRENT =& $PARSED[];
                    } else {
                        $CURRENT =& $PARSED[$x][];
                    }
                } elseif ($x != '!done') {
                    $MATCHES = array();
                    if (preg_match_all('/[^=]+/i', $x, $MATCHES)) {
                        // Reconstruct the value by joining all fragments after the
                        // first match with '=' so values that themselves contain
                        // '=' (common in script sources) are not truncated.
                        $key = isset($MATCHES[0][0]) ? $MATCHES[0][0] : '';
                        if ($key === 'ret') {
                            $singlevalue = isset($MATCHES[0][1]) ? $MATCHES[0][1] : null;
                        }
                        if (isset($MATCHES[0][1])) {
                            $valParts = array_slice($MATCHES[0], 1);
                            $val = implode('=', $valParts);
                        } else {
                            $val = '';
                        }
                        $CURRENT[$key] = $val;
                    }
                }
            }

            if (empty($PARSED) && !is_null($singlevalue)) {
                $PARSED = $singlevalue;
            }

            return $PARSED;
        } else {
            return array();
        }
    }

    public function parseResponse4Smarty($response)
    {
        if (is_array($response)) {
            $PARSED      = array();
            $CURRENT     = null;
            $singlevalue = null;
            foreach ($response as $x) {
                if (in_array($x, array('!fatal','!re','!trap'))) {
                    if ($x == '!re') {
                        $CURRENT =& $PARSED[];
                    } else {
                        $CURRENT =& $PARSED[$x][];
                    }
                } elseif ($x != '!done') {
                    $MATCHES = array();
                    if (preg_match_all('/[^=]+/i', $x, $MATCHES)) {
                        // Reconstruct value preserving '=' characters as above
                        $key = isset($MATCHES[0][0]) ? $MATCHES[0][0] : '';
                        if ($key == 'ret') {
                            $singlevalue = isset($MATCHES[0][1]) ? $MATCHES[0][1] : null;
                        }
                        if (isset($MATCHES[0][1])) {
                            $valParts = array_slice($MATCHES[0], 1);
                            $val = implode('=', $valParts);
                        } else {
                            $val = '';
                        }
                        $CURRENT[$key] = $val;
                    }
                }
            }
            foreach ($PARSED as $key => $value) {
                $PARSED[$key] = $this->arrayChangeKeyName($value);
            }
            return $PARSED;
            if (empty($PARSED) && !is_null($singlevalue)) {
                $PARSED = $singlevalue;
            }
        } else {
            return array();
        }
    }

    public function arrayChangeKeyName(&$array)
    {
        if (is_array($array)) {
            foreach ($array as $k => $v) {
                $tmp = str_replace("-", "_", $k);
                $tmp = str_replace("/", "_", $tmp);
                if ($tmp) {
                    $array_new[$tmp] = $v;
                } else {
                    $array_new[$k] = $v;
                }
            }
            return $array_new;
        } else {
            return $array;
        }
    }

    public function read($parse = true)
    {
        $RESPONSE     = array();
        $receiveddone = false;
        while (true) {
            $BYTE   = ord(fread($this->socket, 1));
            $LENGTH = 0;
            if ($BYTE & 128) {
                if (($BYTE & 192) == 128) {
                    $LENGTH = (($BYTE & 63) << 8) + ord(fread($this->socket, 1));
                } else {
                    if (($BYTE & 224) == 192) {
                        $LENGTH = (($BYTE & 31) << 8) + ord(fread($this->socket, 1));
                        $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                    } else {
                        if (($BYTE & 240) == 224) {
                            $LENGTH = (($BYTE & 15) << 8) + ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                        } else {
                            $LENGTH = ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                        }
                    }
                }
            } else {
                $LENGTH = $BYTE;
            }

            $_ = "";

            if ($LENGTH > 0) {
                $_      = "";
                $retlen = 0;
                while ($retlen < $LENGTH) {
                    $toread = $LENGTH - $retlen;
                    $_ .= fread($this->socket, $toread);
                    $retlen = strlen($_);
                }
                $RESPONSE[] = $_;
                $this->debug('>>> [' . $retlen . '/' . $LENGTH . '] bytes read.');
            }

            if ($_ == "!done") {
                $receiveddone = true;
            }

            $STATUS = socket_get_status($this->socket);
            if ($LENGTH > 0) {
                $this->debug('>>> [' . $LENGTH . ', ' . $STATUS['unread_bytes'] . ']' . $_);
            }

            if ((!$this->connected && !$STATUS['unread_bytes']) || ($this->connected && !$STATUS['unread_bytes'] && $receiveddone)) {
                break;
            }
        }

        if ($parse) {
            $RESPONSE = $this->parseResponse($RESPONSE);
        }

        return $RESPONSE;
    }

    public function write($command, $param2 = true)
    {
        if ($command) {
            // Send the entire command as a single chunk.
            // Splitting on newlines caused multi-line values (like script `source`) to be
            // transmitted as separate commands and get truncated. Preserve the full
            // command so RouterOS receives multi-line script bodies intact.
            $com = $this->sanitizeParam($command);
            $com = trim($com);
            fwrite($this->socket, $this->encodeLength(strlen($com)) . $com);
            $this->debug('<<< [' . strlen($com) . '] ' . $com);

            if (gettype($param2) == 'integer') {
                fwrite($this->socket, $this->encodeLength(strlen('.tag=' . $param2)) . '.tag=' . $param2 . chr(0));
                $this->debug('<<< [' . strlen('.tag=' . $param2) . '] .tag=' . $param2);
            } elseif (gettype($param2) == 'boolean') {
                fwrite($this->socket, ($param2 ? chr(0) : ''));
            }

            return true;
        } else {
            return false;
        }
    }

    public function comm($com, $arr = array())
    {
        $count = count($arr);
        $this->write($com, !$arr);
        $i = 0;
        if ($this->isIterable($arr)) {
            foreach ($arr as $k => $v) {
                // sanitize parameter values before embedding into command
                $v = $this->sanitizeParam($v);
                switch ($k[0]) {
                    case "?":
                        $el = "$k=$v";
                        break;
                    case "~":
                        $el = "$k~$v";
                        break;
                    default:
                        $el = "=$k=$v";
                        break;
                }

                $last = ($i++ == $count - 1);
                $this->write($el, $last);
            }
        }

        return $this->read();
    }

    /**
     * Sanitize a parameter or command before sending to RouterOS.
     * Removes null bytes and control characters that may break the
     * RouterOS API transport, trims length, and ensures a string.
     */
    public function sanitizeParam($val)
    {
        if (is_array($val)) {
            $out = [];
            foreach ($val as $k => $v) {
                $out[$k] = $this->sanitizeParam($v);
            }
            return $out;
        }

        if (!is_string($val)) return $val;

        // Remove null bytes and ASCII control chars except TAB (\t) and space
        $val = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/u', '', $val);
        // Remove CR and LF to avoid breaking protocol framing
        $val = str_replace(["\r", "\n"], ' ', $val);
        // Trim and limit length to a reasonable maximum
        $val = trim($val);
        $max = 8192;
        if (strlen($val) > $max) {
            $val = substr($val, 0, $max);
        }

        return $val;
    }

    public function __destruct()
    {
        $this->disconnect();
    }
}


if (!function_exists('enc_rypt')) {
    function enc_rypt($string, $key=128) {
        if (function_exists('encrypt_secret')) {
            $enc = @encrypt_secret($string);
            if ($enc !== null) return $enc;
        }
        $result = '';
        for($i=0, $k= strlen($string); $i<$k; $i++) {
            $char = substr($string, $i, 1);
            $keychar = substr($key, ($i % strlen($key))-1, 1);
            $char = chr(ord($char)+ord($keychar));
            $result .= $char;
        }
        return base64_encode($result);
    }
}
if (!function_exists('dec_rypt')) {
    function dec_rypt($string, $key=128) {
        if (function_exists('decrypt_secret')) {
            $dec = @decrypt_secret($string);
            if ($dec !== null) return $dec;
        }
        // If the input is not base64-encoded (i.e., it's already plain), return it unchanged.
        $decoded = @base64_decode($string, true);
        if ($decoded === false || $decoded === null) {
            return $string;
        }
        $result = '';
        $string = $decoded;
        for($i=0, $k=strlen($string); $i< $k ; $i++) {
            $char = substr($string, $i, 1);
            $keychar = substr($key, ($i % strlen($key))-1, 1);
            $char = chr(ord($char)-ord($keychar));
            $result .= $char;
        }
        return $result;
    }
}


function get_config($string, $start, $end){
    $string = ' ' . $string;
    $ini = strpos($string, $start);
    if ($ini == 0) return '';
    $ini += strlen($start);
    $len = strpos($string, $end, $ini) - $ini;
    return substr($string, $ini, $len);
}

function formatBytes($size, $decimals = 0){
    $n = floatval($size);
    if($n == 0) return '0B';
    $units = array('','K','M','G','T','P','E','Z','Y');
    $i = 0;
    while($n >= 1000 && $i < count($units)-1){ $n = $n / 1000; $i++; }
    $rounded = round($n, ($decimals>0? $decimals : ($n>=10?0:($n>=1?1:2))));
    if(abs($rounded - round($rounded)) < 0.0001) $rounded = round($rounded);
    return $rounded . $units[$i];
}

function formatBytes2($size, $decimals = 0){
    // decimal units, compact form (e.g. 5M)
    $n = floatval($size);
    if($n == 0) return '0B';
    $units = array('','K','M','G','T','P','E','Z','Y');
    $i = 0;
    while($n >= 1000 && $i < count($units)-1){ $n = $n / 1000; $i++; }
    $rounded = round($n, ($decimals>0? $decimals : ($n>=10?0:($n>=1?1:2))));
    if(abs($rounded - round($rounded)) < 0.0001) $rounded = round($rounded);
    return $rounded . $units[$i];
}

function formatBites($size, $decimals = 0){
    $unit = array(
    '0' => 'bps',
    '1' => 'kbps',
    '2' => 'Mbps',
    '3' => 'Gbps',
    '4' => 'Tbps',
    '5' => 'Pbps',
    '6' => 'Ebps',
    '7' => 'Zbps',
    '8' => 'Ybps'
    );

    for($i = 0; $size >= 1000 && $i <= count($unit); $i++){
    $size = $size/1000;
    }

    return round($size, $decimals).' '.$unit[$i];
}


?>
