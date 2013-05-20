<?php

class Duo {
    const REQUEST_PREFIX = "TX";
    const REQUEST_EXPIRE = 300;
    const RESPONSE_PREFIX = "AUTH";

    public static function signRequest($ikey, $skey, $username, $curTime=NULL)
    {
        $expire = ($curTime != NULL ? $curTime : time());
        $expire += self::REQUEST_EXPIRE;
            
        $val = sprintf("%s|%s|%s", $username, $ikey, $expire);
        $cookie = sprintf("%s|%s", self::REQUEST_PREFIX, base64_encode($val));

        $sig = hash_hmac("sha1", $cookie, $skey);

        return sprintf("%s|%s", $cookie, $sig);
    }

    public static function verifyResponse($skey, $sig_response, $curTime=NULL)
    {
        $ts = ($curTime != NULL ? $curTime : time());

        list($u_prefix, $u_b64, $u_sig) = explode("|", $sig_response);
        $cookie = sprintf("%s|%s", $u_prefix, $u_b64);
        $sig = hash_hmac("sha1", $cookie, $skey);

        if (hash_hmac("sha1", $sig, $skey) != hash_hmac("sha1", $u_sig, $skey)) {
            return NULL;
        }

        if ($u_prefix != self::RESPONSE_PREFIX) {
            return NULL;
        }

        $val = base64_decode($u_b64);
        list($uname, $ikey, $expire) = explode("|", $val);

        if ($ts >= intval($expire)) {
            return NULL;
        }

        return $uname;
    }
}

?>
