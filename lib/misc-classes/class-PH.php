<?php

/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

class PH
{

    public static $UseDomXML = true;

    /**
     * @var null|mixed[]
     */
    public static $args = null;

    public static $ignoreDestructors = false;

    public static $useExceptions = false;

    public static $outputFormattingEnabled = true;

    public static $enableXmlDuplicatesDeletion = false;

    /** @var bool set to true if you want to ignore invalid address objects but print a warning instead */
    public static $ignoreInvalidAddressObjects = false;

    public static $basedir;

    private static $library_version_major = 1;
    private static $library_version_sub = 5;
    private static $library_version_bugfix = 14;

    public static $softwareupdate_key = "658d787f293e631196dac9fb29490f1cc1bb3827";
    public static $softwareupdate_user_encrypt = "NmPyrGw7WYXdu5cdgm2x7HEkDf4LTHob7M/JNNhS+3CIfV5DkV7Tne8xersHIRafbXV3vzgIRECsG06Hs+O80g==";
    public static $softwareupdate_pw_encrypt = "wbCEjb8jaYH36HHvB2PmLMNyaz27MvHgM+Bn64wnofCjrV/4G+25AkoqG+q41Cvigc9uUxBTbOUtW2EhQOPYjA==";


    static public function decrypt( $ciphertext, $key )
    {
        $c = base64_decode($ciphertext);
        $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len=32);
        $ciphertext_raw = substr($c, $ivlen+$sha2len);
        $ciphertext_2 = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
        $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);

        return array($ciphertext_2,$calcmac);
    }

    static public function frameworkVersion()
    {
        return self::$library_version_major . '.' . self::$library_version_sub . '.' . self::$library_version_bugfix;
    }

    /**
     * @param string $versionString ie: '1.2.3' or '1.5'
     * @return bool
     */
    static public function frameworkVersion_isGreaterThan($versionString)
    {
        $numbers = explode('.',$versionString);

        if( count($numbers) < 2 || count($numbers) > 3)
            derr("'{$versionString}' is not a valid version syntax ( 'X.Y' or 'X.Y.Z' is accepted)");

        if( !is_numeric($numbers[0]) )
            derr("'{$numbers[0]}' is not a valid integer");

        if( !is_numeric($numbers[1]) )
            derr("'{$numbers[1]}' is not a valid integer");

        if( count($numbers) == 3 && !is_numeric($numbers[2]) )
            derr("'{$numbers[2]}' is not a valid integer");


        if( self::$library_version_major > intval($numbers[0]) )
            return true;

        $frameWorkValue = self::$library_version_major * 1000 * 1000;
        $localValue = intval($numbers[0]) * 1000 * 1000;

        $frameWorkValue += self::$library_version_sub * 1000;
        $localValue += intval($numbers[1]) * 1000;

        $frameWorkValue += self::$library_version_bugfix;

        if( count($numbers) == 3 )
        {
            $localValue += intval($numbers[2]);
        }

        return $frameWorkValue > $localValue;
    }

    /**
     * @param string $versionString ie: '1.2.3' or '1.5'
     * @return bool
     */
    static public function frameworkVersion_isGreaterOrEqualThan($versionString)
    {
        $numbers = explode('.',$versionString);

        if( count($numbers) < 2 || count($numbers) > 3)
            derr("'{$versionString}' is not a valid version syntax ( 'X.Y' or 'X.Y.Z' is accepted)");

        if( !is_numeric($numbers[0]) )
            derr("'{$numbers[0]}' is not a valid integer");

        if( !is_numeric($numbers[1]) )
            derr("'{$numbers[1]}' is not a valid integer");

        if( count($numbers) == 3 && !is_numeric($numbers[2]) )
            derr("'{$numbers[2]}' is not a valid integer");


        if( self::$library_version_major > intval($numbers[0]) )
            return true;

        $frameWorkValue = self::$library_version_major * 1000 * 1000;
        $localValue = intval($numbers[0]) * 1000 * 1000;

        $frameWorkValue += self::$library_version_sub * 1000;
        $localValue += intval($numbers[1]) * 1000;

        $frameWorkValue += self::$library_version_bugfix;

        if( count($numbers) == 3 )
        {
            $localValue += intval($numbers[2]);
        }

        return $frameWorkValue >= $localValue;
    }


    /**
     * will throw Exceptions instead of print errors (useful for web embeded or scrips that want
     * to support errors handling without quiting.
     */
    static public function enableExceptionSupport()
    {
        PH::$useExceptions = true;
    }

    static public function disableExceptionSupport()
    {
        PH::$useExceptions = false;
    }


    static public function enableOutputFormatting()
    {
        PH::$outputFormattingEnabled = true;
    }

    static public function disableOutputFormatting()
    {
        PH::$outputFormattingEnabled = false;
    }

    public static function processCliArgs()
    {
        global $argv;

        PH::$args = Array();

        $first = true;

        foreach( $argv as &$arg )
        {
            if( $first )
            {
                $first = false;
                continue;
            }
            $nameExplode = explode('=',$arg, 2);
            if( count($nameExplode) != 2 )
                $value = true;
            else
                $value = $nameExplode[1];

            $nameExplode[0] = strtolower($nameExplode[0]);
            $nameExplode[0] = str_ireplace( '-', '', $nameExplode[0]);

            if( isset(PH::$args[$nameExplode[0]]) )
                derr("argument '".$nameExplode[0]."' was input twice in command line");

            PH::$args[$nameExplode[0]] = $value;
        }

        //print_r(PH::$args);
    }

    /**
     * @param $str
     * @param bool $checkFileExists
     * @return string[]
     */
    public static function &processIOMethod($str, $checkFileExists)
    {
        $ret = Array('status' => 'fail' );
        $ret['filename'] = null;

        $pos = strpos($str, 'api://');
        if( $pos !== false)
        {
            PanAPIConnector::loadConnectorsFromUserHome();
            $host = substr($str, strlen('api://') );
            $hostExplode = explode('@', $host);
            if( count($hostExplode) == 1 )
            {
                $fileExplode = explode('/', $host);
                if( count($fileExplode) == 2 )
                {
                    $ret['filename'] = $fileExplode[1];
                    $host = $fileExplode[0];
                }
                $connector = PanAPIConnector::findOrCreateConnectorFromHost($host);
                $connector->setType($connector->info_deviceType);
            }
            else
            {
                $fileExplode = explode('/', $hostExplode[1]);
                if( count($fileExplode) == 2 )
                {
                    $ret['filename'] = $fileExplode[1];
                    $hostExplode[1] = $fileExplode[0];
                }

                $connector = PanAPIConnector::findOrCreateConnectorFromHost($hostExplode[1]);
                $connector->setType('panos-via-panorama', $hostExplode[0]);
            }


            $ret['status'] = 'ok';
            $ret['type'] = 'api';
            $ret['connector'] = $connector;
        }
        else
        {
            //assuming it's a file
            if( $checkFileExists && !file_exists($str) )
            {
                $ret['msg'] = 'file "'.$str.'" does not exist';
                return $ret;
            }
            $ret['status'] = 'ok';
            $ret['type'] = 'file';
            $ret['filename'] = $str;
        }

        return $ret;

    }

    /**
     * @param string $text
     * @return int
     */
    static public function versionFromString($text)
    {
        if( $text === null )
            derr('null is not supported');

        if( !is_string($text) )
            derr('only string is supported as input');


        $explode = explode('.',$text);
        if( count($explode) != 3 )
            derr('unsupported versioning: '.$text );

        $ret = $explode[0]*10 + $explode[1];

        return $ret;
    }

    /**
     * @param string|ReferenceableObject[] $array
     * @return string
     */
    static public function list_to_string(&$array, $separator = ',')
    {
        $ret = '';
        $first = true;

        foreach($array as &$el)
        {
            if( $first )
            {
                $first = false;
                if( is_string($el) )
                    $ret .= $el;
                else
                    $ret .= $el->name();
            }
            else
            {
                if( is_string($el) )
                    $ret .= $separator.$el;
                else
                    $ret .= $separator.$el->name();
            }

        }

        return $ret;

    }

    static public function &boldText($msg)
    {
        $term = getenv('TERM');

        if( $term === false || strpos($term, 'xterm') === false || ! PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[1m".$msg."\033[0m";

        return $msg;
    }

    static public function &underlineText($msg)
    {
        $term = getenv('TERM');

        if( $term === false || strpos($term, 'xterm') === false || ! PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[4m".$msg."\033[0m";

        return $msg;
    }

    static public function &italicText($msg)
    {
        $term = getenv('TERM');

        if( $term === false || strpos($term, 'xterm') === false || ! PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[3m".$msg."\033[0m";

        return $msg;
    }

    static public function &strikethroughText($msg)
    {
        $term = getenv('TERM');

        if( $term === false || strpos($term, 'xterm') === false || ! PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[9m".$msg."\033[0m";

        return $msg;
    }

    static public function &coloredText($msg, $foreground_color='red', $background_color='grey')
    {
        $term = getenv('TERM');

        $color_array = array(   "black" => "\033[30m",
                                "red" => "\033[31m",
                                "green" => "\033[32m",
                                "yellow" => "\033[33m",
                                "blue" => "\033[34m",
                                "magenta" => "\033[35m",
                                "cyan" => "\033[36m",
                                "white" => "\033[37m",
                                "grey" => "\033[47m"
                            );

        if( $term === false || strpos($term, 'xterm') === false || ! PH::$outputFormattingEnabled )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = $color_array[$foreground_color].$color_array[$background_color].$msg."\033[0m";

        return $msg;
    }




    /**
     * @param $panConfObject
     * @return PANConf|PanoramaConf
     * @throws Exception
     */
    public static function findRootObjectOrDie($panConfObject)
    {
        while(true)
        {
            $class = get_class($panConfObject);
            if( $class == 'PANConf' || $class == 'PanoramaConf' )
                return $panConfObject;

            if( isset($panConfObject->owner) && is_object($panConfObject->owner) )
                $panConfObject = $panConfObject->owner;
            else
                break;

        }

        derr("cannot find PanoramaConf or PANConf object");
    }

    /**
     * @param $panConfObject
     * @return PANConf|PanoramaConf|DeviceGroup|VirtualSystem
     * @throws Exception
     */
    public static function findLocationObjectOrDie($panConfObject)
    {
        while(true)
        {
            $class = get_class($panConfObject);
            if( $class == 'PANConf' || $class == 'PanoramaConf' || $class == 'DeviceGroup' || $class == 'VirtualSystem' )
                return $panConfObject;

            if( isset($panConfObject->owner) && is_object($panConfObject->owner) )
                $panConfObject = $panConfObject->owner;
            else
                break;

        }

        derr("cannot find PanoramaConf or PANConf object");
    }

    /**
     * @param $panConfObject
     * @return PANConf|PanoramaConf|DeviceGroup|VirtualSystem
     * @throws Exception
     */
    public static function findLocationObject($panConfObject)
    {
        while(true)
        {
            $class = get_class($panConfObject);
            if( $class == 'PANConf' || $class == 'PanoramaConf' || $class == 'DeviceGroup' || $class == 'VirtualSystem' )
                return $panConfObject;

            if( isset($panConfObject->owner) && is_object($panConfObject->owner) )
                $panConfObject = $panConfObject->owner;
            else
                return null;

        }
    }

    /**
     * @param PathableName $panConfObject
     * @return string
     * @throws Exception
     */
    public static function getLocationString($panConfObject)
    {
        /** @var PANConf|PanoramaConf|DeviceGroup|VirtualSystem $panConfObject */
        while(true)
        {
            $class = get_class($panConfObject);
            if( $class == 'PANConf' || $class == 'PanoramaConf' )
                return 'shared';
            if( $class == 'DeviceGroup' || $class == 'VirtualSystem' )
                return $panConfObject->name();

            if( isset($panConfObject->owner) && is_object($panConfObject->owner) )
                $panConfObject = $panConfObject->owner;
            else
                return false;

        }
    }

    /**
     * @param string $filename
     * @return PANConf|PanoramaConf
     */
    public static function getPanObjectFromConf($filename)
    {
        if( !file_exists($filename) )
            derr("cannot find file '{$filename}'");

        $doc = new DOMDocument();

        if( $doc->load($filename) !== TRUE )
            derr('Invalid XML file found');

        $xpathResults = DH::findXPath('/config/panorama', $doc);

        $panObject = null;

        if( $xpathResults->length > 0 )
            $panObject = new PanoramaConf();
        else
            $panObject = new PANConf();

        $panObject->load_from_domxml($doc);

        return $panObject;
    }

}

foreach( $argv as $argIndex => $arg )
{
    $arg = strtolower($arg);
    if( $arg == 'shadow-disableoutputformatting')
    {
        PH::disableOutputFormatting();
        unset($argv[$argIndex]);
        $argc--;
        continue;
    }
    elseif( $arg == 'shadow-enablexmlduplicatesdeletion' )
    {
        PH::$enableXmlDuplicatesDeletion = true;
        unset($argv[$argIndex]);
        $argc--;
        continue;
    }
    elseif( $arg == 'shadow-ignoreinvalidaddressobjects' )
    {
        PH::$ignoreInvalidAddressObjects = true;
        unset($argv[$argIndex]);
        $argc--;
        continue;
    }
}
unset($argIndex);
unset($arg);