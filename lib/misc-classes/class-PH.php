<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
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

    /**
     * will throw Exceptions instead of print errors (useful for web embeded or scrips that want
     * to support errors handling without quiting.
     */
    public function enableExceptionSupport()
    {
        PH::$useExceptions = true;
    }

    public function disableExceptionSupport()
    {
        PH::$useExceptions = false;
    }

    /**
     * enables faster but very experimental DomXML support in Pan Configurator
     */
    static public function enableDomXMLSupport()
    {
        self::$UseDomXML = true;
        mwarning('this function is deprecated');
    }

    /**
     * disable DOM XML to switch back to old library (but can trigger unpredictable errors)
     */
    static public function disableDomXMLSupport()
    {
        self::$UseDomXML = false;
        print "\n\nWARNING, disabling DOM XML support can trigger unpredictable errors\n\n";
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
                derr("argument '".PH::$args[$nameExplode[0]]."' was input twice in command line");

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
    static public function &list_to_string(&$array)
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
                    $ret .= ','.$el;
                else
                    $ret .= ','.$el->name();
            }

        }

        return $ret;

    }

    static public function &boldText($msg)
    {
        $term = getenv('TERM');

        if( $term === false || strpos($term, 'xterm') === false )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[1m".$msg."\033[0m";

        return $msg;
    }

}

foreach( $argv as $argIndex => &$arg )
{
    if( $arg == 'shadow-disabledomxml')
    {
        PH::disableDomXMLSupport();
        unset($argv[$argIndex]);
        unset($argIndex);
        unset($arg);
        $argc--;
        break;
    }
}