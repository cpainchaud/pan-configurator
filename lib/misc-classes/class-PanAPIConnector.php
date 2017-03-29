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

/**
 * This class will allow you interact with PANOS API
 *
 *
 * Code :
 *
 *  $con = PanAPIConnector::findOrCreateConnectorFromHost( 'fw1.company.com' );
 *  $infos = $con->getSoftwareVersion();
 *  print "Platform: ".$infos['type']." Version: ".$infos['version'];
 *  $pan = new PANConf()
 *
 *  $pan->API_load_from_candidate();
 *
 */
class PanAPIConnector
{
    public $name = 'connector';

    /** @var string */
    public $apikey;
    /** @var string */
    public $apihost;

    public $isPANOS = 1;

    /** @var null */
    public $serial = null;

    /** @var integer */
    public $port = 443;

    /** @var bool */
    public $showApiCalls = FALSE;

    /**
     * @var PanAPIConnector[]
     */
    static public $savedConnectors = Array();
    static private $keyStoreFileName = '.panconfkeystore';
    static private $keyStoreInitialized = FALSE;

    /** @var null|string $info_deviceType can be "panorama" or "panos" (firewall) */
    public $info_deviceType = null;
    /** @var null|string $info_PANOS_version ie: "7.1.2" */
    public $info_PANOS_version = null;
    /** @var null|int $info_PANOS_version_int integer that represents product OS version, bugfix release is ignore. ie: 7.1.4 -> 71 , 5.0.6 -> 50 */
    public $info_PANOS_version_int = null;
    /** @var null|bool $info_multiVSYS true if firewall multi-vsys is enabled */
    public $info_multiVSYS = null;
    /** @var null|string $info_serial product serial number. ie: "00C734556" */
    public $info_serial = null;
    /** @var null|string $info_hostname device hostname. ie: "PA-200" */
    public $info_hostname = null;
    /** @var string $info_model can be unknown|m100|m500|pa200|pa500|pa2020|PA2050|PA3020|PA3050|PA3060|PA4020|PA4060|PA..... */
    public $info_model = 'unknown';
    /** @var string $info_vmlicense can be unknown|VM-100|VM-200|VM-300|VM-1000 */
    public $info_vmlicense = null;

    private $_curl_handle = null;
    private $_curl_count = 0;

    /**
     * @param bool $force Force refresh instead of using cache
     * @throws Exception
     */
    public function refreshSystemInfos($force = FALSE)
    {
        if( $force )
        {
            $this->info_deviceType = null;
            $this->info_PANOS_version = null;
            $this->info_PANOS_version_int = null;
            $this->info_multiVSYS = null;
            $this->info_serial = null;
            $this->info_hostname = null;
            $this->info_vmlicense = null;
        }

        if( $this->info_serial !== null )
            return;

        $cmd = '<show><system><info></info></system></show>';
        $res = $this->sendOpRequest($cmd, TRUE);

        $orig = $res;
        $res = DH::findFirstElement('result', $res);
        if( $res === FALSE )
            derr('cannot find <result>:' . DH::dom_to_xml($orig, 0, TRUE, 2));
        $res = DH::findFirstElement('system', $res);
        if( $res === FALSE )
            derr('cannot find <system>');


        $version = DH::findFirstElement('sw-version', $res);
        if( $version === FALSE )
            derr("cannot find <sw-version>:\n" . DH::dom_to_xml($orig, 0, TRUE, 4));
        $this->info_PANOS_version = $version->textContent;

        $serial = DH::findFirstElement('serial', $res);
        if( $serial === FALSE )
            derr("cannot find <serial>:\n" . DH::dom_to_xml($orig, 0, TRUE, 4));
        $this->info_serial = $serial->textContent;

        $hostname = DH::findFirstElement('hostname', $res);
        if( $hostname === FALSE )
            derr("cannot find <hostname>:\n" . DH::dom_to_xml($orig, 0, TRUE, 4));
        $this->info_hostname = $hostname->textContent;

        $model = DH::findFirstElement('model', $res);
        if( $model === FALSE )
            derr('cannot find <model>', $orig);
        $this->info_model = $model->nodeValue;

        $model = strtolower($this->info_model);

        if( $model === 'pa-vm' )
        {
            $vmlicense = DH::findFirstElement('vm-license', $res);
            if( $vmlicense === FALSE )
                derr('cannot find <vm-license>', $orig);
            $this->info_vmlicense = $vmlicense->nodeValue;
        }

        if( $model == 'panorama' || $model == 'm-100' || $model == 'm-500' )
        {
            $this->info_deviceType = 'panorama';
        }
        else
        {
            $this->info_deviceType = 'panos';
        }

        $vex = explode('.', $this->info_PANOS_version);
        if( count($vex) != 3 )
            derr("ERROR! Unsupported PANOS version :  " . $version . "\n\n");

        $this->info_PANOS_version_int = $vex[0] * 10 + $vex[1] * 1;

        if( $this->info_deviceType == 'panos' )
        {
            $multi = DH::findFirstElement('multi-vsys', $res);
            if( $multi === FALSE )
                derr('cannot find <multi-vsys>', $orig);

            $multi = strtolower($multi->textContent);
            if( $multi == 'on' )
                $this->info_multiVSYS = TRUE;
            elseif( $multi == 'off' )
                $this->info_multiVSYS = FALSE;
            else
                derr("unsupported multi-vsys mode: {$multi}");
        }
    }

    /**
     * @return string[]  Array('type'=> panos|panorama,  'version'=>61 ) (if PANOS=6.1)
     */
    public function getSoftwareVersion()
    {
        if( $this->info_PANOS_version === null )
            $this->refreshSystemInfos();

        return Array('type' => $this->info_deviceType, 'version' => $this->info_PANOS_version_int);
    }

    static public function loadConnectorsFromUserHome()
    {
        if( self::$keyStoreInitialized )
            return;

        self::$keyStoreInitialized = TRUE;

        if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
        {
            if( strlen(getenv('USERPROFILE')) > 0 )
                $file = getenv('USERPROFILE') . "\\" . self::$keyStoreFileName;
            elseif( strlen(getenv('HOMEDRIVE')) > 0 )
                $file = getenv('HOMEDRIVE') . "\\\\" . getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
            else
                $file = getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
        }
        else
            $file = getenv('HOME') . '/' . self::$keyStoreFileName;

        if( file_exists($file) )
        {
            $content = file_get_contents($file);
            $content = explode("\n", $content);
            foreach( $content as &$line )
            {
                if( strlen($line) < 1 ) continue;

                $parts = explode(':', $line);
                if( count($parts) != 2 )
                    continue;

                $host = explode('%', $parts[0]);

                if( count($host) > 1 )
                {
                    self::$savedConnectors[] = new PanAPIConnector($host[0], $parts[1], 'panos', null, $host[1]);
                }
                else
                    self::$savedConnectors[] = new PanAPIConnector($host[0], $parts[1]);
            }
        }
    }

    static public function saveConnectorsToUserHome()
    {
        $content = '';
        foreach( self::$savedConnectors as $conn )
        {
            if( $conn->port != 443 )
                $content = $content . $conn->apihost . '%' . $conn->port . ':' . $conn->apikey . "\n";
            else
                $content = $content . $conn->apihost . ':' . $conn->apikey . "\n";
        }

        if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
        {
            if( strlen(getenv('USERPROFILE')) > 0 )
                $file = getenv('USERPROFILE') . "\\" . self::$keyStoreFileName;
            elseif( strlen(getenv('HOMEDRIVE')) > 0 )
                $file = getenv('HOMEDRIVE') . "\\\\" . getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
            else
                $file = getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
        }
        else
            $file = getenv('HOME') . '/' . self::$keyStoreFileName;

        file_put_contents($file, $content);
    }

    /**
     * @param string $host
     * @param string $apiKey
     * @param bool $promptForKey
     * @param bool $checkConnectivity
     * @return PanAPIConnector
     */
    static public function findOrCreateConnectorFromHost($host, $apiKey = null, $promptForKey = TRUE, $checkConnectivity = TRUE)
    {
        self::loadConnectorsFromUserHome();

        /** @var PanAPIConnector $connector */

        $host = strtolower($host);
        $port = 443;

        $hostExplode = explode(':', $host);
        if( count($hostExplode) > 1 )
        {
            $port = $hostExplode[1];
            $host = $hostExplode[0];
        }

        $wrongLogin = FALSE;

        foreach( self::$savedConnectors as $connector )
        {
            if( $connector->apihost == $host && ($port === null && $connector->port == 443 || $port !== null && $connector->port == $port) )
            {
                $exceptionUse = PH::$useExceptions;
                PH::$useExceptions = TRUE;

                try
                {
                    $connector->getSoftwareVersion();
                } catch(Exception $e)
                {
                    PH::$useExceptions = $exceptionUse;
                    $wrongLogin = TRUE;

                    if( strpos($e->getMessage(), "Invalid credentials.") === FALSE )
                        derr($e->getMessage());

                }
                PH::$useExceptions = $exceptionUse;

                if( !$wrongLogin )
                    return $connector;

                break;
            }
        }

        if( $apiKey === null && $promptForKey === FALSE && $wrongLogin == TRUE )
            derr('API host/key not found and apiKey is blank + promptForKey is disabled');


        if( $apiKey !== null )
        {
            $connector = new PanAPIConnector($host, $apiKey, 'panos', null, $port);
        }
        elseif( $promptForKey )
        {
            if( $wrongLogin )
                print "** Request API access to host '$host' but invalid credentials were detected'\n";
            else
                print "** Request API access to host '$host' but API was not found in cache.\n";

            print "** Please enter API key or username below and hit enter:  ";


            $handle = fopen("php://stdin", "r");
            $line = fgets($handle);
            $apiKey = trim($line);

            if( strlen($apiKey) < 19 )
            {
                $user = $apiKey;
                print "* you input user '$user' , please enter password now: ";
                $line = fgets($handle);
                $password = trim($line);

                print "* Now generating an API key from '$host'...";
                $con = new PanAPIConnector($host, '', 'panos', null, $port);

                $url = "type=keygen&user=" . urlencode($user) . "&password=" . urlencode($password);
                $res = $con->sendRequest($url);

                $res = DH::findFirstElement('response', $res);
                if( $res === FALSE )
                    derr('missing <response> from API answer');

                $res = DH::findFirstElement('result', $res);
                if( $res === FALSE )
                    derr('missing <result> from API answer');

                $res = DH::findFirstElement('key', $res);
                if( $res === FALSE )
                    derr('unsupported response from PANOS API');

                $apiKey = $res->textContent;

                print "OK, key is $apiKey\n\n";

            }

            fclose($handle);

            if( $wrongLogin )
                $connector->apikey = $apiKey;
            else
                $connector = new PanAPIConnector($host, $apiKey, 'panos', null, $port);
        }


        if( $checkConnectivity )
        {
            $connector->testConnectivity();
            if( !$wrongLogin )
                self::$savedConnectors[] = $connector;
            self::saveConnectorsToUserHome();
        }

        return $connector;
    }

    public function testConnectivity()
    {
        print " Testing API connectivity... ";

        $this->refreshSystemInfos();

        print "OK!\n";

    }


    public function toString()
    {
        if( $this->serial !== null )
            $ret = get_class($this) . ':' . $this->apihost . '@' . $this->serial;
        else
            $ret = get_class($this) . ':' . $this->apihost;

        return $ret;
    }

    public function setShowApiCalls($yes)
    {
        $this->showApiCalls = $yes;
    }

    public function setType($type, $serial = null)
    {
        $type = strtolower($type);

        if( $type == 'panos' || $type == 'panos-via-panorama' )
        {
            $this->isPANOS = 1;
            if( $type == 'panos-via-panorama' )
            {
                if( $serial === null )
                    derr('panos-via-panorama type requires a serial number');
                $this->serial = $serial;
            }
        }
        elseif( $type == 'panorama' )
        {
            $this->isPANOS = 0;
        }
        else
            derr('unsupported type: ' . $type);
    }

    /**
     * @param string $host
     * @param string $key
     * @param string $type can be 'panos' 'panorama' or 'panos-via-panorama'
     * @param integer $port
     * @param string|null $serial
     */
    public function __construct($host, $key, $type = 'panos', $serial = null, $port = 443)
    {
        $this->setType($type, $serial);

        $this->apikey = $key;
        $this->apihost = $host;
        $this->port = $port;
    }

    /**
     * @param string $serial serial of the firewall you want to reach through Panorama
     * @return PanAPIConnector
     */
    public function cloneForPanoramaManagedDevice($serial)
    {
        return new PanAPIConnector($this->apihost, $this->apikey, 'panos-via-panorama', $serial, $this->port);
    }


    /**
     * @param string|string[] $ips
     * @param string|string[] $users
     * @param string $vsys
     * @param int $timeout
     * @return mixed
     */
    public function userIDLogin($ips, $users, $vsys = 'vsys1', $timeout = 3600)
    {
        if( is_string($ips) && is_string($users) )
        {
            $ips = Array($ips);
            $users = Array($users);
        }
        elseif( is_string($ips) )
        {
            derr('single IP provided but several users');
        }
        elseif( is_string($ips) )
        {
            derr('single user provided but several IPs');
        }
        elseif( count($ips) != count($users) )
        {
            derr('IPs and Users are not same numbers');
        }

        $ipsIndex = array_keys($ips);
        $usersIndex = array_keys($users);

        $cmd = '<uid-message><version>1.0</version><type>update</type><payload><login>';

        for( $i = 0; $i < count($ips); $i++ )
        {
            $cmd .= '<entry name="' . $users[$usersIndex[$i]] . '" ip="' . $ips[$ipsIndex[$i]] . '" timeout="' . $timeout . '"></entry>';;
        }
        $cmd .= '</login></payload></uid-message>';

        $params = Array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, TRUE);

    }

    /**
     * @param string|string[] $ips
     * @param string|string[] $users
     * @param string $vsys
     * @param int $timeout
     * @return mixed
     */
    public function userIDLogout($ips, $users, $vsys = 'vsys1', $timeout = 3600)
    {
        if( is_string($ips) && is_string($users) )
        {
            $ips = Array($ips);
            $users = Array($users);
        }
        elseif( is_string($ips) )
        {
            derr('single IP provided but several users');
        }
        elseif( is_string($ips) )
        {
            derr('single user provided but several IPs');
        }
        elseif( count($ips) != count($users) )
        {
            derr('IPs and Users are not same numbers');
        }

        $ipsIndex = array_keys($ips);
        $usersIndex = array_keys($users);

        $cmd = '<uid-message><version>1.0</version><type>update</type><payload><logout>';

        for( $i = 0; $i < count($ips); $i++ )
        {
            $cmd .= '<entry name="' . $users[$usersIndex[$i]] . '" ip="' . $ips[$ipsIndex[$i]] . '" timeout="' . $timeout . '"></entry>';;
        }
        $cmd .= '</logout></payload></uid-message>';

        $params = Array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, TRUE);

    }


    /**
     * @param string[] $ips
     * @param string[] $tags
     * @param string $vsys
     * @param int $timeout
     * @return DomDocument
     */
    public function register_tagIPsWithTags($ips, $tags, $vsys = 'vsys1', $timeout = 3600)
    {
        $cmd = '<uid-message><version>1.0</version><type>update</type><payload><register>';

        foreach( $ips as $ip )
        {
            $cmd .= "<entry ip=\"$ip\"><tag>";
            foreach( $tags as $tag )
            {
                $cmd .= "<member>$tag</member>";
            }
            $cmd .= '</tag></entry>';
        }
        $cmd .= '</register></payload></uid-message>';

        $params = Array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, TRUE);
    }

    /**
     * @param string[][] $register ie: Array( '1.1.1.1' => Array('tag1', 'tag3'), '2.3.4.5' => Array('tag7') )
     * @param string[][] $unregister ie: Array( '1.1.1.1' => Array('tag1', 'tag3'), '2.3.4.5' => Array('tag7') )
     * @param string $vsys
     * @param int $timeout
     * @return DomDocument
     */
    public function register_sendUpdate($register = null, $unregister = null, $vsys = 'vsys1', $timeout = 3600)
    {
        $cmd = '<uid-message><version>1.0</version><type>update</type><payload>';

        if( $register !== null )
        {
            $cmd .= '<register>';
            foreach( $register as $ip => &$tags )
            {
                $cmd .= "<entry ip=\"$ip\"><tag>";
                foreach( $tags as $tag )
                {
                    $cmd .= "<member>$tag</member>";
                }
                $cmd .= '</tag></entry>';
            }
            $cmd .= '</register>';
        }

        if( $unregister !== null )
        {
            $cmd .= '<unregister>';
            foreach( $unregister as $ip => &$tags )
            {
                $cmd .= "<entry ip=\"$ip\">";
                if( $tags !== null && count($tags) > 0 )
                {
                    $cmd .= '<tag>';
                    foreach( $tags as $tag )
                    {
                        $cmd .= "<member>$tag</member>";
                    }
                    $cmd .= '</tag>';
                }
                $cmd .= '</entry>';
            }
            $cmd .= '</unregister>';
        }

        $cmd .= '</payload></uid-message>';

        $params = Array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, TRUE);
    }

    /**
     * @param string $vsys
     * @return string[][] $registered ie: Array( '1.1.1.1' => Array('tag1', 'tag3'), '2.3.4.5' => Array('tag7') )
     */
    public function register_getIp($vsys = 'vsys1')
    {
        $cmd = "<show><object><registered-ip><all></all></registered-ip></object></show>";

        $params = Array();
        $params['type'] = 'op';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        $r = $this->sendRequest($params, TRUE);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $ip_array = array();
        foreach( $configRoot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            /** @var DOMElement $node */
            $ip = $node->getAttribute('ip');
            $members = $node->getElementsByTagName('member');

            foreach( $members as $member )
            {
                /** @var DOMElement $member */
                $ip_array[$ip][$member->nodeValue] = $member->nodeValue;
            }
        }
        return $ip_array;
    }


    /**
     * @param string $parameters
     * @param bool $checkResultTag
     * @param string|null $filecontent
     * @param string $filename
     * @param array $moreOptions
     * @return DomDocument
     */
    public function sendRequest(&$parameters, $checkResultTag = FALSE, &$filecontent = null, $filename = '', $moreOptions = Array())
    {
        $sendThroughPost = FALSE;

        if( is_array($parameters) )
            $sendThroughPost = TRUE;

        if( (PHP_MAJOR_VERSION <= 5 && PHP_MINOR_VERSION < 5) || $this->_curl_handle === null || $this->_curl_count > 100 )
        {
            if( $this->_curl_handle !== null )
                curl_close($this->_curl_handle);

            $this->_curl_handle = curl_init();
            $this->_curl_count = 0;
        }
        else
        {
            curl_reset($this->_curl_handle);
            $this->_curl_count++;
        }

        curl_setopt($this->_curl_handle, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYHOST, FALSE);
        if( defined('CURL_SSLVERSION_TLSv1') ) // for older versions of PHP/openssl bundle
            curl_setopt($this->_curl_handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);

        $host = $this->apihost;
        if( $this->port != 443 )
            $host .= ':' . $this->port;

        if( isset($this->serial) && $this->serial !== null )
        {
            if( $this->port == 80 )
                $finalUrl = 'http://' . $host . '/api/';
            else
                $finalUrl = 'https://' . $host . '/api/';

            if( !$sendThroughPost )
                $finalUrl .= '?key=' . urlencode($this->apikey) . '&target=' . $this->serial;
        }
        else
        {
            if( $this->port == 80 )
                $finalUrl = 'http://' . $host . '/api/';
            else
                $finalUrl = 'https://' . $host . '/api/';
            if( !$sendThroughPost )
                $finalUrl .= '?key=' . urlencode($this->apikey);
        }

        if( !$sendThroughPost )
        {
            //$url = str_replace('#', '%23', $parameters);
            $finalUrl .= '&' . $parameters;
        }

        curl_setopt($this->_curl_handle, CURLOPT_URL, $finalUrl);

        if( isset($moreOptions['timeout']) )
            curl_setopt($this->_curl_handle, CURLOPT_CONNECTTIMEOUT, $moreOptions['timeout']);
        else
            curl_setopt($this->_curl_handle, CURLOPT_CONNECTTIMEOUT, 7);

        curl_setopt($this->_curl_handle, CURLOPT_LOW_SPEED_LIMIT, 500);
        if( isset($moreOptions['lowSpeedTime']) )
            curl_setopt($this->_curl_handle, CURLOPT_LOW_SPEED_TIME, $moreOptions['lowSpeedTime']);
        else
            curl_setopt($this->_curl_handle, CURLOPT_LOW_SPEED_TIME, 60);


        if( $sendThroughPost )
        {
            if( isset($this->serial) && $this->serial !== null )
            {
                $parameters['target'] = $this->serial;
            }
            $parameters['key'] = $this->apikey;
            $properParams = http_build_query($parameters);
            curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS, $properParams);
        }

        if( $filecontent !== null )
        {
            $encodedContent = "----ABC1234\r\n"
                . "Content-Disposition: form-data; name=\"file\"; filename=\"" . $filename . "\"\r\n"
                . "Content-Type: application/xml\r\n"
                . "\r\n"
                . $filecontent . "\r\n"
                . "----ABC1234--\r\n";

            //print "content length = ".strlen($content)."\n";
            curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, Array('Content-Type: multipart/form-data; boundary=--ABC1234'));
            curl_setopt($this->_curl_handle, CURLOPT_POST, TRUE);
            curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS, $encodedContent);
        }

        //$this->showApiCalls = true;
        if( $this->showApiCalls )
        {
            if( $sendThroughPost )
            {
                $paramURl = '?';
                foreach( $parameters as $paramIndex => &$param )
                {
                    $paramURl .= '&' . $paramIndex . '=' . str_replace('#', '%23', $param);
                }

                print("API call through POST: \"" . $finalUrl . $paramURl . "\"\r\n");
                print "RAW HTTP POST Content: {$properParams}\n\n";
            }
            else
                print("API call: \"" . $finalUrl . "\"\r\n");
        }

        $httpReplyContent = curl_exec($this->_curl_handle);
        if( $httpReplyContent === false )
        {
            derr('Could not retrieve URL: ' . $finalUrl . ' because of the following error: ' . curl_error($this->_curl_handle));
        }

        $curlHttpStatusCode = curl_getinfo($this->_curl_handle, CURLINFO_HTTP_CODE);
        if( $curlHttpStatusCode != 200 )
        {
            derr("HTTP API returned (code : {$curlHttpStatusCode}); " . curl_exec($this->_curl_handle));
        }

        $xmlDoc = new DOMDocument();
        if( !$xmlDoc->loadXML($httpReplyContent, LIBXML_PARSEHUGE) )
            derr('Invalid xml input :' . $httpReplyContent);

        $firstElement = DH::firstChildElement($xmlDoc);
        if( $firstElement === FALSE )
            derr('cannot find any child Element in xml');

        $statusAttr = DH::findAttribute('status', $firstElement);

        if( $statusAttr === FALSE )
        {
            derr('XML response has no "status" field: ' . DH::dom_to_xml($firstElement));
        }

        if( $statusAttr != 'success' )
        {
            //var_dump($statusAttr);
            derr('API reported a failure: "' . $statusAttr . "\" with the following addition infos: " . $firstElement->nodeValue);
        }

        if( $filecontent !== null )
        {
            return $xmlDoc;
        }
        if( !$checkResultTag )
        {
            return $xmlDoc;
        }

        //$cursor = &searchForName('name', 'result', $xmlarr['children']);
        $cursor = DH::findFirstElement('result', $firstElement);

        if( $cursor === FALSE )
        {
            derr('XML API response has no <result> field', $xmlDoc);
        }

        DH::makeElementAsRoot($cursor, $xmlDoc);
        return $xmlDoc;
    }

    public function &sendExportRequest($category)
    {
        $sendThroughPost = FALSE;

        $host = $this->apihost;
        if( $this->port != 443 )
            $host .= ':' . $this->port;

        if( isset($this->serial) && $this->serial !== null )
        {
            $finalUrl = 'https://' . $host . '/api/';
            if( !$sendThroughPost )
                $finalUrl .= '?key=' . $this->apikey . '&target=' . $this->serial;
        }
        else
        {
            $finalUrl = 'https://' . $host . '/api/';
            if( !$sendThroughPost )
                $finalUrl .= '?key=' . $this->apikey;
        }

        if( !$sendThroughPost )
        {
            $finalUrl .= '&type=export&category=' . $category;
        }


        $c = new mycurl($finalUrl, FALSE);


        if( $sendThroughPost )
        {
            if( isset($this->serial) && $this->serial !== null )
            {
                $parameters['target'] = $this->serial;
            }
            $parameters['key'] = $this->apikey;
            $parameters['category'] = $category;
            $parameters['type'] = 'export';
            $properParams = http_build_query($parameters);
            $c->setPost($properParams);
        }

        if( $this->showApiCalls )
        {
            if( $sendThroughPost )
            {
                $paramURl = '?';
                foreach( $parameters as $paramIndex => &$param )
                {
                    $paramURl .= '&' . $paramIndex . '=' . str_replace('#', '%23', $param);
                }

                print("API call through POST: \"" . $finalUrl . '?' . $paramURl . "\"\r\n");
            }
            else
                print("API call: \"" . $finalUrl . "\"\r\n");
        }


        if( !$c->createCurl() )
        {
            derr('Could not retrieve URL: ' . $finalUrl . ' because of the following error: ' . $c->last_error);
        }


        if( $c->getHttpStatus() != 200 )
        {
            derr('HTTP API ret: ' . $c->__tostring());
        }

        $string = $c->__tostring();

        return $string;
    }


    public function &getReport($req)
    {
        $ret = $this->sendRequest($req);

        //print DH::dom_to_xml($ret, 0, true, 4);

        $cursor = DH::findXPathSingleEntryOrDie('/response', $ret);
        $cursor = DH::findFirstElement('result', $cursor);

        if( $cursor === FALSE )
        {
            $cursor = DH::findFirstElement('report', DH::findXPathSingleEntryOrDie('/response', $ret));
            if( $cursor === FALSE )
                derr("unsupported API answer");

            $report = DH::findFirstElement('result', $cursor);
            if( $report === FALSE )
                derr("unsupported API answer");

        }

        if( !isset($report) )
        {

            $cursor = DH::findFirstElement('job', $cursor);

            if( $cursor === FALSE )
                derr("unsupported API answer, no JOB ID found");

            $jobid = $cursor->textContent;

            while( TRUE )
            {
                sleep(1);
                $query = '&type=report&action=get&job-id=' . $jobid;
                $ret = $this->sendRequest($query);
                //print DH::dom_to_xml($ret, 0, true, 5);

                $cursor = DH::findFirstElement('result', DH::findXPathSingleEntryOrDie('/response', $ret));

                if( $cursor === FALSE )
                    derr("unsupported API answer", $ret);

                $jobcur = DH::findFirstElement('job', $cursor);

                if( $jobcur === FALSE )
                    derr("unsupported API answer", $ret);

                $percent = DH::findFirstElement('percent', $jobcur);

                if( $percent == FALSE )
                    derr("unsupported API answer", $cursor);

                if( $percent->textContent != '100' )
                {
                    sleep(9);
                    continue;
                }

                $cursor = DH::findFirstElement('report', $cursor);

                if( $cursor === FALSE )
                    derr("unsupported API answer", $ret);

                $report = $cursor;

                break;

            }
        }
        $ret = Array();

        foreach( $report->childNodes as $line )
        {
            if( $line->nodeType != XML_ELEMENT_NODE )
                continue;

            $newline = Array();

            foreach( $line->childNodes as $item )
            {
                if( $item->nodeType != XML_ELEMENT_NODE )
                    continue;
                /** @var DOMElement $item */

                $newline[$item->nodeName] = $item->textContent;
            }

            $ret[] = $newline;
        }

        //print_r($ret);

        return $ret;
    }


    public function getRunningConfig()
    {
        $url = 'action=show&type=config&xpath=/config';

        $r = $this->sendRequest($url, TRUE);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === FALSE )
            derr("<config> was not found", $r);

        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }

    public function getMergedConfig()
    {
        $r = $this->sendOpRequest('<show><config><merged/></config></show>', FALSE);

        $configRoot = DH::findFirstElement('response', $r);
        if( $configRoot === FALSE )
            derr("<response> was not found", $r);

        $configRoot = DH::findFirstElement('result', $configRoot);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === FALSE )
            derr("<config> was not found", $r);

        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }

    public function getPanoramaPushedConfig()
    {
        $url = 'action=get&type=config&xpath=/config/panorama';

        $r = $this->sendRequest($url, TRUE);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('panorama', $configRoot);
        if( $configRoot === FALSE )
            derr("<panorama> was not found", $r);

        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }

    public function getCandidateConfig($apiTimeOut = 60)
    {
        return $this->getSavedConfig('candidate-config', $apiTimeOut);
    }

    public function getCandidateConfigAlt()
    {
        $doc = new DOMDocument();
        $doc->loadXML($this->sendExportRequest('configuration'), LIBXML_PARSEHUGE);
        return $doc;
    }

    public function getSavedConfig($configurationName, $apiTimeOut = 60)
    {
        //$url = 'action=get&type=config&xpath=/config';
        $url = "<show><config><saved>$configurationName</saved></config></show>";

        $r = $this->sendCmdRequest($url, TRUE, $apiTimeOut);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === FALSE )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === FALSE )
            derr("<config> was not found", $r);

        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }


    /**
     * @param $xpath string|XmlConvertible
     * @param $element string
     * @param $useChildNodes bool if $element is an object then don't use its root but its childNodes to generate xml
     * @return DomDocument
     */
    public function sendSetRequest($xpath, $element, $useChildNodes = FALSE, $timeout = 30)
    {
        $params = Array();
        $moreOptions = Array('timeout' => $timeout, 'lowSpeedTime' => 0);

        if( is_string($element) )
        {

        }
        elseif( is_object($element) )
        {
            if( $useChildNodes )
                $element = &$element->getChildXmlText_inline();
            else
                $element = &$element->getXmlText_inline();
        }

        $params['type'] = 'config';
        $params['action'] = 'set';
        $params['xpath'] = &$xpath;
        $params['element'] = &$element;

        return $this->sendSimpleRequest($params, $moreOptions);
    }


    public function sendSimpleRequest(&$request, $options = Array())
    {
        $file = null;
        return $this->sendRequest($request, FALSE, $file, '', $options);
    }

    /**
     * @param $xpath string
     * @param $element string|XmlConvertible|DOMElement
     * @param $useChildNodes bool if $element is an object then don't use its root but its childNodes to generate xml
     * @return DomDocument
     */
    public function sendEditRequest($xpath, $element, $useChildNodes = FALSE, $timeout = 30)
    {
        $params = Array();
        $moreOptions = Array('timeout' => $timeout, 'lowSpeedTime' => 0);

        if( is_object($xpath) )
            derr('unsupported yet');

        if( is_string($element) )
        {

        }
        elseif( is_object($element) )
        {
            $elementClass = get_class($element);

            if( $elementClass === 'DOMElement' )
            {
                /** @var DOMElement $element */
                if( $useChildNodes )
                    $element = DH::domlist_to_xml($element->childNodes, -1, FALSE);
                else
                    $element = DH::dom_to_xml($element, -1, FALSE);
            }
            else
            {
                if( $useChildNodes )
                    $element = $element->getChildXmlText_inline();
                else
                    $element = $element->getXmlText_inline();
            }
        }

        $params['type'] = 'config';
        $params['action'] = 'edit';
        $params['xpath'] = &$xpath;
        $params['element'] = &$element;

        return $this->sendSimpleRequest($params, $moreOptions);
    }

    public function sendDeleteRequest($xpath)
    {
        $params = Array();

        $params['type'] = 'config';
        $params['action'] = 'delete';
        $params['xpath'] = &$xpath;

        return $this->sendRequest($params);
    }

    /**
     * @param string $xpath
     * @param string $newname
     * @return DomDocument
     */
    public function sendRenameRequest($xpath, $newname)
    {
        $params = Array();

        $params['type'] = 'config';
        $params['action'] = 'rename';
        $params['xpath'] = &$xpath;
        $params['newname'] = &$newname;

        return $this->sendRequest($params);
    }

    /**
     * @param string $cmd operational command string
     * @param bool $stripResponseTag
     * @return DomDocument
     */
    public function sendOpRequest($cmd, $stripResponseTag = TRUE)
    {
        $params = Array();

        $params['type'] = 'op';
        $params['cmd'] = $cmd;

        return $this->sendRequest($params, $stripResponseTag);
    }

    public function waitForJobFinished($jobID)
    {
        $res = $this->getJobResult($jobID);

        while( $res == 'PEND' )
        {
            sleep(20);
            $res = $this->getJobResult($jobID);
        }

        return $res;


    }

    /**
     * @param $cmd string
     * @param $checkResultTag bool
     * @param $maxWaitTime integer
     * @return DomDocument|string[]
     */
    public function sendCmdRequest($cmd, $checkResultTag = TRUE, $maxWaitTime = -1)
    {
        $req = "type=op&cmd=$cmd";
        if( $maxWaitTime == -1 )
            $moreOptions['lowSpeedTime'] = null;
        else
            $moreOptions['lowSpeedTime'] = $maxWaitTime;

        $nullVar = null;

        $ret = $this->sendRequest($req, $checkResultTag, $nullVar, '', $moreOptions);

        return $ret;
    }

    public function getJobResult($jobID)
    {
        $req = "type=op&cmd=<show><jobs><id>$jobID</id></jobs></show>";
        $ret = $this->sendRequest($req);


        $found = &searchForName('name', 'result', $ret);

        if( $found === null )
        {
            derr('unsupported API answer');
        }

        $found = &searchForName('name', 'job', $found['children']);

        if( $found === null )
        {
            derr('no job id found!');
        }

        $found = &searchForName('name', 'result', $found['children']);

        if( $found === null )
        {
            derr('unsupported API answer');
        }

        return $found['content'];
    }

    public function sendJobRequest($request)
    {
        $ret = $this->sendRequest($request);

        //var_dump($ret);

        $found = &searchForName('name', 'result', $ret);

        if( $found === null )
        {
            derr('unsupported API answer');
        }

        $found = &searchForName('name', 'job', $found['children']);

        if( $found === null )
        {
            derr('no job id found!');
        }

        else return $found['content'];

    }

    /**
     *   send a config to the firewall and save under name $config_name
     *
     * @param DOMNode $configDomXml
     * @param string $configName
     * @param bool $verbose
     * @return DOMNode
     */
    public function uploadConfiguration($configDomXml, $configName = 'stage0.xml', $verbose = TRUE)
    {
        if( $verbose )
            print "Uploadig config to device {$this->apihost}/{$configName}....";

        $url = "&type=import&category=configuration&category=configuration";

        $answer = $this->sendRequest($url, FALSE, DH::dom_to_xml($configDomXml), $configName, Array('timeout' => 7));

        if( $verbose )
            print "OK!\n";

        return $answer;
    }

    /**
     * @return string[][]  ie: Array( Array('serial' => '000C12234', 'hostname' => 'FW-MUNICH4' ) )
     */
    public function & panorama_getConnectedFirewallsSerials()
    {
        $result = $this->sendCmdRequest('<show><devices><connected/></devices></show>');
        $devicesRoot = DH::findXPathSingleEntryOrDie('/result/devices', $result);

        $firewalls = Array();

        foreach( $devicesRoot->childNodes as $entryNode )
        {
            $fw = Array();

            if( $entryNode->nodeType != XML_ELEMENT_NODE )
                continue;
            /** @var DOMElement $entryNode */

            $hostnameNode = DH::findFirstElement('hostname', $entryNode);
            if( $hostnameNode !== false )
                $fw['hostname'] = $hostnameNode->textContent;
            else
                $fw['hostname'] = $entryNode->getAttribute('name');

            $fw['serial'] = $entryNode->getAttribute('name');

            $firewalls[$fw['serial']] = $fw;
        }

        return $firewalls;
    }
    
}



