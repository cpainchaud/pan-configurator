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

    /**
     * @var string
     */
	public $apikey;
    /**
     * @var string
     */
	public $apihost;
	public $isPANOS = 1;

    /**
     * @var null
     */
    public $serial = null;

    /**
     * @var integer
     */
    public $port = 443;

    /**
     * @var bool
     */
    public $showApiCalls=false;

    /**
     * @var PanAPIConnector[]
     */
    static private $savedConnectors = Array();
    static private $keyStoreFileName = '.panconfkeystore';
    static private $keyStoreInitialized = false;

    /**
     * @return string[]  Array('type'=> pano|panorama,  'version'=>61 ) (if PANOS=6.1)
     */
    public function getSoftwareVersion()
    {
        $result = Array();

        $url = "type=op&cmd=<show><system><info></info></system></show>";
        $res = $this->sendRequest($url, true);
        $orig = $res;
        $res = DH::findFirstElement('result', $res);
        if ($res === false )
            derr('cannot find <result>:'.DH::dom_to_xml($orig,0,true,2));
        $res = DH::findFirstElement('system', $res);
        if ($res === false )
            derr('cannot find <system>');


        $version = DH::findFirstElement('sw-version', $res);
        if ($version === false )
            derr("cannot find <sw-version>:\n".DH::dom_to_xml($orig,0,true,4));

        $version = $version->nodeValue;

        $model = DH::findFirstElement('model', $res);
        if ($model === false )
            derr('cannot find <model>');

        $model = $model->nodeValue;

        if ($model == 'Panorama')
        {
            $result['type'] = 'panorama';
            //print "Panorama found!\n";
        } else
        {
            $result['type'] = 'panos';
            //print "PANOS found!\n";
        }

        $vex = explode('.', $version);
        if (count($vex) != 3)
            derr("ERROR! Unsupported PANOS version :  " . $version . "\n\n");

        $result['version'] = $vex[0] * 10 + $vex[1] * 1;

        return $result;
    }

    static public function loadConnectorsFromUserHome()
    {
        if( self::$keyStoreInitialized )
            return;

        self::$keyStoreInitialized = true;

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
        {
            if( strlen(getenv('USERPROFILE')) > 0)
                $file = getenv('USERPROFILE') . "\\" . self::$keyStoreFileName;
            elseif( strlen(getenv('HOMEDRIVE')) > 0)
                $file = getenv('HOMEDRIVE') . "\\\\" . getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
            else
                $file = getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
        }
        else
            $file = getenv('HOME').'/'.self::$keyStoreFileName;

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
                    self::$savedConnectors[] = new PanAPIConnector($host[0], $parts[1], 'panos', null, $host[1] );
                }
                else
                    self::$savedConnectors[] = new PanAPIConnector($host[0], $parts[1] );
            }
        }
    }

    static public function saveConnectorsToUserHome()
    {
        $content = '';
        foreach( self::$savedConnectors as $conn )
        {
            if( $conn->port != 443 )
                $content = $content.$conn->apihost.'%'.$conn->port.':'.$conn->apikey."\n";
            else
                $content = $content.$conn->apihost.':'.$conn->apikey."\n";
        }

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
        {
            if( strlen(getenv('USERPROFILE')) > 0)
                $file = getenv('USERPROFILE') . "\\" . self::$keyStoreFileName;
            elseif( strlen(getenv('HOMEDRIVE')) > 0)
                $file = getenv('HOMEDRIVE') . "\\\\" . getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
            else
                $file = getenv('HOMEPATH') . "\\" . self::$keyStoreFileName;
        }
        else
            $file = getenv('HOME').'/'.self::$keyStoreFileName;

        file_put_contents($file, $content);
    }

    /**
     * @param string $host
     * @param string $apiKey
     * @param bool $promptForKey
     * @param bool $checkConnectivity
     * @return PanAPIConnector
     */
    static public function findOrCreateConnectorFromHost($host, $apiKey = null, $promptForKey = true, $checkConnectivity = true)
    {
        self::loadConnectorsFromUserHome();

        $host = strtolower($host);
        $port = 443;

        $hostExplode = explode(':', $host);
        if( count($hostExplode) > 1 )
        {
            $port = $hostExplode[1];
            $host = $hostExplode[0];
        }


        foreach( self::$savedConnectors as $connector )
        {
            if( $connector->apihost == $host && ($port === null && $connector->port == 443 || $port !== null && $connector->port == $port) )
            {
                return $connector;
            }
        }

        if( $apiKey === null && $promptForKey === false )
            derr('API host/key not found and apiKey is blank + promptForKey is disabled');


        if( $apiKey !== null )
        {
            $connection = new PanAPIConnector($host, $apiKey, 'panos', null, $port);
        }
        elseif( $promptForKey )
        {
            print "** Request API access to host '$host' but API was not found in cache.\n".
                "** Please enter API key or username below and hit enter:  ";
            $handle = fopen ("php://stdin","r");
            $line = fgets($handle);
            $apiKey = trim($line);

            if( strlen($apiKey) < 19)
            {
                $user = $apiKey;
                print "* you input user '$user' , please enter password now: ";
                $line = fgets($handle);
                $password = trim($line);

                print "* Now generating an API key from '$host'...";
                $con = new PanAPIConnector($host, '', 'panos', null, $port);

                $url = "type=keygen&user=".urlencode($user)."&password=".urlencode($password);
                $res = $con->sendRequest($url);

                $res = DH::findFirstElement('response', $res);
                if ($res === false)
                    derr('missing <response> from API answer');

                $res = DH::findFirstElement('result', $res);
                if ($res === false)
                    derr('missing <result> from API answer');

                $res = DH::findFirstElement('key', $res);
                if ($res === false)
                    derr('unsupported response from PANOS API');

                $apiKey = $res->textContent;

                print "OK, key is $apiKey\n\n";

            }

            fclose($handle);

            $connection = new PanAPIConnector($host, $apiKey, 'panos', null, $port);
        }


        if( $checkConnectivity)
        {
            $connection->testConnectivity();
            self::$savedConnectors[] = $connection;
            self::saveConnectorsToUserHome();
        }

        return $connection;
    }

    public function testConnectivity()
    {
        print " Testing API connectivity: ";

        $res = $this->sendOpRequest("<show><system><info></info></system></show>");

        $res = DH::findFirstElement('response', $res);
        if ($res === false)
            derr('missing <response> from API answer');

        $res = DH::findFirstElement('result', $res);
        if ($res === false)
            derr('missing <result> from API answer');

        print "OK!\n";

    }

	
	public function toString()
	{
        if( $this->serial !== null )
            $ret = get_class($this).':'.$this->apihost.'@'.$this->serial;
        else
            $ret = get_class($this).':'.$this->apihost;

		return $ret;
	}

    public function setShowApiCalls($yes)
    {
        $this->showApiCalls = $yes;
    }

    public function setType($type, $serial=null)
    {
        $type = strtolower($type);

        if( $type == 'panos' || $type == 'panos-via-panorama' )
        {
            $this->isPANOS = 1;
           if( $type == 'panos-via-panorama' )
           {
               if( $serial === null )
                   derr('panos-via-panorama type requires a serial number' );
               $this->serial = $serial;
           }
        }
        elseif($type == 'panorama')
        {
            $this->isPANOS = 0;
        }
        else
            derr('unsupported type: '.$type);
    }

    /**
     * @param string $host
     * @param string $key
     * @param string $type can be 'panos' 'panorama' or 'panos-via-panorama'
     * @param integer $port
     * @param string|null $serial
     */
	public function __construct( $host, $key, $type = 'panos', $serial = null, $port = 443)
	{
		$this->setType($type, $serial);
		
		$this->apikey = $key;
		$this->apihost = $host;
        $this->port = $port;
	}


    /**
     * @param string|string[] $ips
     * @param string|string[] $users
     * @param string $vsys
     * @param int $timeout
     * @return mixed
     */
    public function userIDLogin( $ips, $users, $vsys = 'vsys1', $timeout = 3600 )
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

        for( $i=0; $i<count($ips); $i++ )
        {
            $cmd .= '<entry name="'.$users[$usersIndex[$i]].'" ip="'.$ips[$ipsIndex[$i]].'" timeout="'.$timeout.'"></entry>';;
        }
        $cmd .= '</login></payload></uid-message>';

        $params = Array();
        $params['type'] = 'user-id';
        $params['action'] = 'set';
        $params['vsys'] = $vsys;
        $params['cmd'] = &$cmd;

        return $this->sendRequest($params, true);

    }


    public function registerIPsWithTags( $ips, $tags, $vsys = 'vsys1', $timeout = 3600 )
    {
        $cmd = '<uid-message><version>1.0</version><type>update</type><payload><register>';

        foreach($ips as $ip)
        {
            $cmd .= "<entry ip=\"$ip\"><tag>";
            foreach($tags as $tag)
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

        return $this->sendRequest($params, true);
    }


    /**
     * @param string $parameters
     * @param bool $checkResultTag
     * @param string|null $filecontent
     * @param string $filename
     * @param Array $moreOptions
     * @return DomDocument
     */
	public function sendRequest(&$parameters, $checkResultTag=false, &$filecontent=null, $filename = '', $moreOptions=Array())
	{

        $sendThroughPost = false;

        if( is_array($parameters) )
            $sendThroughPost = true;

        $host = $this->apihost;
        if( $this->port != 443 )
            $host .= ':'.$this->port;

        if( isset($this->serial) && $this->serial !== null )
        {
            if($this->port == 80 )
                $finalUrl = 'http://'.$host.'/api/';
            else
                $finalUrl = 'https://'.$host.'/api/';

            if( !$sendThroughPost )
             $finalUrl .= '?key='.urlencode($this->apikey).'&target='.$this->serial;
        }
        else
        {
            if($this->port == 80 )
                $finalUrl = 'http://' . $host . '/api/';
            else
                $finalUrl = 'https://' . $host . '/api/';
            if( !$sendThroughPost )
                $finalUrl .= '?key=' . urlencode($this->apikey);
        }

        if( !$sendThroughPost )
        {
            $url = str_replace('#', '%23',$parameters);
            $finalUrl .= '&'.$parameters;
        }


        if( isset($moreOptions['timeout']) )
            $timeout = $moreOptions['timeout'];
        else
            $timeout = 7;

        $c = new mycurl($finalUrl, false, $timeout);

        if( array_key_exists('lowSpeedTime', $moreOptions ) )
        {
            $c->_lowspeedtime = $moreOptions['lowSpeedTime'];
        }


        if( $filecontent !== null )
        {
            $c->setInfile($filecontent, $filename);
        }

        if( $sendThroughPost )
        {
            if( isset($this->serial) && $this->serial !== null )
            {
                $parameters['target'] = $this->serial;
            }
            $parameters['key'] = $this->apikey;
            $properParams = http_build_query($parameters);
            $c->setPost($properParams);
        }

        //$this->showApiCalls = true;

        if( $this->showApiCalls )
        {
            if( $sendThroughPost)
            {
                $paramURl = '?';
                foreach( $parameters as $paramIndex => &$param )
                {
                    $paramURl .= '&'.$paramIndex.'='.str_replace('#', '%23',$param);
                }

                print("API call through POST: \"".$finalUrl.$paramURl."\"\r\n");
                print "RAW HTTP POST Content: $properParams\n\n";
            }
            else
                print("API call: \"".$finalUrl."\"\r\n");
        }


		if( ! $c->createCurl() )
		{
			derr('Could not retrieve URL: '.$finalUrl.' because of the following error: '.$c->last_error);
		}


        if( $c->getHttpStatus() != 200 )
        {
            derr("HTTP API ret (code : {$c->getHttpStatus()})".$c->__tostring());
        }

        $xmlDoc = new DOMDocument();
        if( ! $xmlDoc->loadXML($c->__tostring(), LIBXML_PARSEHUGE) )
            derr('Invalid xml input :'.$c->__tostring() );

        $firstElement = DH::firstChildElement($xmlDoc);
        if( $firstElement === false )
            derr('cannot find any child Element in xml');

        $statusAttr = DH::findAttribute('status', $firstElement);

        if( $statusAttr === false )
        {
            derr('XML response has no "status" field: ' . DH::dom_to_xml($firstElement));
        }

        if($statusAttr != 'success')
        {
            var_dump($statusAttr);

            derr('API reported a failure: "'.$statusAttr."\"with the following addition infos: ". $firstElement->nodeValue);
        }

        if ( $filecontent !== null )
        {
            return $xmlDoc;
        }
        if (!$checkResultTag)
        {
            return $xmlDoc;
        }

        //$cursor = &searchForName('name', 'result', $xmlarr['children']);
        $cursor = DH::findFirstElement('result', $firstElement);

        if(  $cursor === false )
        {
            derr('XML API response has no <result> field', $xmlDoc);
        }

        DH::makeElementAsRoot($cursor, $xmlDoc);
        return $xmlDoc;
	}

    public function &sendExportRequest($category)
    {
        $sendThroughPost = false;

        $host = $this->apihost;
        if( $this->port != 443 )
            $host .= ':'.$this->port;

        if( isset($this->serial) && $this->serial !== null )
        {
            $finalUrl = 'https://'.$host.'/api/';
            if( !$sendThroughPost )
                $finalUrl .= '?key='.$this->apikey.'&target='.$this->serial;
        }
        else
        {
            $finalUrl = 'https://' . $host . '/api/';
            if( !$sendThroughPost )
                $finalUrl .= '?key=' . $this->apikey;
        }

        if( !$sendThroughPost )
        {
            $finalUrl .= '&type=export&category='.$category;
        }


        $c = new mycurl($finalUrl, false);


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
            if( $sendThroughPost)
            {
                $paramURl = '?';
                foreach( $parameters as $paramIndex => &$param )
                {
                    $paramURl .= '&'.$paramIndex.'='.str_replace('#', '%23',$param);
                }

                print("API call through POST: \"".$finalUrl.'?'.$paramURl."\"\r\n");
            }
            else
                print("API call: \"".$finalUrl."\"\r\n");
        }


        if( ! $c->createCurl() )
        {
            derr('Could not retrieve URL: '.$finalUrl.' because of the following error: '.$c->last_error);
        }


        if( $c->getHttpStatus() != 200 )
        {
            derr('HTTP API ret: '.$c->__tostring());
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

        if( $cursor === false )
        {
            $cursor = DH::findFirstElement('report', DH::findXPathSingleEntryOrDie('/response', $ret));
            if( $cursor === false )
                derr("unsupported API answer");

            $report = DH::findFirstElement('result', $cursor);
            if( $report === false )
                derr("unsupported API answer");

        }

        if( !isset($report) )
        {

            $cursor = DH::findFirstElement('job', $cursor);

            if( $cursor === false )
                derr("unsupported API answer, no JOB ID found");

            $jobid = $cursor->textContent;

            while( true )
            {
                sleep(1);
                $query = '&type=report&action=get&job-id='.$jobid;
                $ret = $this->sendRequest($query);
                //print DH::dom_to_xml($ret, 0, true, 5);

                $cursor = DH::findFirstElement('result', DH::findXPathSingleEntryOrDie('/response', $ret));
                
                if( $cursor === false )
                    derr("unsupported API answer", $ret);

                $jobcur = DH::findFirstElement('job', $cursor);

                if( $jobcur === false )
                    derr("unsupported API answer", $ret);

                $percent = DH::findFirstElement('percent', $jobcur);

                if( $percent == false )
                    derr("unsupported API answer", $cursor);

                if( $percent->textContent != '100')
                {
                    sleep(9);
                    continue;
                }

                $cursor = DH::findFirstElement('report', $cursor);

                if( $cursor === false )
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

        $r = $this->sendRequest($url, true);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === false )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === false )
            derr("<config> was not found", $r);

        DH::makeElementAsRoot($configRoot, $r);

        return $r;
	}

    public function getMergedConfig()
    {
        $r = $this->sendOpRequest('<show><config><merged/></config></show>');

        $configRoot = DH::findFirstElement('response', $r);
        if( $configRoot === false )
            derr("<response> was not found", $r);

        $configRoot = DH::findFirstElement('result', $configRoot);
        if( $configRoot === false )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === false )
            derr("<config> was not found", $r);

        DH::makeElementAsRoot($configRoot, $r);

        return $r;
    }

    public function getCandidateConfig($apiTimeOut=60)
    {
        return $this->getSavedConfig('candidate-config', $apiTimeOut);
    }

    public function getCandidateConfigAlt()
    {
        $doc = new DOMDocument();
        $doc->loadXML($this->sendExportRequest('configuration'), LIBXML_PARSEHUGE);
        return $doc;
    }

    public function getSavedConfig($configurationName, $apiTimeOut=60)
    {
        //$url = 'action=get&type=config&xpath=/config';
        $url = "<show><config><saved>$configurationName</saved></config></show>";

        $r = $this->sendCmdRequest($url, true, $apiTimeOut);

        $configRoot = DH::findFirstElement('result', $r);
        if( $configRoot === false )
            derr("<result> was not found", $r);

        $configRoot = DH::findFirstElement('config', $configRoot);
        if( $configRoot === false )
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
    public function sendSetRequest($xpath, $element, $useChildNodes=false, $timeout = 30)
    {
        $params = Array();
        $moreOptions = Array( 'timeout' => $timeout, 'lowSpeedTime' => 0);

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

        $params['type']  = 'config';
        $params['action']  = 'set';
        $params['xpath']  = &$xpath;
        $params['element']  = &$element;

        return $this->sendSimpleRequest($params, $moreOptions);
    }


    public function sendSimpleRequest(&$request, $options=Array())
    {
        $file = null;
        return $this->sendRequest($request, false, $file, '', $options);
    }

    /**
     * @param $xpath string
     * @param $element string|XmlConvertible|DOMElement
     * @param $useChildNodes bool if $element is an object then don't use its root but its childNodes to generate xml
     * @return DomDocument
     */
    public function sendEditRequest($xpath, $element, $useChildNodes=false, $timeout = 30)
    {
        $params = Array();
        $moreOptions = Array( 'timeout' => $timeout, 'lowSpeedTime' => 0);

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
                if ($useChildNodes)
                    $element = DH::domlist_to_xml($element->childNodes, -1, false);
                else
                    $element = DH::dom_to_xml($element, -1, false);
            }
            else
            {
                if ($useChildNodes)
                    $element = $element->getChildXmlText_inline();
                else
                    $element = $element->getXmlText_inline();
            }
        }

        $params['type']  = 'config';
        $params['action']  = 'edit';
        $params['xpath']  = &$xpath;
        $params['element']  = &$element;

        return $this->sendSimpleRequest($params, $moreOptions);
    }

    public function sendDeleteRequest($xpath)
    {
        $params = Array();

        $params['type']  = 'config';
        $params['action']  = 'delete';
        $params['xpath']  = &$xpath;

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

        $params['type']  = 'config';
        $params['action']  = 'rename';
        $params['xpath']  = &$xpath;
        $params['newname']  = &$newname;

        return $this->sendRequest($params);
    }

    /**
     * @param string $cmd
     * @return DomDocument
     */
    public function sendOpRequest($cmd)
    {
        $params = Array();

        $params['type']  = 'op';
        $params['cmd']  = $cmd;

        return $this->sendRequest($params);
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
    public function sendCmdRequest($cmd, $checkResultTag = true, $maxWaitTime = -1)
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
     *
     * @param DOMNode $configDomXml
     * @param string $configName
     * @param bool $verbose
     * @return DOMNode
     */
    public function uploadConfiguration( $configDomXml, $configName = 'stage0.xml', $verbose = true )
    {
        if( $verbose )
            print "Uploadig config to device {$this->apihost}/{$configName}....";

        $url = "&type=import&category=configuration&category=configuration";

        $answer = $this->sendRequest($url, false, DH::dom_to_xml($configDomXml), $configName, Array('timeout'=>7) );

        if( $verbose )
            print "OK!\n";

        return $answer;
    }
}


/**
* @ignore
*/
class mycurl
{ 
     protected $_useragent = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1'; 
     protected $_url; 
     protected $_followlocation; 
     protected $_timeout; 
     protected $_maxRedirects; 
     protected $_cookieFileLocation = './cookie.txt'; 
     protected $_post; 
     protected $_postFields; 
     protected $_referer ="http://panapiconnector"; 

     protected $_session; 
     protected $_webpage; 
     protected $_includeHeader; 
     protected $_noBody; 
     protected $_status; 
     protected $_binaryTransfer;

     protected $_infilecontent;
     protected $_infilename;

     public $_lowspeedtime = 60;

     public    $authentication = 0; 
     public    $auth_name      = ''; 
     public    $auth_pass      = ''; 

     public function useAuth($use){ 
       $this->authentication = 0; 
       if($use == true) $this->authentication = 1; 
     } 

     public function setName($name){ 
       $this->auth_name = $name; 
     } 
     public function setPass($pass){ 
       $this->auth_pass = $pass; 
     } 

     public function __construct($url,$followlocation = false,$timeOut = 30,$maxRedirecs = 4,$binaryTransfer = false,$includeHeader = false,$noBody = false) 
     { 
         $this->_url = $url; 
         $this->_followlocation = $followlocation; 
         $this->_timeout = $timeOut; 
         $this->_maxRedirects = $maxRedirecs; 
         $this->_noBody = $noBody; 
         $this->_includeHeader = $includeHeader; 
         $this->_binaryTransfer = $binaryTransfer; 
         $this->_infilecontent = null;

         $this->_cookieFileLocation = dirname(__FILE__).'/cookie.txt'; 

     } 

     public function setReferer($referer){ 
       $this->_referer = $referer; 
     } 

     public function setCookiFileLocation($path) 
     { 
         $this->_cookieFileLocation = $path; 
     } 

     public function setPost (&$postFields) 
     { 
        $this->_post = true; 
        $this->_postFields = &$postFields; 
     } 

     public function setUserAgent($userAgent) 
     { 
         $this->_useragent = $userAgent; 
     } 

     public function createCurl(&$url = 'nul') 
     { 
        if($url != 'nul'){ 
          $this->_url = $url; 
        } 

         $s = curl_init(); 

         curl_setopt($s,CURLOPT_URL, str_replace(' ', '%20',$this->_url) ); 
         //curl_setopt($s,CURLOPT_HTTPHEADER,array('Expect:')); 
         curl_setopt($s,CURLOPT_CONNECTTIMEOUT,$this->_timeout);
         curl_setopt($s,CURLOPT_TIMEOUT,3600);

         if( $this->_lowspeedtime !== null )
         {
             curl_setopt($s,CURLOPT_LOW_SPEED_LIMIT,500);
             curl_setopt($s, CURLOPT_LOW_SPEED_TIME, $this->_lowspeedtime);
         }

         curl_setopt($s,CURLOPT_MAXREDIRS,$this->_maxRedirects); 
         curl_setopt($s,CURLOPT_RETURNTRANSFER,true); 
         curl_setopt($s,CURLOPT_FOLLOWLOCATION,$this->_followlocation);
        
         //curl_setopt($s,CURLOPT_COOKIEJAR,$this->_cookieFileLocation); 
         //curl_setopt($s,CURLOPT_COOKIEFILE,$this->_cookieFileLocation); 

         if($this->authentication == 1){ 
           curl_setopt($s, CURLOPT_USERPWD, $this->auth_name.':'.$this->auth_pass); 
         } 
         if($this->_post) 
         { 
            curl_setopt($s,CURLOPT_POSTFIELDS,$this->_postFields); 
         } 

         if($this->_includeHeader) 
         { 
               curl_setopt($s,CURLOPT_HEADER,true); 
         } 

         if($this->_noBody) 
         { 
             curl_setopt($s,CURLOPT_NOBODY,true); 
         } 
         /* 
         if($this->_binary) 
         { 
             curl_setopt($s,CURLOPT_BINARYTRANSFER,true); 
         } 
         */ 
         curl_setopt($s,CURLOPT_USERAGENT,$this->_useragent); 
         curl_setopt($s,CURLOPT_REFERER,$this->_referer); 
         
         curl_setopt($s,CURLOPT_SSL_VERIFYPEER,false);
         curl_setopt($s,CURLOPT_SSL_VERIFYHOST,false);
         curl_setopt($s,CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
         //curl_setopt($s,CURLOPT_VERBOSE, 1); 


         if( $this->_infilecontent !== null )
         {

            $content =  "----ABC1234\r\n"
                        . "Content-Disposition: form-data; name=\"file\"; filename=\"".$this->_infilename."\"\r\n"
                        . "Content-Type: application/xml\r\n"
                        . "\r\n"
                        . $this->_infilecontent . "\r\n"
                        . "----ABC1234--\r\n";

            //print "content length = ".strlen($content)."\n";            
            curl_setopt($s, CURLOPT_HTTPHEADER, Array('Content-Type: multipart/form-data; boundary=--ABC1234') );
            curl_setopt($s, CURLOPT_POST, true); 
            curl_setopt($s, CURLOPT_POSTFIELDS, $content);

         }

         $er = curl_exec($s);
         
         if( $er === FALSE )
         {
         	 $this->last_error = curl_error($s);
         	 return false;
         }
         
         $this->_webpage = $er; 
         
         
         $this->_status = curl_getinfo($s,CURLINFO_HTTP_CODE); 
         curl_close($s); 
         
         return true;

     } 

   public function getHttpStatus() 
   { 
       return $this->_status; 
   } 

   public function setInfile( &$fc, $filename )
   {
        $this->_infilecontent = &$fc;
        $this->_infilename = $filename;
   }

   public function __tostring(){ 
      return $this->_webpage; 
   }
}


